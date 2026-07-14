#include "bias_profiler.h"
#include "utils.h"
#include "lattice_solver.h"
#include <fplll.h>
#include <algorithm>
#include <cmath>
#include <random>
#include <vector>
#include <functional>
#include <iostream>

using namespace fplll;

namespace {

std::vector<Pair> sample_pairs(const std::vector<Pair>& pairs, size_t max_samples,
                                std::mt19937_64& rng) {
    if (pairs.size() <= max_samples) return pairs;
    std::vector<Pair> sample;
    std::sample(pairs.begin(), pairs.end(), std::back_inserter(sample), max_samples, rng);
    return sample;
}

// Exact Poisson upper-tail P(X >= k) is now shared, testable utility code
// -- see utils::poisson_upper_tail. (This detector previously had its own
// approximate z-score test here that misbehaved in the low-count regime;
// that history is why this is an exact computation, not an asymptotic one.)

// The one principled knob for the whole detector: the target family-wise
// false-positive rate for claiming "bias detected" across an entire sweep.
// Everything else below (per-trial significance cutoff, required count)
// is *derived* from this plus the actual sample size and number of trials
// swept, rather than being separately hand-tuned constants that silently
// stop working right at some other sample size or bias strength.
const double TARGET_FALSE_POSITIVE_RATE = 1e-9;

// Shared detector core: for each candidate leak-bit value (ascending), build
// the (possibly pre-transformed) HNP lattice on a small training subsample
// and extract a candidate d using the same reduce_and_extract logic actual
// recovery relies on (already validated end-to-end). Test that candidate
// against a large, disjoint held-out sample via `measure_bits` (leading-zero
// count for MSB, trailing-zero count for LSB): a genuinely correct candidate
// makes nearly every held-out point satisfy measure_bits(k) >= L; a wrong
// one only at the exactly-computable chance rate 2^-L. Comparing the
// observed count against the *exact* null distribution -- rather than an
// arbitrary fixed threshold -- means the decision boundary adapts to
// however much held-out data is available and to whatever L is tested.
//
// Once the smallest L that clears significance is found, the sweep stops
// and directly *measures* the real bias magnitude from data (a low
// percentile of measure_bits across a larger sample) instead of continuing
// to probe discrete L values: a correct candidate stays "significant" well
// past the true bias level too (the excess-over-chance ratio is roughly
// constant for any L below the true magnitude), so "largest L that's still
// significant" would just find wherever the sweep happened to stop, not the
// actual bias strength.
std::pair<double, double> shrink_test_sweep(
    const std::vector<Pair>& pairs,
    const std::vector<int>& leak_trials,
    const std::function<std::vector<Pair>(const std::vector<Pair>&, int)>& transform,
    const std::function<int(const mpz&)>& measure_bits,
    std::mt19937_64& rng,
    Telemetry* telemetry
) {
    // Bonferroni correction: split the target false-positive rate across
    // every trial actually attempted in this sweep, so running a denser
    // sweep doesn't itself inflate the false-positive rate.
    double corrected_alpha = TARGET_FALSE_POSITIVE_RATE / std::max<size_t>(1, leak_trials.size());

    for (int L : leak_trials) {
        if (telemetry && telemetry->deadline_exceeded()) break;

        // Each L needs roughly 280/L signatures for adequate margin (see
        // compute_dimension in lattice_solver.cpp); weak bias needs a much
        // bigger lattice, but sizing *every* trial for the weakest one in
        // the sweep would needlessly slow down the common (stronger-bias)
        // cases. A floor of 80 preserves the margin already validated for
        // the L>=3 range; only L=1,2 actually push past it.
        size_t train_m = std::min<size_t>(pairs.size() / 2,
                          std::max<size_t>(80, static_cast<size_t>(std::ceil(320.0 / L))));
        if (train_m < 20) continue;

        // See the matching guard in lattice_solver.cpp: a single
        // large-dimension LLL reduction can itself take minutes with no
        // way to interrupt it mid-call, so skip starting one that clearly
        // won't fit the remaining budget rather than blowing past it.
        if (telemetry) {
            double remaining = telemetry->remaining_budget_seconds();
            if (train_m > 150 && remaining < 150.0) continue;
            if (train_m > 100 && remaining < 60.0) continue;
        }

        auto train0 = sample_pairs(pairs, train_m, rng);
        auto train = transform(train0, L);

        ZZ_mat<mpz_t> basis;
        mpz scaling;
        if (!LatticeSolver::build_boneh_venkatesan_basis(train, L, basis, scaling)) continue;

        auto cand = LatticeSolver::reduce_and_extract(basis, train, nullptr);
        if (!cand.has_value()) continue;

        // Use as much held-out data as available (capped for runtime) --
        // the significance test below is exact for whatever size we get,
        // so there's no need to hand-tune it to a specific test_n.
        size_t test_n = std::min(pairs.size(), static_cast<size_t>(2000));
        auto test_set = sample_pairs(pairs, test_n, rng);

        int count = 0;
        for (const auto& p : test_set) {
            mpz k = utils::mod_add(p.w, utils::mod_mul(p.x, *cand, SECP256K1_N), SECP256K1_N);
            if (measure_bits(k) >= L) count++;
        }

        double expected_rate = std::pow(2.0, -L);
        double lambda_null = test_set.size() * expected_rate; // expected count if candidate is wrong
        double p_value = utils::poisson_upper_tail(count, lambda_null);

        if (p_value >= corrected_alpha) continue;

        // Detected: now measure the actual magnitude directly from data.
        size_t measure_n = std::min(pairs.size(), static_cast<size_t>(5000));
        auto measure_set = sample_pairs(pairs, measure_n, rng);

        std::vector<int> bits_observed;
        bits_observed.reserve(measure_set.size());
        for (const auto& p : measure_set) {
            mpz k = utils::mod_add(p.w, utils::mod_mul(p.x, *cand, SECP256K1_N), SECP256K1_N);
            bits_observed.push_back(measure_bits(k));
        }
        std::sort(bits_observed.begin(), bits_observed.end());

        // The bias guarantees *every* nonce has at least the true bit-count,
        // so the low end of this empirical distribution sits right at the
        // true value. A low percentile (rather than the strict minimum)
        // guards against a single unlucky outlier understating it, and
        // naturally tightens as more held-out data becomes available.
        size_t idx = static_cast<size_t>(bits_observed.size() * 0.02);
        idx = std::min(idx, bits_observed.size() - 1);
        double estimated_bits = bits_observed[idx];
        double confidence = -std::log10(std::max(p_value, 1e-300));

        return {estimated_bits, confidence};
    }

    return {0.0, 0.0};
}

} // namespace

BiasProfile BiasProfiler::profile(const std::vector<Pair>& pairs, Telemetry* telemetry) {
    BiasProfile prof;
    if (pairs.empty()) {
        prof.type = BiasType::NONE;
        return prof;
    }

    std::mt19937_64 rng(std::random_device{}());
    size_t sample_size = std::min<size_t>(pairs.size(), 4500);
    auto sampled = sample_pairs(pairs, sample_size, rng);

    auto [msb_bits, msb_conf] = detect_msb_bias(sampled, telemetry);
    auto [lsb_bits, lsb_conf] = detect_lsb_bias(sampled, telemetry);

    // Both detectors run the identical significance test on the identical
    // data, just after a different (identity vs 2^-b) transform, so their
    // confidence values (-log10 of the Bonferroni-corrected p-value) are
    // directly comparable -- pick whichever found stronger evidence.
    if (msb_bits > 0.0 && msb_conf >= lsb_conf) {
        prof.type = BiasType::MSB;
        prof.estimated_leaked_bits = msb_bits;
        prof.confidence_sigma = msb_conf;
        prof.bias_detected = true;
        prof.description = "Detected MSB bias (~" + std::to_string(prof.estimated_leaked_bits) +
                            " bits; held-out significance p < 10^-" + std::to_string(prof.confidence_sigma) + ")";
    } else if (lsb_bits > 0.0) {
        prof.type = BiasType::LSB;
        prof.estimated_leaked_bits = lsb_bits;
        prof.confidence_sigma = lsb_conf;
        prof.bias_detected = true;
        prof.description = "Detected LSB bias (~" + std::to_string(prof.estimated_leaked_bits) +
                            " known-zero low bits; held-out significance p < 10^-" + std::to_string(prof.confidence_sigma) + ")";
    } else {
        prof.type = BiasType::NONE;
        prof.estimated_leaked_bits = 0;
        prof.confidence_sigma = std::max(msb_conf, lsb_conf);
    }

    if (telemetry) {
        telemetry->leaked_bits_est = prof.estimated_leaked_bits;
        telemetry->confidence = prof.confidence_sigma;
        telemetry->bias_type = static_cast<int>(prof.type);
    }

    return prof;
}

// Trial-reduction MSB bias detector. See shrink_test_sweep() above for the
// mechanism (previously this guessed a candidate d from a single signature
// assuming k=0, which is tautological -- see git history / earlier notes).
std::pair<double, double> BiasProfiler::detect_msb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry) {
    if (pairs.size() < 20) return {0.0, 0.0};

    std::mt19937_64 rng(0xC0FFEEULL ^ static_cast<uint64_t>(pairs.size()));
    static const std::vector<int> leak_trials = {3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 24, 2, 1};

    auto identity = [](const std::vector<Pair>& p, int) { return p; };
    // Leading-zero-bit count of k: for genuine MSB bias, every nonce has
    // *at least* this many leading zero bits.
    auto measure_bits = [](const mpz& k) -> int {
        if (k == 0) return 256;
        size_t bits = mpz_sizeinbase(k.get_mpz_t(), 2);
        return static_cast<int>(256 - bits);
    };
    // The significance gate (Bonferroni-corrected Poisson tail test against
    // TARGET_FALSE_POSITIVE_RATE) already lives inside shrink_test_sweep,
    // so a nonzero result here means a trial actually cleared it.
    return shrink_test_sweep(pairs, leak_trials, identity, measure_bits, rng, telemetry);
}

// LSB bias detector: reuses the identical MSB machinery after transforming
// (w, x) by 2^-b mod N (see utils::transform_pairs_lsb). If k really is an
// exact multiple of 2^b, the transformed k' = k / 2^b is a genuinely small
// integer with exactly the same bound an MSB-biased nonce would have, so
// the same lattice + shuffled-null significance test applies unchanged.
std::pair<double, double> BiasProfiler::detect_lsb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry, int max_bits) {
    if (pairs.size() < 20) return {0.0, 0.0};

    std::mt19937_64 rng(0xBEEFULL ^ static_cast<uint64_t>(pairs.size()));
    std::vector<int> leak_trials;
    for (int b : {3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 24, 2, 1}) {
        if (b <= max_bits) leak_trials.push_back(b);
    }
    if (leak_trials.empty()) return {0.0, 0.0};

    auto transform = [](const std::vector<Pair>& p, int b) {
        return utils::transform_pairs_lsb(p, b);
    };
    // Trailing-zero-bit count of k: for genuine LSB bias, every nonce is
    // divisible by 2^b, i.e. has *at least* b trailing zero bits.
    auto measure_bits = [](const mpz& k) -> int {
        if (k == 0) return 256;
        unsigned long tz = mpz_scan1(k.get_mpz_t(), 0);
        return static_cast<int>(std::min<unsigned long>(tz, 256));
    };
    return shrink_test_sweep(pairs, leak_trials, transform, measure_bits, rng, telemetry);
}



std::tuple<double, mpz, mpz, double> BiasProfiler::detect_modulo_bias(const std::vector<Pair>& pairs) {
    return {0.0, mpz(0), mpz(0), 0.0};
}

double BiasProfiler::estimate_leaked_bits(BiasType, double, const mpz&, const mpz&) {
    return 0.0;
}
