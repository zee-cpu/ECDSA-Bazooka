#include "bias_profiler.h"
#include "utils.h"
#include "lattice_solver.h"
#include <fplll.h>
#include <algorithm>
#include <cmath>
#include <random>
#include <vector>
#include <functional>
#include <tuple>
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

// Hard ceiling on the detector's lattice-training sample size / dimension.
// Detection deliberately uses only plain LLL (no BKZ escalation), so it can
// only ever confirm bias it can resolve cheaply -- i.e. the strong/moderate
// range (L>=7). Weak/mid bias (L<=6) is NOT detected here; it is recovered
// blind via the FALLBACK path's BKZ sweep in lattice_solver.cpp instead. So
// there is no point provisioning detection past what LLL can use: kept at
// 120 to keep the common (strong-bias) detection fast. (The recovery cap is
// separate and larger -- see lattice_solver.cpp.)
constexpr size_t TRAIN_M_CAP = 120;

// Phase 6e: total number of independent train/held-out partitions available to
// the detector. A single arbitrary split can be unlucky on borderline bias --
// its training slice fails to resolve a candidate, or its held-out draw doesn't
// quite clear significance -- yielding a false negative that a different split
// would have caught. profile() uses these in two stages: stage 1 evaluates only
// partition 0 (the old single-split detector) for both hypotheses; stage 2
// evaluates partitions 1..R-1, but ONLY if stage 1 found nothing at all. So
// strong bias (found on partition 0) costs exactly one split -- no slower than
// before, and the extra partitions never touch the recovery budget -- while
// borderline / no-bias inputs get up to R independent chances (bounded by the
// run's time budget). Crucially this does NOT relax the false-positive rate:
// the Bonferroni family in shrink_test_sweep is the full R*leak_trials, so the
// family-wise TARGET_FALSE_POSITIVE_RATE holds regardless of how many
// partitions actually run.
constexpr int DETECTION_ENSEMBLE_SPLITS = 5;

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
    uint64_t base_seed,
    int r_begin,
    int r_end,
    Telemetry* telemetry
) {
    // Bonferroni correction: split the target false-positive rate across
    // every test in the *full* family -- both the L values swept AND all R
    // partitions (Phase 6e) -- even when this call only evaluates a subset of
    // partitions. Using the full R here keeps the family-wise
    // TARGET_FALSE_POSITIVE_RATE exact regardless of how profile() splits the
    // partitions across its two-phase calls or how early it stops.
    const int R = DETECTION_ENSEMBLE_SPLITS;
    double corrected_alpha =
        TARGET_FALSE_POSITIVE_RATE / std::max<size_t>(1, leak_trials.size() * R);

    for (int r = r_begin; r < r_end; ++r) {
        if (telemetry && telemetry->deadline_exceeded()) break;

        // Per-partition RNG is a pure function of (base_seed, r): partition 0
        // uses base_seed directly, reproducing the old single-split detector
        // *exactly* (zero regression), while each extra partition gets an
        // independent, deterministic seed. Deriving from (base_seed, r) rather
        // than a running stream makes the two-phase call structure in profile()
        // -- partition 0 first, extra partitions only as a fallback -- fully
        // reproducible run-to-run and independent of --seed.
        std::mt19937_64 prng(r == 0 ? base_seed
            : base_seed + 0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(r + 1));

        // Partition into disjoint training and held-out pools. Previously
        // train0/test_set/measure_set were each drawn independently from the
        // *same* full `pairs`, so for small inputs the "held-out" set could
        // equal the entire dataset, overlapping training completely -- a
        // candidate that overfits noise in a small training slice then gets
        // re-tested partly against the exact points it was fit to, which can
        // manufacture a spuriously tiny p-value for a wrong candidate.
        // Splitting once per partition and drawing every subsample from its
        // own half guarantees zero overlap regardless of input size.
        std::vector<Pair> shuffled = pairs;
        std::shuffle(shuffled.begin(), shuffled.end(), prng);
        size_t split = shuffled.size() / 2;
        std::vector<Pair> train_pool(shuffled.begin(), shuffled.begin() + split);
        std::vector<Pair> held_out_pool(shuffled.begin() + split, shuffled.end());

        for (int L : leak_trials) {
            if (telemetry && telemetry->deadline_exceeded()) break;

            // Detection sizing: LLL-only, so this only needs enough dimension
            // to confirm the strong/moderate range it can actually resolve.
            // ~320/L floored at 80, capped at TRAIN_M_CAP (weak L is left to
            // FALLBACK's BKZ recovery, not detected here).
            size_t train_m = std::min({train_pool.size(), TRAIN_M_CAP,
                              std::max<size_t>(80, static_cast<size_t>(std::ceil(320.0 / L)))});
            if (train_m < 20) continue;

            // See the matching guard in lattice_solver.cpp: a single
            // large-dimension LLL reduction can itself take minutes with no
            // way to interrupt it mid-call, so skip starting one that clearly
            // won't fit the remaining budget rather than blowing past it.
            if (telemetry) {
                double remaining = telemetry->remaining_budget_seconds();
                if (train_m > 100 && remaining < 60.0) continue;
            }

            auto train0 = sample_pairs(train_pool, train_m, prng);
            auto train = transform(train0, L);

            ZZ_mat<mpz_t> basis;
            mpz scaling;
            if (!LatticeSolver::build_boneh_venkatesan_basis(train, L, basis, scaling)) continue;

            auto cand = LatticeSolver::reduce_and_extract(basis, train, nullptr);
            if (!cand.has_value()) continue;

            // Use as much held-out data as available (capped for runtime) --
            // the significance test below is exact for whatever size we get.
            // Drawn from held_out_pool only -- disjoint from every training
            // draw above, for any L in this partition.
            size_t test_n = std::min(held_out_pool.size(), static_cast<size_t>(2000));
            auto test_set = sample_pairs(held_out_pool, test_n, prng);

            int count = 0;
            for (const auto& p : test_set) {
                mpz k = utils::mod_add(p.w, utils::mod_mul(p.x, *cand, SECP256K1_N), SECP256K1_N);
                if (measure_bits(k) >= L) count++;
            }

            double expected_rate = std::pow(2.0, -L);
            double lambda_null = test_set.size() * expected_rate; // expected count if candidate is wrong
            double p_value = utils::poisson_upper_tail(count, lambda_null);

            if (p_value >= corrected_alpha) continue;

            // This partition detected: measure the actual magnitude directly
            // from data, again from the same disjoint held-out pool.
            size_t measure_n = std::min(held_out_pool.size(), static_cast<size_t>(5000));
            auto measure_set = sample_pairs(held_out_pool, measure_n, prng);

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
            // guards against a single unlucky outlier understating it.
            size_t idx = static_cast<size_t>(bits_observed.size() * 0.02);
            idx = std::min(idx, bits_observed.size() - 1);
            double estimated_bits = bits_observed[idx];
            double confidence = -std::log10(std::max(p_value, 1e-300));

            // First partition to clear wins. Strong bias is found on partition
            // 0, so the common path costs exactly one split -- no slower than
            // the old single-split detector -- while borderline bias that an
            // unlucky split would miss gets up to R independent chances. The
            // R-widened Bonferroni above bounds the family-wise false-positive
            // rate whether we stop here or exhaust all R partitions.
            return {estimated_bits, confidence};
        }
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

    // Deterministic by default: seed from the run's configured sampling_seed
    // (fixed unless overridden via --seed) rather than std::random_device, so
    // the same input reproduces the same sampling -- and therefore the same
    // result -- on every run.
    uint64_t seed = telemetry ? telemetry->sampling_seed.load() : DEFAULT_SAMPLING_SEED;
    std::mt19937_64 rng(seed);
    size_t sample_size = std::min<size_t>(pairs.size(), 4500);
    auto sampled = sample_pairs(pairs, sample_size, rng);

    // Phase 6e detection is two-stage, to stay cheap on strong bias while
    // being thorough on borderline bias. Stage 1 evaluates only partition 0 of
    // each hypothesis -- exactly the old single-split detector -- so any input
    // that detected before detects here at the same cost, never touching the
    // recovery budget. Stage 2 runs the extra ensemble partitions, but ONLY if
    // stage 1 found nothing at all: that is the borderline/no-bias case where a
    // single unlucky split can miss genuine-but-weak bias, and where there's no
    // recovery to protect anyway. Strong bias never reaches stage 2, which is
    // what fixes the regression where a non-matching detector's ensemble ran
    // the full R-split sweep and starved recovery.
    double msb_bits, msb_conf, lsb_bits, lsb_conf;
    std::tie(msb_bits, msb_conf) = detect_msb_bias(sampled, telemetry);
    std::tie(lsb_bits, lsb_conf) = detect_lsb_bias(sampled, telemetry);
    if (msb_bits == 0.0 && lsb_bits == 0.0) {
        std::tie(msb_bits, msb_conf) = detect_msb_bias(sampled, telemetry, /*extra_splits=*/true);
        if (msb_bits == 0.0)
            std::tie(lsb_bits, lsb_conf) = detect_lsb_bias(sampled, telemetry, /*extra_splits=*/true);
    }

    // Both detectors run the identical significance test on the identical
    // data, just after a different (identity vs 2^-b) transform, so their
    // confidence values (-log10 of the Bonferroni-corrected p-value) are
    // directly comparable -- pick whichever found stronger evidence.
    if (msb_bits > 0.0 && msb_conf >= lsb_conf) {
        prof.type = BiasType::MSB;
        prof.estimated_leaked_bits = msb_bits;
        prof.neg_log10_p = msb_conf;
        prof.bias_detected = true;
        prof.description = "Detected MSB bias (~" + std::to_string(prof.estimated_leaked_bits) +
                            " bits; held-out significance p < 10^-" + std::to_string(prof.neg_log10_p) + ")";
    } else if (lsb_bits > 0.0) {
        prof.type = BiasType::LSB;
        prof.estimated_leaked_bits = lsb_bits;
        prof.neg_log10_p = lsb_conf;
        prof.bias_detected = true;
        prof.description = "Detected LSB bias (~" + std::to_string(prof.estimated_leaked_bits) +
                            " known-zero low bits; held-out significance p < 10^-" + std::to_string(prof.neg_log10_p) + ")";
    } else {
        prof.type = BiasType::NONE;
        prof.estimated_leaked_bits = 0;
        prof.neg_log10_p = std::max(msb_conf, lsb_conf);
    }

    if (telemetry) {
        telemetry->leaked_bits_est = prof.estimated_leaked_bits;
        telemetry->confidence = prof.neg_log10_p;
        telemetry->bias_type = static_cast<int>(prof.type);
    }

    return prof;
}

// Trial-reduction MSB bias detector. See shrink_test_sweep() above for the
// mechanism (previously this guessed a candidate d from a single signature
// assuming k=0, which is tautological -- see git history / earlier notes).
std::pair<double, double> BiasProfiler::detect_msb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry, bool extra_splits) {
    if (pairs.size() < 20) return {0.0, 0.0};

    // Fixed per-detector base seed (independent of --seed); shrink_test_sweep
    // derives each partition's RNG from it deterministically.
    uint64_t base = 0xC0FFEEULL ^ static_cast<uint64_t>(pairs.size());
    // L=1 excluded: see TRAIN_M_CAP comment above -- its ~320-signature
    // requirement is far past the cap, so it has no realistic chance of
    // resolving and would just burn the time budget.
    static const std::vector<int> leak_trials = {3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 24, 2};

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
    // so a nonzero result here means a trial actually cleared it. Stage 1
    // (extra_splits=false) runs partition 0; stage 2 runs partitions 1..R-1.
    int r_begin = extra_splits ? 1 : 0;
    int r_end = extra_splits ? DETECTION_ENSEMBLE_SPLITS : 1;
    return shrink_test_sweep(pairs, leak_trials, identity, measure_bits, base, r_begin, r_end, telemetry);
}

// LSB bias detector: reuses the identical MSB machinery after transforming
// (w, x) by 2^-b mod N (see utils::transform_pairs_lsb). If k really is an
// exact multiple of 2^b, the transformed k' = k / 2^b is a genuinely small
// integer with exactly the same bound an MSB-biased nonce would have, so
// the same lattice + shuffled-null significance test applies unchanged.
std::pair<double, double> BiasProfiler::detect_lsb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry, bool extra_splits, int max_bits) {
    if (pairs.size() < 20) return {0.0, 0.0};

    uint64_t base = 0xBEEFULL ^ static_cast<uint64_t>(pairs.size());
    std::vector<int> leak_trials;
    // L=1 excluded: see TRAIN_M_CAP comment above -- its ~320-signature
    // requirement is far past the cap, so it has no realistic chance of
    // resolving and would just burn the time budget.
    for (int b : {3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 24, 2}) {
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
    int r_begin = extra_splits ? 1 : 0;
    int r_end = extra_splits ? DETECTION_ENSEMBLE_SPLITS : 1;
    return shrink_test_sweep(pairs, leak_trials, transform, measure_bits, base, r_begin, r_end, telemetry);
}



std::tuple<double, mpz, mpz, double> BiasProfiler::detect_modulo_bias(
        [[maybe_unused]] const std::vector<Pair>& pairs) {
    // Phase 6c note: modulo / Extended-HNP bias IS now recovered -- but not from
    // here. Because "statistically detectable" does not imply "cryptographically
    // exploitable" for a windowed-zero nonce, the only honest confirmation is an
    // actual pubkey-verified recovery, which needs the public key (this profiler
    // has only the (w,x) pairs). So detection+recovery live together in
    // RecoveryEngine::try_modulo / LatticeSolver::recover_modulo, driven either
    // by a supplied (omega,bound) hint or `-m modulo`'s bounded sweep. This
    // profiler hook is intentionally left inert; it is not on the modulo path.
    return {0.0, mpz(0), mpz(0), 0.0};
}

double BiasProfiler::estimate_leaked_bits(BiasType, double, const mpz&, const mpz&) {
    return 0.0;
}
