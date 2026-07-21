#include "last_resort.h"
#include "lattice_solver.h"
#include "recovery_engine.h"
#include "sieve_config.h"
#include "utils.h"
#include <algorithm>
#include <cstdlib>
#include <random>
#include <string>
#include <thread>
#include <chrono>

namespace last_resort {

double stage_deadline(double overall_ceiling, double elapsed, double stage_budget) {
    double d = elapsed + stage_budget;
    if (overall_ceiling > 0.0 && d > overall_ceiling) d = overall_ceiling;
    return d;
}

std::vector<double> feasible_rungs(const sieve_estimator::MachineFacts& m) {
    std::vector<double> out;
    for (double L : sieve_ladder())
        if (sieve_estimator::estimate(L, m).feasible_here) out.push_back(L);
    return out;
}

std::vector<Pair> shared_prefix_pairs(
    const std::vector<Pair>& pairs, size_t pivot, int prefix_bits) {
    std::vector<Pair> out;
    if (prefix_bits <= 0 || prefix_bits >= 256) return out;
    if (pairs.size() < 5 || pivot >= pairs.size()) return out;  // pivot + >=4 rows
    const mpz& N = SECP256K1_N;
    mpz Bp = mpz(1) << (256 - prefix_bits);   // B' = 2^(256-P)
    const Pair& piv = pairs[pivot];
    out.reserve(pairs.size() - 1);
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i == pivot) continue;
        mpz X = (pairs[i].x - piv.x) % N; if (X < 0) X += N;
        mpz W = (pairs[i].w - piv.w + Bp) % N; if (W < 0) W += N;
        out.push_back(Pair{W, X});   // Pair{w, x}; source_index/known_low_value default
    }
    return out;
}

size_t ransac_subset_size(int L, size_t pool) {
    long base = std::lround(256.0 / std::max(1, L)) + 8;
    long lo = 24;
    long hi = std::max<long>(lo, std::min<long>(64, static_cast<long>(pool)));
    return static_cast<size_t>(std::clamp(base, lo, hi));
}

fork_pool::Work ransac_work_unit(const std::vector<Pair>& pairs,
                                 const mpz& pubkey_hint, uint64_t seed,
                                 size_t iter, int L) {
    return [&pairs, pubkey_hint, seed, iter, L]() -> std::optional<mpz> {
        size_t s = ransac_subset_size(L, pairs.size());
        if (pairs.size() < s) return std::nullopt;
        // Deterministic per (seed, iter, L): a fixed input+seed reproduces
        // the whole draw sequence and result (invariant 4). Note: std::sample's
        // selection order is implementation-defined, so reproducibility is
        // guaranteed only within one toolchain/stdlib build (which is all
        // invariant 4 requires); a stdlib change could shift which subsets are
        // drawn -- never correctness (pubkey-gated), only the draw sequence.
        std::mt19937_64 rng(seed ^ (iter * 0x9E3779B97F4A7C15ULL)
                                 ^ (static_cast<uint64_t>(L) << 1));
        std::vector<Pair> subset;
        subset.reserve(s);
        std::sample(pairs.begin(), pairs.end(), std::back_inserter(subset), s, rng);
        fplll::ZZ_mat<mpz_t> basis;
        mpz scaling;
        if (!LatticeSolver::build_boneh_venkatesan_basis(subset, L, basis, scaling))
            return std::nullopt;
        auto d = LatticeSolver::reduce_and_extract(basis, subset, nullptr, 0, pubkey_hint);
        if (d.has_value() && utils::verify_pubkey(*d, pubkey_hint)) return d;
        return std::nullopt;
    };
}
// Note: capturing `pairs` by reference is safe in the forked child -- it reads
// the child's COW copy of parent memory. `pubkey_hint` (mpz) is captured by value.

std::optional<mpz> ransac_recover(
    const std::vector<Pair>& pairs, const mpz& pubkey_hint,
    uint64_t seed, size_t max_iters,
    const std::vector<int>& l_candidates, Telemetry* tel) {
    if (pubkey_hint <= 1) return std::nullopt;   // pubkey is the consensus gate
    if (pairs.size() < 24) return std::nullopt;  // too few pairs for the HNP
    for (size_t it = 0; it < max_iters; ++it) {
        if (tel && tel->deadline_exceeded()) break;
        if (tel) tel->set_status("RANSAC resample iter " + std::to_string(it + 1));
        for (size_t li = 0; li < l_candidates.size(); ++li) {
            int L = l_candidates[li];
            auto d = ransac_work_unit(pairs, pubkey_hint, seed, it, L)();
            if (d.has_value()) return d;
        }
    }
    return std::nullopt;
}

} // namespace last_resort

std::optional<mpz> RecoveryEngine::try_shared_prefix_reuse(
    const std::vector<Pair>& pairs, const mpz& pubkey_hint) {
    if (pubkey_hint <= 1) return std::nullopt;   // pubkey is the detector/gate
    if (pairs.size() < 5) return std::nullopt;
    tel_.set_phase("last-resort: shared-prefix nonce reuse (differenced HNP)");

    size_t use = std::min(pairs.size(), last_resort::SHARED_PREFIX_MAX_SIGS);
    std::vector<Pair> slice(pairs.begin(), pairs.begin() + use);
    size_t max_pivots = std::min<size_t>(slice.size(), 3);

    for (int P : last_resort::shared_prefix_widths()) {
        if (tel_.deadline_exceeded()) break;
        for (size_t piv = 0; piv < max_pivots; ++piv) {
            if (tel_.deadline_exceeded()) break;
            std::vector<Pair> diff = last_resort::shared_prefix_pairs(slice, piv, P);
            if (diff.size() < 4) continue;
            fplll::ZZ_mat<mpz_t> basis;
            mpz scaling;
            if (!LatticeSolver::build_boneh_venkatesan_basis(diff, P - 1, basis, scaling))
                continue;   // pivot's differenced x not invertible; try next pivot
            tel_.set_status("shared-prefix: P=" + std::to_string(P) +
                            " pivot=" + std::to_string(piv));
            auto d = LatticeSolver::reduce_and_extract(basis, diff, &tel_, 0, pubkey_hint);
            if (d.has_value() && utils::verify_pubkey(*d, pubkey_hint)) {
                tel_.active_method = static_cast<int>(RecoveryMethod::AUTO);
                tel_.method_chosen = true;
                last_resort_desc_ =
                    "shared-prefix nonce reuse -- differenced HNP (no "
                    "lattice-detectable single-nonce bias)";
                return d;
            }
        }
    }
    return std::nullopt;
}

std::optional<mpz> RecoveryEngine::try_ransac_resample(
    const std::vector<Pair>& pairs, const mpz& pubkey_hint) {
    if (pubkey_hint <= 1) return std::nullopt;
    if (pairs.size() < 24) return std::nullopt;
    tel_.set_phase("last-resort: RANSAC resampling (parallel, outlier-robust)");

    double budget = tel_.remaining_budget_seconds();
    if (budget <= 0.0) return std::nullopt;  // no budget left -> don't start
                                              // (also: a negative deadline reads
                                              // as "no deadline" to the pool)

    std::vector<fork_pool::Work> works;
    works.reserve(last_resort::RANSAC_MAX_ITERS * last_resort::ransac_l_candidates().size());
    uint64_t seed = tel_.sampling_seed.load();
    for (size_t it = 0; it < last_resort::RANSAC_MAX_ITERS; ++it)
        for (int L : last_resort::ransac_l_candidates())
            works.push_back(last_resort::ransac_work_unit(pairs, pubkey_hint, seed, it, L));

    unsigned hw = std::thread::hardware_concurrency();
    size_t conc = hw ? hw : 1;

    bool any_spawned = false;
    std::optional<mpz> d;
    {
        // Fork-safety: quiesce the render thread so it is not mid-malloc at any
        // fork. RAII guard so resume_rendering() always runs, even if the pool
        // throws (e.g. bad_alloc).
        struct RenderQuiesce {
            Telemetry& t; explicit RenderQuiesce(Telemetry& tt): t(tt){ t.pause_rendering(); }
            ~RenderQuiesce(){ t.resume_rendering(); }
        } _rq(tel_);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));  // let an in-flight render_once finish
        d = fork_pool::run_until_first(works, conc, budget, &any_spawned);
    }

    if (!d.has_value() && !any_spawned) {
        // Forking unavailable (resource exhaustion) -> serial fallback so the
        // RANSAC route is never silently skipped (invariant 6). The serial path
        // is deadline-gated, so on a genuine no-recovery it is a near-no-op.
        d = last_resort::ransac_recover(pairs, pubkey_hint, seed,
                                        last_resort::RANSAC_MAX_ITERS,
                                        last_resort::ransac_l_candidates(), &tel_);
    }

    if (d.has_value() && utils::verify_pubkey(*d, pubkey_hint)) {
        tel_.active_method = static_cast<int>(RecoveryMethod::AUTO);
        tel_.method_chosen = true;
        last_resort_desc_ = "outlier-robust RANSAC resampling (parallel, fork-isolated)";
        return d;
    }
    return std::nullopt;
}

std::optional<mpz> RecoveryEngine::try_last_resort(
    const std::vector<Signature>& signatures,
    const std::vector<Pair>& pairs,
    const mpz& pubkey_hint,
    size_t max_sigs,
    double overall_ceiling)   // 0 == no overall limit (auditor / --max-time unset)
{
    if (pubkey_hint <= 1) return std::nullopt;     // predicate/gate needs a key
    tel_.set_phase("Exhaustive last-resort search (may take longer)");

    auto verified = [&](const std::optional<mpz>& c) {
        return c.has_value() && utils::verify_pubkey(*c, pubkey_hint);
    };
    auto ceiling_hit = [&]() {
        return overall_ceiling > 0.0 && tel_.elapsed_seconds() >= overall_ceiling;
    };

    // 0. Shared-prefix nonce reuse (Tier 1.2a): cheapest rung -- one LLL per
    //    (width, pivot). A group sharing a fixed unknown nonce high-part is
    //    invisible to the profiler and to repeated_nonce/LCG; the differenced
    //    HNP exposes it. Runs first; short-circuits modulo/sieve on a verified
    //    hit.
    if (!ceiling_hit()) {
        tel_.time_budget_sec = last_resort::stage_deadline(
            overall_ceiling, tel_.elapsed_seconds(), last_resort::SHARED_PREFIX_CAP_SEC);
        tel_.set_status("last-resort: shared-prefix nonce reuse");
        auto d = try_shared_prefix_reuse(pairs, pubkey_hint);
        if (verified(d)) return d;
    }

    // 0b. RANSAC resampling (Tier 1.3): outlier-robust. Draw random subsets
    //     (small s minimizes outliers/draw) and pubkey-verify; profiler-
    //     independent. Recovers light-moderate noise; heavy noise exhausts the
    //     budget without a wrong key. Cheaper/more common than modulo, so first
    //     among the lattice sweeps after shared-prefix.
    if (!ceiling_hit()) {
        tel_.time_budget_sec = last_resort::stage_deadline(
            overall_ceiling, tel_.elapsed_seconds(), last_resort::RANSAC_CAP_SEC);
        tel_.set_status("last-resort: RANSAC resampling");
        auto d = try_ransac_resample(pairs, pubkey_hint);
        if (verified(d)) return d;
    }

    // 1. Modulo/EHNP window sweep, first. Given its OWN bounded budget so
    //    recover_modulo converges rather than over-exploring; it can't be
    //    starved by the sieve ladder that follows.
    if (!ceiling_hit()) {
        tel_.time_budget_sec = last_resort::stage_deadline(
            overall_ceiling, tel_.elapsed_seconds(), last_resort::MODULO_SWEEP_SEC);
        tel_.set_status("last-resort: modulo/EHNP window sweep");
        auto d = try_modulo(pairs, mpz(0), mpz(0), max_sigs, pubkey_hint);
        if (verified(d)) return d;
    }

    // 2. Speculative deep-MSB sieve ladder: every RAM-feasible rung, shallow->deep,
    //    each with a generous per-rung cap. Skipped if g6k is unavailable.
    if (ceiling_hit()) return std::nullopt;
    sieve_config::ensure_env();
    const char* py  = std::getenv("BAZOOKA_SIEVE_PYTHON");
    const char* pp  = std::getenv("PYTHONPATH");
    const char* ldp = std::getenv("LD_LIBRARY_PATH");
    if (!sieve_config::python_has_g6k(py ? py : "", pp ? pp : "", ldp ? ldp : "")) {
        tel_.set_status("last-resort: sieve ladder skipped (g6k unavailable)");
        return std::nullopt;
    }

    auto machine = sieve_estimator::detect_machine();
    for (double L : last_resort::feasible_rungs(machine)) {
        if (ceiling_hit()) break;
        double per_rung = last_resort::PER_RUNG_CEILING_SEC;   // generous per-rung cap
        if (overall_ceiling > 0.0) {
            double remaining = overall_ceiling - tel_.elapsed_seconds();
            if (remaining <= 0.0) break;
            per_rung = std::min(per_rung, remaining);
        }
        tel_.time_budget_sec = tel_.elapsed_seconds() + per_rung;  // bound this rung
        BiasProfile prof;
        prof.type = BiasType::MSB;
        prof.estimated_leaked_bits = L;
        prof.bias_detected = true;
        prof.description = "last-resort speculative sieve L=" + std::to_string(L);
        tel_.set_status("last-resort: sieve rung L=" + std::to_string(L));
        auto d = try_sieve(signatures, prof, max_sigs, pubkey_hint, per_rung);
        if (verified(d)) return d;
    }
    return std::nullopt;
}
