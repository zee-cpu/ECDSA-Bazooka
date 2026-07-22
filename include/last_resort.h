#pragma once
#include "sieve_estimator.h"
#include "types.h"
#include "fork_pool.h"
#include <vector>
#include <optional>
#include <cstdint>

// Wiring for AUTO's last-resort stage. Pure helpers here are unit-tested; the
// last-resort route steps that use them are assembled in RecoveryEngine::
// build_route_plan (src/route_planner.cpp).
namespace last_resort {

    // Cap (s) for the statistical bias profiler. Detection is cheap; with an
    // unbounded budget it over-explores (heavy lattice work) for many minutes on
    // data with no detectable bias, starving dispatch + last-resort. A missed
    // detection merely routes to fallback/last-resort -- the safety net.
    constexpr double PROFILER_CAP_SEC = 30.0;
    // Cap (s) for the fallback heuristic that runs BEFORE last-resort, so it
    // can't consume the budget last-resort needs. Fallback only runs when the
    // profiler detected nothing -- it is a bounded last-ditch, and the deep work
    // belongs to last-resort.
    constexpr double FALLBACK_CAP_SEC = 90.0;
    // Bounded budget (s) for the modulo/EHNP window sweep, so recover_modulo
    // CONVERGES instead of over-exploring: with an unbounded budget the lattice
    // escalates endlessly rather than resolving.
    constexpr double MODULO_SWEEP_SEC = 300.0;
    // Generous per-rung cap (s) for the speculative sieve ladder -- a deep dim-89
    // rung legitimately runs ~1h. The ladder runs every RAM-feasible rung.
    constexpr double PER_RUNG_CEILING_SEC = 3600.0;

    // Candidate MSB leak widths, shallow->deep. A rung at L catches every true
    // bias >= L (undershoot-safe), so cheap shallow rungs run first.
    inline const std::vector<double>& sieve_ladder() {
        static const std::vector<double> L = {4.0, 3.5, 3.0, 2.75, 2.5, 2.25, 2.0};
        return L;
    }

    // Absolute deadline for a bounded sub-stage: elapsed + stage_budget, clamped
    // to overall_ceiling when that is set (> 0). overall_ceiling == 0 means "no
    // overall limit" (the --max-time-unset / auditor case) -- the sub-stage still
    // gets its own bounded stage_budget so the lattice methods converge.
    double stage_deadline(double overall_ceiling, double elapsed, double stage_budget);

    // Ladder rungs whose estimated sieve DB fits this machine's RAM
    // (estimator feasible_here), shallow->deep.
    std::vector<double> feasible_rungs(const sieve_estimator::MachineFacts& m);

    // ---- Tier 1.2a: shared-prefix nonce reuse (differenced BV-HNP) ----
    // Bounded budget (s) for the shared-prefix rung: a small (width x pivot)
    // grid of one LLL each. Cheapest last-resort rung, so it runs first.
    constexpr double SHARED_PREFIX_CAP_SEC = 120.0;
    // Cap on signatures fed to the differenced lattice, to bound its dimension
    // (strong sharing needs only a handful: m * P > 256).
    constexpr size_t SHARED_PREFIX_MAX_SIGS = 64;
    // Candidate shared-prefix widths P, strongest sharing first. Undershoot-safe
    // (a smaller assumed P is a looser, still-correct bound), so a descending
    // sweep never emits a wrong key. Tunable against the Tier-0 corpus.
    inline const std::vector<int>& shared_prefix_widths() {
        static const std::vector<int> P = {64, 48, 32, 24, 16};
        return P;
    }
    // Pivot-difference `pairs` against index `pivot` and add the centering
    // offset B' = 2^(256-prefix_bits) to each constant, yielding pairs that form
    // a standard centered BV-HNP with leak (prefix_bits - 1) in the SAME unknown
    // d (see the design's equivalence proof). Returns the m-1 differenced pairs
    // (i != pivot), or empty if args are degenerate (too few sigs / bad pivot /
    // prefix_bits out of (0,256)).
    std::vector<Pair> shared_prefix_pairs(
        const std::vector<Pair>& pairs, size_t pivot, int prefix_bits);

    // ---- Tier 1.3: RANSAC-style resampling for outlier robustness ----
    // Bounded budget (s) for the RANSAC rung. noise5/noise10 resolve <60s at
    // s=40 (probe); wide margin. Runs after shared-prefix, before modulo.
    constexpr double RANSAC_CAP_SEC = 300.0;
    // Iteration cap: noise5/noise10 hit by ~iter 34 (probe); margin for seed
    // variance. The rung stops at the budget OR this cap, whichever comes first.
    constexpr size_t RANSAC_MAX_ITERS = 150;
    // Assumed MSB leak widths for resampled subsets. L too large fails to verify
    // (discarded); L too small still recovers (undershoot-safe).
    inline const std::vector<int>& ransac_l_candidates() {
        static const std::vector<int> L = {8, 12};
        return L;
    }
    // Subset size for assumed leak L over a pool of `pool` pairs. EMPIRICAL
    // heuristic (probe): ~256/L (info-theoretic floor for an L-bit-leak HNP) + 8
    // margin, clamped to [24, min(pool,64)]. Small s minimizes outliers per draw
    // while still resolving the HNP; NOT a theoretical guarantee.
    size_t ransac_subset_size(int L, size_t pool);
    // Draw random s-subsets and solve the BV lattice on each, pubkey-gated, until
    // a verified key is found or max_iters / the telemetry deadline is reached.
    // Deterministic for a given (pairs, seed). tel may be null (unit tests): then
    // there is no deadline and no status output.
    std::optional<mpz> ransac_recover(
        const std::vector<Pair>& pairs, const mpz& pubkey_hint,
        uint64_t seed, size_t max_iters,
        const std::vector<int>& l_candidates, Telemetry* tel);

    // Work-unit for RANSAC iteration `iter`, leak `L`: sample a seeded subset,
    // build the BV lattice, reduce+extract, and return a pubkey-verified key or
    // nullopt. Shared by the serial (ransac_recover) and parallel (pool) paths so
    // both draw identical, deterministic subsets from (seed, iter, L).
    fork_pool::Work ransac_work_unit(const std::vector<Pair>& pairs,
                                     const mpz& pubkey_hint, uint64_t seed,
                                     size_t iter, int L);

} // namespace last_resort
