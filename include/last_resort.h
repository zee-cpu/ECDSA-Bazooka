#pragma once
#include "sieve_estimator.h"
#include "types.h"
#include <vector>

// Wiring for AUTO's last-resort stage. Pure helpers here are unit-tested; the
// RecoveryEngine::try_last_resort method that uses them lives in last_resort.cpp.
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

} // namespace last_resort
