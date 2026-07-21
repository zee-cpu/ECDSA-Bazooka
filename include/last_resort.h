#pragma once
#include "sieve_estimator.h"
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

} // namespace last_resort
