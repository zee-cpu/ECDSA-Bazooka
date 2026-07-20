#pragma once
#include "sieve_estimator.h"
#include <vector>

// Wiring for AUTO's last-resort stage. Pure helpers here are unit-tested; the
// RecoveryEngine::try_last_resort method that uses them lives in last_resort.cpp.
namespace last_resort {

    // Default wall-clock budget (s) when the user passed no --max-time.
    constexpr double DEFAULT_BUDGET_SEC = 600.0;
    // Ceiling (s) for a single sieve rung under a *bounded* budget, so one
    // optimistically-"feasible" deep rung can't swallow a large budget whole.
    // Not applied under an unlimited budget.
    constexpr double PER_RUNG_CEILING_SEC = 3600.0;

    // Candidate MSB leak widths, shallow->deep. A rung at L catches every true
    // bias >= L (undershoot-safe), so cheap shallow rungs run first.
    inline const std::vector<double>& sieve_ladder() {
        static const std::vector<double> L = {4.0, 3.5, 3.0, 2.75, 2.5, 2.25, 2.0};
        return L;
    }

    // Absolute deadline (seconds-from-recovery-start) the last-resort stage
    // runs under; 0 == unlimited (matches Telemetry::time_budget_sec).
    //  - no --max-time (explicit=false): fresh allowance, elapsed_sec + DEFAULT_BUDGET_SEC.
    //  - explicit --max-time 0 (or <=0): unlimited (0).
    //  - explicit --max-time T (>0): T, the whole-run absolute bound (so the
    //    stage gets only the time remaining within T, and none if T is spent).
    double resolve_deadline(double max_time_sec, bool max_time_explicit, double elapsed_sec);

    // Ladder rungs whose estimated sieve DB fits this machine's RAM
    // (estimator feasible_here), shallow->deep.
    std::vector<double> feasible_rungs(const sieve_estimator::MachineFacts& m);

} // namespace last_resort
