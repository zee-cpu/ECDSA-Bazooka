#include "last_resort.h"

namespace last_resort {

double resolve_deadline(double max_time_sec, bool max_time_explicit, double elapsed_sec) {
    if (!max_time_explicit) return elapsed_sec + DEFAULT_BUDGET_SEC;  // fresh default allowance
    if (max_time_sec <= 0.0) return 0.0;                             // explicit 0 -> unlimited
    return max_time_sec;                                             // explicit T -> absolute bound
}

std::vector<double> feasible_rungs(const sieve_estimator::MachineFacts& m) {
    std::vector<double> out;
    for (double L : sieve_ladder())
        if (sieve_estimator::estimate(L, m).feasible_here) out.push_back(L);
    return out;
}

} // namespace last_resort
