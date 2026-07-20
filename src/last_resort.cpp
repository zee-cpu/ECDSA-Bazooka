#include "last_resort.h"
#include "recovery_engine.h"
#include "sieve_config.h"
#include "utils.h"
#include <algorithm>
#include <cstdlib>
#include <string>

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

std::optional<mpz> RecoveryEngine::try_last_resort(
    const std::vector<Signature>& signatures,
    const std::vector<Pair>& pairs,
    const mpz& pubkey_hint,
    size_t max_sigs)
{
    if (pubkey_hint <= 1) return std::nullopt;     // predicate/gate needs a key
    tel_.set_phase("Exhaustive last-resort search (may take longer)");
    // The deadline (tel_.time_budget_sec; 0 == unlimited) was set by the caller
    // via last_resort::resolve_deadline. recover_modulo and the rung loop honour it.

    auto verified = [&](const std::optional<mpz>& c) {
        return c.has_value() && utils::verify_pubkey(*c, pubkey_hint);
    };

    // 1. Bounded modulo/EHNP blind sweep, first (finite; can't be starved).
    if (!tel_.deadline_exceeded()) {
        tel_.set_status("last-resort: modulo/EHNP window sweep");
        auto d = try_modulo(pairs, mpz(0), mpz(0), max_sigs, pubkey_hint);
        if (verified(d)) return d;
    }

    // 2. Speculative deep-MSB sieve ladder (shallow->deep, RAM-feasible rungs).
    //    Skipped when the deadline is spent or g6k is unavailable.
    if (tel_.deadline_exceeded()) return std::nullopt;
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
        if (tel_.deadline_exceeded()) break;
        double per_rung = 0.0;                       // 0 == unbounded rung (unlimited budget)
        double budget = tel_.time_budget_sec;        // 0 == unlimited
        if (budget > 0.0) {
            double remaining = budget - tel_.elapsed_seconds();
            if (remaining <= 0.0) break;
            per_rung = std::min(remaining, last_resort::PER_RUNG_CEILING_SEC);
        }
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
