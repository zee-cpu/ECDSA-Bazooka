#include "last_resort.h"
#include "recovery_engine.h"
#include "sieve_config.h"
#include "utils.h"
#include <algorithm>
#include <cstdlib>
#include <string>

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

} // namespace last_resort

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
