#include "recovery_engine.h"
#include "utils.h"

// Tier 2.7 Task 2: single plan executor. build_route_plan (Task 3) will be
// appended to this file once it lands; for now this file holds only the
// executor.
bool RecoveryEngine::execute_route_plan(
    const RoutePlan& plan,
    const mpz& pubkey_hint,
    double overall_ceiling,
    RecoveryResult& result)
{
    auto ceiling_hit = [&]() {
        return overall_ceiling > 0.0 && tel_.elapsed_seconds() >= overall_ceiling;
    };

    std::optional<mpz> winner, provisional;
    const RouteStep* winning_step = nullptr;
    const RouteStep* provisional_step = nullptr;

    for (const RouteStep& step : plan) {
        if (step.set_budget) step.set_budget();
        if (step.ceiling_gated && ceiling_hit()) continue;  // Tier 2.8 will log the skip reason here

        std::optional<mpz> cand = step.attempt();
        if (!cand.has_value() || *cand == 0) continue;

        bool ok = pubkey_hint > 1 && utils::verify_pubkey(*cand, pubkey_hint);
        if (step.accept == AcceptPolicy::CLOSED_FORM || ok) {
            winner = cand; winning_step = &step; break;
        }
        // BEST_EFFORT unverified: keep the FIRST unverified candidate only.
        if (!provisional.has_value()) { provisional = cand; provisional_step = &step; }
    }

    const std::optional<mpz>& chosen = winner.has_value() ? winner : provisional;
    const RouteStep* chosen_step   = winner.has_value() ? winning_step : provisional_step;
    if (!chosen.has_value() || *chosen == 0) return false;

    result.private_key = *chosen;
    result.private_key_hex = utils::mpz_to_hex(*chosen);
    if (chosen_step->on_win) chosen_step->on_win(result);
    return true;
}
