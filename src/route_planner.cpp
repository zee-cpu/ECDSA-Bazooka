#include "recovery_engine.h"
#include "utils.h"
#include "bias_profiler.h"
#include "last_resort.h"
#include "sieve_config.h"
#include "sieve_estimator.h"
#include <algorithm>
#include <cstdlib>
#include <memory>
#include <optional>

// Tier 2.7 Task 2: single plan executor. Task 3 appends build_route_plan +
// make_lazy_profile below; the executor above and the planner below are the
// consolidated routing (replacing dispatch_and_recover / try_last_resort).
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

namespace {
    // Phase 6b: the shared known-low-bit width if EVERY valid signature carries
    // the same one, else 0. Requiring all valid sigs to be annotated (no zeros
    // mixed in) is deliberate -- an un-annotated pair would be misread as "low
    // bits == 0" and corrupt the lattice, so partial annotation disables the
    // known-LSB path and we fall back to statistical detection.
    // (Moved verbatim from recovery_engine.cpp; make_lazy_profile is now its
    // only caller.)
    int uniform_known_low_bits(const std::vector<Signature>& sigs) {
        int b = 0;
        bool any = false;
        for (const auto& s : sigs) {
            if (!s.valid) continue;
            any = true;
            if (s.known_low_bits <= 0) return 0;
            if (b == 0) b = s.known_low_bits;
            else if (s.known_low_bits != b) return 0;
        }
        return any ? b : 0;
    }
}

// Memoized profile: built at most once, only when first requested. Preserves
// run()'s laziness (pre-scan wins never trigger profiling). The body is moved
// VERBATIM from recovery_engine.cpp's AUTO profile branch (per-signature MSB,
// supplied MSB, known-LSB, statistical-with-PROFILER_CAP), including the
// save/restore of tel_.time_budget_sec around BiasProfiler::profile.
// (overall_ceiling already equals the old `max_time_explicit ? max_time_sec :
// 0.0`, so max_time_explicit is redundant here and left unnamed.)
std::function<const BiasProfile&()> RecoveryEngine::make_lazy_profile(
    const std::vector<Signature>& signatures, const std::vector<Pair>& pairs,
    double msb_leaked_bits, double overall_ceiling, bool /*max_time_explicit*/)
{
    auto cache = std::make_shared<std::optional<BiasProfile>>();
    return [this, &signatures, &pairs, msb_leaked_bits, overall_ceiling, cache]()
        -> const BiasProfile& {
        if (cache->has_value()) return **cache;
        BiasProfile profile;
        int known_bits = uniform_known_low_bits(signatures);
        // Per-signature MSB leakage supplied in the input (LeakedBits: N on every
        // valid signature). The exact per-signature bounds drive the sieve; the
        // average sets the profile/gate. Takes precedence over the global hint.
        size_t n_valid = 0, n_leaked = 0;
        double sum_leaked = 0.0;
        for (const auto& s : signatures) {
            if (!s.valid) continue;
            n_valid++;
            if (s.msb_leaked_bits > 0) { n_leaked++; sum_leaked += s.msb_leaked_bits; }
        }
        bool per_signature_leak = (n_valid > 0 && n_leaked == n_valid);
        if (per_signature_leak) {
            profile.type = BiasType::MSB;
            profile.estimated_leaked_bits = sum_leaked / static_cast<double>(n_valid);
            profile.bias_detected = true;
            profile.description = "MSB leak (per-signature supplied): avg " +
                std::to_string(profile.estimated_leaked_bits) + " leaked high bit(s)";
            tel_.set_phase("Per-signature-MSB recovery");
            tel_.leaked_bits_est = profile.estimated_leaked_bits;
            tel_.bias_type = static_cast<int>(BiasType::MSB);
        } else if (msb_leaked_bits > 0.0) {
            // Sieve hint: the MSB-zero leakage width is *supplied* (side-channel
            // model), not detected. Build the MSB profile directly so the deep-leak
            // sieve route has the exact L it needs -- statistical detection fails at
            // L<=3 with the small sample counts the sieve uses. May be fractional.
            profile.type = BiasType::MSB;
            profile.estimated_leaked_bits = msb_leaked_bits;
            profile.bias_detected = true;
            profile.description = "MSB leak (supplied): " +
                std::to_string(msb_leaked_bits) + " leaked high bit(s)";
            tel_.set_phase("Supplied-MSB recovery");
            tel_.leaked_bits_est = msb_leaked_bits;
            tel_.bias_type = static_cast<int>(BiasType::MSB);
        } else if (known_bits > 0) {
            // Phase 6b: the leak is *supplied*, not detected. Build the profile
            // directly and let the lattice use each pair's known low-bit residue
            // (Pair::known_low_value, folded in by transform_pairs_lsb). This is
            // the side-channel model: known bits are exact, so we skip the
            // statistical detector entirely rather than re-discovering them.
            profile.type = BiasType::LSB;
            profile.estimated_leaked_bits = static_cast<double>(known_bits);
            profile.bias_detected = true;
            profile.description = "known-LSB: " + std::to_string(known_bits) +
                " leaked low bit(s) supplied per signature";
            tel_.set_phase("Known-LSB recovery");
            tel_.leaked_bits_est = static_cast<double>(known_bits);
            tel_.bias_type = static_cast<int>(BiasType::LSB);
        } else {
            // Profile. With an unbounded budget the statistical profiler
            // over-explores (heavy lattice work) for minutes on data with no
            // detectable bias, starving dispatch + last-resort. Cap it -- a
            // missed detection merely routes to fallback/last-resort (the net).
            tel_.set_phase("Profiling bias");
            double saved_budget = tel_.time_budget_sec;
            double oc = overall_ceiling;
            tel_.time_budget_sec = last_resort::stage_deadline(
                oc, tel_.elapsed_seconds(), last_resort::PROFILER_CAP_SEC);
            profile = BiasProfiler::profile(pairs, &tel_);
            tel_.time_budget_sec = saved_budget;
        }
        *cache = profile;
        return **cache;
    };
}

RoutePlan RecoveryEngine::build_route_plan(
    const std::vector<Signature>& signatures, const std::vector<Pair>& pairs,
    RecoveryMethod force, size_t max_sigs, const mpz& pubkey_hint,
    const mpz& modulo_omega, const mpz& modulo_bound,
    const mpz& lcg_a, const mpz& lcg_b, double msb_leaked_bits,
    double overall_ceiling, bool max_time_explicit, std::string& fail_message)
{
    RoutePlan plan;
    fail_message = "No candidate produced";

    // 1. Closed-form pre-scans (always first; short-circuit on any candidate).
    {
        RouteStep s; s.name = "repeated-nonce"; s.accept = AcceptPolicy::CLOSED_FORM;
        s.ceiling_gated = false;
        s.attempt = [this, &signatures, &pubkey_hint]() { return try_repeated_nonce(signatures, pubkey_hint); };
        s.on_win = [&signatures](RecoveryResult& r) {
            r.method_used = RecoveryMethod::REPEATED_NONCE;
            r.signatures_used = signatures.size();
            r.bias_profile.description =
                "Reused nonce (r-collision) -- recovered by closed-form algebra, no lattice";
        };
        plan.push_back(std::move(s));
    }
    {
        bool forced_linear = (force == RecoveryMethod::LINEAR);
        RouteStep s; s.name = "lcg"; s.accept = AcceptPolicy::CLOSED_FORM; s.ceiling_gated = false;
        s.attempt = [this, &signatures, &pairs, &pubkey_hint, lcg_a, lcg_b, forced_linear]() {
            return try_linear_nonce(signatures, pairs, pubkey_hint, lcg_a, lcg_b, forced_linear);
        };
        s.on_win = [this, &signatures, lcg_a](RecoveryResult& r) {
            tel_.active_method = static_cast<int>(RecoveryMethod::LINEAR);
            tel_.method_chosen = true;
            r.method_used = RecoveryMethod::LINEAR;
            r.signatures_used = signatures.size();
            r.bias_profile.description = (lcg_a > 0
                ? "Linearly-related nonces (LCG, known multiplier) -- closed-form, no lattice"
                : "Linearly-related nonces (LCG) -- closed-form 4x4 solve, no lattice");
        };
        plan.push_back(std::move(s));
    }

    // 2. Forced/hinted terminal plans (no dispatch, no last-resort).
    if (force == RecoveryMethod::LINEAR) {
        fail_message = "No linearly-related (LCG) nonce structure found";
        return plan;  // only the two closed-form steps; miss -> fail with this message
    }
    if (force == RecoveryMethod::MODULO || (modulo_omega > 0 && modulo_bound > 0)) {
        fail_message = "No candidate produced (modulo/EHNP)";
        RouteStep s; s.name = "modulo-hint"; s.accept = AcceptPolicy::VERIFIED_ONLY; s.ceiling_gated = false;
        s.attempt = [this, &pairs, modulo_omega, modulo_bound, max_sigs, &pubkey_hint]() {
            return try_modulo(pairs, modulo_omega, modulo_bound, max_sigs, pubkey_hint);
        };
        s.on_win = [modulo_omega, modulo_bound](RecoveryResult& r) {
            r.method_used = RecoveryMethod::MODULO;
            r.bias_profile.type = BiasType::MODULO;
            r.bias_profile.modulo_omega = modulo_omega;
            r.bias_profile.modulo_bound = modulo_bound;
            r.bias_profile.bias_detected = true;
            r.bias_profile.description = "modulo / Extended-HNP: k mod omega in [0, bound)";
        };
        plan.push_back(std::move(s));
        return plan;
    }

    // 3. AUTO: one lazy dispatch step (sieve/lattice+alt-bias/fallback), then last-resort rungs.
    auto profile = std::make_shared<std::function<const BiasProfile&()>>(
        make_lazy_profile(signatures, pairs, msb_leaked_bits, overall_ceiling, max_time_explicit));
    {
        RouteStep s; s.name = "dispatch"; s.accept = AcceptPolicy::BEST_EFFORT; s.ceiling_gated = false;
        s.attempt = [this, &signatures, &pairs, max_sigs, &pubkey_hint, profile, overall_ceiling, force]()
            -> std::optional<mpz> {
            const BiasProfile& prof = (*profile)();

            // FALLBACK-cap gate (moved from recovery_engine.cpp:763-766): cap the
            // fallback heuristic so it can't consume the budget the last-resort
            // stage needs. Only when nothing was detected (dispatch will route to
            // FALLBACK) and a pubkey is present (last-resort applies).
            if (pubkey_hint > 1 && !prof.bias_detected) {
                tel_.time_budget_sec = last_resort::stage_deadline(
                    overall_ceiling, tel_.elapsed_seconds(), last_resort::FALLBACK_CAP_SEC);
            }

            // AUTO method selection (moved from dispatch_and_recover,
            // recovery_engine.cpp:534-574).
            RecoveryMethod chosen = force;
            if (chosen == RecoveryMethod::AUTO) {
                // Deep MSB leakage (L<=3) is past the lattice barrier: plain
                // LLL/BKZ cannot reach it. Route to the sieving-with-predicate
                // worker, but only when a public key is present (the predicate IS
                // the pubkey check). L>=4 (and any no-pubkey case) keeps Phase 1/2.
                if (prof.bias_detected && prof.type == BiasType::MSB &&
                    prof.estimated_leaked_bits <= 3.0 && pubkey_hint > 1) {
                    chosen = RecoveryMethod::SIEVE;
                } else if (prof.bias_detected && prof.estimated_leaked_bits >= 3.0) {
                    chosen = RecoveryMethod::LATTICE;
                } else {
                    chosen = RecoveryMethod::FALLBACK;
                }
            }

            std::optional<mpz> candidate;
            auto verified = [&](const std::optional<mpz>& c) {
                return c.has_value() && pubkey_hint > 0 && utils::verify_pubkey(*c, pubkey_hint);
            };

            if (chosen == RecoveryMethod::SIEVE) {
                candidate = try_sieve(signatures, prof, max_sigs, pubkey_hint);
            } else if (chosen == RecoveryMethod::LATTICE) {
                candidate = try_lattice(pairs, prof, max_sigs, pubkey_hint);
                if (!verified(candidate) && !tel_.deadline_exceeded()) {
                    // The profiler's chosen bias shape (MSB vs LSB) is itself a
                    // heuristic call -- if it doesn't check out, try the other
                    // shape before giving up rather than reporting failure outright.
                    BiasProfile alt = prof;
                    alt.type = (prof.type == BiasType::MSB) ? BiasType::LSB : BiasType::MSB;
                    auto alt_cand = try_lattice(pairs, alt, max_sigs, pubkey_hint);
                    if (verified(alt_cand) || !candidate.has_value()) {
                        candidate = alt_cand;
                    }
                }
            } else {
                candidate = try_fallback_ladder(pairs, prof, max_sigs, pubkey_hint);
            }

            dispatch_method_ = chosen;  // read by on_win to report the sub-method
            return candidate;
        };
        s.on_win = [this](RecoveryResult& r) { r.method_used = dispatch_method_; };
        plan.push_back(std::move(s));
    }

    // 4. Last-resort rungs (only when pubkey present; each ceiling-gated with its own budget).
    if (pubkey_hint > 1) {
        // Shared on_win for every last-resort rung: label with the specific rung
        // that recovered (set by shared-prefix/ransac on a verified hit), else the
        // generic last-resort description. Mirrors old run()'s last-resort block.
        auto lr_on_win = [this](RecoveryResult& r) {
            r.method_used = RecoveryMethod::AUTO;
            r.bias_profile.description = last_resort_desc_.empty()
                ? "last-resort recovery (blind modulo/sieve)" : last_resort_desc_;
            r.signatures_used = tel_.signatures_valid.load();
        };
        auto add_lr = [&](const std::string& name, const std::string& status, double cap,
                          AcceptPolicy pol, std::function<std::optional<mpz>()> att) {
            RouteStep s; s.name = name; s.accept = pol; s.ceiling_gated = true;
            s.set_budget = [this, overall_ceiling, cap]() {
                tel_.time_budget_sec = last_resort::stage_deadline(
                    overall_ceiling, tel_.elapsed_seconds(), cap);
            };
            s.attempt = [this, status, att = std::move(att)]() -> std::optional<mpz> {
                tel_.set_status(status);
                return att();
            };
            s.on_win = lr_on_win;
            plan.push_back(std::move(s));
        };
        last_resort_desc_.clear();
        add_lr("shared-prefix", "last-resort: shared-prefix nonce reuse",
               last_resort::SHARED_PREFIX_CAP_SEC, AcceptPolicy::VERIFIED_ONLY,
               [this, &pairs, &pubkey_hint]() { return try_shared_prefix_reuse(pairs, pubkey_hint); });
        add_lr("ransac", "last-resort: RANSAC resampling",
               last_resort::RANSAC_CAP_SEC, AcceptPolicy::VERIFIED_ONLY,
               [this, &pairs, &pubkey_hint]() { return try_ransac_resample(pairs, pubkey_hint); });
        add_lr("modulo-sweep", "last-resort: modulo/EHNP window sweep",
               last_resort::MODULO_SWEEP_SEC, AcceptPolicy::VERIFIED_ONLY,
               [this, &pairs, max_sigs, &pubkey_hint]() { return try_modulo(pairs, mpz(0), mpz(0), max_sigs, pubkey_hint); });

        // Speculative deep-MSB sieve ladder (moved from last_resort.cpp:245-275):
        // one VERIFIED_ONLY ceiling-gated step per RAM-feasible rung, shallow->deep,
        // each with its own generous per-rung cap. Emitted only when g6k is
        // available (preserves the current skip). The g6k probe + feasible_rungs
        // are evaluated here at plan-build time.
        sieve_config::ensure_env();
        const char* py  = std::getenv("BAZOOKA_SIEVE_PYTHON");
        const char* pp  = std::getenv("PYTHONPATH");
        const char* ldp = std::getenv("LD_LIBRARY_PATH");
        if (sieve_config::python_has_g6k(py ? py : "", pp ? pp : "", ldp ? ldp : "")) {
            auto machine = sieve_estimator::detect_machine();
            for (double L : last_resort::feasible_rungs(machine)) {
                auto per_rung_cell = std::make_shared<double>(last_resort::PER_RUNG_CEILING_SEC);
                RouteStep s;
                s.name = "sieve-rung-L=" + std::to_string(L);
                s.accept = AcceptPolicy::VERIFIED_ONLY;
                s.ceiling_gated = true;
                s.set_budget = [this, overall_ceiling, per_rung_cell]() {
                    double per_rung = last_resort::PER_RUNG_CEILING_SEC;   // generous per-rung cap
                    if (overall_ceiling > 0.0) {
                        double remaining = overall_ceiling - tel_.elapsed_seconds();
                        // remaining <= 0 -> the step is ceiling-skipped by the executor.
                        if (remaining > 0.0) per_rung = std::min(per_rung, remaining);
                    }
                    *per_rung_cell = per_rung;
                    tel_.time_budget_sec = tel_.elapsed_seconds() + per_rung;  // bound this rung
                };
                s.attempt = [this, &signatures, max_sigs, &pubkey_hint, L, per_rung_cell]()
                    -> std::optional<mpz> {
                    BiasProfile prof;
                    prof.type = BiasType::MSB;
                    prof.estimated_leaked_bits = L;
                    prof.bias_detected = true;
                    prof.description = "last-resort speculative sieve L=" + std::to_string(L);
                    tel_.set_status("last-resort: sieve rung L=" + std::to_string(L));
                    return try_sieve(signatures, prof, max_sigs, pubkey_hint, *per_rung_cell);
                };
                s.on_win = lr_on_win;
                plan.push_back(std::move(s));
            }
        } else {
            tel_.set_status("last-resort: sieve ladder skipped (g6k unavailable)");
        }
    }
    return plan;
}
