#include "recovery_engine.h"
#include "lattice_solver.h"
#include "fft_solver.h"
#include "verifier.h"
#include "bias_profiler.h"
#include "utils.h"
#include <chrono>
#include <iostream>
#include <optional>
#include <vector>

RecoveryEngine::RecoveryEngine(Telemetry& tel) : tel_(tel) {}

std::optional<mpz> RecoveryEngine::try_lattice(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs) {
    tel_.set_phase("Lattice recovery (Boneh-Venkatesan)");
    tel_.active_method = static_cast<int>(RecoveryMethod::LATTICE);
    tel_.method_chosen = true;

    return LatticeSolver::recover_private_key(pairs, bias, max_sigs, &tel_);
}

std::optional<mpz> RecoveryEngine::try_fft(const std::vector<Pair>& pairs, const BiasProfile& bias) {
    tel_.set_phase("FFT recovery (Bleichenbacher)");
    tel_.active_method = static_cast<int>(RecoveryMethod::FFT);
    tel_.method_chosen = true;

    return FFTSolver::recover_private_key(pairs, bias, &tel_);
}

std::optional<mpz> RecoveryEngine::try_fallback_ladder(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs, const mpz& pubkey_hint) {
    tel_.set_phase("Fallback lattice ladder");
    tel_.active_method = static_cast<int>(RecoveryMethod::FALLBACK);
    tel_.method_chosen = true;

    // recover_private_key already internally sweeps a wide range of
    // leak-bit values regardless of the point estimate handed to it, so
    // there's no need to loop over many outer "assumed bits" guesses here
    // (that was mostly redundant work). What *does* matter is trying both
    // bias shapes -- MSB and LSB use different lattice transforms.
    //
    // Crucially: recover_private_key can return a *plausible-looking but
    // wrong* candidate (its internal scoring is a heuristic, not proof),
    // so this must verify each candidate against the pubkey before
    // accepting it. Previously this returned on the first non-null
    // candidate unconditionally, which meant a wrong MSB-shaped guess on
    // LSB-biased data silently pre-empted ever trying LSB at all.
    std::optional<mpz> best_unverified;

    for (BiasType t : {BiasType::MSB, BiasType::LSB}) {
        if (tel_.recovery_complete.load()) break;
        if (tel_.deadline_exceeded()) break;

        BiasProfile fake = bias;
        fake.type = t;
        fake.estimated_leaked_bits = 8.0;

        tel_.set_status(std::string("Fallback sweep (") + (t == BiasType::MSB ? "MSB" : "LSB") + ")");
        auto cand = LatticeSolver::recover_private_key(pairs, fake, max_sigs ? max_sigs : 4000, &tel_);
        if (!cand.has_value()) continue;

        if (pubkey_hint > 0 && utils::verify_pubkey(*cand, pubkey_hint)) {
            return cand;
        }
        if (!best_unverified.has_value()) best_unverified = cand;
    }

    // No pubkey to check against (shouldn't normally happen), or nothing
    // verified: fall back to whatever was found so the caller's own
    // verification step still runs and reports honestly.
    return best_unverified;
}

bool RecoveryEngine::dispatch_and_recover(
    const BiasProfile& profile,
    const std::vector<Pair>& pairs,
    RecoveryMethod force,
    size_t max_sigs,
    const mpz& pubkey_hint,
    RecoveryResult& result
) {
    result.bias_profile = profile;
    result.signatures_used = pairs.size();

    RecoveryMethod chosen = force;
    if (chosen == RecoveryMethod::AUTO) {
        if (profile.bias_detected && profile.estimated_leaked_bits >= 3.0) {
            chosen = RecoveryMethod::LATTICE;
        } else {
            chosen = RecoveryMethod::FALLBACK;
        }
    }

    std::optional<mpz> candidate;

    auto verified = [&](const std::optional<mpz>& c) {
        return c.has_value() && pubkey_hint > 0 && utils::verify_pubkey(*c, pubkey_hint);
    };

    if (chosen == RecoveryMethod::LATTICE) {
        candidate = try_lattice(pairs, profile, max_sigs);
        if (!verified(candidate) && !tel_.deadline_exceeded()) {
            // The profiler's chosen bias shape (MSB vs LSB) is itself a
            // heuristic call -- if it doesn't check out, try the other
            // shape before giving up rather than reporting failure outright.
            BiasProfile alt = profile;
            alt.type = (profile.type == BiasType::MSB) ? BiasType::LSB : BiasType::MSB;
            auto alt_cand = try_lattice(pairs, alt, max_sigs);
            if (verified(alt_cand) || !candidate.has_value()) {
                candidate = alt_cand;
            }
        }
    } else if (chosen == RecoveryMethod::FFT) {
        candidate = try_fft(pairs, profile);
    } else {
        candidate = try_fallback_ladder(pairs, profile, max_sigs, pubkey_hint);
    }

    if (!candidate.has_value() || *candidate == 0) {
        result.success = false;
        result.verification_details = "No candidate produced";
        return false;
    }

    result.private_key = *candidate;
    result.private_key_hex = utils::mpz_to_hex(*candidate);
    result.method_used = chosen;
    return true;
}

RecoveryResult RecoveryEngine::run(
    const std::vector<Signature>& signatures,
    const std::vector<Pair>& pairs,
    RecoveryMethod force_method,
    size_t max_sigs,
    double max_time_sec
) {
    RecoveryResult result;
    auto start = std::chrono::steady_clock::now();

    tel_.reset();
    tel_.time_budget_sec = max_time_sec; // 0 = unlimited
    tel_.start_time = start;
    tel_.signatures_loaded = signatures.size();
    tel_.signatures_valid = pairs.size();

    if (pairs.empty()) {
        tel_.set_error("No valid pairs");
        result.success = false;
        return result;
    }

    // Profile
    tel_.set_phase("Profiling bias");
    BiasProfile profile = BiasProfiler::profile(pairs, &tel_);

    mpz pubkey_hint = signatures.empty() ? mpz(0) : signatures[0].pubkey;

    bool dispatch_ok = dispatch_and_recover(profile, pairs, force_method, max_sigs, pubkey_hint, result);

    if (!dispatch_ok || !result.private_key) {
        result.success = false;
        tel_.recovery_complete = true;
        return result;
    }

    // Strict verification
    tel_.set_phase("Verifying candidate");
    std::string details;
    bool verified = Verifier::verify_candidate(result.private_key, signatures, details, &tel_);

    result.verification_details = details;
    result.success = verified;

    // Hard PubKey gate
    if (!signatures.empty() && signatures[0].pubkey != 0) {
        if (details.find("PubKey match: NO") != std::string::npos) {
            result.success = false;
            result.verification_details = details + " [REJECTED: PubKey required]";
        }
    }

    tel_.recovery_complete = true;
    tel_.verification_passed = result.success;

    if (result.success) {
        tel_.set_recovered_key(result.private_key_hex);
        tel_.set_status("RECOVERED KEY VERIFIED");
    } else {
        tel_.set_error("Verification failed");
    }

    auto end = std::chrono::steady_clock::now();
    result.runtime_seconds = std::chrono::duration<double>(end - start).count();

    return result;
}
