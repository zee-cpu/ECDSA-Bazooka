#include "recovery_engine.h"
#include "lattice_solver.h"
#include "verifier.h"
#include "bias_profiler.h"
#include "utils.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <map>
#include <optional>
#include <vector>

namespace {

    // Solve a small NxN linear system M*v = rhs over Z/n (n prime, so a field)
    // by Gauss-Jordan elimination. Returns v, or nullopt if the matrix is
    // singular mod n. Used by the Phase 6d LCG recovery, where the consecutive-
    // nonce constraints become linear once the product a*d is its own unknown.
    std::optional<std::vector<mpz>> solve_modn(std::vector<std::vector<mpz>> M,
                                               std::vector<mpz> rhs, const mpz& n) {
        size_t N = M.size();
        for (size_t i = 0; i < N; ++i) M[i].push_back(rhs[i]);  // augmented column
        for (size_t col = 0; col < N; ++col) {
            size_t piv = N;
            for (size_t r = col; r < N; ++r) {
                mpz v = M[r][col] % n; if (v < 0) v += n;
                if (v != 0) { piv = r; break; }
            }
            if (piv == N) return std::nullopt;  // singular
            std::swap(M[col], M[piv]);
            mpz ic = utils::mod_inverse(M[col][col], n);
            if (ic == 0) return std::nullopt;
            for (size_t k = col; k <= N; ++k) M[col][k] = utils::mod_mul(M[col][k], ic, n);
            for (size_t r = 0; r < N; ++r) {
                if (r == col) continue;
                mpz f = M[r][col] % n; if (f < 0) f += n;
                if (f == 0) continue;
                for (size_t k = col; k <= N; ++k) {
                    mpz t = (M[r][k] - utils::mod_mul(f, M[col][k], n)) % n;
                    if (t < 0) t += n;
                    M[r][k] = t;
                }
            }
        }
        std::vector<mpz> sol(N);
        for (size_t i = 0; i < N; ++i) { mpz v = M[i][N] % n; if (v < 0) v += n; sol[i] = v; }
        return sol;
    }

    // Phase 6b: the shared known-low-bit width if EVERY valid signature carries
    // the same one, else 0. Requiring all valid sigs to be annotated (no zeros
    // mixed in) is deliberate -- an un-annotated pair would be misread as "low
    // bits == 0" and corrupt the lattice, so partial annotation disables the
    // known-LSB path and we fall back to statistical detection.
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

RecoveryEngine::RecoveryEngine(Telemetry& tel) : tel_(tel) {}

std::optional<mpz> RecoveryEngine::try_lattice(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs, const mpz& pubkey_hint) {
    tel_.set_phase("Lattice recovery (Boneh-Venkatesan)");
    tel_.active_method = static_cast<int>(RecoveryMethod::LATTICE);
    tel_.method_chosen = true;

    return LatticeSolver::recover_private_key(pairs, bias, max_sigs, &tel_, pubkey_hint);
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
        auto cand = LatticeSolver::recover_private_key(pairs, fake, max_sigs ? max_sigs : 4000, &tel_, pubkey_hint);
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

std::optional<mpz> RecoveryEngine::try_repeated_nonce(
    const std::vector<Signature>& signatures, const mpz& pubkey_hint) {
    tel_.set_phase("Scanning for repeated nonces");

    const mpz& n = SECP256K1_N;
    // First r we've seen -> its signature index. A later signature with the
    // same r reused the same nonce: r = (k*G).x mod n depends only on k, so a
    // repeated r means a repeated k. (Two *different* nonces k and n-k also
    // share an r, since they have the same x-coordinate -- the pubkey check
    // below is what rejects that antipodal case, so a same-r hit is a
    // candidate, not a proof.)
    std::map<mpz, size_t> first_seen;

    for (size_t i = 0; i < signatures.size(); ++i) {
        const Signature& a = signatures[i];
        if (!a.valid) continue;

        auto [it, inserted] = first_seen.try_emplace(a.r, i);
        if (inserted) continue;  // first time we've seen this r
        const Signature& b = signatures[it->second];

        // Same r on a and b. From s = k^-1 (z + r d):
        //   s_a - s_b = k^-1 (z_a - z_b)  =>  k = (z_a - z_b)(s_a - s_b)^-1
        //   d = (s_a k - z_a) r^-1  (mod n)
        // If s_a == s_b the difference is non-invertible: either a literal
        // duplicate record (z_a == z_b) or a degenerate case. Skip it and keep
        // scanning -- other collisions may still be genuine.
        mpz s_diff = (a.s - b.s) % n; if (s_diff < 0) s_diff += n;
        if (s_diff == 0) continue;
        mpz z_diff = (a.z - b.z) % n; if (z_diff < 0) z_diff += n;

        mpz k = utils::mod_mul(z_diff, utils::mod_inverse(s_diff, n), n);

        mpz num = ((a.s * k) % n - a.z) % n; if (num < 0) num += n;
        mpz d = utils::mod_mul(num, utils::mod_inverse(a.r, n), n);
        if (d <= 0 || d >= n) continue;

        // Exact gate. With a pubkey we can prove correctness outright, which
        // also rejects the antipodal (k_b = n - k_a) false collision -- on a
        // mismatch we keep scanning rather than returning a wrong key. Without
        // a pubkey (opt-in best-effort mode) there is nothing here to prove it
        // against, so we return the algebraic candidate and let run()'s own
        // Verifier::verify_candidate be the honest gate; it checks d against
        // signatures *other* than a and b, which a wrong antipodal d fails.
        if (pubkey_hint != 0 && !utils::verify_pubkey(d, pubkey_hint)) continue;

        tel_.active_method = static_cast<int>(RecoveryMethod::REPEATED_NONCE);
        tel_.method_chosen = true;
        tel_.set_status("Reused nonce: signatures #" + std::to_string(b.index) +
                        " and #" + std::to_string(a.index));
        return d;
    }
    return std::nullopt;
}

std::optional<mpz> RecoveryEngine::try_modulo(
    const std::vector<Pair>& pairs, const mpz& modulo_omega,
    const mpz& modulo_bound, size_t max_sigs, const mpz& pubkey_hint) {
    tel_.active_method = static_cast<int>(RecoveryMethod::MODULO);
    tel_.method_chosen = true;
    tel_.bias_type = static_cast<int>(BiasType::MODULO);
    tel_.set_phase("Extended-HNP (modulo) recovery");

    // Hint supplied (the side-channel / known-structure model, mirroring the
    // known-LSB hint): solve that single instance directly.
    if (modulo_omega > 0 && modulo_bound > 0) {
        return LatticeSolver::recover_modulo(pairs, modulo_omega, modulo_bound,
                                             max_sigs, &tel_, pubkey_hint);
    }

    // No hint: sweep a small set of common power-of-two windows, widest window
    // first (cheapest and most reliable to resolve). recover_modulo is itself
    // pubkey-gated, so a wrong (omega,bound) guess reduces a lattice that simply
    // fails to verify and we move on -- never a wrong key. Deliberately NOT run
    // from plain AUTO: each wrong rung costs a full reduction, so the blind
    // sweep is opt-in via `-m modulo` rather than taxing every recovery.
    struct Cand { int a, c; };  // omega = 2^a, bound = 2^c, window = a-c
    static const std::vector<Cand> cands = {{20, 4}, {16, 4}, {24, 8}, {12, 4}};
    for (const auto& cd : cands) {
        if (tel_.deadline_exceeded()) break;
        mpz omega = mpz(1) << cd.a;
        mpz bound = mpz(1) << cd.c;
        tel_.set_status("modulo sweep: omega=2^" + std::to_string(cd.a) +
                        " bound=2^" + std::to_string(cd.c));
        auto d = LatticeSolver::recover_modulo(pairs, omega, bound, max_sigs, &tel_, pubkey_hint);
        if (d.has_value()) return d;
    }
    return std::nullopt;
}

std::optional<mpz> RecoveryEngine::try_linear_nonce(
    const std::vector<Signature>& signatures, const std::vector<Pair>& /*pairs*/,
    const mpz& pubkey_hint, const mpz& lcg_a, const mpz& lcg_b, bool forced) {
    const mpz& n = SECP256K1_N;
    tel_.set_phase("Scanning for linearly-related (LCG) nonces");

    // Recompute the HNP coordinates (w = z*s^-1, x = r*s^-1) in file order,
    // carrying each signature's timestamp so the ordering fallback below can
    // reorder by it. (We can't reuse the Pair vector alone -- it doesn't carry
    // the timestamp, which is exactly the field 6d finally puts to use.)
    struct WX { mpz w, x; int64_t ts; bool timestamp_present; };
    std::vector<WX> seq;
    for (const auto& s : signatures) {
        if (!s.valid) continue;
        mpz sinv = utils::mod_inverse(s.s, n);
        if (sinv == 0) continue;
        seq.push_back({ utils::mod_mul(s.z, sinv, n), utils::mod_mul(s.r, sinv, n),
                        s.timestamp, s.timestamp_present });
    }
    if (seq.size() < (lcg_a > 0 ? static_cast<size_t>(2) : static_cast<size_t>(6)))
        return std::nullopt;

    auto accept = [&](const mpz& d) -> bool {
        if (d <= 1 || d >= n - 1) return false;
        // With a pubkey this is definitive. Without one (opt-in best-effort),
        // there is nothing to prove it against here, so defer to run()'s own
        // Verifier -- but the caller (unknown-a,b path) only reaches here after
        // an independent second window agreed, which a wrong solve won't do.
        if (pubkey_hint > 1) return utils::verify_pubkey(d, pubkey_hint);
        return true;
    };

    auto pass = [&](const std::vector<WX>& q) -> std::optional<mpz> {
        if (q.size() < 6 && lcg_a <= 0) return std::nullopt;
        if (lcg_a > 0) {
            // Known multiplier a (and increment b): a single consecutive pair
            //   k_{i+1} = a*k_i + b  and  k = w + x*d  give
            //   d = (a*w_i + b - w_{i+1}) * (x_{i+1} - a*x_i)^-1  (mod n).
            size_t lim = forced ? q.size() - 1 : std::min<size_t>(q.size() - 1, 64);
            for (size_t i = 0; i < lim; ++i) {
                mpz denom = (q[i+1].x - utils::mod_mul(lcg_a, q[i].x, n)) % n;
                if (denom < 0) denom += n;
                if (denom == 0) continue;
                mpz num = (utils::mod_mul(lcg_a, q[i].w, n) + lcg_b - q[i+1].w) % n;
                if (num < 0) num += n;
                mpz d = utils::mod_mul(num, utils::mod_inverse(denom, n), n);
                if (accept(d)) return d;
            }
            return std::nullopt;
        }
        // Unknown a,b: five consecutive signatures give four linear constraints
        //   x_{i+1} d - x_i e - w_i a - b = -w_{i+1},   e := a*d
        // in the four unknowns (d, e, a, b). Solve each 4x4 for d.
        //
        // A single solve on non-LCG data is meaningless noise, so trust d only
        // when two ADJACENT (overlapping) windows land on the SAME value --
        // genuine LCG makes every window agree; random data effectively never
        // does. This is also what keeps the pre-scan cheap enough to run on every
        // recovery: on non-LCG input it is solve-only modular arithmetic (no
        // scalar multiplications), and the one pubkey check happens only on the
        // rare adjacent agreement. (Needs >=6 consecutive sigs for two windows.)
        std::optional<mpz> prev;
        size_t lim = forced ? q.size() - 4 : std::min<size_t>(q.size() - 4, 48);
        for (size_t i = 0; i < lim; ++i) {
            std::vector<std::vector<mpz>> M(4, std::vector<mpz>(4));
            std::vector<mpz> rhs(4);
            for (size_t j = 0; j < 4; ++j) {
                mpz nx = (n - q[i+j].x % n) % n;
                mpz nw = (n - q[i+j].w % n) % n;
                M[j][0] = q[i+j+1].x % n;   // d
                M[j][1] = nx;               // e = a*d
                M[j][2] = nw;               // a
                M[j][3] = n - 1;            // b   (coefficient -1)
                rhs[j]  = (n - q[i+j+1].w % n) % n;
            }
            auto sol = solve_modn(M, rhs, n);
            if (!sol) { prev.reset(); continue; }
            mpz d = (*sol)[0];
            if (d <= 1 || d >= n - 1) { prev.reset(); continue; }
            if (prev && *prev == d && accept(d)) return d;
            prev = d;
        }
        return std::nullopt;
    };

    if (auto d = pass(seq)) return d;

    // Ordering fallback: the LCG advances in nonce-generation order, which the
    // file order may not preserve but the timestamp usually does. Retry on the
    // timestamp-sorted sequence -- but only if every participating record has a
    // timestamp and they are not all identical. Partial timestamp metadata is
    // not a trustworthy ordering key: sorting missing entries as zero could
    // manufacture an order the input never asserted.
    bool all_have_ts = std::all_of(seq.begin(), seq.end(),
        [](const WX& item) { return item.timestamp_present; });
    bool timestamps_vary = all_have_ts && std::any_of(seq.begin() + 1, seq.end(),
        [&](const WX& item) { return item.ts != seq.front().ts; });
    if (timestamps_vary) {
        std::vector<WX> byts = seq;
        std::stable_sort(byts.begin(), byts.end(),
                         [](const WX& x, const WX& y) { return x.ts < y.ts; });
        if (auto d = pass(byts)) return d;
    }
    return std::nullopt;
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
        candidate = try_lattice(pairs, profile, max_sigs, pubkey_hint);
        if (!verified(candidate) && !tel_.deadline_exceeded()) {
            // The profiler's chosen bias shape (MSB vs LSB) is itself a
            // heuristic call -- if it doesn't check out, try the other
            // shape before giving up rather than reporting failure outright.
            BiasProfile alt = profile;
            alt.type = (profile.type == BiasType::MSB) ? BiasType::LSB : BiasType::MSB;
            auto alt_cand = try_lattice(pairs, alt, max_sigs, pubkey_hint);
            if (verified(alt_cand) || !candidate.has_value()) {
                candidate = alt_cand;
            }
        }
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
    double max_time_sec,
    uint64_t sampling_seed,
    const mpz& modulo_omega,
    const mpz& modulo_bound,
    const mpz& lcg_a,
    const mpz& lcg_b
) {
    RecoveryResult result;
    auto start = std::chrono::steady_clock::now();

    tel_.reset();
    tel_.time_budget_sec = max_time_sec; // 0 = unlimited
    tel_.sampling_seed = sampling_seed;  // set after reset so it reaches the profiler
    tel_.start_time = start;
    tel_.signatures_loaded = signatures.size();
    tel_.signatures_valid = pairs.size();

    if (pairs.empty()) {
        tel_.set_error("No valid pairs");
        result.success = false;
        return result;
    }

    // Use any supplied PubKey, not only the first record. Best-effort input may
    // legitimately begin with keyless records while later records carry the
    // shared key established by the input-integrity boundary.
    mpz pubkey_hint = 0;
    for (const auto& sig : signatures) {
        if (sig.valid && sig.pubkey != 0) {
            pubkey_hint = sig.pubkey;
            break;
        }
    }

    // Phase 6a pre-scan: a reused nonce is the most common catastrophic ECDSA
    // RNG failure in the wild (Sony PS3, the 2013 Android SecureRandom Bitcoin
    // thefts). It is not a *bias* the lattice can exploit -- it is a nonce
    // *collision* that hands over the key by closed-form algebra, from as few
    // as two signatures, in O(n log n). So check it first and short-circuit
    // the entire profile/lattice pipeline on a verified hit. When there's no
    // collision this is a cheap no-op and recovery proceeds normally.
    if (auto rn = try_repeated_nonce(signatures, pubkey_hint)) {
        result.private_key = *rn;
        result.private_key_hex = utils::mpz_to_hex(*rn);
        result.method_used = RecoveryMethod::REPEATED_NONCE;
        result.signatures_used = signatures.size();
        result.bias_profile.description =
            "Reused nonce (r-collision) -- recovered by closed-form algebra, no lattice";
    } else if (auto ln = try_linear_nonce(signatures, pairs, pubkey_hint, lcg_a, lcg_b,
                                          force_method == RecoveryMethod::LINEAR)) {
        // Phase 6d pre-scan: linearly-related (LCG) nonces yield the key by
        // closed-form algebra (a small modular linear system over consecutive
        // signatures), no lattice -- like the repeated-nonce case. Cheap and
        // pubkey-gated, so it runs on every AUTO recovery and a spurious solve
        // on non-LCG data is discarded rather than returned.
        result.private_key = *ln;
        result.private_key_hex = utils::mpz_to_hex(*ln);
        result.method_used = RecoveryMethod::LINEAR;
        result.signatures_used = signatures.size();
        tel_.active_method = static_cast<int>(RecoveryMethod::LINEAR);
        tel_.method_chosen = true;
        result.bias_profile.description =
            (lcg_a > 0
                 ? "Linearly-related nonces (LCG, known multiplier) -- closed-form, no lattice"
                 : "Linearly-related nonces (LCG) -- closed-form 4x4 solve, no lattice");
    } else if (force_method == RecoveryMethod::LINEAR) {
        // Forced LINEAR but no such structure found: fail honestly rather than
        // silently falling through to statistical profiling.
        result.success = false;
        result.verification_details = "No linearly-related (LCG) nonce structure found";
        tel_.recovery_complete = true;
        return result;
    } else if (force_method == RecoveryMethod::MODULO ||
               (modulo_omega > 0 && modulo_bound > 0)) {
        // Phase 6c: modulo / Extended-HNP. Either the (omega,bound) is supplied
        // as a hint (route straight to the EHNP lattice, skipping statistical
        // detection, exactly as the known-LSB path does) or `-m modulo` forces a
        // blind sweep over common windows. Not reachable from plain AUTO -- see
        // try_modulo for why the blind sweep is opt-in.
        auto d = try_modulo(pairs, modulo_omega, modulo_bound, max_sigs, pubkey_hint);
        if (d.has_value()) {
            result.private_key = *d;
            result.private_key_hex = utils::mpz_to_hex(*d);
            result.method_used = RecoveryMethod::MODULO;
            result.signatures_used = pairs.size();
            result.bias_profile.type = BiasType::MODULO;
            result.bias_profile.modulo_omega = modulo_omega;
            result.bias_profile.modulo_bound = modulo_bound;
            result.bias_profile.bias_detected = true;
            result.bias_profile.description =
                "modulo / Extended-HNP: k mod omega in [0, bound)";
        } else {
            result.success = false;
            result.verification_details = "No candidate produced (modulo/EHNP)";
            tel_.recovery_complete = true;
            return result;
        }
    } else {
        BiasProfile profile;
        int known_bits = uniform_known_low_bits(signatures);
        if (known_bits > 0) {
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
            // Profile
            tel_.set_phase("Profiling bias");
            profile = BiasProfiler::profile(pairs, &tel_);
        }

        bool dispatch_ok = dispatch_and_recover(profile, pairs, force_method, max_sigs, pubkey_hint, result);

        if (!dispatch_ok || !result.private_key) {
            result.success = false;
            tel_.recovery_complete = true;
            return result;
        }
    }

    // Strict verification
    tel_.set_phase("Verifying candidate");
    std::string details;
    bool verified = Verifier::verify_candidate(result.private_key, signatures, details, &tel_);

    result.verification_details = details;
    result.success = verified;

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
