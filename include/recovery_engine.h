#pragma once

#include "types.h"
#include <vector>
#include <string>

class RecoveryEngine {
public:
    explicit RecoveryEngine(Telemetry& tel);

    RecoveryResult run(
        const std::vector<Signature>& signatures,
        const std::vector<Pair>& pairs,
        RecoveryMethod force_method = RecoveryMethod::AUTO,
        size_t max_sigs = 0,
        double max_time_sec = 0.0,
        uint64_t sampling_seed = DEFAULT_SAMPLING_SEED,
        // Phase 6c: optional modulo/EHNP hint (k mod omega in [0, bound)). When
        // both are > 0 the leak structure is *supplied* -- like the known-LSB
        // hint -- and recovery routes straight to the Extended-HNP lattice,
        // skipping statistical detection. Both 0 (the default) leaves behaviour
        // identical to before.
        const mpz& modulo_omega = mpz(0),
        const mpz& modulo_bound = mpz(0),
        // Phase 6d: optional linearly-related (LCG) nonce hint, k_{i+1} = a*k_i+b
        // (mod n). When lcg_a > 0 the multiplier (and increment lcg_b, default 0)
        // are supplied and two consecutive signatures suffice. lcg_a == 0 (the
        // default) leaves the unknown-(a,b) closed-form pre-scan to discover the
        // key on its own, or -- absent any LCG structure -- to find nothing.
        const mpz& lcg_a = mpz(0),
        const mpz& lcg_b = mpz(0)
    );

private:
    Telemetry& tel_;

    std::optional<mpz> try_lattice(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs, const mpz& pubkey_hint);
    std::optional<mpz> try_fallback_ladder(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs, const mpz& pubkey_hint);

    // Phase 6a: cheap O(n log n) pre-scan for reused nonces. Two signatures
    // that share r were made with the same nonce k, which yields the private
    // key by closed-form algebra alone. Returns the key only if it checks out
    // against pubkey_hint (or, in best-effort no-pubkey mode, the algebraic
    // result for the caller's own verification to gate). std::nullopt if no
    // usable collision exists.
    std::optional<mpz> try_repeated_nonce(const std::vector<Signature>& signatures, const mpz& pubkey_hint);

    // Phase 6c: Extended-HNP recovery for modulo / windowed-zero bias
    // (k mod omega in [0, bound)). When omega/bound are supplied (hint path) it
    // solves that one instance; otherwise it sweeps a small set of common
    // (omega, bound) candidates and returns the first that yields a
    // pubkey-verified key. std::nullopt if none recover. Pubkey-gated, so a
    // wrong candidate never produces a wrong key.
    std::optional<mpz> try_modulo(const std::vector<Pair>& pairs, const mpz& modulo_omega,
                                  const mpz& modulo_bound, size_t max_sigs, const mpz& pubkey_hint);

    // Phase 6d: closed-form recovery from linearly-related (LCG) nonces,
    // k_{i+1} = a*k_i + b (mod n). With a supplied multiplier (lcg_a > 0, plus
    // increment lcg_b) two consecutive signatures give d directly. With a,b
    // unknown, five consecutive signatures give a 4x4 modular linear system in
    // (d, a*d, a, b) that still yields d. Signatures are taken in file order,
    // then (as a fallback) sorted by timestamp -- the LCG advances in generation
    // order, which the timestamp usually reflects. Pubkey-gated, so a spurious
    // solve on non-LCG data never yields a wrong key. `forced` widens the search
    // from the cheap bounded pre-scan to every window. std::nullopt if none
    // recover.
    std::optional<mpz> try_linear_nonce(const std::vector<Signature>& signatures,
                                        const std::vector<Pair>& pairs,
                                        const mpz& pubkey_hint,
                                        const mpz& lcg_a, const mpz& lcg_b, bool forced);

    bool dispatch_and_recover(
        const BiasProfile& profile,
        const std::vector<Pair>& pairs,
        RecoveryMethod force,
        size_t max_sigs,
        const mpz& pubkey_hint,
        RecoveryResult& result
    );
};
