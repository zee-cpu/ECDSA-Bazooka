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
        uint64_t sampling_seed = DEFAULT_SAMPLING_SEED
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

    bool dispatch_and_recover(
        const BiasProfile& profile,
        const std::vector<Pair>& pairs,
        RecoveryMethod force,
        size_t max_sigs,
        const mpz& pubkey_hint,
        RecoveryResult& result
    );
};
