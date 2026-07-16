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

    bool dispatch_and_recover(
        const BiasProfile& profile,
        const std::vector<Pair>& pairs,
        RecoveryMethod force,
        size_t max_sigs,
        const mpz& pubkey_hint,
        RecoveryResult& result
    );
};
