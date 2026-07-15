#pragma once

#include "types.h"
#include <vector>
#include <optional>

#include <fplll/fplll.h>

class LatticeSolver {
public:
    // Main entry for lattice-based recovery (Boneh-Venkatesan / HGS style)
    // Returns candidate d or nullopt on failure
    // pubkey_hint (when nonzero) lets recovery verify each extracted
    // candidate against the real public key directly, instead of relying
    // solely on the internal leading-zero scoring heuristic to pick a
    // single winner. Verification is one scalar-mult -- negligible next to
    // an LLL/BKZ reduction -- so checking every candidate removes the
    // failure mode where the correct key is extracted but out-scored by a
    // wrong candidate and silently discarded before it ever reaches the
    // engine's verification gate.
    static std::optional<mpz> recover_private_key(
        const std::vector<Pair>& pairs,
        const BiasProfile& bias,
        size_t max_signatures = 0,
        Telemetry* telemetry = nullptr,
        const mpz& pubkey_hint = mpz(0)
    );

    // Build the lattice matrix (for debugging / standalone)
    static bool build_boneh_venkatesan_basis(
        const std::vector<Pair>& pairs,
        int leaked_bits,
        fplll::ZZ_mat<mpz_t>& basis,
        mpz& scaling_factor
    );

    // Perform lattice reduction and extract a candidate d. bkz_block_size
    // == 0 uses plain LLL (fast, sufficient for most cases actually seen
    // so far); > 0 uses BKZ with that block size instead (stronger
    // reduction, escalation for cases LLL alone doesn't resolve cleanly --
    // see recover_private_key for how the block size is chosen). Public
    // so the bias profiler can reuse this exact, validated extraction
    // logic as the core of its detector.
    static std::optional<mpz> reduce_and_extract(
        fplll::ZZ_mat<mpz_t>& basis,
        const std::vector<Pair>& pairs,
        Telemetry* telemetry,
        int bkz_block_size = 0,
        const mpz& pubkey_hint = mpz(0)
    );

private:
};
