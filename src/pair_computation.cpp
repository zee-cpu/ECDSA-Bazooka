#include "pair_computation.h"
#include "utils.h"

std::vector<Pair> PairComputer::compute_pairs(const std::vector<Signature>& sigs, Telemetry* telemetry) {
    std::vector<Pair> pairs;
    pairs.reserve(sigs.size());

    size_t processed = 0;

    for (const auto& sig : sigs) {
        if (!sig.valid) continue;

        // s^{-1} mod n
        mpz sinv = utils::mod_inverse(sig.s, SECP256K1_N);
        if (sinv == 0) {
            // should be rare; skip
            if (telemetry) telemetry->signatures_skipped++;
            continue;
        }

        // w = z * s^{-1} mod n
        mpz w = utils::mod_mul(sig.z, sinv, SECP256K1_N);

        // x = r * s^{-1} mod n
        mpz x = utils::mod_mul(sig.r, sinv, SECP256K1_N);

        Pair p;
        p.w = w;
        p.x = x;
        p.source_index = sig.index;  // preserve provenance to the source record
        pairs.push_back(p);

        ++processed;
        if (telemetry && (processed % 500 == 0)) {
            telemetry->signatures_valid = processed; // reuse temporarily
        }
    }

    return pairs;
}
