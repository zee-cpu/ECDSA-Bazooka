#pragma once

#include "types.h"
#include <vector>

class Verifier {
public:
    // Verify candidate d against signatures via the standard ECDSA
    // verification equation (see verify_ecdsa_equation below). Also
    // cross-checks the file's PubKey field, if present, as an
    // informational consistency note.
    static bool verify_candidate(
        const mpz& d,
        const std::vector<Signature>& signatures,
        std::string& details_out,
        Telemetry* telemetry = nullptr
    );

    // Genuine, self-contained ECDSA verification: recompute R' = u1*G + u2*P
    // (P = d*G, derived fresh from the candidate, not read from any file
    // field) and check R'.x mod N == r. This is the actual verification
    // equation, not derived from k/w/x at all, so unlike the old
    // "reconstruct k, recompute s" check it is not tautological: a wrong
    // d satisfies it for a given real (r,s,z) only with probability ~1/N.
    static bool verify_ecdsa_equation(const mpz& d, const mpz& r, const mpz& s, const mpz& z);

    // Recompute s' = k^{-1} * (z + r*d) mod n  given d and k (computed).
    // Kept only for diagnostic display -- see verify_candidate for why this
    // reconstruction reproduces the original s for *any* d and therefore
    // cannot itself be used as evidence of correctness.
    static mpz recompute_s(const mpz& d, const mpz& k, const mpz& r, const mpz& z);
};
