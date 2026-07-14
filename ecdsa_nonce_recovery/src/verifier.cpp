#include "verifier.h"
#include "utils.h"
#include "secp256k1.h"
#include <sstream>

mpz Verifier::recompute_s(const mpz& d, const mpz& k, const mpz& r, const mpz& z) {
    mpz kinv = utils::mod_inverse(k, SECP256K1_N);
    if (kinv == 0) return mpz(0);
    mpz tmp = utils::mod_add(z, utils::mod_mul(r, d, SECP256K1_N), SECP256K1_N);
    return utils::mod_mul(kinv, tmp, SECP256K1_N);
}

bool Verifier::verify_ecdsa_equation(const mpz& d, const mpz& r, const mpz& s, const mpz& z) {
    if (r <= 0 || r >= SECP256K1_N || s <= 0 || s >= SECP256K1_N) return false;

    mpz sinv = utils::mod_inverse(s, SECP256K1_N);
    if (sinv == 0) return false;

    mpz u1 = utils::mod_mul(z, sinv, SECP256K1_N);
    mpz u2 = utils::mod_mul(r, sinv, SECP256K1_N);

    secp256k1::Point P = secp256k1::scalar_mult(d, secp256k1::G);
    secp256k1::Point R1 = secp256k1::scalar_mult(u1, secp256k1::G);
    secp256k1::Point R2 = secp256k1::scalar_mult(u2, P);
    secp256k1::Point R = secp256k1::point_add(R1, R2);

    if (R.infinity) return false;

    mpz rx_mod = R.x % SECP256K1_N;
    if (rx_mod < 0) rx_mod += SECP256K1_N;
    return rx_mod == r;
}

bool Verifier::verify_candidate(
    const mpz& d,
    const std::vector<Signature>& signatures,
    std::string& details_out,
    Telemetry* telemetry
) {
    if (d <= 0 || d >= SECP256K1_N) {
        details_out = "Candidate d out of range";
        return false;
    }

    std::ostringstream oss;

    // === PRIMARY, authoritative check: genuine ECDSA verification ===
    // Self-contained -- doesn't trust or require any PubKey field from the
    // input file, since P = d*G is derived fresh from the candidate. A
    // wrong d passes this for a given real signature with probability
    // ~1/N, so requiring it across several independent signatures gives
    // overwhelming confidence without depending on external/parsed data.
    int checked = 0;
    int equation_matches = 0;
    const int MAX_CHECK = 5;

    for (size_t i = 0; i < signatures.size() && checked < MAX_CHECK; ++i) {
        if (!signatures[i].valid) continue;
        const Signature& sig = signatures[i];

        bool ok = verify_ecdsa_equation(d, sig.r, sig.s, sig.z);
        if (ok) ++equation_matches;
        ++checked;

        if (checked <= 3) {
            oss << "sig#" << (i + 1) << "=" << (ok ? "OK " : "FAIL ");
        }
    }

    bool equation_verified = (checked > 0 && equation_matches == checked);

    // === Secondary, informational cross-check: does the file's own
    // claimed PubKey (if present) agree with the pubkey our candidate
    // implies? This flags inconsistent/corrupted input data, but is not
    // itself the gate -- the standard ECDSA equation above already proves
    // correctness independent of what this field claims. ===
    bool pubkey_field_present = !signatures.empty() && signatures[0].pubkey != 0;
    bool pubkey_field_matches = false;
    if (pubkey_field_present) {
        pubkey_field_matches = utils::verify_pubkey(d, signatures[0].pubkey);
        oss << " | file PubKey " << (pubkey_field_matches ? "consistent" : "MISMATCH");
    }

    bool success = equation_verified;

    if (success) {
        oss << "  -> VERIFIED (standard ECDSA equation, " << equation_matches << "/" << checked << " signatures)";
    } else {
        oss << "  -> VERIFICATION FAILED (" << equation_matches << "/" << checked << " signatures satisfied ECDSA equation)";
    }

    details_out = oss.str();

    if (telemetry) {
        telemetry->verification_passed = success;
        telemetry->set_status(success ? "ECDSA verification PASSED" : "ECDSA verification FAILED");
    }

    return success;
}
