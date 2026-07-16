// Differential-test I/O shim (Phase 4). Reads hex private scalars (one per
// line, 0x-prefixed or bare) from stdin and prints, for each, the uncompressed
// SEC1 public key of d*G -- 130 lowercase hex chars, 04||X||Y -- computed by
// THIS project's hand-rolled secp256k1 arithmetic.
//
// It is not a test on its own; tests/ecc_differential_test.py drives it with
// edge + random scalars and compares every line against the trusted `ecdsa`
// library, so any discrepancy in point_add / point_double / scalar_mult is
// caught rather than trusted. Kept as a tiny shim so the reference comparison
// can live in Python where the trusted library is.
#include "secp256k1.h"
#include "utils.h"
#include <iostream>
#include <string>

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        size_t a = line.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) continue;
        size_t b = line.find_last_not_of(" \t\r\n");
        std::string h = line.substr(a, b - a + 1);
        if (h.size() > 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) h = h.substr(2);

        mpz d;
        try { d.set_str(h, 16); } catch (...) { std::cout << "ERR\n"; continue; }

        secp256k1::Point P = secp256k1::scalar_mult(d, secp256k1::G);
        mpz pub = secp256k1::point_to_pubkey(P);  // 04||x||y as an mpz (0 if O)

        // Left-pad to the canonical 130 hex chars (GMP drops the 04 marker's
        // leading zero nibble, and X/Y can have leading zero bytes too).
        std::string s = pub.get_str(16);
        if (s.size() < 130) s = std::string(130 - s.size(), '0') + s;
        std::cout << s << "\n";
    }
    return 0;
}
