#include "predicate_shim.h"

#include "types.h"
#include "utils.h"

#include <gmpxx.h>

namespace {

// Big-endian byte buffer -> mpz. len bytes, most-significant byte first.
mpz bytes_to_mpz(const uint8_t* buf, size_t len) {
    mpz v;
    mpz_import(v.get_mpz_t(), len, /*order=*/1, /*size=*/1,
               /*endian=*/1, /*nails=*/0, buf);
    return v;
}

} // namespace

extern "C" int bazooka_predicate(const uint8_t d[32], const uint8_t pubkey[33]) {
    mpz d_scalar = bytes_to_mpz(d, 32);
    // Interpret the 33 compressed bytes as the SEC1 integer pubkey_to_point expects.
    mpz pubkey_mpz = bytes_to_mpz(pubkey, 33);
    return utils::verify_pubkey(d_scalar, pubkey_mpz) ? 1 : 0;
}
