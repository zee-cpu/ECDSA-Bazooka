#pragma once

#include <cstdint>

// C ABI shim exposing the tool's validated secp256k1 public-key check to the
// (out-of-process) sieve worker via cffi. Reuses utils::verify_pubkey, so the
// worker's predicate runs the same EC code as the rest of the tool.
//
// This shim depends only on the tool's own secp256k1/utils sources; it links
// no lattice/sieve libraries and is safe to build into the main binary.
extern "C" {

// Return 1 iff d (32-byte big-endian scalar, 0 < d < n) satisfies d*G == pubkey,
// where pubkey is a 33-byte compressed SEC1 point (0x02/0x03 || x). Return 0
// otherwise (wrong key, out-of-range scalar, or malformed pubkey encoding).
int bazooka_predicate(const uint8_t d[32], const uint8_t pubkey[33]);

}
