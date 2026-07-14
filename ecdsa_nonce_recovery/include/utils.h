#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <optional>

namespace utils {

    // Modular inverse using GMP (extended euclid)
    mpz mod_inverse(const mpz& a, const mpz& m);

    // Modular multiply
    mpz mod_mul(const mpz& a, const mpz& b, const mpz& m);

    // Modular add
    mpz mod_add(const mpz& a, const mpz& b, const mpz& m);

    // Convert mpz to hex string (lowercase, no 0x)
    std::string mpz_to_hex(const mpz& v);

    // Convert hex string to mpz
    mpz hex_to_mpz(const std::string& hex);

    // Print progress-safe hex (truncate if needed for UI)
    std::string mpz_to_hex_trunc(const mpz& v, size_t max_chars = 64);

    // Compute secp256k1 pubkey from d (d * G)
    // Returns uncompressed 04||X||Y as mpz (for verification)
    mpz compute_pubkey(const mpz& d);

    // Verify d * G == given pubkey point
    bool verify_pubkey(const mpz& d, const mpz& pubkey_mpz);

    // Statistical helpers
    double z_score_from_proportion(double observed, double expected, size_t n);
    double chi_squared_uniform(const std::vector<double>& observed_freq, size_t total_samples);

    // Transform (w, x) pairs for LSB-bias handling: if k is an exact
    // multiple of 2^b (LSB bias with b known-zero low bits), then
    // k' := k * inv(2^b) mod N is an exact small integer (k/2^b, no
    // wraparound, since 2^b divides k exactly and the quotient is < N).
    // Substituting k' into k ≡ w + x*d (mod N) and dividing through by
    // 2^b gives k' ≡ w' + x'*d (mod N) with w' = w*inv(2^b) mod N,
    // x' = x*inv(2^b) mod N -- i.e. LSB bias in k becomes MSB-shaped
    // bias in k' (k' is bounded exactly like an MSB-biased nonce with
    // the same bit count), so the existing MSB machinery can be reused
    // unchanged on the transformed pairs.
    std::vector<Pair> transform_pairs_lsb(const std::vector<Pair>& pairs, int b);

    // Exact Poisson upper-tail P(X >= k) for X ~ Poisson(lambda), by direct
    // log-space summation of the CDF up to k-1. Exact (not an asymptotic
    // approximation) for the small (lambda, k) regime used throughout this
    // codebase's significance tests.
    double poisson_upper_tail(int k, double lambda);

} // namespace utils
