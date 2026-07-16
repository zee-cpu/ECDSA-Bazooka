#include "utils.h"
#include "secp256k1.h"
#include <iomanip>
#include <sstream>
#include <cmath>
#include <random>

namespace utils {

mpz mod_inverse(const mpz& a, const mpz& m) {
    mpz result;
    if (mpz_invert(result.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0) {
        return mpz(0);
    }
    return result;
}

mpz mod_mul(const mpz& a, const mpz& b, const mpz& m) {
    mpz result = (a * b) % m;
    if (result < 0) result += m;
    return result;
}

mpz mod_add(const mpz& a, const mpz& b, const mpz& m) {
    mpz result = (a + b) % m;
    if (result < 0) result += m;
    return result;
}

std::string mpz_to_hex(const mpz& v) {
    if (v == 0) return "0";
    return v.get_str(16);
}

mpz hex_to_mpz(const std::string& hex) {
    std::string h = hex;
    if (h.size() > 2 && (h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))) {
        h = h.substr(2);
    }
    mpz res;
    res.set_str(h, 16);
    return res;
}

std::string mpz_to_hex_trunc(const mpz& v, size_t max_chars) {
    std::string h = mpz_to_hex(v);
    if (h.size() > max_chars) {
        return h.substr(0, max_chars / 2) + "..." + h.substr(h.size() - max_chars / 2);
    }
    return h;
}

// === REAL EC IMPLEMENTATION ===

mpz compute_pubkey(const mpz& d) {
    if (d <= 0 || d >= SECP256K1_N) return mpz(0);

    auto point = secp256k1::scalar_mult(d, secp256k1::G);
    if (point.infinity) return mpz(0);

    return secp256k1::point_to_pubkey(point);
}

bool verify_pubkey(const mpz& d, const mpz& pubkey_mpz) {
    if (d <= 0 || d >= SECP256K1_N) return false;
    if (pubkey_mpz == 0) return false;   // no pubkey to compare against

    auto expected_point = secp256k1::pubkey_to_point(pubkey_mpz);
    if (!expected_point.has_value()) return false;

    auto computed_point = secp256k1::scalar_mult(d, secp256k1::G);

    return secp256k1::points_equal(computed_point, *expected_point);
}

double z_score_from_proportion(double observed, double expected, size_t n) {
    if (n == 0 || expected == 0) return 0.0;
    double p = observed / n;
    double p0 = expected;
    double se = std::sqrt(p0 * (1.0 - p0) / n);
    if (se < 1e-12) return 0.0;
    return (p - p0) / se;
}

double chi_squared_uniform(const std::vector<double>& observed_freq, size_t total_samples) {
    if (observed_freq.empty() || total_samples == 0) return 0.0;
    size_t bins = observed_freq.size();
    double expected = static_cast<double>(total_samples) / bins;
    double chi = 0.0;
    for (double obs : observed_freq) {
        double diff = obs - expected;
        chi += (diff * diff) / expected;
    }
    return chi;
}

std::vector<Pair> transform_pairs_lsb(const std::vector<Pair>& pairs, int b) {
    mpz N = SECP256K1_N;
    mpz two_b = mpz(1) << b;
    mpz inv2b = mod_inverse(two_b, N);

    std::vector<Pair> out;
    out.reserve(pairs.size());
    for (const auto& p : pairs) {
        Pair tp;
        // Phase 6b generalization: for a known low-bit residue c (k ≡ c mod
        // 2^b), k - c is the exact multiple of 2^b, so subtract c from w first.
        // k' = (k - c)/2^b = 2^-b*(w - c) + 2^-b*x*d (mod N). c defaults to 0,
        // recovering the original LSB-zero transform (k' = 2^-b*w + ...).
        mpz w_shifted = (p.w - p.known_low_value) % N;
        if (w_shifted < 0) w_shifted += N;
        tp.w = mod_mul(w_shifted, inv2b, N);
        tp.x = mod_mul(p.x, inv2b, N);
        // The transformed pair describes k' directly, which carries no further
        // known low bits, so the offset does not propagate.
        out.push_back(tp);
    }
    return out;
}

double poisson_upper_tail(int k, double lambda) {
    if (lambda <= 0.0) return (k <= 0) ? 1.0 : 0.0;
    if (k <= 0) return 1.0;
    double log_term = -lambda; // log P(X=0)
    double cdf = std::exp(log_term);
    for (int i = 1; i < k; ++i) {
        log_term += std::log(lambda) - std::log(static_cast<double>(i));
        cdf += std::exp(log_term);
    }
    return std::max(0.0, 1.0 - cdf);
}

} // namespace utils
