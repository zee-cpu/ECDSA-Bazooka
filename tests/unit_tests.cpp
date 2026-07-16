// Fast, isolated unit tests for the pieces of this codebase whose
// correctness doesn't require a full (slow) end-to-end recovery run to
// check. These are meant to catch a regression in seconds, not five
// minutes -- e.g. a subtle sign error in the pivot-elimination algebra,
// or the exact padding bug that once made every PubKey verification
// silently fail. See tests/e2e_recovery_test.sh for the complementary
// full-pipeline coverage.
#include "types.h"
#include "utils.h"
#include "secp256k1.h"
#include "verifier.h"
#include "lattice_solver.h"
#include "parser.h"
#include <iostream>
#include <cmath>
#include <random>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& desc) {
    g_checks++;
    if (cond) {
        std::cout << "  [PASS] " << desc << "\n";
    } else {
        std::cout << "  [FAIL] " << desc << "\n";
        g_failures++;
    }
}

void check_close(double actual, double expected, double tol, const std::string& desc) {
    check(std::abs(actual - expected) < tol,
          desc + " (actual=" + std::to_string(actual) + ", expected=" + std::to_string(expected) + ")");
}

// ---------------------------------------------------------------------
// utils::poisson_upper_tail: check against hand-computable reference
// values (small enough lambda/k to verify by direct combinatorics).
// ---------------------------------------------------------------------
void test_poisson_upper_tail() {
    std::cout << "-- utils::poisson_upper_tail --\n";

    check_close(utils::poisson_upper_tail(0, 5.0), 1.0, 1e-9, "P(X>=0)=1");
    check_close(utils::poisson_upper_tail(1, 0.0), 0.0, 1e-9, "lambda=0 => P(X>=1)=0");
    check_close(utils::poisson_upper_tail(1, 1.0), 1.0 - std::exp(-1.0), 1e-9, "Poisson(1) P(X>=1)");
    check_close(utils::poisson_upper_tail(5, 5.0), 0.5595, 5e-4, "Poisson(5) P(X>=5) matches reference");

    double prev = 1.1;
    bool monotone = true;
    for (int k = 0; k <= 20; ++k) {
        double p = utils::poisson_upper_tail(k, 5.0);
        if (p > prev) monotone = false;
        prev = p;
    }
    check(monotone, "P(X>=k) is non-increasing in k");

    check_close(utils::poisson_upper_tail(1, 1e-6), 1e-6, 1e-9,
                "tiny-lambda regime doesn't blow up (this is what the old z-score test got wrong)");
}

// ---------------------------------------------------------------------
// LSB transform exactness: construct a synthetic (w, x) pair directly
// from a known d and a k that's an exact multiple of 2^b, and confirm
// the transform + a single back-substitution recovers d exactly --
// without needing any lattice reduction at all.
// ---------------------------------------------------------------------
void test_lsb_transform_exactness() {
    std::cout << "-- utils::transform_pairs_lsb --\n";

    mpz N = SECP256K1_N;
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<uint64_t> dist;

    mpz d = 0;
    while (d == 0) d = ((mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng)) % N;

    int b = 20;
    mpz k_high = (mpz(dist(rng)) << 64) + dist(rng);
    mpz k = (k_high % (N >> b)) * (mpz(1) << b); // exact multiple of 2^b

    mpz x = ((mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng)) % N;
    if (x == 0) x = 1;

    mpz w = (k - utils::mod_mul(x, d, N)) % N;
    if (w < 0) w += N;

    Pair p{w, x};
    auto transformed = utils::transform_pairs_lsb({p}, b);
    check(transformed.size() == 1, "transform preserves pair count");

    mpz k_prime_expected = k / (mpz(1) << b);
    mpz k_prime_actual = utils::mod_add(transformed[0].w, utils::mod_mul(transformed[0].x, d, N), N);
    check(k_prime_actual == k_prime_expected, "transformed k' equals exact k/2^b, no wraparound noise");

    mpz x0inv = utils::mod_inverse(transformed[0].x, N);
    mpz d_recovered = utils::mod_mul((k_prime_actual - transformed[0].w + N) % N, x0inv, N);
    check(d_recovered == d, "back-substitution from transformed pivot recovers original d exactly");
}

// ---------------------------------------------------------------------
// Pivot-elimination algebra: construct several synthetic (w, x) pairs
// from a known d and known k's, and verify the derived a_i, t_i satisfy
// k_i = a_i*k_0 + t_i (mod N) exactly -- pure modular arithmetic, no
// lattice reduction, isolating the algebra from the LLL step entirely.
// ---------------------------------------------------------------------
void test_pivot_elimination_algebra() {
    std::cout << "-- pivot-elimination algebra (k_i = a_i*k_0 + t_i mod N) --\n";

    mpz N = SECP256K1_N;
    std::mt19937_64 rng(999);
    std::uniform_int_distribution<uint64_t> dist;

    auto rand_mpz = [&]() {
        mpz v = (mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng);
        return v % N;
    };

    mpz d = rand_mpz();
    if (d == 0) d = 1;

    const int m = 5;
    std::vector<mpz> w(m), x(m), k(m);
    for (int i = 0; i < m; ++i) {
        x[i] = rand_mpz();
        if (x[i] == 0) x[i] = 1;
        k[i] = rand_mpz();
        w[i] = (k[i] - utils::mod_mul(x[i], d, N)) % N;
        if (w[i] < 0) w[i] += N;
    }

    mpz x0inv = utils::mod_inverse(x[0], N);
    bool all_hold = true;
    for (int i = 1; i < m; ++i) {
        mpz a_i = utils::mod_mul(x[i], x0inv, N);
        mpz aw0 = utils::mod_mul(a_i, w[0], N);
        mpz t_i = (w[i] - aw0) % N;
        if (t_i < 0) t_i += N;

        mpz rhs = utils::mod_add(utils::mod_mul(a_i, k[0], N), t_i, N);
        if (rhs != k[i]) all_hold = false;
    }
    check(all_hold, "k_i = a_i*k_0 + t_i (mod N) holds exactly for all derived pairs");
}

// ---------------------------------------------------------------------
// PubKey round-trip: the exact bug class that once made every PubKey
// verification silently fail (GMP's get_str never prints insignificant
// leading zero hex digits). Test across enough random keys, and
// specifically flag cases where X itself starts with a zero byte too.
// ---------------------------------------------------------------------
void test_pubkey_roundtrip() {
    std::cout << "-- secp256k1 pubkey round-trip (padding fix regression check) --\n";

    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist;

    int mismatches = 0;
    const int trials = 200;
    for (int t = 0; t < trials; ++t) {
        mpz d = 0;
        while (d == 0) d = ((mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng)) % SECP256K1_N;
        mpz pubkey = utils::compute_pubkey(d);
        if (!utils::verify_pubkey(d, pubkey)) mismatches++;
    }
    check(mismatches == 0, "compute_pubkey -> verify_pubkey round-trips for " + std::to_string(trials) + " random keys");

    // The marker byte is 0x04 -- nibble sequence '0','4'. GMP's get_str
    // strips the leading '0', but the '4' right after it is fixed and
    // non-zero, so it always anchors the start of the significant-digit
    // sequence; everything after it (including X's own zero-padded high
    // nibbles from point_to_pubkey's explicit padding) is now *interior*,
    // and interior zeros are never stripped. So exactly one hex digit is
    // always missing -- never more, regardless of X or Y's value -- which
    // is exactly what pubkey_to_point's left-pad-to-130-chars fix handles.
    // This asserts that's still true (a second digit vanishing would mean
    // something changed in point_to_pubkey's padding).
    bool always_129 = true;
    for (int t = 0; t < 500; ++t) {
        mpz d = 0;
        while (d == 0) d = ((mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng)) % SECP256K1_N;
        mpz pubkey = utils::compute_pubkey(d);
        if (utils::mpz_to_hex(pubkey).size() != 129) always_129 = false;
    }
    check(always_129, "marker byte always strips to exactly 129 hex chars (never more) -- confirms the padding fix's assumption");
}

// ---------------------------------------------------------------------
// Genuine ECDSA verification: construct a real, valid synthetic
// signature from a known d, and confirm verify_ecdsa_equation accepts
// the correct d and rejects a wrong one -- a regression guard against
// the old tautological check, which accepted *any* d unconditionally.
// ---------------------------------------------------------------------
void test_ecdsa_equation_verification() {
    std::cout << "-- Verifier::verify_ecdsa_equation --\n";

    mpz N = SECP256K1_N;
    std::mt19937_64 rng(7);
    std::uniform_int_distribution<uint64_t> dist;
    auto rand_scalar = [&]() {
        mpz v = 0;
        while (v == 0) v = ((mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng)) % N;
        return v;
    };

    mpz d = rand_scalar();
    mpz k = rand_scalar();
    mpz z = rand_scalar();

    secp256k1::Point R = secp256k1::scalar_mult(k, secp256k1::G);
    mpz r = R.x % N;
    mpz kinv = utils::mod_inverse(k, N);
    mpz s = utils::mod_mul(kinv, utils::mod_add(z, utils::mod_mul(r, d, N), N), N);

    check(Verifier::verify_ecdsa_equation(d, r, s, z), "correct d passes genuine ECDSA verification");

    mpz wrong_d = rand_scalar();
    check(!Verifier::verify_ecdsa_equation(wrong_d, r, s, z),
          "wrong d is rejected (regression guard vs. the old tautological check)");

    check(!Verifier::verify_ecdsa_equation(d, mpz(0), s, z), "r=0 rejected");
    check(!Verifier::verify_ecdsa_equation(d, r, mpz(0), z), "s=0 rejected");
}

// ---------------------------------------------------------------------
// Lattice basis construction: dimension formula and edge-case handling,
// without running the (slow) LLL reduction itself.
// ---------------------------------------------------------------------
void test_lattice_basis_construction() {
    std::cout << "-- LatticeSolver::build_boneh_venkatesan_basis --\n";

    mpz N = SECP256K1_N;
    std::mt19937_64 rng(123);
    std::uniform_int_distribution<uint64_t> dist;
    auto rand_mpz = [&]() {
        mpz v = ((mpz(dist(rng)) << 192) + (mpz(dist(rng)) << 128) + (mpz(dist(rng)) << 64) + dist(rng)) % N;
        return v == 0 ? mpz(1) : v;
    };

    std::vector<Pair> too_few = {{rand_mpz(), rand_mpz()}, {rand_mpz(), rand_mpz()}};
    fplll::ZZ_mat<mpz_t> basis_fail;
    mpz scaling_fail;
    check(!LatticeSolver::build_boneh_venkatesan_basis(too_few, 12, basis_fail, scaling_fail),
          "too few pairs (m<4) correctly rejected");

    int m = 40;
    std::vector<Pair> pairs;
    for (int i = 0; i < m; ++i) pairs.push_back({rand_mpz(), rand_mpz()});

    fplll::ZZ_mat<mpz_t> basis;
    mpz scaling;
    bool ok = LatticeSolver::build_boneh_venkatesan_basis(pairs, 12, basis, scaling);
    check(ok, "basis construction succeeds for m=40 pairs");
    check(basis.get_rows() == m + 1, "dimension is exactly m+1 (n=m-1 residual dims + k0 dim + embedding dim)");
    check(basis.get_cols() == m + 1, "basis is square");
}

// ---------------------------------------------------------------------
// secp256k1 curve membership (Phase 2 pubkey gate). A malformed, off-curve,
// or out-of-field pubkey must never be accepted as a recovery target -- this
// is the check that used to be entirely absent.
// ---------------------------------------------------------------------
void test_curve_membership() {
    std::cout << "-- secp256k1 curve membership (Phase 2 pubkey gate) --\n";
    using namespace secp256k1;

    check(is_on_curve(G), "generator G is on the curve");

    Point off = G; off.y = (off.y + 1) % P;
    check(!is_on_curve(off), "point with y+1 is rejected (off curve)");

    Point inf{mpz(0), mpz(0), true};
    check(!is_on_curve(inf), "point at infinity is not a valid pubkey");

    Point oob = G; oob.x = P;  // x == field prime is outside [0, P)
    check(!is_on_curve(oob), "coordinate == field prime P is rejected (out of field)");

    // A real uncompressed pubkey parses to d*G; an off-curve re-encoding is rejected.
    mpz d("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    mpz pk = utils::compute_pubkey(d);
    auto pt = pubkey_to_point(pk);
    check(pt.has_value(), "valid uncompressed pubkey parses to a point");
    if (pt.has_value())
        check(points_equal(*pt, scalar_mult(d, G)), "parsed pubkey equals d*G");

    Point badpt = *pt; badpt.y = (badpt.y + 1) % P;
    mpz badpk = point_to_pubkey(badpt);
    check(!pubkey_to_point(badpk).has_value(),
          "off-curve pubkey (y+1) is rejected by pubkey_to_point");
}

// ---------------------------------------------------------------------
// Parser input-integrity boundary (Phase 2): scalar-range and malformed-field
// rejection with actionable reasons, and the single-key grouping / missing-
// pubkey policy. Replaces the old "r,s != 0" rubber stamp.
// ---------------------------------------------------------------------
void test_input_validation_and_grouping() {
    std::cout << "-- parser input-integrity boundary (Phase 2) --\n";

    const mpz d("0x1111111111111111111111111111111111111111111111111111111111111111");
    const std::string pk_hex = utils::compute_pubkey(d).get_str(16);

    auto block = [&](const std::string& r, const std::string& s,
                     const std::string& z, const std::string& pk) {
        std::string b = "Signature #1\n";
        if (!r.empty()) b += "R = " + r + "\n";
        if (!s.empty()) b += "S = " + s + "\n";
        if (!z.empty()) b += "Z = " + z + "\n";
        if (!pk.empty()) b += "PubKey: " + pk + "\n";
        return b;
    };
    auto has = [](const std::string& hay, const std::string& needle) {
        return hay.find(needle) != std::string::npos;
    };

    // Well-formed block accepted.
    auto ok = SignatureParser::parse_block(block("1", "2", "abc", pk_hex));
    check(ok.has_value() && ok->valid, "well-formed signature block is accepted");

    // r = 0 and r >= n rejected with an actionable reason.
    auto r0 = SignatureParser::parse_block(block("0", "2", "abc", pk_hex));
    check(r0.has_value() && !r0->valid && has(r0->reject_reason, "r out of range"),
          "r = 0 rejected: '" + (r0 ? r0->reject_reason : std::string()) + "'");
    std::string n_hex = SECP256K1_N.get_str(16);
    auto rn = SignatureParser::parse_block(block(n_hex, "2", "abc", pk_hex));
    check(rn.has_value() && !rn->valid && has(rn->reject_reason, "r out of range"),
          "r = n rejected (>= curve order)");

    // Malformed / missing fields named specifically.
    auto badr = SignatureParser::parse_block(block("xyz", "2", "abc", pk_hex));
    check(badr.has_value() && !badr->valid && has(badr->reject_reason, "malformed R"),
          "non-hex R rejected as malformed");
    auto over = SignatureParser::parse_block(block(std::string(65, 'a'), "2", "abc", pk_hex));
    check(over.has_value() && !over->valid && has(over->reject_reason, "malformed R"),
          "over-length R (65 hex digits) rejected");
    auto noz = SignatureParser::parse_block(block("1", "2", "", pk_hex));
    check(noz.has_value() && !noz->valid && has(noz->reject_reason, "missing Z"),
          "missing Z field rejected");

    // Off-curve pubkey in a block rejected.
    secp256k1::Point bad = *secp256k1::pubkey_to_point(utils::compute_pubkey(d));
    bad.y = (bad.y + 1) % secp256k1::P;
    auto offc = SignatureParser::parse_block(block("1", "2", "abc",
                    secp256k1::point_to_pubkey(bad).get_str(16)));
    check(offc.has_value() && !offc->valid && has(offc->reject_reason, "not a valid secp256k1 point"),
          "off-curve PubKey in a block rejected");

    // ---- grouping / missing-pubkey policy ----
    auto mk = [](const mpz& pk) {
        Signature s; s.r = 1; s.s = 2; s.z = 3; s.pubkey = pk; s.valid = true;
        return s;
    };
    const mpz pkA = utils::compute_pubkey(d);
    const mpz pkB = utils::compute_pubkey(mpz("0x2222222222222222222222222222222222222222222222222222222222222222"));

    auto g_single = SignatureParser::validate_and_group({mk(pkA), mk(pkA), mk(pkA)}, false);
    check(g_single.ok && g_single.pubkey == pkA && has(g_single.policy, "strict"),
          "single-key group accepted under strict policy");

    auto g_mixed = SignatureParser::validate_and_group({mk(pkA), mk(pkB)}, false);
    check(!g_mixed.ok && has(g_mixed.error, "distinct public keys"),
          "mixed distinct keys rejected");

    auto g_miss = SignatureParser::validate_and_group({mk(pkA), mk(mpz(0))}, false);
    check(!g_miss.ok && has(g_miss.error, "missing a PubKey"),
          "missing PubKey rejected by default");

    auto g_allow = SignatureParser::validate_and_group({mk(pkA), mk(mpz(0))}, true);
    check(g_allow.ok && has(g_allow.policy, "best-effort"),
          "missing PubKey accepted best-effort with --allow-no-pubkey");
}

} // namespace

int main() {
    std::cout << "=== Fast isolated unit tests ===\n\n";

    test_poisson_upper_tail();
    std::cout << "\n";
    test_lsb_transform_exactness();
    std::cout << "\n";
    test_pivot_elimination_algebra();
    std::cout << "\n";
    test_pubkey_roundtrip();
    std::cout << "\n";
    test_ecdsa_equation_verification();
    std::cout << "\n";
    test_lattice_basis_construction();
    std::cout << "\n";
    test_curve_membership();
    std::cout << "\n";
    test_input_validation_and_grouping();

    std::cout << "\n=== " << (g_checks - g_failures) << "/" << g_checks << " checks passed ===\n";
    return g_failures == 0 ? 0 : 1;
}
