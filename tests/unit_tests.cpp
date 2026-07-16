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
#include "pair_computation.h"
#include "recovery_engine.h"
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
// Repeated-nonce (r-collision) recovery (Phase 6a). Two signatures that reuse
// the same nonce k share the same r, and that alone yields the private key by
// closed-form algebra -- no lattice, no bias. The pre-scan must find such a
// collision buried in a larger set and short-circuit to the exact key.
// ---------------------------------------------------------------------
namespace {
    // Minimal ECDSA sign for tests: r = (k*G).x mod n; s = k^-1 (z + r*d) mod n.
    Signature make_sig(const mpz& d, const mpz& z, const mpz& k,
                       const mpz& pubkey, size_t idx) {
        const mpz& n = SECP256K1_N;
        secp256k1::Point R = secp256k1::scalar_mult(k, secp256k1::G);
        mpz r = R.x % n;
        mpz s = utils::mod_mul(utils::mod_inverse(k, n), (z + r * d) % n, n);
        Signature sig;
        sig.r = r; sig.s = s; sig.z = z; sig.pubkey = pubkey;
        sig.valid = true; sig.index = idx;
        return sig;
    }
}

void test_repeated_nonce() {
    std::cout << "-- repeated-nonce (r-collision) recovery (Phase 6a) --\n";
    const mpz d("0x0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0");
    const mpz pubkey = utils::compute_pubkey(d);

    // A realistic set with three tricky cases mixed together:
    //   idx 1-3: distinct nonces (populate the r-map, no collision)
    //   idx 4-5: a literal DUPLICATE record (identical r,s,z) -- shares r but
    //            s_diff == 0 is non-invertible, so it must be SKIPPED, not
    //            crash or yield a bogus key
    //   idx 6-7: a genuine reused nonce (same k, different messages) -- the
    //            one exploitable collision, which must recover the exact key
    // The pre-scan has to skip the duplicate and still find the real reuse.
    const mpz base_k("0x7fabc0ffee1234567890fedcba09876543210abcdef1234567890abcdef01234");
    const mpz dup_k ("0x1122334455667788990011223344556677889900112233445566778899001122");
    const mpz k_reused("0x00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef");
    std::vector<Signature> sigs;
    for (int i = 1; i <= 3; ++i)
        sigs.push_back(make_sig(d, mpz(1000 + i), base_k + i, pubkey, i));
    sigs.push_back(make_sig(d, mpz(42), dup_k, pubkey, 4));   // duplicate pair...
    sigs.push_back(make_sig(d, mpz(42), dup_k, pubkey, 5));   // ...identical r,s,z
    sigs.push_back(make_sig(d, mpz("0xdeadbeef01"), k_reused, pubkey, 6));
    sigs.push_back(make_sig(d, mpz("0xdeadbeef02"), k_reused, pubkey, 7));

    check(sigs[3].r == sigs[4].r && sigs[3].s == sigs[4].s, "duplicate record shares r and s");
    check(sigs[5].r == sigs[6].r && sigs[5].s != sigs[6].s, "reused-nonce pair shares r but not s");
    check(sigs[0].r != sigs[1].r, "distinct-nonce signatures have distinct r");

    Telemetry tel;
    auto pairs = PairComputer::compute_pairs(sigs, &tel);
    RecoveryEngine engine(tel);
    RecoveryResult res = engine.run(sigs, pairs);

    check(res.success, "repeated-nonce set recovers a verified key");
    check(res.method_used == RecoveryMethod::REPEATED_NONCE,
          "recovery method is reported as REPEATED_NONCE");
    check(res.private_key == d,
          "recovered key equals the true private key (duplicate record skipped, real reuse found)");
}

// ---------------------------------------------------------------------
// Known-nonzero-LSB recovery (Phase 6b). Generalizes LSB recovery from "low b
// bits are zero" to "low b bits are a known value c" (side-channel leak model).
// Correct recovery requires subtracting each nonce's known residue before the
// LSB lattice transform; if the offset were ignored the transformed pairs would
// be wrong and no key would verify.
// ---------------------------------------------------------------------
void test_known_lsb() {
    std::cout << "-- known-nonzero-LSB recovery (Phase 6b) --\n";
    const mpz d("0x0a1b2c3d4e5f60718293a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f");
    const mpz pubkey = utils::compute_pubkey(d);

    // (1) Parser reads a well-formed KnownLow field and rejects an out-of-range one.
    {
        const std::string ok = "/tmp/test_knownlow_ok.txt";
        { std::ofstream f(ok);
          f << "Signature #1\nR = 0x1\nS = 0x2\nZ = 0x3\n"
            << "PubKey: " << pubkey.get_str(16) << "\nKnownLow: 8 0xab\n\n"; }
        Telemetry t; auto s = SignatureParser::parse_file(ok, &t);
        check(s.size() == 1 && s[0].known_low_bits == 8 && s[0].known_low_value == mpz(0xab),
              "parser reads 'KnownLow: 8 0xab' as b=8, c=0xab");

        const std::string bad = "/tmp/test_knownlow_bad.txt";
        { std::ofstream f(bad);
          f << "Signature #1\nR = 0x1\nS = 0x2\nZ = 0x3\n"
            << "PubKey: " << pubkey.get_str(16) << "\nKnownLow: 8 0x1ff\n\n"; }  // 0x1ff > 8 bits
        Telemetry t2; auto b = SignatureParser::parse_file(bad, &t2);
        check(b.empty(), "KnownLow value that overflows its bit width is rejected");
    }

    // (2) End-to-end recovery with a KNOWN, NONZERO, per-signature low-b-bit
    // residue. High parts are kept small so the lattice is fast; what's under
    // test is that the nonzero residue is folded in correctly.
    const int b = 32;
    const mpz two_b = mpz(1) << b;
    std::mt19937_64 rng(0xC0FFEEULL);
    std::vector<Signature> sigs;
    for (size_t i = 1; i <= 40; ++i) {
        mpz khigh = mpz(static_cast<unsigned long>(rng() % (1ull << 30))) + 1;  // k' small
        mpz c     = mpz(static_cast<unsigned long>((rng() % (1ull << b)) | 1ull)); // c in [1, 2^b)
        mpz k = khigh * two_b + c;                 // low b bits of k == c (nonzero)
        Signature s = make_sig(d, mpz(2000 + i), k, pubkey, i);
        s.known_low_bits = b;
        s.known_low_value = c;
        sigs.push_back(s);
    }

    Telemetry tel;
    auto pairs = PairComputer::compute_pairs(sigs, &tel);
    RecoveryEngine engine(tel);
    RecoveryResult res = engine.run(sigs, pairs);
    check(res.success, "known-nonzero-LSB set recovers a verified key");
    check(res.private_key == d, "recovered key equals the true private key");
}

// ---------------------------------------------------------------------
// Compressed SEC1 pubkey support. pubkey_to_point used to accept only the
// uncompressed (0x04) form; a 33-byte compressed key (0x02/0x03 || x, y
// recovered from the curve) was padded to 130 chars and rejected. Pin the
// decompression math and parity selection so a refactor can't regress it.
// ---------------------------------------------------------------------
namespace {
    // Canonical compressed SEC1 encoding of a point: marker byte (0x02 if y is
    // even, 0x03 if odd) followed by the 32-byte X coordinate, as an mpz.
    mpz compress(const secp256k1::Point& p) {
        std::string xstr = p.x.get_str(16);
        xstr = std::string(64 - xstr.size(), '0') + xstr;
        const char* marker = (mpz_odd_p(p.y.get_mpz_t()) != 0) ? "03" : "02";
        return mpz(std::string("0x") + marker + xstr);
    }
}

void test_compressed_pubkey() {
    std::cout << "-- compressed SEC1 pubkey support --\n";
    using namespace secp256k1;

    // G in compressed form must decompress back to exactly G.
    check(pubkey_to_point(compress(G)).has_value() &&
          points_equal(*pubkey_to_point(compress(G)), G),
          "compressed G decompresses to G");

    // A real key d*G survives a compress -> decompress round-trip.
    mpz d("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    Point dG = scalar_mult(d, G);
    auto pt = pubkey_to_point(compress(dG));
    check(pt.has_value(), "compressed d*G parses to a point");
    if (pt.has_value())
        check(points_equal(*pt, dG), "compressed d*G decompresses to d*G");

    // Flipping only the marker byte must yield the *other* root, P - y, which
    // is the negation of the point -- still on-curve, but not the same point.
    // get_str drops the marker byte's leading zero nibble, so the marker's low
    // nibble is chex[0] ('2' or '3') -- flip that, not the following X digit.
    std::string chex = compress(dG).get_str(16);
    chex[0] = (chex[0] == '2') ? '3' : '2';   // 0x02 <-> 0x03
    auto flipped = pubkey_to_point(mpz(std::string("0x") + chex));
    check(flipped.has_value() && is_on_curve(*flipped) && !points_equal(*flipped, dG),
          "flipping the marker selects the opposite-parity root");
    if (flipped.has_value())
        check((*flipped).y == (P - dG.y), "opposite root is P - y (the negation)");

    // An X that is not a valid compressed key (no y solves the curve) is
    // rejected rather than silently accepted. x=5: y^2 = 132 is a non-residue
    // mod P, so no point has this X.
    mpz bad_x("0x02" "0000000000000000000000000000000000000000000000000000000000000005");
    check(!pubkey_to_point(bad_x).has_value(),
          "compressed key with non-residue X is rejected");

    // End to end: an all-compressed dataset parses through the parser and the
    // shared key groups as a single strict-policy key.
    const mpz key("0x1111111111111111111111111111111111111111111111111111111111111111");
    const std::string ck = compress(scalar_mult(key, G)).get_str(16);
    std::string doc;
    for (int i = 1; i <= 2; ++i) {
        doc += "Signature #" + std::to_string(i) + "\n";
        doc += "R = 0x1\nS = 0x2\nZ = 0x3\n";
        doc += "PubKey: " + ck + "\n\n";
    }
    std::string path = "/tmp/test_compressed_ds.txt";
    { std::ofstream f(path); f << doc; }
    Telemetry tel;
    auto sigs = SignatureParser::parse_file(path, &tel);
    check(sigs.size() == 2, "both compressed-key records parse as valid");
    auto grp = SignatureParser::validate_and_group(sigs, /*allow_no_pubkey=*/false);
    check(grp.ok && grp.policy.rfind("strict", 0) == 0,
          "all-compressed dataset groups as one strict-policy key");
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

// ---------------------------------------------------------------------
// secp256k1 point-arithmetic edge cases (Phase 4). Self-contained algebraic
// invariants that don't need an external reference; the exhaustive random
// cross-check against the `ecdsa` library lives in the ctest `ecc_differential`.
// ---------------------------------------------------------------------
void test_ec_point_arithmetic() {
    std::cout << "-- secp256k1 point arithmetic edge cases (Phase 4) --\n";
    using namespace secp256k1;
    const Point O{mpz(0), mpz(0), true};

    check(points_equal(point_add(G, O), G), "G + O == G (identity on the right)");
    check(points_equal(point_add(O, G), G), "O + G == G (identity on the left)");

    // Adding a point to its negation gives O.
    Point negG{G.x, (P - G.y) % P, false};
    check(point_add(G, negG).infinity, "G + (-G) == O");

    // Doubling via add and via double must agree, and be on-curve.
    Point dbl_add = point_add(G, G);
    Point dbl_fn = point_double(G);
    check(points_equal(dbl_add, dbl_fn), "point_add(G,G) == point_double(G)");
    check(is_on_curve(dbl_fn), "2G is on the curve");

    // Scalar-mult basics.
    check(points_equal(scalar_mult(mpz(1), G), G), "1*G == G");
    check(points_equal(scalar_mult(mpz(2), G), dbl_fn), "2*G == point_double(G)");
    check(scalar_mult(mpz(0), G).infinity, "0*G == O");

    // (n-1)*G == -G  (group order n), a strong end-of-range check.
    Point n_minus_1_G = scalar_mult(N - 1, G);
    check(points_equal(n_minus_1_G, negG), "(n-1)*G == -G");
    // n*G == O.
    check(scalar_mult(N, G).infinity, "n*G == O");
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
    test_repeated_nonce();
    std::cout << "\n";
    test_known_lsb();
    std::cout << "\n";
    test_compressed_pubkey();
    std::cout << "\n";
    test_input_validation_and_grouping();
    std::cout << "\n";
    test_ec_point_arithmetic();

    std::cout << "\n=== " << (g_checks - g_failures) << "/" << g_checks << " checks passed ===\n";
    return g_failures == 0 ? 0 : 1;
}
