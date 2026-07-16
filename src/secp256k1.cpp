#include "secp256k1.h"
#include "utils.h"

namespace secp256k1 {

const mpz P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const mpz N("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

// Generator G (secp256k1)
const Point G = {
    mpz("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    mpz("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    false
};

// Modular reduction
// Modular inverse
static mpz modinv(const mpz& a, const mpz& m) {
    return utils::mod_inverse(a, m);
}

// Point addition
Point point_add(const Point& a, const Point& b) {
    if (a.infinity) return b;
    if (b.infinity) return a;

    mpz p = P;

    if (a.x == b.x && (a.y + b.y) % p == 0) {
        // a + (-a) = O
        return {mpz(0), mpz(0), true};
    }

    mpz lambda;
    if (a.x == b.x && a.y == b.y) {
        // doubling. A point with y == 0 has order 2, so 2P = O; the a + (-a)
        // check above already returns O for it (a.y + b.y == 0), so den = 2y
        // is guaranteed nonzero here. Keep an explicit guard anyway so a future
        // refactor of that check can't silently reintroduce a divide-by-zero.
        if (a.y == 0) return {mpz(0), mpz(0), true};
        mpz num = 3 * a.x * a.x;          // 3x^2
        mpz den = 2 * a.y;
        lambda = (num * modinv(den, p)) % p;
    } else {
        mpz num = b.y - a.y;
        mpz den = b.x - a.x;
        lambda = (num * modinv(den, p)) % p;
    }

    mpz x3 = (lambda * lambda - a.x - b.x) % p;
    if (x3 < 0) x3 += p;

    mpz y3 = (lambda * (a.x - x3) - a.y) % p;
    if (y3 < 0) y3 += p;

    return {x3, y3, false};
}

Point point_double(const Point& a) {
    return point_add(a, a);
}

// Scalar multiplication (double-and-add). k == 0 (or k <= 0) yields O, the
// identity, since the loop never runs.
Point scalar_mult(const mpz& k, const Point& p) {
    Point result{mpz(0), mpz(0), true}; // O
    Point addend = p;

    mpz kk = k;
    while (kk > 0) {
        if ((kk % 2) == 1) {
            result = point_add(result, addend);
        }
        addend = point_double(addend);
        kk /= 2;
    }
    return result;
}

bool is_on_curve(const Point& pt) {
    if (pt.infinity) return false;
    // Field-membership: reject coordinates outside [0, P). Without this an
    // attacker-supplied pubkey could carry out-of-range coordinates that
    // happen to satisfy the reduced curve equation only after reduction.
    if (pt.x < 0 || pt.x >= P || pt.y < 0 || pt.y >= P) return false;
    // secp256k1: y^2 == x^3 + 7 (mod P). (a = 0, b = 7.)
    mpz lhs = (pt.y * pt.y) % P;
    mpz rhs = (((pt.x * pt.x) % P) * pt.x + 7) % P;
    return lhs == rhs;
}

std::optional<Point> pubkey_to_point(const mpz& pubkey_mpz) {
    if (pubkey_mpz <= 0) return std::nullopt;
    std::string hex = pubkey_mpz.get_str(16);

    // GMP's get_str never prints insignificant leading zero hex digits, so the
    // stored value is always short by at least the marker byte's high nibble
    // (which is 0 for every SEC1 form). We reconstruct the dropped leading
    // zeros by left-padding to the canonical width for whichever encoding this
    // is -- uncompressed (65 bytes / 130 hex) or compressed (33 bytes / 66 hex).
    //
    // The two widths never collide: an uncompressed key (marker 0x04) always
    // yields exactly 129 significant hex digits, and a compressed key
    // (marker 0x02/0x03) always yields exactly 65, because the marker's low
    // nibble is nonzero and sits at a fixed high position. So length alone
    // tells the forms apart; the 66-char threshold cleanly separates them.
    if (hex.size() > 130) return std::nullopt; // too large to be a valid point

    const bool compressed = hex.size() <= 66;
    const size_t width = compressed ? 66 : 130;
    if (hex.size() < width) {
        hex = std::string(width - hex.size(), '0') + hex;
    }

    std::string prefix = hex.substr(0, 2);
    mpz x;

    if (!compressed) {
        if (prefix != "04") return std::nullopt;
        std::string xhex = hex.substr(2, 64);
        std::string yhex = hex.substr(66, 64);
        mpz y;
        x.set_str(xhex, 16);
        y.set_str(yhex, 16);
        // Reject off-curve / out-of-field points instead of trusting the
        // encoding. A malformed or attacker-supplied pubkey that parses
        // structurally but is not a real curve point must never be accepted
        // as a recovery target.
        Point pt{x, y, false};
        if (!is_on_curve(pt)) return std::nullopt;
        return pt;
    }

    // Compressed SEC1: marker (0x02 => even y, 0x03 => odd y) followed by the
    // 32-byte X coordinate. We recover Y by solving the curve equation for it.
    if (prefix != "02" && prefix != "03") return std::nullopt;
    x.set_str(hex.substr(2, 64), 16);
    if (x < 0 || x >= P) return std::nullopt;  // X must be a field element

    // Modular square root of y^2 = x^3 + 7 (mod P). secp256k1's P is prime and
    // P % 4 == 3, so a square root (when one exists) is a^((P+1)/4) mod P.
    mpz alpha = (((x * x) % P) * x + 7) % P;  // y^2
    mpz y;
    mpz exp = (P + 1) / 4;
    mpz_powm(y.get_mpz_t(), alpha.get_mpz_t(), exp.get_mpz_t(), P.get_mpz_t());

    // The candidate is only a real root if squaring it returns alpha; when x is
    // not a valid compressed X (no y satisfies the curve), it won't -- reject.
    if ((y * y) % P != alpha) return std::nullopt;

    // Two roots exist: y and P-y, with opposite parities. Pick the one whose
    // low bit matches the marker (0x02 => even, 0x03 => odd).
    bool want_odd = (prefix == "03");
    if ((mpz_odd_p(y.get_mpz_t()) != 0) != want_odd) {
        y = P - y;
    }

    Point pt{x, y, false};
    if (!is_on_curve(pt)) return std::nullopt;
    return pt;
}

mpz point_to_pubkey(const Point& p) {
    if (p.infinity) return mpz(0);

    std::string xstr = p.x.get_str(16);
    std::string ystr = p.y.get_str(16);

    // pad to 64 hex chars
    xstr = std::string(64 - xstr.size(), '0') + xstr;
    ystr = std::string(64 - ystr.size(), '0') + ystr;

    return mpz("0x04" + xstr + ystr);
}

bool points_equal(const Point& a, const Point& b) {
    if (a.infinity && b.infinity) return true;
    if (a.infinity || b.infinity) return false;
    return a.x == b.x && a.y == b.y;
}

} // namespace secp256k1
