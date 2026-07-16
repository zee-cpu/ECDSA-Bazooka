#pragma once

#include "types.h"
#include <optional>

// secp256k1 curve parameters
namespace secp256k1 {

    // Field prime p
    extern const mpz P;

    // Curve order n
    extern const mpz N;

    // Generator G
    struct Point {
        mpz x;
        mpz y;
        bool infinity = false;
    };

    extern const Point G;

    // Point addition
    Point point_add(const Point& a, const Point& b);

    // Point doubling
    Point point_double(const Point& a);

    // Scalar multiplication: k * P
    Point scalar_mult(const mpz& k, const Point& p);

    // True iff pt is a finite affine point with both coordinates in the
    // field [0, P) AND satisfying the curve equation y^2 == x^3 + 7 (mod P).
    // The point at infinity is deliberately not "on curve" here: a public key
    // must be a real affine point.
    bool is_on_curve(const Point& pt);

    // Convert a SEC1 pubkey mpz to a Point. Accepts both the uncompressed
    // form (65 bytes, 0x04 || x || y) and the compressed form (33 bytes,
    // 0x02/0x03 || x, with y recovered from the curve). Returns nullopt
    // unless the encoding is canonical, coordinates are within the field,
    // and the point lies on the curve.
    std::optional<Point> pubkey_to_point(const mpz& pubkey_mpz);

    // Convert point back to uncompressed pubkey mpz (04 || x(32B) || y(32B))
    mpz point_to_pubkey(const Point& p);

    // Check if two points are equal
    bool points_equal(const Point& a, const Point& b);

} // namespace secp256k1
