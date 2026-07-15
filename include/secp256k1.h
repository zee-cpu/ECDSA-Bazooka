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

    // Convert uncompressed pubkey (04 || x || y) mpz to Point
    std::optional<Point> pubkey_to_point(const mpz& pubkey_mpz);

    // Convert point back to uncompressed pubkey mpz (04 || x(32B) || y(32B))
    mpz point_to_pubkey(const Point& p);

    // Check if two points are equal
    bool points_equal(const Point& a, const Point& b);

} // namespace secp256k1
