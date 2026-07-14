#include <fplll.h>
#include <iostream>
#include <cassert>
#include <gmpxx.h>

// Standalone fplll integration test as required by spec.
// Constructs a trivial hand-computed lattice and verifies LLL output.
// This is a 2D example: basis [[1,0], [0,1]] should stay similar after LLL.

int main() {
    using namespace fplll;

    std::cout << "fplll version check via headers: OK" << std::endl;

    // Create a small integer lattice basis
    ZZ_mat<mpz_t> b(2, 2);
    // Identity basis
    b[0][0] = 1;
    b[0][1] = 0;
    b[1][0] = 0;
    b[1][1] = 1;

    ZZ_mat<mpz_t> u, u_inv;
    // u empty (identity)
    u.resize(0, 0);
    u_inv.resize(0, 0);

    // Call wrapper LLL (delta=0.99, eta=0.51 typical)
    double delta = 0.99;
    double eta = 0.51;
    int flags = LLL_DEFAULT;

    Wrapper w(b, u, u_inv, delta, eta, flags);
    bool ok = w.lll();

    std::cout << "LLL call status: " << (ok ? "success" : "fail") << std::endl;
    std::cout << "Wrapper status: " << w.status << std::endl;

    // Print resulting basis
    std::cout << "Reduced basis:" << std::endl;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            mpz_class val;
            mpz_set(val.get_mpz_t(), b[i][j].get_data());
            std::cout << val << " ";
        }
        std::cout << std::endl;
    }

    // For identity, reduced should still be short vectors (1,0) etc.
    // Check that the smallest vector length is 1 (squared)
    bool found_unit = false;
    for (int i = 0; i < 2; i++) {
        mpz_class v0, v1;
        mpz_set(v0.get_mpz_t(), b[i][0].get_data());
        mpz_set(v1.get_mpz_t(), b[i][1].get_data());
        if ((v0 == 1 && v1 == 0) || (v0 == 0 && v1 == 1) ||
            (v0 == -1 && v1 == 0) || (v0 == 0 && v1 == -1)) {
            found_unit = true;
        }
    }

    std::cout << "Unit vector present after reduction: " << (found_unit ? "YES" : "NO") << std::endl;

    // A more meaningful test: simple 2x2 HNP style
    // Suppose approximate relation: k ~ 0.5 * d  mod n , n large but here small
    // Lattice for 1 sample (demo): columns for d, 1
    ZZ_mat<mpz_t> b2(3, 3);
    // Typical BV embedding for 1 sample (low dimension demo)
    // Assume we have k approx a = known, x=1 , n= some
    // To keep simple: test that LLL finds short vector on a crafted matrix
    // e.g. basis for known short relation
    b2[0][0] = 100; b2[0][1] = 0; b2[0][2] = 0;
    b2[1][0] = 0; b2[1][1] = 100; b2[1][2] = 0;
    b2[2][0] = 23; b2[2][1] = 47; b2[2][2] = 1000;   // crafted short vector is approx (23,47,1000) -> short relation

    ZZ_mat<mpz_t> u2, u_inv2;
    u2.resize(0,0); u_inv2.resize(0,0);

    Wrapper w2(b2, u2, u_inv2, 0.99, 0.51, LLL_DEFAULT);
    bool ok2 = w2.lll();

    std::cout << "\nSecond LLL (crafted HNP-like): status=" << (ok2 ? "ok" : "fail") << std::endl;
    std::cout << "Reduced basis (first few rows):" << std::endl;
    for (int i = 0; i < std::min(3, (int)b2.get_rows()); ++i) {
        for (int j = 0; j < std::min(3, (int)b2.get_cols()); ++j) {
            mpz_class val;
            mpz_set(val.get_mpz_t(), b2[i][j].get_data());
            std::cout << val << "\t";
        }
        std::cout << std::endl;
    }

    // Check if short vector exists (small entries)
    bool found_small = false;
    for (int i = 0; i < b2.get_rows(); ++i) {
        mpz_class norm2 = 0;
        for (int j = 0; j < b2.get_cols(); ++j) {
            mpz_class v;
            mpz_set(v.get_mpz_t(), b2[i][j].get_data());
            norm2 += v * v;
        }
        if (norm2 < 100000) {  // very loose
            found_small = true;
            std::cout << "Found reasonably short vector row " << i << " (norm2 ~ " << norm2 << ")" << std::endl;
        }
    }

    if (ok && found_unit && ok2 && found_small) {
        std::cout << "\n[SUCCESS] fplll_sanity_test passed." << std::endl;
        return 0;
    } else {
        std::cout << "\n[FAIL] fplll sanity checks did not fully pass." << std::endl;
        return 1;
    }
}
