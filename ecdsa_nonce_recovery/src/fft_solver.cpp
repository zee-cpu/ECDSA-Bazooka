#include "fft_solver.h"
#include "lattice_solver.h"
#include <iostream>
#include <random>
#include "utils.h"

// See fft_solver.h for why this is no longer a standalone Fourier
// pipeline: that approach had a fundamental (not just buggy) flaw, and
// the corrected role for very-weak-bias detection is to reuse the
// existing, already-validated lattice machinery at a larger dimension.

size_t FFTSolver::value_to_grid(const mpz& val, size_t grid_size, const mpz& n) {
    mpz prod = val * mpz(grid_size);
    mpz idx = prod / n;
    if (idx >= static_cast<long>(grid_size)) idx = grid_size - 1;
    return static_cast<size_t>(idx.get_ui());
}

mpz FFTSolver::grid_to_value(size_t idx, size_t grid_size, const mpz& n) {
    mpz prod = mpz(idx) * n;
    mpz val = prod / mpz(grid_size);
    mpz remainder = prod % mpz(grid_size);
    if (remainder * 2 >= mpz(grid_size)) {
        val += 1;
    }
    return val % n;
}

bool FFTSolver::run_roundtrip_test(size_t num_tests) {
    std::cout << "[FFT] Running round-trip encode/decode consistency test (" << num_tests << " trials)..." << std::endl;

    mpz n = SECP256K1_N;
    const size_t grid = 65536;

    std::mt19937 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);

    size_t failures = 0;
    for (size_t t = 0; t < num_tests; ++t) {
        mpz val;
        uint64_t w0 = dist(rng);
        uint64_t w1 = dist(rng);
        uint64_t w2 = dist(rng);
        uint64_t w3 = dist(rng) & 0xFFFFFFFFULL;
        val = (mpz(w3) << 192) | (mpz(w2) << 128) | (mpz(w1) << 64) | mpz(w0);
        val %= n;

        size_t idx = value_to_grid(val, grid, n);
        mpz recovered = grid_to_value(idx, grid, n);

        mpz diff = (recovered > val) ? (recovered - val) : (val - recovered);
        mpz tol = n / grid + 1;

        if (diff > tol) {
            ++failures;
            if (failures < 5) {
                std::cerr << "Roundtrip FAIL: val=" << val.get_str(16).substr(0,16)
                          << " idx=" << idx << " recovered=" << recovered.get_str(16).substr(0,16)
                          << " diff=" << diff << std::endl;
            }
        }
    }

    bool passed = (failures == 0);
    std::cout << "[FFT] Round-trip test: " << (passed ? "PASSED" : "FAILED")
              << " (" << (num_tests - failures) << "/" << num_tests << " exact)" << std::endl;
    return passed;
}

std::optional<mpz> FFTSolver::recover_private_key(
    const std::vector<Pair>& pairs,
    const BiasProfile& bias,
    Telemetry* telemetry
) {
    // This floor is a practical minimum, not a derived one: the sample
    // size actually needed for real detection power depends on the bias
    // strength itself, which is exactly what this path targets finding
    // out (down to 1-2 bit hard bias). 10,000 is a reasonable point below
    // which there's little reason to expect enough margin; it does not
    // guarantee success above that either.
    if (pairs.size() < 10000) {
        if (telemetry) telemetry->set_error("Weak-bias path requires >=10000 signatures");
        return std::nullopt;
    }

    // Force the weak-bias assumption regardless of what the profiler's
    // point estimate says -- this entry point exists specifically for
    // the case where normal detection found nothing (or something weak),
    // and LatticeSolver's own leak-bit sweep already covers 1..24 bits
    // with per-trial dimension sizing (see lattice_solver.cpp), so this
    // is a real, not cosmetic, attempt at the very-weak end of that range.
    BiasProfile weak_bias = bias;
    weak_bias.estimated_leaked_bits = 1.0;

    if (telemetry) telemetry->set_phase("Weak-bias lattice sweep (down to 1-2 bits)");

    return LatticeSolver::recover_private_key(pairs, weak_bias, 0, telemetry);
}
