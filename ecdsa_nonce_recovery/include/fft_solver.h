#pragma once

#include "types.h"
#include <vector>
#include <optional>

// NOTE ON HISTORY: this used to be a standalone Bleichenbacher-style FFT
// peak-search pipeline. That approach turned out to have a fundamental
// flaw, not just a bug: for k = w + x*d (mod N), shifting a trial d by
// even a single integer (d -> d+1) replaces the correlation with
// k + x (mod N) -- and since x is essentially uniform and independent per
// signature, adding it destroys any coherence with the original bias
// *completely*, for any nonzero shift. The "peak" in that formulation is
// a single point in a ~2^256 search space; no grid resolution or number
// of coarse-to-fine refinement stages can land on it by more than chance,
// which was confirmed empirically (a real 1-bit hard-bias dataset showed
// a peak of magnitude ~7669 in a direct calculation at the true d, but
// only ~100-400 -- noise level -- anywhere reachable via grid search).
//
// The corrected role for detecting very weak (1-2 bit) hard-bound bias is
// to reuse the *existing*, already-validated lattice machinery
// (BiasProfiler + LatticeSolver) at a larger dimension, rather than a
// separate algorithm -- weak bias is still lattice-exploitable, it just
// needs more signatures per attempt (~320/L). That widening now lives
// directly in bias_profiler.cpp and lattice_solver.cpp. This class is
// kept as a thin, explicit entry point for that same lattice path (for
// callers that specifically ask for the weak-bias path) plus the grid
// round-trip self-test, which is a real, independent, still-useful
// sanity check unrelated to the retired peak-search code.
class FFTSolver {
public:
    static std::optional<mpz> recover_private_key(
        const std::vector<Pair>& pairs,
        const BiasProfile& bias,
        Telemetry* telemetry = nullptr
    );

    // Standalone exact round-trip grid encode/decode test (required by spec)
    static bool run_roundtrip_test(size_t num_tests = 10000);

private:
    static size_t value_to_grid(const mpz& val, size_t grid_size, const mpz& n);
    static mpz grid_to_value(size_t idx, size_t grid_size, const mpz& n);
};
