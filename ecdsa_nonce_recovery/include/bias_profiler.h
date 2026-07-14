#pragma once

#include "types.h"
#include <vector>

class BiasProfiler {
public:
    static BiasProfile profile(const std::vector<Pair>& pairs, Telemetry* telemetry = nullptr);

private:
    // Helper: detect LSB bias via clustering of candidate d mod 2^b
    static std::pair<double, double> detect_lsb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry, int max_bits = 24);

    // Detect MSB bias via heuristic (sampling candidate low-k)
    static std::pair<double, double> detect_msb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry);

    // Detect modulo bias
    static std::tuple<double, mpz, mpz, double> detect_modulo_bias(const std::vector<Pair>& pairs);

    // Estimate leaked bits from bias magnitude
    static double estimate_leaked_bits(BiasType type, double raw_stat, const mpz& omega, const mpz& bound);
};
