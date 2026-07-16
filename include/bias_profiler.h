#pragma once

#include "types.h"
#include <vector>

class BiasProfiler {
public:
    static BiasProfile profile(const std::vector<Pair>& pairs, Telemetry* telemetry = nullptr);

private:
    // Detect LSB / MSB bias. extra_splits selects the Phase-6e ensemble stage:
    // false => evaluate only partition 0 (the original single-split detector);
    // true  => evaluate the extra partitions 1..R-1 (run only as a fallback,
    // by profile(), when partition 0 of both hypotheses found nothing).
    static std::pair<double, double> detect_lsb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry, bool extra_splits = false, int max_bits = 24);

    static std::pair<double, double> detect_msb_bias(const std::vector<Pair>& pairs, Telemetry* telemetry, bool extra_splits = false);

    // Detect modulo bias
    static std::tuple<double, mpz, mpz, double> detect_modulo_bias(const std::vector<Pair>& pairs);

    // Estimate leaked bits from bias magnitude
    static double estimate_leaked_bits(BiasType type, double raw_stat, const mpz& omega, const mpz& bound);
};
