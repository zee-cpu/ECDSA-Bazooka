#include "sieve_estimator.h"

#include <algorithm>
#include <cmath>
#include <thread>

#if defined(__linux__)
#include <sys/sysinfo.h>
#endif

namespace sieve_estimator {

namespace {
    constexpr double CYCLES_PER_SEC = 2.0e9; // assume ~2 GHz per core
}

MachineFacts detect_machine() {
    MachineFacts f{};
    unsigned c = std::thread::hardware_concurrency();
    f.cores = c ? c : 1u;
    f.ram_gb = 0.0;
#if defined(__linux__)
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        f.ram_gb = static_cast<double>(si.totalram) * static_cast<double>(si.mem_unit) / 1e9;
    }
#endif
    return f;
}

Estimate estimate(double leaked_bits, const MachineFacts& machine) {
    Estimate e{};
    double L = (!std::isfinite(leaked_bits) || leaked_bits < 1.0) ? 1.0 : leaked_bits;

    // Sample threshold -- matches recovery_engine::try_sieve's target_m
    // sizing (ceil(256/L)+2), validated against the applicability thresholds
    // L=2 -> dim131, L=3 -> dim89.
    e.m = static_cast<int>(std::ceil(256.0 / L)) + 2;
    e.dim = e.m + 1;
    double d = static_cast<double>(e.dim);

    // Albrecht-Heninger sieve cost model (cycles).
    if (d <= 90.0)
        e.log2_cycles = 0.65819 * d - 30.460 * std::log(d) + 119.91;
    else
        e.log2_cycles = 0.37495 * d + 8.12;

    double cycles = std::pow(2.0, e.log2_cycles);
    e.core_hours = cycles / (CYCLES_PER_SEC * 3600.0);

    // Sieve DB RAM: db_factor * (4/3)^(sieve_dim/2) * bytes/vec, with G6K's
    // default dimensions-for-free (11.5 + 0.075 d). Reported as a range.
    double d4f = 11.5 + 0.075 * d;
    double sieve_dim = std::max(0.0, d - d4f);
    double vecs = 3.5 * std::pow(4.0 / 3.0, sieve_dim / 2.0);
    e.ram_low_gb = vecs * 200.0 / 1e9;
    e.ram_high_gb = vecs * 350.0 / 1e9;

    unsigned cores = machine.cores ? machine.cores : 1u;
    e.wall_hours = e.core_hours / static_cast<double>(cores);
    e.feasible_here = (machine.ram_gb <= 0.0) ? true : (e.ram_high_gb <= machine.ram_gb);
    return e;
}

} // namespace sieve_estimator
