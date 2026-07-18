#pragma once

// Fast, dependency-free (no g6k/Python) cost model for the sieving-with-
// predicate route, so the tool can report RAM/time for any leak level on any
// machine -- even one that could never run the sieve. Model constants are the
// Albrecht-Heninger sieve cost model, validated against bdd-predicate's estimator.
namespace sieve_estimator {

    struct MachineFacts {
        unsigned cores;   // logical cores (>=1)
        double ram_gb;    // total RAM in GB (0 if unknown)
    };

    struct Estimate {
        int m;              // signatures the sieve needs
        int dim;            // lattice dimension d = m + 1
        double log2_cycles; // log2 of estimated CPU cycles
        double core_hours;  // cycles / (2e9 cyc/s * 3600)
        double ram_low_gb;  // sieve DB size, low end
        double ram_high_gb; // sieve DB size, high end
        double wall_hours;  // core_hours / machine.cores
        bool feasible_here; // ram_high_gb <= machine.ram_gb (rough; true if RAM unknown)
    };

    // Detect this machine's logical cores and total RAM.
    MachineFacts detect_machine();

    // Estimate sieve cost for `leaked_bits` (may be fractional) on `machine`.
    Estimate estimate(double leaked_bits, const MachineFacts& machine);

} // namespace sieve_estimator
