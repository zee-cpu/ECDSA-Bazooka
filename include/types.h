#pragma once

#include <gmpxx.h>
#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <atomic>
#include <mutex>

using mpz = mpz_class;

// secp256k1 order n (hardcoded for performance, verified)
const mpz SECP256K1_N(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

// Default seed for the profiler's sampling RNG. Fixed (not random_device) so a
// given input is reproducible run-to-run by default; overridable via --seed.
constexpr uint64_t DEFAULT_SAMPLING_SEED = 0x5EEDC0DEULL;

// Signature record (parsed)
struct Signature {
    mpz r;
    mpz s;
    mpz z;
    mpz pubkey;        // uncompressed SEC1 integer (04 || x || y)
    std::string txid;
    int64_t timestamp;
    bool valid = false;
    // Provenance + diagnostics (Phase 2 input-integrity boundary): the
    // 1-based position of this block in the source file, and, when invalid,
    // a human-readable reason so failures can be reported against the exact
    // input record rather than a silent skip.
    size_t index = 0;
    std::string reject_reason;
};

// Computed (w, x) pair
struct Pair {
    mpz w;  // = z * s^{-1} mod n
    mpz x;  // = r * s^{-1} mod n
    // Index of the Signature this pair was derived from (see Signature::index),
    // preserved so a recovery/verification failure can name the source record.
    size_t source_index = 0;
};

// Bias profile returned by profiler
enum class BiasType {
    NONE,
    MSB,
    LSB,
    MODULO,
    UNKNOWN
};

struct BiasProfile {
    BiasType type = BiasType::UNKNOWN;
    double estimated_leaked_bits = 0.0;
    // -log10(held-out significance p-value). Despite the superficial
    // resemblance, this is NOT a sigma/stddev count -- those are different
    // quantities under the standard statistical convention (p=1e-5 is
    // ~4.4 sigma, not "5 sigma"). Previously misnamed confidence_sigma and
    // printed as "Confidence σ:", which misled anyone reading it under the
    // sigma convention; kept as -log10(p) here since that's what's actually
    // computed (see bias_profiler.cpp) and how the live TUI already
    // displays it ("p < 10^-X").
    double neg_log10_p = 0.0;
    mpz modulo_omega;                // for MODULO bias
    mpz modulo_bound;                // range size within period
    std::string description;
    bool bias_detected = false;
};

// Recovery method
enum class RecoveryMethod {
    AUTO,
    LATTICE,
    FALLBACK,
    // Closed-form recovery from a reused nonce (two signatures share r because
    // they share k). Not a statistical bias -- a nonce *collision* -- so it
    // bypasses the lattice entirely. New values go at the end: Telemetry casts
    // this enum to int, so appending keeps existing on-the-wire values stable.
    REPEATED_NONCE
};

// Telemetry state for live dashboard (thread-safe)
struct Telemetry {
    // Atomic counters for live update
    std::atomic<size_t> signatures_loaded{0};
    std::atomic<size_t> signatures_valid{0};
    std::atomic<size_t> signatures_skipped{0};

    std::atomic<double> leaked_bits_est{0.0};
    std::atomic<double> confidence{0.0};
    std::atomic<int> bias_type{0};  // cast of BiasType

    std::atomic<bool> method_chosen{false};
    std::atomic<int> active_method{0};  // cast RecoveryMethod

    std::atomic<size_t> lattice_dim{0};
    std::atomic<size_t> signatures_used{0};
    std::atomic<size_t> current_attempt{0};
    std::atomic<size_t> total_attempts{0};

    // Which trial is currently running, for display alongside lattice_dim:
    // the leak-bit level (L, or LSB known-bit count) being attempted, and
    // the BKZ block size (0 for plain LLL trials, since block size only
    // applies to the BKZ escalation path).
    std::atomic<int> current_leak_l{0};
    std::atomic<int> current_block_size{0};

    std::atomic<bool> lattice_in_progress{false};

    std::atomic<bool> verification_passed{false};
    std::atomic<bool> recovery_complete{false};

    // Optional wall-clock budget (seconds) for the whole recovery run; 0
    // means unlimited. Checked by the lattice sweep, fallback ladder, and
    // alt-bias-shape retry so --max-time actually stops long-running
    // sweeps instead of being accepted and silently ignored.
    std::atomic<double> time_budget_sec{0.0};

    // Seed for the profiler's sampling RNG (see DEFAULT_SAMPLING_SEED). Set
    // once per run from --seed; recorded in the run output so a result can be
    // reproduced exactly.
    std::atomic<uint64_t> sampling_seed{DEFAULT_SAMPLING_SEED};

    bool deadline_exceeded() const {
        double budget = time_budget_sec.load();
        if (budget <= 0.0) return false;
        double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start_time).count();
        return elapsed >= budget;
    }

    // Seconds left in the budget, or a large sentinel if unlimited. Lets
    // callers skip *starting* a trial they can estimate won't fit, rather
    // than only detecting the overrun after an expensive single call
    // (like one LLL reduction) has already blown well past the deadline --
    // deadline_exceeded() alone can't help there since there's no way to
    // interrupt fplll mid-reduction.
    double remaining_budget_seconds() const {
        double budget = time_budget_sec.load();
        if (budget <= 0.0) return 1e18;
        double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start_time).count();
        return budget - elapsed;
    }

    // Protected strings (guarded). mutable so const getters can lock it
    // without const_cast -- locking a mutex is not a logical mutation of the
    // object's observable state, which is exactly what mutable is for.
    mutable std::mutex str_mutex;
    std::string current_phase;
    std::string status_message;
    std::string recovered_key_hex;
    std::string error_message;

    // Timing
    std::chrono::steady_clock::time_point start_time;

    void reset() {
        signatures_loaded = 0;
        signatures_valid = 0;
        signatures_skipped = 0;
        leaked_bits_est = 0.0;
        confidence = 0.0;
        bias_type = static_cast<int>(BiasType::UNKNOWN);
        method_chosen = false;
        active_method = static_cast<int>(RecoveryMethod::AUTO);
        lattice_dim = 0;
        signatures_used = 0;
        current_attempt = 0;
        total_attempts = 0;
        current_leak_l = 0;
        current_block_size = 0;
        lattice_in_progress = false;
        verification_passed = false;
        recovery_complete = false;
        {
            std::lock_guard<std::mutex> lock(str_mutex);
            current_phase.clear();
            status_message.clear();
            recovered_key_hex.clear();
            error_message.clear();
        }
        start_time = std::chrono::steady_clock::now();
    }

    void set_phase(const std::string& phase) {
        std::lock_guard<std::mutex> lock(str_mutex);
        current_phase = phase;
    }

    std::string get_phase() const {
        std::lock_guard<std::mutex> lock(str_mutex);
        return current_phase;
    }

    void set_status(const std::string& msg) {
        std::lock_guard<std::mutex> lock(str_mutex);
        status_message = msg;
    }

    std::string get_status() const {
        std::lock_guard<std::mutex> lock(str_mutex);
        return status_message;
    }

    void set_recovered_key(const std::string& hex) {
        std::lock_guard<std::mutex> lock(str_mutex);
        recovered_key_hex = hex;
    }

    std::string get_recovered_key() const {
        std::lock_guard<std::mutex> lock(str_mutex);
        return recovered_key_hex;
    }

    void set_error(const std::string& err) {
        std::lock_guard<std::mutex> lock(str_mutex);
        error_message = err;
    }

    std::string get_error() const {
        std::lock_guard<std::mutex> lock(str_mutex);
        return error_message;
    }
};

// Full result structure
struct RecoveryResult {
    bool success = false;
    mpz private_key;
    std::string private_key_hex;
    RecoveryMethod method_used = RecoveryMethod::AUTO;
    BiasProfile bias_profile;
    size_t signatures_used = 0;
    std::string verification_details;
    double runtime_seconds = 0.0;
};
