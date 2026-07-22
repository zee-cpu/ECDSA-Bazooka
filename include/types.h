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
    int64_t timestamp = 0;
    bool timestamp_present = false;
    bool valid = false;
    // Provenance + diagnostics (Phase 2 input-integrity boundary): the
    // 1-based position of this block in the source file, and, when invalid,
    // a human-readable reason so failures can be reported against the exact
    // input record rather than a silent skip.
    size_t index = 0;
    std::string reject_reason;
    // Phase 6b: known leaked low bits of this signature's nonce (e.g. from a
    // side channel). known_low_bits == 0 means "none supplied" -- the default,
    // which leaves behaviour identical to before. When > 0, the nonce is known
    // to satisfy k ≡ known_low_value (mod 2^known_low_bits), and recovery uses
    // that as an exact constraint (generalizing the LSB-zero case to a known
    // nonzero residue). 0 <= known_low_value < 2^known_low_bits.
    int known_low_bits = 0;
    mpz known_low_value = 0;
    // Sieve route: known MSB-zero leakage width for THIS signature's nonce
    // (k < 2^(256-msb_leaked_bits)). 0 means "not supplied". Lets real
    // variable-leakage data carry an exact per-signature bound, rather than a
    // single global --leaked-bits average. Range-checked in the parser.
    int msb_leaked_bits = 0;
};

// Computed (w, x) pair
struct Pair {
    mpz w;  // = z * s^{-1} mod n
    mpz x;  // = r * s^{-1} mod n
    // Index of the Signature this pair was derived from (see Signature::index),
    // preserved so a recovery/verification failure can name the source record.
    size_t source_index = 0;
    // Phase 6b: known low-bit residue of this pair's nonce (see
    // Signature::known_low_value). 0 both for the default no-leak case and for
    // a genuine leaked value of 0, which are treated identically -- subtracting
    // 0 is a no-op, so the LSB transform reduces to the original LSB-zero form.
    mpz known_low_value = 0;
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
    REPEATED_NONCE,
    // Phase 6c: Extended-HNP recovery for modulo / windowed-zero bias
    // (k mod omega in [0, bound)). Uses the two-block lattice, not the
    // single-block Boneh-Venkatesan basis. Appended for the same wire-stability
    // reason as REPEATED_NONCE above.
    MODULO,
    // Phase 6d: closed-form recovery from linearly-related (LCG) nonces
    // (k_{i+1} = a*k_i + b mod n). Like the repeated-nonce case it is algebra,
    // not a lattice -- a small modular linear system over consecutive
    // signatures. Appended for wire stability.
    LINEAR,
    // Sieving-with-predicate route for deep MSB leakage (L<=3), which plain
    // LLL/BKZ cannot reach (the "lattice barrier"). Delegated to an external
    // GPL g6k worker over a subprocess boundary, gated on a public key being
    // present (the predicate IS the pubkey check). Appended for wire stability.
    SIEVE
};

// Tier 2.8: durable per-run audit of every recovery route's disposition.
enum class RouteOutcome {
    Recovered,   // this route produced the result (verified, or best-effort no-pubkey)
    Attempted,   // ran, produced no usable key (detail explains, e.g. "g6k unavailable")
    Skipped,     // never ran (build-excluded / ceiling-gated / no-pubkey)
    NotReached   // not run because an earlier route already recovered
};

struct RouteRecord {
    std::string  name;
    RouteOutcome outcome;
    std::string  detail;
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

    // 0-based norm-rank of the reduced-basis row whose extracted candidate
    // verified against the pubkey (-1 if no verified hit). Norm-ordering makes
    // this the position in the shortest-first traversal -- recorded so the
    // Tier-0 corpus can measure how deep candidate harvesting must reach.
    std::atomic<int> verified_row_norm_rank{-1};

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

    // Fork-safety: set true to make the render thread idle (no malloc/IO) so the
    // process is effectively single-threaded across a fork-pool section.
    std::atomic<bool> render_paused_{false};
    void pause_rendering()  { render_paused_ = true; }
    void resume_rendering() { render_paused_ = false; }

    double elapsed_seconds() const {
        std::lock_guard<std::mutex> lock(str_mutex);
        return std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start_time).count();
    }

    bool deadline_exceeded() const {
        double budget = time_budget_sec.load();
        if (budget <= 0.0) return false;
        double elapsed = elapsed_seconds();
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
        double elapsed = elapsed_seconds();
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
    std::vector<RouteRecord> route_log;   // guarded by str_mutex

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
        verified_row_norm_rank = -1;
        lattice_in_progress = false;
        verification_passed = false;
        recovery_complete = false;
        render_paused_ = false;
        {
            std::lock_guard<std::mutex> lock(str_mutex);
            current_phase.clear();
            status_message.clear();
            recovered_key_hex.clear();
            error_message.clear();
            route_log.clear();
            start_time = std::chrono::steady_clock::now();
        }
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

    void log_route(const std::string& name, RouteOutcome outcome, const std::string& detail = "") {
        std::lock_guard<std::mutex> lock(str_mutex);
        route_log.push_back(RouteRecord{name, outcome, detail});
    }

    // Finalize a route's outcome after strict verify (route names are unique/run).
    void amend_route_outcome(const std::string& name, RouteOutcome outcome) {
        std::lock_guard<std::mutex> lock(str_mutex);
        for (auto it = route_log.rbegin(); it != route_log.rend(); ++it)
            if (it->name == name) { it->outcome = outcome; return; }
    }

    std::vector<RouteRecord> get_route_log() const {
        std::lock_guard<std::mutex> lock(str_mutex);
        return route_log;
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
