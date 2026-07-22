#pragma once

#include "types.h"
#include <vector>
#include <string>
#include <functional>
#include <optional>

// Tier 2.7: acceptance policy for a single RouteStep in a RoutePlan (see
// below). Governs when a step's candidate becomes a terminal winner vs. a
// provisional (keep-first-unverified) result -- see execute_route_plan's
// contract for the exact rules.
enum class AcceptPolicy {
    CLOSED_FORM,   // any candidate is a terminal winner (short-circuit; strict-verify is the final gate)
    BEST_EFFORT,   // verified -> terminal; else provisional (keep-first-unverified)
    VERIFIED_ONLY  // leaf returns only pubkey-verified candidates -> terminal winner
};

// A single step in a RoutePlan: names one recovery attempt (typically an
// unchanged try_* leaf), its acceptance policy, whether it should be skipped
// once overall_ceiling has been exceeded, an optional budget-setter run
// before the attempt, the attempt itself, and how to record a win into a
// RecoveryResult.
struct RouteStep {
    std::string name;                                 // stable id (for tests + Tier 2.8 logging)
    AcceptPolicy accept;
    bool ceiling_gated;                               // honor overall_ceiling before running
    std::function<void()> set_budget;                 // may be null; sets tel_.time_budget_sec
    std::function<std::optional<mpz>()> attempt;      // calls an unchanged try_* leaf
    std::function<void(RecoveryResult&)> on_win;      // sets method_used/description/etc.
};

using RoutePlan = std::vector<RouteStep>;

class RecoveryEngine {
public:
    explicit RecoveryEngine(Telemetry& tel);

    RecoveryResult run(
        const std::vector<Signature>& signatures,
        const std::vector<Pair>& pairs,
        RecoveryMethod force_method = RecoveryMethod::AUTO,
        size_t max_sigs = 0,
        double max_time_sec = 0.0,
        uint64_t sampling_seed = DEFAULT_SAMPLING_SEED,
        // Phase 6c: optional modulo/EHNP hint (k mod omega in [0, bound)). When
        // both are > 0 the leak structure is *supplied* -- like the known-LSB
        // hint -- and recovery routes straight to the Extended-HNP lattice,
        // skipping statistical detection. Both 0 (the default) leaves behaviour
        // identical to before.
        const mpz& modulo_omega = mpz(0),
        const mpz& modulo_bound = mpz(0),
        // Phase 6d: optional linearly-related (LCG) nonce hint, k_{i+1} = a*k_i+b
        // (mod n). When lcg_a > 0 the multiplier (and increment lcg_b, default 0)
        // are supplied and two consecutive signatures suffice. lcg_a == 0 (the
        // default) leaves the unknown-(a,b) closed-form pre-scan to discover the
        // key on its own, or -- absent any LCG structure -- to find nothing.
        const mpz& lcg_a = mpz(0),
        const mpz& lcg_b = mpz(0),
        // Sieve hint: supplied MSB-zero leakage width L (k < 2^(256-L)). When > 0
        // the leak is *supplied* (side-channel model), not statistically detected
        // -- essential for deep leaks (L<=3) where too-few-samples detection fails.
        // Builds an MSB profile directly and, with a pubkey present, routes to the
        // sieving-with-predicate worker. May be fractional (e.g. 2.5 -> a per-
        // signature mix of the two bracketing bounds). 0 (default) leaves
        // behaviour unchanged.
        double msb_leaked_bits = 0.0,
        // When true, honour max_time_sec verbatim for the last-resort stage
        // (0 == unlimited, the auditor case); when false (no --max-time), the
        // stage uses last_resort::DEFAULT_BUDGET_SEC.
        bool max_time_explicit = false
    );

    // Tier 2.7: walk a RoutePlan in order, running each step's set_budget()
    // (if set), skipping it if ceiling_gated and overall_ceiling has already
    // elapsed, else calling attempt(). A CLOSED_FORM candidate, or any
    // pubkey-verified candidate, is a terminal winner (stop immediately). An
    // unverified BEST_EFFORT candidate becomes the provisional only if none
    // is set yet (keep-first-unverified). After the loop, the winner (else
    // the provisional) is written into result via that step's on_win, and
    // execute_route_plan returns true; returns false if no candidate was
    // produced at all. Public: takes an explicit RoutePlan and
    // RecoveryResult&, so exposing it is harmless (the CLI never calls it
    // directly) and it is the natural unit-test seam for the executor's
    // acceptance semantics in isolation from build_route_plan (Task 3).
    bool execute_route_plan(
        const RoutePlan& plan,
        const mpz& pubkey_hint,
        double overall_ceiling,
        RecoveryResult& result);

private:
    Telemetry& tel_;
    // Sub-method chosen by the AUTO dispatch step's attempt(), read by its on_win().
    RecoveryMethod dispatch_method_ = RecoveryMethod::AUTO;

    RoutePlan build_route_plan(
        const std::vector<Signature>& signatures,
        const std::vector<Pair>& pairs,
        RecoveryMethod force,
        size_t max_sigs,
        const mpz& pubkey_hint,
        const mpz& modulo_omega, const mpz& modulo_bound,
        const mpz& lcg_a, const mpz& lcg_b,
        double msb_leaked_bits,
        double overall_ceiling,
        bool max_time_explicit,
        std::string& fail_message);

    // Tier 2.7: memoized bias profile for the AUTO dispatch step. Returns a
    // callable that computes the profile at most once, only when first invoked,
    // so a closed-form pre-scan win never triggers profiling (preserves run()'s
    // laziness). Encapsulates the per-signature-MSB / supplied-MSB / known-LSB /
    // statistical-with-PROFILER_CAP branch selection.
    std::function<const BiasProfile&()> make_lazy_profile(
        const std::vector<Signature>& signatures, const std::vector<Pair>& pairs,
        double msb_leaked_bits, double overall_ceiling, bool max_time_explicit);

    // Set by a last-resort rung on a verified hit so run() can label the result
    // with the specific rung that recovered (empty -> the generic last-resort
    // description). Cleared before each last-resort stage.
    std::string last_resort_desc_;

    std::optional<mpz> try_lattice(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs, const mpz& pubkey_hint);
    std::optional<mpz> try_fallback_ladder(const std::vector<Pair>& pairs, const BiasProfile& bias, size_t max_sigs, const mpz& pubkey_hint);

    // Phase 6a: cheap O(n log n) pre-scan for reused nonces. Two signatures
    // that share r were made with the same nonce k, which yields the private
    // key by closed-form algebra alone. Returns the key only if it checks out
    // against pubkey_hint (or, in best-effort no-pubkey mode, the algebraic
    // result for the caller's own verification to gate). std::nullopt if no
    // usable collision exists.
    std::optional<mpz> try_repeated_nonce(const std::vector<Signature>& signatures, const mpz& pubkey_hint);

    // Phase 6c: Extended-HNP recovery for modulo / windowed-zero bias
    // (k mod omega in [0, bound)). When omega/bound are supplied (hint path) it
    // solves that one instance; otherwise it sweeps a small set of common
    // (omega, bound) candidates and returns the first that yields a
    // pubkey-verified key. std::nullopt if none recover. Pubkey-gated, so a
    // wrong candidate never produces a wrong key.
    std::optional<mpz> try_modulo(const std::vector<Pair>& pairs, const mpz& modulo_omega,
                                  const mpz& modulo_bound, size_t max_sigs, const mpz& pubkey_hint);

    // Phase 6d: closed-form recovery from linearly-related (LCG) nonces,
    // k_{i+1} = a*k_i + b (mod n). With a supplied multiplier (lcg_a > 0, plus
    // increment lcg_b) two consecutive signatures give d directly. With a,b
    // unknown, five consecutive signatures give a 4x4 modular linear system in
    // (d, a*d, a, b) that still yields d. Signatures are taken in file order,
    // then (as a fallback) sorted by timestamp -- the LCG advances in generation
    // order, which the timestamp usually reflects. Pubkey-gated, so a spurious
    // solve on non-LCG data never yields a wrong key. `forced` widens the search
    // from the cheap bounded pre-scan to every window. std::nullopt if none
    // recover.
    std::optional<mpz> try_linear_nonce(const std::vector<Signature>& signatures,
                                        const std::vector<Pair>& pairs,
                                        const mpz& pubkey_hint,
                                        const mpz& lcg_a, const mpz& lcg_b, bool forced);

    // Sieving-with-predicate route (L<=3 MSB, pubkey required). Serializes the
    // signatures + compressed pubkey and delegates to the external GPL g6k
    // worker (worker_cli.py) over a subprocess boundary, reading back the
    // recovered key. Hard-requires a pubkey (pubkey_hint > 1): the predicate is
    // the pubkey check, so without one the method does not exist -- it returns
    // nullopt rather than silently falling through to a heuristic path that
    // cannot succeed at this leakage level. The worker path and interpreter are
    // configured via the BAZOOKA_SIEVE_WORKER / BAZOOKA_SIEVE_PYTHON env vars.
    std::optional<mpz> try_sieve(
        const std::vector<Signature>& signatures,
        const BiasProfile& profile,
        size_t max_sigs,
        const mpz& pubkey_hint,
        // Per-rung wall-clock cap for the worker subprocess (0 = unbounded,
        // preserving the original popen path). > 0 routes through the bounded
        // capture helper so a single deep rung can't overrun the budget.
        double worker_timeout_sec = 0.0
    );

    // Tier 1.3: outlier-robust RANSAC resampling. Biased signatures mixed with
    // non-biased outliers defeat the profiler (Type NONE) and the prefix-trained
    // lattice; this draws random subsets and pubkey-verifies (see
    // last_resort::ransac_recover). Recovers light-moderate noise (<=~10-12%);
    // heavy noise exhausts the budget without a wrong key. Defined in last_resort.cpp.
    std::optional<mpz> try_ransac_resample(
        const std::vector<Pair>& pairs, const mpz& pubkey_hint);

    // Tier 1.2a: shared-prefix nonce reuse. A group sharing a fixed unknown
    // nonce high-part leaves no single-nonce bias; differencing against a pivot
    // cancels the shared part and yields a BV-HNP (see last_resort::
    // shared_prefix_pairs). Sweeps candidate prefix widths x a few pivots, each
    // one bounded LLL, pubkey-gated. Cheapest last-resort rung. Defined in
    // last_resort.cpp.
    std::optional<mpz> try_shared_prefix_reuse(
        const std::vector<Pair>& pairs, const mpz& pubkey_hint);
};
