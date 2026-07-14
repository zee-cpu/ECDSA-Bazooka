# Handoff: ECDSA Nonce-Bias Recovery Tool

Picking this up in Claude Code after an extended session in claude.ai chat
that couldn't run long enough to finish the current task. Read this fully
before doing anything -- it replaces re-explaining the project.

## What this is

A VARA-licensed wallet-recovery firm's internal tool: given a set of ECDSA
signatures from the same private key where the nonce (`k`) has some kind of
statistical bias (MSB, LSB, modulo, or weak/soft bias), detect the bias and
recover the private key. Core approach: eliminate `d` algebraically via a
pivot-elimination trick across signature pairs, reducing to a Hidden Number
Problem in one small unknown (`k_0`), solved via lattice reduction (LLL/BKZ)
with a Kannan CVP-to-SVP embedding.

## Everything that's been fixed and validated (don't redo this work)

The tool was fundamentally broken when this started. In order:

1. **Bias detector was tautological** -- it derived a candidate key by
   assuming one signature's nonce was exactly 0, then "confirmed" bias by
   checking that same signature, which is true by construction regardless
   of the data. Replaced with a held-out statistical test: extract a
   candidate on a training subsample via the real lattice pipeline, test it
   against disjoint held-out data, exact Poisson significance test.

2. **Lattice embedding was fundamentally wrong**, not just buggy -- it put
   the private key `d` (which spans the full 256-bit range) directly into
   the target vector, so the vector could never be short regardless of
   bias. Replaced with pivot elimination (eliminate `d` algebraically first,
   leaving only genuinely-small nonces in the lattice) + Kannan embedding.
   This is the actual core of `lattice_solver.cpp` now -- read the big
   comment above `build_boneh_venkatesan_basis` before touching it.

3. **PubKey verification was silently broken for every key, always** --
   GMP's `get_str(16)` never prints insignificant leading zero hex digits,
   and the code didn't account for that, so `pubkey_to_point` always failed
   to parse and `verify_pubkey` always returned false. This means recovery
   could have been finding correct keys for a long time and reporting
   failure. Fixed in `secp256k1.cpp::pubkey_to_point`.

4. **The signature-recompute "verification" was also tautological** --
   algebraically it reproduces the original `s` for *any* candidate `d`,
   correct or not (shown by direct derivation). Replaced with genuine
   independent ECDSA verification (`u1*G + u2*P` equation) in `verifier.cpp`.
   This was serious: for files with no PubKey field, that tautological
   check used to be the *sole* decision criterion.

5. **LSB and modulo bias detection were literal stubs** returning zero.
   LSB is now implemented properly (exact modular-inverse transform reduces
   it to the same shape as MSB bias, reusing the same validated machinery).
   Modulo/Extended-HNP is still a stub -- not attempted yet, see below.

6. **Statistical thresholds were hardcoded magic numbers** (a fixed `50.0`
   FFT threshold, a fixed significance ratio) that didn't scale with sample
   size or bias strength. Replaced with derived formulas (exact Poisson
   tests, Bonferroni correction across sweep size). Also found and removed
   a hardcoded override in `recovery_engine.cpp` that fabricated a fake
   "MSB, 7 bits detected" result whenever real detection found nothing --
   this was corrupting reported output, not just an internal heuristic.

7. **`--max-time` was parsed but silently never enforced.** Now real:
   `Telemetry::deadline_exceeded()` / `remaining_budget_seconds()`, checked
   before starting each expensive trial (not just after -- a single LLL
   call can't be interrupted mid-computation, so trials whose estimated
   dimension won't fit the remaining budget are skipped before starting).

8. **BKZ escalation added**, bounded to at most one extra reduction per
   `recover_private_key` call (only if the full LLL sweep didn't already
   find a fully-convincing candidate), block size scaled to dimension.
   Empirically confirmed to matter: at m=24 for 12-bit bias, LLL fails and
   BKZ succeeds with the exact correct key.

9. **Fast unit test suite added** (`tests/unit_tests.cpp`, `<1s`, runs via
   `ctest -R unit_tests`) covering the pieces above in isolation -- Poisson
   math, LSB transform exactness, pivot-elimination algebra, pubkey
   round-trip, genuine-vs-tautological ECDSA verification. Complements
   `tests/e2e_recovery_test.sh` (real recovery against real ground truth,
   ~5 min, run via `ctest -R e2e_recovery`).

10. **TUI dashboard rebuilt** (`telemetry.cpp`) as a live multi-line ANSI
    display with a real fix for the box-alignment bug class (UTF-8
    display-width computation instead of `std::string::size()`, which
    counts bytes not columns).

All of the above is validated: full `ctest` suite passes, including real
recovery against fresh ground-truth data at 8/12/16-bit MSB and LSB bias,
and a fresh unbiased control correctly failing (no false positives).

## Current task: weak (1-2 bit) bias support -- BLOCKED, here's why

Original plan was a genuine multi-stage Bleichenbacher/FFT refinement for
very weak bias. That turned out to have a fundamental flaw, not a bug: for
`k = w + x*d (mod N)`, shifting a trial `d` by even one integer replaces
the correlation with `k + x*epsilon (mod N)` -- and since `x` is uniform
random and independent per signature, that destroys coherence with the
original bias *completely*, for any nonzero shift. The "peak" in that
formulation is a single point in a ~2^256 search space; no grid resolution
or refinement staging can land on it by more than chance. Confirmed
empirically before abandoning it: direct calculation at the true `d` gave
a coherent sum of ~7669 for 12,000 signatures with 1-bit hard bias; every
grid-search variant found only ~100-400 (noise floor), including with
exact (non-floored) indices. `fft_solver.cpp` was rewritten to retire that
approach -- it's now a thin wrapper delegating to the lattice path with a
forced weak-bias assumption. Read the big comment at the top of that file.

**The corrected approach** (agreed with the user): reuse the *existing*,
already-validated lattice machinery at larger dimension, since weak hard
bias is still lattice-exploitable in principle -- it just needs more
signatures (~320/L for leak level L). This is implemented:
`bias_profiler.cpp` and `lattice_solver.cpp` both widened their leak-bit
sweeps down to L=1,2, with per-trial dimension sizing (not a flat cap),
weak trials moved to the *end* of the sweep order, and an early-stop once
a fully-convincing candidate is found (so normal-strength cases, L>=3,
stay fast and are unaffected).

**Where it's actually blocked:** dimension scaling. Exact big-integer LLL
does not scale gracefully -- dimension ~25 is near-instant, dimension ~161
(needed for L=2) did not finish in 4.5+ minutes, dimension ~321 (needed
for L=1) likewise. This looks roughly consistent with LLL's known
complexity scaling as a high-degree polynomial in dimension for exact
bignum entries (moving from dim 25 to dim 161, a 6.4x increase, being
~1000x+ slower is in the right ballpark for d^5-ish scaling). This is a
**real performance wall in fplll's exact reduction**, not a logic bug --
the math and the widened-sweep code are correct; they're just impractical
to run to completion at that dimension in interactive time.

### Next steps (pick one, or investigate in this order)

1. **Cap dimension hard and drop L=1 from default sweeps.** Was about to
   do this when the session ended. Concretely: clamp `train_m` to something
   like 120 regardless of what the `320.0/L` formula would otherwise ask
   for, and exclude L=1 entirely from the default `leak_trials` lists in
   both `bias_profiler.cpp` and `lattice_solver.cpp` (its true requirement,
   ~m=320, is far past any reasonable cap, so attempting it with a capped
   dimension wastes time with no realistic chance of enough margin). Treat
   L=2 as best-effort/not-guaranteed at the capped dimension. This is the
   safe, honest, low-risk option -- it just narrows the claimed capability
   rather than fixing the underlying speed problem.

2. **Try a faster reduction backend.** fplll's exact LLL is the bottleneck.
   `fpylll` (Python bindings) exposes float-based / hybrid reduction modes
   that may be dramatically faster at this dimension while remaining
   correct (floating-point LLL variants trade some reduction quality for
   large constant-factor speedups; whether the quality loss still finds
   the target vector at these dimensions needs empirical testing, same
   discipline as everything else in this project -- generate ground-truth
   data, test, don't assume). This is real, unstarted investigation.

3. **Reduce the required dimension itself.** The `320/L` margin was chosen
   generously; the bare Boneh-Venkatesan theoretical minimum is `256/L`
   (e.g. ~256 for L=1 instead of ~320). Narrower margin means faster but
   less reliable (a `m=24` vs `m=26` comparison earlier in the project
   showed LLL can fail right at the margin -- see the BKZ escalation
   history above). Could combine with BKZ specifically at the margin
   rather than deep in the safe zone. Also unstarted.

Whichever you pick: validate the same way everything else in this project
was validated -- generate real ground-truth data (`generate_mock_signatures.py`
supports `--bias msb --bias-bits 1` etc.), run the actual binary, confirm
against the printed ground-truth key. Don't declare something fixed on
theory alone; this project's history is full of things that looked right
algebraically and weren't (see items 1-4 above). Time yourself against a
real dataset before assuming a change helped -- several "fixes" in this
project's history turned out to need a second pass once actually timed.

## Not started at all

- **Modulo/Extended-HNP bias** (`detect_modulo_bias` is a stub returning
  zeros). Genuinely harder: needs the full Extended HNP lattice
  construction (roughly double dimension, one extra helper column per
  signature to absorb the unknown multiplier). Substantial, separate task.
- **The `pairs` parameter warning in `detect_modulo_bias`** and the FFT
  `bias` parameter -- both are placeholders for the above, not cleanup
  items; leave them until modulo bias is actually implemented.

## Orientation: where things live

- `src/lattice_solver.cpp` -- the core recovery engine. Read the comment
  block above `build_boneh_venkatesan_basis` first; it explains the
  pivot-elimination + Kannan embedding from scratch.
- `src/bias_profiler.cpp` -- detection. `shrink_test_sweep` is the shared
  core used by both MSB and LSB detection.
- `src/recovery_engine.cpp` -- dispatch: picks LATTICE vs FALLBACK vs FFT,
  verifies candidates, owns the retry-with-alt-bias-shape logic.
- `src/verifier.cpp` -- genuine ECDSA verification (the real gate).
- `src/secp256k1.cpp` -- EC primitives; `pubkey_to_point`'s padding fix is
  worth reading if touching anything hex/pubkey related.
- `tests/unit_tests.cpp` -- fast checks, run these constantly.
- `tests/e2e_recovery_test.sh` -- slow, real, ground-truth checks.
