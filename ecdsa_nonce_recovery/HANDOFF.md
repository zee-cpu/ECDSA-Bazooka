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

11. **BKZ escalation ignored `--max-time`.** It only checked
    `deadline_exceeded()` (has the deadline already passed) before
    *starting* the escalation, never `remaining_budget_seconds()` (will
    this specific call actually fit) -- so a real run asked for `-t 180`
    and took 84m47s, because once a BKZ call is in flight it can't be
    interrupted. Fixed by adding a `bkz_budget_needed` threshold, sized to
    the block size about to be attempted, checked against
    `remaining_budget_seconds()` before the call starts (`lattice_solver.cpp`,
    the BKZ escalation branch in `recover_private_key`).

12. **BKZ was running with zero pruning -- full exhaustive enumeration --
    on every call.** This was found while investigating item 11 and the
    weak-bias dimension wall below. `bkz_reduction(basis, block_size,
    BKZ_DEFAULT)`, the plain 3-arg convenience call used everywhere in this
    codebase, builds a `BKZParam` with an *empty* strategies vector; fplll's
    own `BKZParam` constructor then defaults every block to
    `Strategy::EmptyStrategy`, whose `PruningParams` fplll's own source
    documents as "means no pruning." This had nothing to do with float vs.
    exact precision (`FT_DEFAULT` already resolves to `FT_DOUBLE` --
    confirmed in fplll's `bkz.cpp`) -- it was a missing pruning strategy,
    full stop. Fixed via `load_bkz_pruning_strategies()` in
    `lattice_solver.cpp`, which loads fplll's own bundled, pre-tuned
    `default.json` strategy file (the same one fplll's CLI tool uses by
    default) and passes it into the full `BKZParam`-based `bkz_reduction`
    overload; falls back to the old unpruned call if the file isn't
    installed. Measured impact at the *same* reduction strength (not a
    quality tradeoff): block_size=30 at dim~161 went from not finishing in
    20 minutes to ~18-30s. This is a real, broadly-applicable win, kept
    regardless of what happened with weak-bias support below.

13. **Train/held-out overlap bug in `shrink_test_sweep`** (`bias_profiler.cpp`).
    The training sample and the "held-out" test/measure samples were all
    drawn independently from the same full `pairs` vector, not from disjoint
    partitions -- for small `n` the "held-out" set could trivially overlap or
    even equal the training set, undermining the whole point of the
    held-out significance test from item 1. Found while investigating a real
    59-signature file that reported `Confidence sigma: 300 / Leaked bits est: 0`,
    an internally-inconsistent result. Fixed by shuffling and partitioning
    `pairs` once up front into disjoint `train_pool` / `held_out_pool`
    before any sampling. Verified: genuine bias is still detected correctly;
    genuinely unbiased data and the 59-signature file both now report a
    clean `Confidence sigma: 0` instead of the anomalous reading.

All of the above is validated: full `ctest` suite passes, including real
recovery against fresh ground-truth data at 8/12/16-bit MSB and LSB bias,
and a fresh unbiased control correctly failing (no false positives).

**Known pre-existing gap, not yet fixed:** `ctest -R e2e_recovery`'s
unbiased-control case times out past 120s. Confirmed via `git stash` that
this predates all of this session's changes (the e2e script doesn't pass
`-t`, so `remaining_budget_seconds()` returns the unlimited sentinel and
none of the budget-fit guards above apply there) -- it's a separate,
pre-existing issue, not a regression. Whoever picks this up next should
decide whether to fix it or just give that e2e case an explicit `-t`.

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

### Update: options 1 and 2 are both done. L=2 is a real algorithmic limit,
### not a budget/tuning problem -- here's the evidence.

1. **Cap dimension hard and drop L=1 from default sweeps -- DONE.**
   `TRAIN_M_CAP = 120` (near the top of `lattice_solver.cpp`, mirrored in
   `bias_profiler.cpp`) now hard-clamps `train_m` regardless of what
   `320.0/L` would otherwise ask for. `1` was removed from every default
   `leak_trials` list in both files; the `base_l` / per-trial floors were
   raised from `max(1, ...)` to `max(2, ...)` to match. L=2 is treated as
   best-effort at the capped dimension, per the original plan.

2. **Try a faster reduction backend -- DONE, but not the backend HANDOFF
   originally guessed.** The premise here was wrong: fpylll's float-based
   BKZ would have called the *same* underlying routine fplll's C++ BKZ
   already uses by default (`FT_DEFAULT` resolves to `FT_DOUBLE` -- see
   `bkz.cpp`), so it would not have been faster. The actual bottleneck,
   found by reading fplll's own `BKZParam`/`Strategy`/`PruningParams`
   source, was missing pruning (item 12 above) -- fixed directly in this
   codebase's existing fplll C++ usage, no Python bindings needed.
   Measured ~100x+ speedup at identical block size/dimension.

**But the speedup doesn't rescue L=2.** After the pruning fix, block size
was swept directly against `reduce_and_extract` on a fresh, real L=2
ground-truth fixture (2-bit MSB, 700 sigs), at both the production-capped
dimension (train_m=120, dim=121) and the full theoretical margin
(train_m=160, dim=161, i.e. `320/L` for L=2 with no cap at all):

| block_size | dim | time | found correct key? |
|---|---|---|---|
| 30 | 121 | 13.5s | no |
| 40 | 121 | didn't finish in 600s | -- |
| 30 | 161 | 30.4s | no |
| 31 | 161 | didn't finish in 900s | -- |
| 35 | 161 | didn't finish in ~870s | -- |

Two things this rules out:

- **It isn't a dimension problem.** Going from dim=121 to the full-margin
  dim=161 at the same block_size=30 didn't change the outcome (still no
  match), just made each call ~2x slower.
- **It isn't a budget problem.** block_size=30 -> 31, one increment, took
  cost from 30s to over 900s without finishing. This is a genuine cliff in
  BKZ's cost curve, not a smooth ramp -- there is no practical timeout that
  buys you the next block size up. Block sizes that finish in reasonable
  time (<=~30) aren't strong enough to resolve a 2-bit bias; block sizes
  that might be strong enough (>=31) are computationally out of reach.

Conclusion: **L=2 recovery is a fundamental limit of this embedding at
these dimensions, not something fixable by more time, more signatures, or
a faster float backend.** Options 1 and 2 from the original plan are both
implemented and validated as genuine improvements (safer defaults, ~100x
faster BKZ) but neither one, nor the two combined, makes L=2 reliably
solvable. Treat L=2 as unlikely/best-effort in practice; L>=3 remains the
reliable floor.

3. **Reduce the required dimension itself -- still unstarted, and now a
   lower-confidence bet than it looked.** The `320/L` margin down to the
   bare `256/L` theoretical minimum was never tried, but the block_size
   cliff data above suggests the bottleneck is block_size cost, not
   dimension/margin -- shrinking the margin would only help if a *smaller*
   block size became sufficient at the same L, which the dim=121 vs
   dim=161 comparison (both block_size=30, both no match) doesn't support.
   Not ruled out entirely, but don't expect it to be the fix without
   testing it the same rigorous way as the above.

Whichever you pick next: validate the same way everything else in this
project was validated -- generate real ground-truth data
(`generate_mock_signatures.py` supports `--bias msb --bias-bits 1` etc.),
run the actual binary, confirm against the printed ground-truth key. Don't
declare something fixed on theory alone; this project's history is full of
things that looked right algebraically and weren't (see items 1-4 above).
Time yourself against a real dataset before assuming a change helped --
several "fixes" in this project's history turned out to need a second pass
once actually timed.

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
