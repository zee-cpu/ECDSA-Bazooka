# ECDSA Nonce-Bias Recovery Tool

[![CI](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml/badge.svg)](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml)

Given a set of real ECDSA signatures from the same private key with an
exploitable nonce (`k`) weakness, detect it and recover the private key.
Different weaknesses call for different math: statistical bias in the nonce's
high or low bits is a Hidden Number Problem solved by lattice reduction
(LLL/BKZ), a windowed / modulo bias uses an Extended-HNP two-block lattice,
and a reused nonce or an LCG-related nonce sequence hands over the key by
closed-form algebra with no lattice at all. The lattice core eliminates the
private key `d` via a pivot-elimination trick across signature pairs, reducing
to an HNP in one small unknown, solved with a Kannan CVP-to-SVP embedding.

Every recovered key is verified against the public key, so a wrong guess or a
non-exploitable input is reported as failure — never as a wrong key.

## Quick start

```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
cd ..
./build/unit_tests                       # a few seconds, run after every change

python3 scripts/generate_mock_signatures.py --count 500 --bias msb --bias-bits 12 \
  --output /tmp/test.txt --seed 1        # prints the ground-truth key to stdout

./build/ecdsa_nonce_recovery -i /tmp/test.txt -q
```

See `COMMANDS.md` for the full CLI/flag reference and prerequisite package
list.

## Current capability

The tool covers the known *exploitable* nonce-weakness classes below, auto-routing
to the right method and reporting "no exploitable bias" otherwise.

| Weakness | Nonce model | Method | Notes |
|----------|-------------|--------|-------|
| MSB bias | `k < 2^(256-L)` | Lattice (LLL/BKZ) | By leak depth L — see below |
| LSB bias (zero) | `k ≡ 0 (mod 2^b)` | Lattice (LSB transform) | Same L-depth frontier as MSB |
| Known-offset LSB | `k ≡ c (mod 2^b)`, `c` known | Lattice | Side-channel leak; optional per-signature `KnownLow:` field |
| Modulo / Extended-HNP | `k mod ω ∈ [0, bound)` | Two-block EHNP lattice | Windowed zeros mid-nonce — see below |
| Repeated nonce | two signatures share `k` | Closed-form algebra | From 2 signatures; the classic RNG-reset break |
| Linear / LCG | `k_{i+1} = a·k_i + b (mod n)` | Closed-form algebra | Auto-recovers even with `a,b` unknown (5 sigs) |
| Distributional skew | low-entropy but per-nonce value unknown | — | Correctly *rejected*: detectable ≠ exploitable |

### Lattice recovery by leak depth (MSB / LSB)

Recovery is by leak depth L (the number of biased high or low bits):

- **L >= 5 bits: robustly recovered and validated.** Strong bias (L >= 7)
  resolves under plain LLL in seconds; L = 5-6 use a focused BKZ pass (tens
  of seconds to a couple of minutes).
- **L = 4 bits: best-effort.** Recoverable, but right at the edge of what a
  block-30 BKZ reduction can resolve at 256-bit, so it takes a few minutes
  and two independent dimension attempts. Both test seeds recover; it is not
  guaranteed for every key.
- **L <= 3 bits: out of reach in practice.** L = 3 needs block_size >= 40 at
  dimension >= 450 (> 15 min per attempt, no guarantee of convergence); L = 2
  does not converge at feasible cost; L = 1 is out of scope entirely (a
  genuine Fourier / Bleichenbacher attack there needs millions of same-key
  signatures -- see De Mulder et al. CHES 2013, Osaki & Kunihiro SAC 2024,
  Aranha et al. CCS 2020 -- which a wallet's on-chain history cannot supply).

Give weak-bias cases a generous `--max-time` (e.g. `-t 400`): the L = 4-6 BKZ
pass is budget-gated and is skipped if it cannot fit the remaining time.

### Modulo / Extended-HNP (windowed zeros)

Nonces with a zero window in the *middle* -- `k mod ω ∈ [0, bound)`, neither MSB
(`k` is full-width) nor LSB (the low bits are free) -- are recovered by a
two-block Extended-HNP lattice. Difficulty tracks the window width just like an
MSB leak: a window of >= ~12 bits resolves under LLL in ~15s, while a narrow
~8-bit window needs heavy BKZ and is best-effort (like MSB L=4). Supply the
`(ω, bound)` hint the generator prints (`--modulo-omega/--modulo-bound`), or use
`-m modulo` to sweep common windows.

### Repeated-nonce and LCG (closed-form, no lattice)

A reused nonce (two signatures sharing `r`) or an LCG-related nonce sequence
(`k_{i+1} = a·k_i + b mod n`) hands over the key by modular algebra -- no lattice.
Both run as cheap, pubkey-gated pre-scans on every recovery, so `-i file` alone
catches them. The LCG solver recovers even when `a` and `b` are **unknown** (from
five consecutive signatures, via a 4x4 modular solve) and retries in timestamp
order so out-of-order logs still recover.

## Concurrency

Lattice reductions run **serially by design**. The independent trials look
parallelizable, but fplll is not thread-safe for concurrent reductions (its LLL
wrapper mutates a process-global MPFR precision, and BKZ calls LLL internally),
so running two at once races and crashes. A threaded version was built and
reverted for this reason. The only safe way to parallelize would be process
(`fork`) isolation, one fplll per worker — not threads.

The fplll BKZ pruning-strategy file is located via the `ECDSA_FPLLL_STRATEGY`
environment variable if set, otherwise the standard install prefixes. Recovery
still works without it (falling back to slower unpruned enumeration), so it is
an optimization, not a hard dependency.

## Testing

```bash
./build/unit_tests                  # fast (a few seconds): math, transforms, validation, recovery paths, ECC edge cases
ctest -R ecc_differential            # local ECC vs the trusted `ecdsa` library (edge + random)
ctest -R e2e_recovery                # slow (~5min): real recovery against real ground truth
```

CI (`.github/workflows/ci.yml`) runs, on every push/PR: a warning-gated Release
build, the unit + differential tests, an ASan/UBSan pass, and a bounded
end-to-end recovery smoke test. Sanitizer builds are available locally via
`cmake --preset asan`.

## Where things live

- `src/lattice_solver.cpp` -- the core lattice recovery: the single-block
  pivot-elimination + Kannan embedding (`build_boneh_venkatesan_basis` --
  read its comment before touching it), and the two-block Extended-HNP lattice
  for modulo/windowed bias (`recover_modulo`).
- `src/bias_profiler.cpp` -- bias detection; `shrink_test_sweep` is the
  shared core used by both MSB and LSB detection.
- `src/recovery_engine.cpp` -- dispatch and routing: the closed-form
  pre-scans (`try_repeated_nonce`, `try_linear_nonce`), modulo/EHNP routing
  (`try_modulo`), the lattice paths (LATTICE vs FALLBACK), candidate
  verification, and retry logic.
- `src/verifier.cpp` -- genuine independent ECDSA verification.
- `src/secp256k1.cpp` -- EC primitives.
- `tests/unit_tests.cpp` / `tests/e2e_recovery_test.sh` -- the two test
  suites above.

## More context

- `COMMANDS.md` -- complete CLI reference and build prerequisites.

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
