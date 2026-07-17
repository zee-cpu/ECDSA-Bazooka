# ECDSA Nonce-Bias Recovery Tool

[![CI](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml/badge.svg)](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml)

This command-line tool analyzes ECDSA signatures produced by the same private
key when their nonce values follow an exploitable structure. It selects a
closed-form or lattice-based method based on the supplied data and options.

Every candidate is checked against the supplied public key. If the input does
not provide enough usable structure, the program reports failure instead of
returning an incorrect key.

## What it handles

| Pattern | Nonce model | Method |
|---|---|---|
| MSB bias | `k < 2^(256-L)` | LLL or BKZ lattice reduction |
| LSB bias | `k ≡ 0 (mod 2^b)` | LSB transform and lattice reduction |
| Known-offset LSB | `k ≡ c (mod 2^b)`, with `c` supplied | Exact-constraint lattice reduction |
| Modulo window | `k mod ω ∈ [0, bound)` | Two-block Extended-HNP lattice |
| Repeated nonce | Two signatures share the same `k` | Closed-form modular algebra |
| Linear sequence | `k[i+1] = a·k[i] + b (mod n)` | Closed-form modular algebra |
| Distributional skew | Low entropy without a per-value constraint | Detected when possible, but not recoverable by this tool |

Repeated and linear patterns are checked automatically before the more
expensive lattice paths. Use `--method` when you need to select a specific
route.

## Quick start

From the repository root:

```bash
cmake --preset release
cmake --build --preset release -j"$(nproc)"
./build/unit_tests

python3 scripts/generate_mock_signatures.py \
  --count 500 \
  --bias msb \
  --bias-bits 12 \
  --output data/demo.txt \
  --seed 1

./build/ecdsa_nonce_recovery -i data/demo.txt -q
```

See [COMMANDS.md](COMMANDS.md) for prerequisites, all build and test variants,
fixture recipes, and the complete CLI reference.

## Practical limits

Difficulty increases sharply as the number of constrained bits decreases.
These ranges describe the current 256-bit lattice path; results still depend
on the input set and available time.

| Constrained bits | Expected path | Practical expectation |
|---|---|---|
| 7 or more | LLL | Normally fast and reliable for suitable inputs |
| 5–6 | Focused BKZ | Often needs a larger `--max-time` budget |
| 4 | Heavier BKZ | Best-effort and not guaranteed for every input |
| 3 or fewer | — | Outside practical scope for this implementation |

Modulo-window inputs follow a similar curve: wider windows are easier, while
narrow windows can require expensive BKZ passes. Supply `--modulo-omega` and
`--modulo-bound` when those values are known.

Lattice reductions run serially. The linked reduction library changes shared
process state during reduction, so concurrent reductions in one process are
not safe. Set `ECDSA_FPLLL_STRATEGY` to override the pruning-strategy file; the
program can continue with slower unpruned enumeration when it is unavailable.

## Testing

Run the fast regression group after routine changes:

```bash
ctest --test-dir build --output-on-failure \
  -R '^(unit_tests|fplll_sanity|cli_validation)$'
```

Run the focused differential and end-to-end checks separately:

```bash
ctest --test-dir build --output-on-failure -R '^ecc_differential$'
ctest --test-dir build --output-on-failure -R '^e2e_recovery$'
```

CI also performs a warning-gated release build and sanitizer checks. Local
sanitizer builds are available through the `asan` CMake preset.

## Project layout

| Path | Responsibility |
|---|---|
| `src/lattice_solver.cpp` | Single-block and two-block lattice construction and reduction |
| `src/bias_profiler.cpp` | MSB and LSB structure detection |
| `src/recovery_engine.cpp` | Method selection, recovery orchestration, and candidate checks |
| `src/verifier.cpp` | Independent ECDSA verification |
| `src/secp256k1.cpp` | Elliptic-curve primitives |
| `tests/` | Unit, CLI, differential, integration, and end-to-end checks |

## Documentation

[COMMANDS.md](COMMANDS.md) is the complete build, test, fixture-generation,
runtime, option, and troubleshooting reference.

## License

Released under the MIT License. See [LICENSE](LICENSE).
