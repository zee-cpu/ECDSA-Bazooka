# ECDSA Nonce-Bias Recovery Tool

A wallet-recovery firm's internal tool: given a set of real ECDSA signatures
from the same private key where the nonce (`k`) has some kind of statistical
bias (MSB, LSB, or weak/soft bias), detect the bias and recover the private
key. Core approach: eliminate the private key `d` algebraically via a
pivot-elimination trick across signature pairs, reducing to a Hidden Number
Problem in one small unknown, solved via lattice reduction (LLL/BKZ) with a
Kannan CVP-to-SVP embedding.

## Quick start

```bash
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
cd ..
./build/unit_tests                       # <1s, run after every change

python3 scripts/generate_mock_signatures.py --count 500 --bias msb --bias-bits 12 \
  --output /tmp/test.txt --seed 1        # prints the ground-truth key to stdout

./build/ecdsa_nonce_recovery -i /tmp/test.txt -q
```

See `COMMANDS.md` for the full CLI/flag reference and prerequisite package
list.

## Current capability

- **MSB and LSB bias**: implemented and validated, including a BKZ
  escalation path for cases plain LLL doesn't resolve cleanly.
- **Modulo/Extended-HNP bias**: not implemented (`detect_modulo_bias` is a
  stub).
- **Weak (1-2 bit) bias**: out of scope. Both the lattice/BKZ path and the
  theoretical Fourier-analysis (Bleichenbacher) alternative were
  investigated and hit hard, literature-confirmed walls at this bit depth
  for realistic signature volumes -- see `HANDOFF.md` for the full
  writeup and citations. **L>=3 bits is the tool's reliable floor.**

## Testing

```bash
./build/unit_tests                  # fast (<1s): math, transforms, verification logic
ctest -R e2e_recovery                # slow (~5min): real recovery against real ground truth
```

## Where things live

- `src/lattice_solver.cpp` -- the core recovery engine (pivot-elimination +
  Kannan embedding). Read the comment above `build_boneh_venkatesan_basis`
  before touching it.
- `src/bias_profiler.cpp` -- bias detection; `shrink_test_sweep` is the
  shared core used by both MSB and LSB detection.
- `src/recovery_engine.cpp` -- dispatch (LATTICE vs FALLBACK vs FFT),
  candidate verification, retry logic.
- `src/verifier.cpp` -- genuine independent ECDSA verification.
- `src/secp256k1.cpp` -- EC primitives.
- `tests/unit_tests.cpp` / `tests/e2e_recovery_test.sh` -- the two test
  suites above.

## More context

- `HANDOFF.md` -- full project history: every bug found and fixed, what's
  validated, and the investigation behind the weak-bias conclusion above.
  Read this before making non-trivial changes.
- `COMMANDS.md` -- complete CLI reference and build prerequisites.
