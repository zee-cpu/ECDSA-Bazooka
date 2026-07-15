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

Recovery is by leak depth L (the number of biased high or low bits), for
both MSB and LSB bias:

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
- **Modulo/Extended-HNP bias**: not implemented (`detect_modulo_bias` is a
  stub).

Give weak-bias cases a generous `--max-time` (e.g. `-t 400`): the L = 4-6 BKZ
pass is budget-gated and is skipped if it cannot fit the remaining time.

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

- `COMMANDS.md` -- complete CLI reference and build prerequisites.
