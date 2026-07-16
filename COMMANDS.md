# ECDSA Nonce-Bias Key Recovery Engine — Command Reference

This document gives the exact command set to build, test, and run the project.

## 1. Project Layout

```
ecdsa_nonce_recovery/
├── CMakeLists.txt
├── CMakePresets.json         ← release / debug / asan presets
├── COMMANDS.md               ← this file
├── README.md
├── include/                  ← all .h headers
├── src/                      ← all .cpp sources (compiled into ecdsa_recovery_core)
├── scripts/
│   └── generate_mock_signatures.py
├── tests/
│   ├── unit_tests.cpp        ← fast isolated unit tests
│   ├── fplll_sanity.cpp
│   └── e2e_recovery_test.sh
├── build/                    ← created by cmake
└── data/                     ← generated signature files
```

## 2. Prerequisites (one-time)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    cmake g++ \
    libgmp-dev libgmpxx4ldbl \
    libfplll-dev libfplll9 \
    libmpfr-dev \
    python3-pip

# Python dependencies for mock generator
pip3 install ecdsa
```

### Dependency / version matrix

Tested against the versions below (Ubuntu 24.04). Others likely work; these are
what the build and validation runs used.

| Component     | Package (apt)              | Version tested | Required            |
|---------------|----------------------------|----------------|---------------------|
| CMake         | `cmake`                    | 3.28 (≥ 3.16; presets need ≥ 3.21) | yes |
| C++ compiler  | `g++`                      | C++20 (GCC 13) | yes                 |
| GMP           | `libgmp-dev`               | 6.x            | yes                 |
| GMP C++       | `libgmpxx4ldbl`            | 6.x            | yes                 |
| fplll         | `libfplll-dev` / `libfplll9` | 5.4.x        | yes                 |
| MPFR          | `libmpfr-dev`              | 4.x            | yes (via fplll)     |
| Python + ecdsa| `python3`, `pip install ecdsa` | 3.10+     | test data only      |

FFTW is **not** a dependency (the former FFT path was removed). fplll's bundled
BKZ pruning strategy file (`default.json`) is used if found on a standard prefix;
override its location with `ECDSA_FPLLL_STRATEGY=/path/to/default.json`.

## 3. Full Build (CMake + Make)

The recommended path is CMake presets (needs CMake ≥ 3.21):

```bash
cd /home/user/ecdsa_nonce_recovery
cmake --preset release          # configures into build/
cmake --build --preset release -j$(nproc)
ctest --preset release          # runs unit_tests + fplll_sanity + e2e
```

Available presets: `release` (build/), `debug` (build-debug/), `asan`
(build-asan/, AddressSanitizer + UBSan). The plain flow still works:

```bash
rm -rf build && mkdir -p build data
cd build && cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)                 # all targets
make -j$(nproc) ecdsa_nonce_recovery   # or just the CLI
```

All first-party code compiles into one library (`ecdsa_recovery_core`); the CLI
and the unit tests both link it, so they exercise the same implementation.

**Resulting binaries:**
- `build/ecdsa_nonce_recovery` — main recovery tool
- `build/unit_tests`           — fast isolated unit tests
- `build/fplll_sanity_test`    — standalone fplll integration test

## 4. Quick Sanity Check (fplll)

```bash
cd /home/user/ecdsa_nonce_recovery/build
./fplll_sanity_test
```

Expected output contains:
```
[SUCCESS] fplll_sanity_test passed.
```

## 5. Generate Mock Signature Data

The Python script creates files exactly matching the required format and prints the **ground-truth private key**.

### Basic usage

```bash
cd /home/user/ecdsa_nonce_recovery

# MSB bias, 12 leaked bits, 800 signatures
python3 scripts/generate_mock_signatures.py \
    --count 800 \
    --bias msb \
    --bias-bits 12 \
    --output data/msb_12b_800.txt \
    --seed 424242
```

### Other common test cases

```bash
# High-bias (16 bits) — lattice should recover fast
python3 scripts/generate_mock_signatures.py \
    --count 1200 --bias msb --bias-bits 16 \
    --output data/msb_16b_1200.txt --seed 12345

# Moderate bias (8 bits) — needs more signatures
python3 scripts/generate_mock_signatures.py \
    --count 5000 --bias msb --bias-bits 8 \
    --output data/msb_8b_5k.txt --seed 999

# LSB bias
python3 scripts/generate_mock_signatures.py \
    --count 3000 --bias lsb --bias-bits 8 \
    --output data/lsb_8b_3k.txt --seed 777

# MODULO bias -- generator only; recovery is NOT implemented
# (detect_modulo_bias is a stub). The tool will report failure on this
# input. Kept as a negative fixture, not a supported recovery benchmark.
python3 scripts/generate_mock_signatures.py \
    --count 50000 --bias modulo --bias-bits 8 \
    --output data/modulo_8b_50k.txt --seed 2026

# No bias (should fail to recover)
python3 scripts/generate_mock_signatures.py \
    --count 1000 --bias none \
    --output data/nobias_1k.txt --seed 42
```

**Important:** The script always prints the **ground-truth private key** at the end:
```
[+] Ground-truth private key (exact for verification): 0x...
```

### Optional: supplying known leaked nonce bits (side-channel data)

Each signature block may carry an optional `KnownLow` field giving the *known*
low bits of that signature's nonce `k` (e.g. recovered from a side channel):

```
Signature #1
  R = ...
  S = ...
  Z = ...
  PubKey: 04...
  KnownLow: 8 0xab      # low 8 bits of k are known to be 0xab  (k ≡ 0xab mod 2^8)
```

Format is `KnownLow: <bits> <value_hex>`, with `1 ≤ bits ≤ 64` and
`0 ≤ value < 2^bits`. When **every** signature in the file carries the same
`bits` width, the tool skips statistical bias detection and recovers directly
from the supplied constraint (generalizing the low-bits-are-zero case to any
known residue). Partial or mixed-width annotation is ignored and the tool falls
back to normal detection. As always, a reported key is verified against the
PubKey, so a wrong leak simply fails to recover — it never yields a bad key.

## 6. Run the Recovery Tool

### Basic run (quiet — for logs/scripts)

```bash
cd /home/user/ecdsa_nonce_recovery/build

./ecdsa_nonce_recovery \
    -i ../data/msb_12b_800.txt \
    -q
```

### Run with live dashboard (recommended for real use)

```bash
./ecdsa_nonce_recovery \
    -i ../data/msb_12b_800.txt \
    -v
```

The dashboard updates every ~120ms and shows:
- Signatures loaded / valid
- Detected bias type + leaked bits + confidence (σ)
- Active recovery method
- Lattice progress (leak level L, LLL/BKZ, dimension)
- Final result + verification status

### Force a specific method (debugging)

```bash
# Force lattice only
./ecdsa_nonce_recovery -i ../data/msb_12b_800.txt -m lattice -v

# Force fallback ladder (wider lattice sweep for weak/undetected bias)
./ecdsa_nonce_recovery -i ../data/nobias_1k.txt -m fallback -v
```

### Limit resources

```bash
# Use at most 1500 signatures
./ecdsa_nonce_recovery -i ../data/msb_8b_5k.txt -s 1500 -v

# Max 30 seconds
./ecdsa_nonce_recovery -i ../data/msb_8b_5k.txt -t 30 -v
```

## 7. Full Test Workflow (Recommended)

```bash
cd /home/user/ecdsa_nonce_recovery

# 1. Build everything
rm -rf build && mkdir -p build data
cd build
cmake .. && make -j$(nproc)

# 2. Run fplll sanity
./fplll_sanity_test

# 3. Generate a realistic test set
cd ..
python3 scripts/generate_mock_signatures.py \
    --count 2000 --bias msb --bias-bits 12 \
    --output data/test_msb12_2k.txt --seed 123

# 4. Run with live UI and watch dashboard
cd build
./ecdsa_nonce_recovery -i ../data/test_msb12_2k.txt -v

# 5. Compare recovered key against printed ground-truth
# (the tool prints the recovered d on success)
```

## 8. Verifying Correctness (Ground Truth)

After every recovery run:

1. The generator printed: `Ground-truth private key: 0x<hex>`
2. The C++ tool (on success) prints: `d = 0x<hex>`
3. They must match **exactly**.

You can also do it programmatically:

```bash
# Example after running the tool
GROUND_TRUTH="0x88a0a8b792e19f1a915a7f79df5bab03e57e02d0147f2e18adc67c94c8065965"
RECOVERED="..."   # copy from tool output

if [ "$GROUND_TRUTH" = "$RECOVERED" ]; then
    echo "MATCH ✓"
else
    echo "MISMATCH ✗"
fi
```

## 9. Clean / Rebuild Commands

```bash
cd /home/user/ecdsa_nonce_recovery

# Full clean rebuild
rm -rf build
mkdir -p build
cd build
cmake ..
make -j$(nproc)

# Just recompile changed files
cd build && make -j$(nproc)
```

## 10. Common Flags Summary

| Flag                  | Meaning                              | Default   |
|-----------------------|--------------------------------------|-----------|
| `-i FILE` / `--input` | Signature file (required)            | —         |
| `-m METHOD`           | `auto \| lattice \| fallback`        | `auto`    |
| `-s N`                | Max signatures to use                | all       |
| `-t SEC`              | Max time budget                      | unlimited |
| `-v`                  | Live telemetry dashboard             | on        |
| `-q`                  | Quiet (no live updates)              | off       |
| `--allow-no-pubkey`   | Best-effort recovery w/o PubKey (unverifiable) | off |
| `--seed N`            | Sampling RNG seed (hex or decimal), for reproducibility | fixed |
| `-h`                  | Help                                 | —         |

## 11. Expected Behavior per Bias Level

| Bias Type | Leaked Bits | Signatures | Expected Method | Notes |
|-----------|-------------|------------|------------------|-------|
| MSB/LSB   | ≥ 7         | 500–2000   | Lattice (LLL)    | Fast, seconds |
| MSB/LSB   | 5–6         | ~1000–2000 | Lattice (BKZ b=30) | Tens of sec to ~2 min |
| MSB/LSB   | 4           | ~2000      | Lattice (BKZ b=30) | Best-effort, few min, not guaranteed for every key |
| MSB/LSB   | ≤ 3         | —          | —                | Out of reach in practice (see README feasibility notes) |
| MODULO    | any         | —          | —                | Not implemented (`detect_modulo_bias` is a stub) |
| none      | 0           | any        | Reports failure  | No false positives |

## 12. Troubleshooting

- **"No signatures parsed"** → Check file format (must have "Signature #N" blocks)
- **fplll not found at configure** → `sudo apt-get install libfplll-dev`
- **Live dashboard looks frozen** → Run with `-v` in a real terminal (not piped to file)
- **Wrong key recovered** → Always compare exactly against generator output. Verify that verification step passed.
- **Compile errors about `mpz_class`** → The project already follows the `static_cast<unsigned long>` rule for 64-bit values.

## 13. One-Liner Full Demo

```bash
cd /home/user/ecdsa_nonce_recovery && \
rm -rf build && mkdir -p build data && \
cd build && cmake .. && make -j$(nproc) && \
cd .. && \
python3 scripts/generate_mock_signatures.py --count 1500 --bias msb --bias-bits 12 --output data/demo.txt --seed 42 && \
cd build && \
./ecdsa_nonce_recovery -i ../data/demo.txt -v
```

Copy the ground-truth key printed by the generator and compare it with the key reported by the tool.

---

**Project is ready for all Section 9 acceptance tests once you run the above workflow on the generated files.**
