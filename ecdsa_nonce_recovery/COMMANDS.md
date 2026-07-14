# ECDSA Nonce-Bias Key Recovery Engine — Command Reference

This document gives the exact command set to build, test, and run the project.

## 1. Project Layout

```
ecdsa_nonce_recovery/
├── CMakeLists.txt
├── COMMANDS.md               ← this file
├── include/                  ← all .h headers
├── src/                      ← all .cpp sources
├── scripts/
│   └── generate_mock_signatures.py
├── tests/
│   └── fplll_sanity.cpp
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
    libfftw3-dev \
    libmpfr-dev \
    python3-pip

# Python dependencies for mock generator
pip3 install ecdsa
```

## 3. Full Build (CMake + Make)

```bash
# Go to project root
cd /home/user/ecdsa_nonce_recovery

# Clean previous build (recommended)
rm -rf build
mkdir -p build data

# Configure
cd build
cmake ..

# Build (all targets)
make -j$(nproc)

# (Optional) build just the main binary or test
make -j$(nproc) ecdsa_nonce_recovery
make fplll_sanity_test
```

**Resulting binaries:**
- `build/ecdsa_nonce_recovery` — main recovery tool
- `build/fplll_sanity_test`   — standalone fplll integration test

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

# MODULO bias (the regression benchmark)
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
- Lattice/FFT progress
- Final result + verification status

### Force a specific method (debugging)

```bash
# Force lattice only
./ecdsa_nonce_recovery -i ../data/msb_12b_800.txt -m lattice -v

# Force FFT (only useful for very low bias + huge files)
./ecdsa_nonce_recovery -i ../data/modulo_8b_50k.txt -m fft -v

# Force fallback ladder
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
| `-m METHOD`           | `auto \| lattice \| fft \| fallback` | `auto`    |
| `-s N`                | Max signatures to use                | all       |
| `-t SEC`              | Max time budget                      | unlimited |
| `-v`                  | Live telemetry dashboard             | on        |
| `-q`                  | Quiet (no live updates)              | off       |
| `-h`                  | Help                                 | —         |

## 11. Expected Behavior per Bias Level

| Bias Type | Leaked Bits | Signatures | Expected Method | Notes |
|-----------|-------------|------------|------------------|-------|
| MSB       | 12–16       | 800–2000   | Lattice          | Fast recovery |
| MSB       | 8           | 3000–5000  | Lattice          | Works reliably |
| LSB       | 8           | 3000–5000  | Lattice          | Works |
| MODULO    | ~8          | 20k–50k    | Lattice          | Primary benchmark |
| MSB       | 4           | 20k+       | Lattice (auto-sized) | Slower |
| Very low  | 1–2         | 50k–100k+  | FFT (auto)       | Very large files |
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
