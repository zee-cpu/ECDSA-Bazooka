# Command Reference

This is the complete build, test, fixture-generation, and runtime reference.
See [README.md](README.md) for the project overview and practical limits.

Run commands from the repository root unless a section says otherwise.

## Prerequisites

Ubuntu and Debian-based systems can install the required packages with:

```bash
sudo apt-get update
sudo apt-get install -y \
  cmake \
  g++ \
  libgmp-dev \
  libgmpxx4ldbl \
  libfplll-dev \
  libfplll9 \
  libmpfr-dev \
  python3-pip

python3 -m pip install ecdsa
```

Use a Python virtual environment if your distribution does not allow global
package installation.

| Component | Requirement | Purpose |
|---|---|---|
| CMake | 3.16 minimum; 3.21 for presets | Configure and build |
| C++ compiler | C++20 support | Compile the program and tests |
| GMP and GMP C++ | 6.x tested | Multiprecision arithmetic |
| fplll | 5.4.x tested | LLL and BKZ reduction |
| MPFR | 4.x tested | fplll dependency |
| Python | 3.10+ tested | Fixture generation and differential testing |
| Python `ecdsa` | Optional for the main binary | Fixtures and differential testing |

FFTW is not required. The program looks for fplll's `default.json` pruning
strategy in standard installation locations. Set
`ECDSA_FPLLL_STRATEGY=/path/to/default.json` to use a specific file. Recovery
can continue with slower unpruned enumeration if no strategy file is found.

## Build

CMake presets are the recommended build path.

### Release build

```bash
cmake --preset release
cmake --build --preset release -j"$(nproc)"
```

Output directory: `build/`

### Debug build

```bash
cmake --preset debug
cmake --build --preset debug -j"$(nproc)"
```

Output directory: `build-debug/`

### Sanitizer build

```bash
cmake --preset asan
cmake --build --preset asan -j"$(nproc)"
```

Output directory: `build-asan/`. This preset enables AddressSanitizer and
UndefinedBehaviorSanitizer.

### Plain CMake build

Use this flow with CMake 3.16–3.20 or when presets are not desired:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The release build produces:

| Binary | Purpose |
|---|---|
| `build/ecdsa_nonce_recovery` | Main command-line program |
| `build/unit_tests` | Fast isolated regression tests |
| `build/fplll_sanity_test` | fplll integration check |
| `build/ecc_diff_tool` | Helper for differential curve tests |

## Test

Configure and build the selected preset before running its tests.

### Fast regression tests

Use this group after routine changes:

```bash
ctest --test-dir build --output-on-failure \
  -R '^(unit_tests|fplll_sanity|cli_validation)$'
```

### Individual tests

```bash
ctest --test-dir build --output-on-failure -R '^unit_tests$'
ctest --test-dir build --output-on-failure -R '^fplll_sanity$'
ctest --test-dir build --output-on-failure -R '^cli_validation$'
ctest --test-dir build --output-on-failure -R '^ecc_differential$'
ctest --test-dir build --output-on-failure -R '^e2e_recovery$'
```

The differential test exits successfully with a skip message when the Python
`ecdsa` package is unavailable. The end-to-end test is the slowest case and has
a ten-minute CTest timeout.

### Complete test preset

```bash
ctest --preset release
```

This includes all registered tests, including the slower end-to-end case. For
the sanitizer build, use `ctest --preset asan`.

## Generate fixtures

The generator writes records in the accepted input format and prints the
ground-truth value. It also prints applicable modulo or linear parameters.

### MSB and LSB examples

```bash
python3 scripts/generate_mock_signatures.py \
  --count 800 --bias msb --bias-bits 12 \
  --output data/msb_12b_800.txt --seed 424242

python3 scripts/generate_mock_signatures.py \
  --count 1200 --bias lsb --bias-bits 8 \
  --output data/lsb_8b_1200.txt --seed 777
```

### Modulo-window example

This example constrains `k mod 65536` to a 12-bit-narrower interval. The
generator prints the corresponding period and bound.

```bash
python3 scripts/generate_mock_signatures.py \
  --count 250 --bias modulo --bias-bits 12 --omega 65536 \
  --output data/modulo_12b.txt --seed 41
```

### Linear-sequence example

```bash
python3 scripts/generate_mock_signatures.py \
  --count 40 --bias linear --lcg-a 3 --lcg-b 7 \
  --output data/linear.txt --seed 44
```

Omit `--lcg-a` and `--lcg-b` to let the generator choose and print them.

### Unstructured example

Use this as a negative fixture. A successful candidate is not expected.

```bash
python3 scripts/generate_mock_signatures.py \
  --count 1000 --bias none \
  --output data/unstructured_1k.txt --seed 42
```

See every generator option with:

```bash
python3 scripts/generate_mock_signatures.py --help
```

## Run the program

### Automatic selection

Automatic selection is the default. The live dashboard is enabled unless `-q`
is supplied.

```bash
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt -q
```

The automatic path first checks inexpensive repeated and linear relationships,
then profiles the remaining input and selects an appropriate lattice route.

### Select a method

```bash
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt -m lattice -v
./build/ecdsa_nonce_recovery -i data/unstructured_1k.txt -m fallback -v
./build/ecdsa_nonce_recovery -i data/modulo_12b.txt -m modulo -v
./build/ecdsa_nonce_recovery -i data/linear.txt -m linear -v
```

`fallback` runs a wider lattice sweep. `modulo` searches common windows when no
parameters are supplied. `linear` widens the linear-sequence scan.

### Provide modulo parameters

Use the period and bound printed by the generator:

```bash
./build/ecdsa_nonce_recovery -i data/modulo_12b.txt \
  --modulo-omega 65536 --modulo-bound 16 -v
```

Both options are required together. Values must be positive, and the bound
must be smaller than the period.

### Provide linear parameters

```bash
./build/ecdsa_nonce_recovery -i data/linear.txt \
  --lcg-a 3 --lcg-b 7 -v
```

`--lcg-b` requires `--lcg-a`. The increment defaults to zero when only the
multiplier is supplied. Without either option, the program can infer unknown
parameters from five consecutive signatures.

### Limit work

```bash
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt \
  --max-sigs 500 --max-time 60 --seed 0x1234 -q
```

`--max-sigs` is a decimal count and `--max-time` accepts non-negative seconds.
The sampling seed and numeric hints accept decimal or `0x`-prefixed values.

## CLI options

| Option | Purpose | Default |
|---|---|---|
| `-i, --input FILE` | Input signature file | required |
| `-m, --method METHOD` | `auto`, `lattice`, `fallback`, `modulo`, or `linear` | `auto` |
| `-s, --max-sigs N` | Maximum signatures to use | all |
| `-t, --max-time SEC` | Time budget in seconds | unlimited |
| `-v, --verbose` | Enable the live dashboard | on |
| `-q, --quiet` | Disable live updates | off |
| `--allow-no-pubkey` | Allow an unverifiable best-effort result | off |
| `--seed N` | Sampling seed in decimal or `0x` notation | fixed |
| `--modulo-omega N` | Modulo period | unset |
| `--modulo-bound N` | Residue bound paired with the period | unset |
| `--lcg-a N` | Linear multiplier | unset |
| `--lcg-b N` | Linear increment; requires `--lcg-a` | `0` |
| `-h, --help` | Show command help | — |

Show the live help at any time:

```bash
./build/ecdsa_nonce_recovery --help
```

## Optional input annotations

Each input record requires `R`, `S`, and `Z`. A public key is required by
default. `KnownLow` can supply an exact low-bit residue for each nonce:

```text
Signature #1
R = ...
S = ...
Z = ...
PubKey: 04...
KnownLow: 8 0xab
```

`KnownLow: 8 0xab` means `k ≡ 0xab (mod 2^8)`. The width must be from 1 through
64, and the value must fit within that width. Malformed or duplicate
annotations cause the affected record to be rejected.

Exact-constraint routing requires every usable signature to carry the same
width; the residue value may differ per signature. Partial or mixed-width sets
fall back to normal structure detection.

`LeakedBits` supplies the MSB-zero leakage width for a single signature's nonce,
for the sieving-with-predicate route (deep leaks, roughly `L <= 3`):

```text
Signature #1
R = ...
S = ...
Z = ...
PubKey: 04...
LeakedBits: 3
```

`LeakedBits: 3` means `k < 2^(256-3)`. The width must be from 1 through 200.
Because the widths are per signature, they may differ across records, which
lets real variable-leakage side-channel data express a non-uniform (and hence
fractional-average) leak exactly. When every usable signature carries a
`LeakedBits` value and a public key is present, the sieve route is used with
those exact bounds -- no `--leaked-bits` flag needed. For a single global
value instead, use `--leaked-bits N` (which may be fractional, e.g. `2.5`).

## Expected behavior

These are practical guidelines, not fixed performance guarantees.

| Input pattern | Typical size | Expected path | Guidance |
|---|---:|---|---|
| MSB or LSB, 7+ bits | 500–2,000 | LLL | Normally fast for suitable inputs |
| MSB or LSB, 5–6 bits | 1,000–2,000 | Focused BKZ | Can require a larger time budget |
| MSB or LSB, 4 bits | Around 2,000 | Heavier BKZ | Best-effort; can require minutes |
| MSB or LSB, 3 bits or fewer | — | — | Outside practical scope |
| Modulo window, about 12+ bits | 250–500 | Extended-HNP with LLL | Normally the easier modulo case |
| Modulo window, about 8 bits | 500+ | Extended-HNP with BKZ | Best-effort and potentially slow |
| Repeated value | 2 | Closed-form | Automatic pre-scan |
| Linear sequence, unknown parameters | 5+ | Closed-form | Uses consecutive records |
| Linear sequence, known parameters | 2+ | Closed-form | Supply `--lcg-a` and optional `--lcg-b` |
| Unstructured input | any | No candidate | Expected to report failure |

For weaker constraints, provide a comfortable `--max-time`. A BKZ attempt can
be skipped when the remaining budget is too small to run it.

## Clean and rebuild

Clean generated build outputs without deleting the build directory, then
rebuild the release preset:

```bash
cmake --build --preset release --target clean
cmake --build --preset release -j"$(nproc)"
```

Rerun `cmake --preset release` first after changing CMake configuration files.

## Troubleshooting

| Problem | Check |
|---|---|
| No signatures parsed | Confirm the file uses `Signature #N` records with valid `R`, `S`, and `Z` fields. |
| fplll missing during configuration | Install `libfplll-dev` and rerun the CMake configure step. |
| Dashboard output looks frozen or messy | Use `-q` when redirecting output or writing logs. |
| A low-bit-count case stops without an attempt | Increase `--max-time`; expensive BKZ passes are budget-gated. |
| Modulo options are rejected | Supply both options and keep `0 < bound < omega < n`. |
| Linear options are rejected | Supply `--lcg-a` before `--lcg-b`; values must be within the accepted scalar range. |
| Differential test reports a skip | Install the Python `ecdsa` package. |
| Pruning strategy cannot be found | Set `ECDSA_FPLLL_STRATEGY` to the installed `default.json`; unpruned fallback remains available. |
