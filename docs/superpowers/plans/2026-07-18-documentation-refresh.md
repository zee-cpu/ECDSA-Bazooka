# Documentation Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give new users a concise project landing page and give operators a complete, task-oriented command reference.

**Architecture:** `README.md` owns orientation, capability summaries, one quick-start path, practical limits, and repository navigation. `COMMANDS.md` owns prerequisites, every supported build/test/generation/run command, the complete option table, input annotations, cleanup, and troubleshooting. The README change is completed and tested before the command-reference change begins.

**Tech Stack:** GitHub-flavored Markdown, Bash command examples, CMake presets, CTest, C++20 CLI, Python fixture generator

## Global Constraints

- Use short paragraphs, descriptive headings, compact tables, and focused code blocks.
- Use repository-relative commands instead of machine-specific absolute paths.
- Remove numbered headings, stale phase labels, repeated explanations, and claims that are not useful to operating the current code.
- Keep terminology and examples consistent between the two documents.
- Preserve the existing technical meaning and command coverage.
- Do not inspect or modify generated files under `data/`.
- Complete and test `README.md` before modifying `COMMANDS.md`.

---

## File map

- `README.md`: concise landing page for first-time readers.
- `COMMANDS.md`: complete operational and CLI reference.
- `CMakePresets.json`: source of truth for preset names; read-only.
- `CMakeLists.txt`: source of truth for test names and dependency floors; read-only.
- `src/main.cpp`: source of truth for CLI flags, valid methods, validation rules, and defaults; read-only.
- `scripts/generate_mock_signatures.py`: source of truth for fixture-generator options; read-only.

### Task 1: Rewrite the project landing page

**Files:**
- Modify: `README.md`
- Reference: `COMMANDS.md`
- Reference: `CMakePresets.json`
- Reference: `CMakeLists.txt`

**Interfaces:**
- Consumes: the approved document split and current repository-relative executable paths.
- Produces: a short landing page that links to `COMMANDS.md` for operational detail.

- [ ] **Step 1: Run the structural check against the old README**

Run:

```bash
if rg -n '^## (Concurrency|More context)$' README.md; then
  echo 'README still mixes implementation notes into onboarding'
  exit 1
fi
```

Expected: FAIL and print the existing `Concurrency` or `More context` heading.

- [ ] **Step 2: Replace the README with the final landing-page structure**

Use this exact heading order:

```markdown
# ECDSA Nonce-Bias Recovery Tool

## What it handles

## Quick start

## Practical limits

## Testing

## Project layout

## Documentation

## License
```

Apply these exact content rules under the headings:

- Keep the existing CI badge directly below the title.
- Open with two short paragraphs: the first says the program analyzes
  same-key signature sets with structured nonce behavior; the second says
  every candidate is checked against the supplied public key and unsuccessful
  inputs are reported as failures.
- Under `What it handles`, retain one compact table with the six supported
  rows: MSB, LSB, known-offset LSB, modulo/window, repeated nonce, and linear
  sequence. Include distributional skew as an explicitly unsupported row.
- Under `Quick start`, use only this repository-relative workflow:

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

- End the quick start with one sentence linking to `[COMMANDS.md](COMMANDS.md)`.
- Under `Practical limits`, retain the current leak-depth guidance in a table:
  `>= 7` uses LLL and is normally fast; `5-6` uses focused BKZ and needs a
  larger time budget; `4` is best-effort and not guaranteed; `<= 3` is outside
  practical scope. Retain a short modulo-window note and the note that lattice
  reductions run serially because the linked reduction library is not
  thread-safe in this process.
- Under `Testing`, show the exact fast and targeted commands:

  ```bash
  ctest --test-dir build --output-on-failure \
    -R '^(unit_tests|fplll_sanity|cli_validation)$'

  ctest --test-dir build --output-on-failure -R '^ecc_differential$'
  ctest --test-dir build --output-on-failure -R '^e2e_recovery$'
  ```

- Under `Project layout`, use a two-column table for `src/lattice_solver.cpp`,
  `src/bias_profiler.cpp`, `src/recovery_engine.cpp`, `src/verifier.cpp`,
  `src/secp256k1.cpp`, and `tests/`.
- Under `Documentation`, link to `[COMMANDS.md](COMMANDS.md)` and avoid a
  redundant `More context` heading.
- Keep the MIT license sentence and `[LICENSE](LICENSE)` link.
- Do not add a table of contents; the README is intentionally short.

- [ ] **Step 3: Validate the README structure and references**

Run:

```bash
git diff --check -- README.md
test "$(rg -c '^## ' README.md)" -eq 7
! rg -n '^## (Concurrency|More context)$|/home/[^/]+/' README.md
for path in COMMANDS.md LICENSE src/lattice_solver.cpp src/bias_profiler.cpp \
  src/recovery_engine.cpp src/verifier.cpp src/secp256k1.cpp tests; do
  test -e "$path"
done
cmake --list-presets | rg '"release"'
./build/ecdsa_nonce_recovery --help | rg -- '--input FILE'
```

Expected: every command exits 0; the preset check prints `"release"`; the CLI
check prints the input-option line; no machine-specific path is reported.

- [ ] **Step 4: Run the fast regression tests before proceeding**

Run:

```bash
ctest --test-dir build --output-on-failure \
  -R '^(unit_tests|fplll_sanity|cli_validation)$'
```

Expected: `100% tests passed, 0 tests failed out of 3`.

- [ ] **Step 5: Commit the completed README improvement**

```bash
git add README.md
git commit -m "docs: streamline project README"
```

### Task 2: Rewrite the command reference

**Files:**
- Modify: `COMMANDS.md`
- Reference: `README.md`
- Reference: `CMakePresets.json`
- Reference: `CMakeLists.txt`
- Reference: `src/main.cpp`
- Reference: `scripts/generate_mock_signatures.py`

**Interfaces:**
- Consumes: the concise README from Task 1 and current build, test, CLI, and
  generator interfaces.
- Produces: a complete task-oriented reference with no onboarding duplication.

- [ ] **Step 1: Run the stale-format check against the old command reference**

Run:

```bash
if rg -n '^## [0-9]+\.|/home/user/|Phase [0-9]' COMMANDS.md; then
  echo 'COMMANDS.md still contains numbered, machine-specific, or stale labels'
  exit 1
fi
```

Expected: FAIL and print matches from the current file.

- [ ] **Step 2: Replace the command reference with a task-oriented structure**

Use this exact heading order:

```markdown
# Command Reference

## Prerequisites

## Build

### Release build
### Debug build
### Sanitizer build
### Plain CMake build

## Test

### Fast regression tests
### Individual tests
### Complete test preset

## Generate fixtures

### MSB and LSB examples
### Modulo-window example
### Linear-sequence example
### Unstructured example

## Run the program

### Automatic selection
### Select a method
### Provide modulo parameters
### Provide linear parameters
### Limit work

## CLI options

## Optional input annotations

## Expected behavior

## Clean and rebuild

## Troubleshooting
```

Write a one-sentence introduction pointing readers back to
`[README.md](README.md)` for the project overview.

Use this prerequisite command and keep the version table compact:

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

State that CMake 3.16 is the project minimum, CMake 3.21 is required for the
presets, the compiler must support C++20, and the Python `ecdsa` package is
needed only by fixture generation and the differential test. Retain the
`ECDSA_FPLLL_STRATEGY` override note and state that FFTW is not required.

Use these exact build blocks:

```bash
cmake --preset release
cmake --build --preset release -j"$(nproc)"
```

```bash
cmake --preset debug
cmake --build --preset debug -j"$(nproc)"
```

```bash
cmake --preset asan
cmake --build --preset asan -j"$(nproc)"
```

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

List the resulting binaries as `build/ecdsa_nonce_recovery`,
`build/unit_tests`, `build/fplll_sanity_test`, and `build/ecc_diff_tool`.

Use these exact test blocks:

```bash
ctest --test-dir build --output-on-failure \
  -R '^(unit_tests|fplll_sanity|cli_validation)$'
```

```bash
ctest --test-dir build --output-on-failure -R '^unit_tests$'
ctest --test-dir build --output-on-failure -R '^fplll_sanity$'
ctest --test-dir build --output-on-failure -R '^cli_validation$'
ctest --test-dir build --output-on-failure -R '^ecc_differential$'
ctest --test-dir build --output-on-failure -R '^e2e_recovery$'
```

```bash
ctest --preset release
```

Explain that the complete preset includes the slower end-to-end case.

Keep fixture recipes focused and use one command per behavior. The exact
generator options must remain within the live interface:

```bash
python3 scripts/generate_mock_signatures.py \
  --count 800 --bias msb --bias-bits 12 \
  --output data/msb_12b_800.txt --seed 424242

python3 scripts/generate_mock_signatures.py \
  --count 1200 --bias lsb --bias-bits 8 \
  --output data/lsb_8b_1200.txt --seed 777
```

```bash
python3 scripts/generate_mock_signatures.py \
  --count 250 --bias modulo --bias-bits 12 --omega 65536 \
  --output data/modulo_12b.txt --seed 41
```

```bash
python3 scripts/generate_mock_signatures.py \
  --count 40 --bias linear --lcg-a 3 --lcg-b 7 \
  --output data/linear.txt --seed 44
```

```bash
python3 scripts/generate_mock_signatures.py \
  --count 1000 --bias none \
  --output data/unstructured_1k.txt --seed 42
```

State that the generator prints the ground-truth value and, for applicable
modes, the parameters needed by the matching command example.

Use these exact runtime examples:

```bash
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt -q
```

```bash
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt -m lattice -v
./build/ecdsa_nonce_recovery -i data/unstructured_1k.txt -m fallback -v
./build/ecdsa_nonce_recovery -i data/modulo_12b.txt -m modulo -v
./build/ecdsa_nonce_recovery -i data/linear.txt -m linear -v
```

```bash
./build/ecdsa_nonce_recovery -i data/modulo_12b.txt \
  --modulo-omega 65536 --modulo-bound 16 -v
```

```bash
./build/ecdsa_nonce_recovery -i data/linear.txt \
  --lcg-a 3 --lcg-b 7 -v
```

```bash
./build/ecdsa_nonce_recovery -i data/msb_12b_800.txt \
  --max-sigs 500 --max-time 60 --seed 0x1234 -q
```

State the parameter pairing rules: `--modulo-omega` and `--modulo-bound` must
be supplied together; `--modulo-bound` must be smaller; `--lcg-b` requires
`--lcg-a`; decimal and `0x`-prefixed integers are accepted for long-form
parameters where the CLI uses base autodetection.

Use a CLI table with these exact rows and defaults:

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

For `Optional input annotations`, show this exact record shape:

```text
Signature #1
R = ...
S = ...
Z = ...
PubKey: 04...
KnownLow: 8 0xab
```

State that the annotation means `k ≡ 0xab (mod 2^8)`, the width must be from
1 through 64, the value must fit in that width, and malformed or duplicate
annotations cause that record to be rejected. State that exact-constraint
routing requires every usable signature to carry the same width; partial or
mixed-width sets fall back to detection.

Under `Expected behavior`, reuse a compact version of the README limit table
and add rows for modulo windows, repeated values, linear sequences, and
unstructured input. Avoid promises tied to a particular CPU or exact runtime;
use `normally fast`, `can require minutes`, and `best-effort` wording.

Use non-destructive cleanup commands:

```bash
cmake --build --preset release --target clean
cmake --build --preset release -j"$(nproc)"
```

Troubleshooting must cover: no parsed signatures, missing fplll, a dashboard
used through redirected output, insufficient time for low-bit-count cases,
invalid paired parameters, missing Python `ecdsa`, and the pruning-strategy
override. Remove the ground-truth shell-variable comparison and the destructive
full-demo one-liner; both distract from the command reference.

- [ ] **Step 3: Validate the command reference against live interfaces**

Run:

```bash
git diff --check -- COMMANDS.md
! rg -n '^## [0-9]+\.|/home/user/|Phase [0-9]' COMMANDS.md
for heading in Prerequisites Build Test 'Generate fixtures' 'Run the program' \
  'CLI options' 'Optional input annotations' 'Expected behavior' \
  'Clean and rebuild' Troubleshooting; do
  rg -q "^## ${heading}$" COMMANDS.md
done
for path in README.md CMakePresets.json CMakeLists.txt src/main.cpp \
  scripts/generate_mock_signatures.py; do
  test -f "$path"
done
cmake --list-presets | rg '"(release|debug|asan)"'
./build/ecdsa_nonce_recovery --help | rg -- '--method METHOD'
./build/ecdsa_nonce_recovery --help | rg -- '--modulo-omega N'
./build/ecdsa_nonce_recovery --help | rg -- '--lcg-a N'
python3 scripts/generate_mock_signatures.py --help | \
  rg -- '--bias \{msb,lsb,modulo,linear,none\}'
python3 scripts/generate_mock_signatures.py --help | rg -- '--omega OMEGA'
python3 scripts/generate_mock_signatures.py --help | rg -- '--lcg-a LCG_A'
```

Expected: every command exits 0; no stale-format match appears; all three
presets and all selected CLI/generator options are printed.

- [ ] **Step 4: Run the fast regression tests before final integration checks**

Run:

```bash
ctest --test-dir build --output-on-failure \
  -R '^(unit_tests|fplll_sanity|cli_validation)$'
```

Expected: `100% tests passed, 0 tests failed out of 3`.

- [ ] **Step 5: Validate both documents together**

Run:

```bash
git diff --check -- README.md COMMANDS.md
rg -n '^## ' README.md COMMANDS.md
! rg -n '/home/user/|Phase [0-9]|^## [0-9]+\.' README.md COMMANDS.md
git diff --stat -- README.md COMMANDS.md
```

Expected: no whitespace or stale-format errors; the heading listing shows the
approved split; the stat lists only `README.md` and `COMMANDS.md`.

- [ ] **Step 6: Commit the completed command-reference improvement**

```bash
git add COMMANDS.md
git commit -m "docs: reorganize command reference"
```

- [ ] **Step 7: Confirm the final repository state**

Run:

```bash
git status --short
git log -3 --oneline
```

Expected: the two documentation commits are present. The pre-existing
`docs/superpowers/plans/2026-07-17-recovery-reliability-hardening.md` may remain
untracked and must not be added to either commit.
