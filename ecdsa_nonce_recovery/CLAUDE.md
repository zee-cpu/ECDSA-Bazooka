# ECDSA Nonce-Bias Recovery Tool

Read `HANDOFF.md` first, in full, before doing any work. It has the complete
history, what's validated, and what's currently blocked. Don't ask the user
to re-explain any of this -- it's all in that file.

## Critical: don't read files in data/ or /tmp/*.txt

`data/*.txt` and any `/tmp/test_*.txt` are generated signature fixtures --
each one is thousands of lines of hex-encoded signature data. They are
**inputs to the compiled binary**, not something to read as text. Never
`cat`, `view`, or otherwise read one into context. If you need to inspect
a file's *format*, use `head -8 path/to/file.txt` (just the header of one
signature) -- never the whole file.

To create test data, run the generator, don't read its output:
```
python3 scripts/generate_mock_signatures.py --count 500 --bias msb --bias-bits 12 \
  --output /tmp/test.txt --seed 1
```
It prints the ground-truth private key to stdout -- capture that, don't
read it back out of the file.

## Build

```
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
```

## Fast tests first, always

```
./build/unit_tests          # <1 second, run this after every change
```
Only run the full e2e suite (`ctest -R e2e_recovery`, ~5 minutes) once
unit tests pass and you believe the change is solid -- it's expensive.

## Commands reference

See `COMMANDS.md` for CLI flags.

## Style

Comments in this codebase explain *why*, especially around anything that
was previously buggy (there's a lot of history -- read the comment before
"simplifying" something that looks odd). Match that style: when you fix
something non-obvious, explain why the old version was wrong in a comment,
not just what the new code does.
