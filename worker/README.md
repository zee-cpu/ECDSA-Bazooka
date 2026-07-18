# Sieve-with-predicate worker

External worker for the deep-MSB-leakage (`L <= 3`) recovery route, which plain
LLL/BKZ cannot reach (the "lattice barrier"). The main C++ tool spawns this as a
subprocess when it routes to `RecoveryMethod::SIEVE`; the worker runs G6K's
sieving-with-predicate (Albrecht–Heninger) and returns the recovered key.

It is a **separate process** on purpose: G6K/fpylll are GPL-2.0 (hence this
project is GPL-2.0), keep global state that wants process isolation, and cannot
be interrupted mid-call, so the parent enforces timeouts by killing the child.

## Quick setup

One command does the whole Tier-2 setup (find/build a G6K Python, clone
bdd-predicate, install deps, build the shim, write the env file, self-check):

```bash
worker/bootstrap.sh                 # uses a G6K Python already on PATH
# or, if you don't have G6K yet (slow, builds from source):
worker/bootstrap.sh --build-g6k --max-sieving-dim 192   # 192 needed for L=2

source worker/sieve-env.sh          # exports the env vars below
./build/ecdsa_nonce_recovery -i data/leak.txt --method sieve --leaked-bits 2
```

The manual steps are documented in the rest of this file; the bootstrap just
chains them.

## Layout

| File | Role |
|---|---|
| `worker.py` | `SieveWorker`: Sage-free HNP basis + predicate + key recovery; reuses `usvp.usvp_pred_solve`. Non-uniform (per-signature) klen supported. |
| `worker_cli.py` | subprocess entry point: reads a JSON spec on stdin, prints the recovered key hex (or `FAIL`). |
| `predicate_shim.py` | cffi loader for `libbazooka_predicate.so` (the C pubkey check). |
| `ecdsa_fixture.py` | test-only instance generator. |
| `build_shim.sh` | standalone build of the shim `.so` (CMake target `bazooka_predicate` is preferred). |
| `test_worker.py`, `test_predicate_shim.py` | pytest suites. |

## Dependencies (not vendored)

- **G6K + fpylll + fplll** — build once into a Python env (use G6K's `bootstrap.sh`).
  For `L = 2` (sieve dim 131) rebuild G6K with `--with-max-sieving-dim=192`.
- **bdd-predicate** (upstream, `github.com/malb/bdd-predicate`) — only `usvp.py`
  is used (Sage-free). Clone it and point `BDD_PREDICATE_DIR` at it; the default
  is `third_party/bdd-predicate` under the repo (gitignored).
- Python: `cffi`, `ecdsa`.

## Build the shim

```bash
cmake --preset release && cmake --build --preset release --target bazooka_predicate
# or, without CMake:  ./worker/build_shim.sh
```

The loader searches `$BAZOOKA_PREDICATE_SO`, then `build/`, then `worker/build/`.

## How the C++ tool calls it

The tool spawns `$BAZOOKA_SIEVE_PYTHON $BAZOOKA_SIEVE_WORKER < spec.json`:

| Env var | Meaning | Default |
|---|---|---|
| `BAZOOKA_SIEVE_WORKER` | path to `worker_cli.py` | (required) |
| `BAZOOKA_SIEVE_PYTHON` | interpreter with G6K available | `python3` |
| `BDD_PREDICATE_DIR` | bdd-predicate checkout | `third_party/bdd-predicate` |
| `BAZOOKA_PREDICATE_SO` | shim `.so` override | search `build/`, `worker/build/` |

Spec on stdin: `{"pubkey": "<x||y hex, opt 04 prefix>", "signatures": [[klen,
h_hex, r_hex, s_hex], ...], "solver": "sieve_pred"}`. `klen` is per signature
(= `256 - leaked_bits`), so non-uniform / fractional-average leakage is exact.

Example:

```bash
export BAZOOKA_SIEVE_WORKER="$PWD/worker/worker_cli.py"
export BAZOOKA_SIEVE_PYTHON=/path/to/python-with-g6k
./build/ecdsa_nonce_recovery -i data/leak.txt --method sieve --leaked-bits 2
```

## Tests

```bash
cd worker && python -m pytest -q      # needs G6K, bdd-predicate, and the shim built
```
