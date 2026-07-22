# ECDSA Nonce-Bias Recovery Tool

[![CI](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml/badge.svg)](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml)

Recovers an ECDSA (secp256k1) private key from a set of signatures whose nonces
have an exploitable structure — biased high or low bits, reused nonces, modular
windows, linear/LCG relations, a shared unknown nonce prefix, or the same
structure hidden among unbiased outliers. **Every candidate is verified against
the public key, so the tool reports failure rather than ever emitting a wrong
key.**

## What it can recover

The default `auto` mode tries the applicable routes in cost order and stops at
the first *verified* key. No flags are needed to reach any of them.

| Route | Structure it exploits | Cost |
|---|---|---|
| **Reused nonce** | two signatures share `r` (same `k`) | closed-form, instant |
| **Linear / LCG nonces** | `k_{i+1} = a·k_i + b (mod n)`, known or unknown `a,b` | closed-form, instant |
| **MSB / LSB lattice** | biased high or low nonce bits (Boneh–Venkatesan HNP) | LLL/BKZ; fast at 7+ bits |
| **Modulo / Extended-HNP** | windowed nonces, `k mod ω < bound` | two-block lattice |
| **Shared-prefix reuse** | a group sharing a fixed *unknown* nonce high-part | differenced HNP |
| **Outlier-robust (RANSAC)** | biased signatures mixed with unbiased noise | resampled lattice |
| **Deep MSB sieve** | very weak leakage (`L ≤ 3`), past the lattice barrier | sieving-with-predicate (g6k) |

When statistical detection finds nothing, `auto` still runs a pubkey-gated
**last-resort ladder** (shared-prefix reuse → RANSAC resampling → blind modulo
sweep → speculative sieve) before giving up, so structure that no profiler
flagged is still attempted. Recovery thoroughness is favored over speed; bound a
run with `--max-time` when you need to.

## No route is silently skipped

Every run ends with an audit of what each recovery route did — attempted,
skipped (with the reason), recovered, or not reached — so a "no key" result is
always explainable:

```
Routes attempted/skipped:
  repeated-nonce  attempted  no candidate
  lcg             attempted  no candidate
  dispatch        RECOVERED  LATTICE
  Remaining routes not attempted (already recovered).
```

## Quickstart

**Native:**
```bash
sudo apt-get install -y cmake g++ libgmp-dev libgmpxx4ldbl libfplll-dev libmpfr-dev
cmake --preset release && cmake --build --preset release -j"$(nproc)"
python3 scripts/generate_mock_signatures.py --count 500 --bias msb --bias-bits 12 \
  --output data/demo.txt --seed 1
./build/ecdsa_nonce_recovery -i data/demo.txt -v
```

**Docker (everything prebuilt, including the sieve):**
```bash
docker run --rm -v "$PWD/data:/data" ghcr.io/zee-cpu/ecdsa-bazooka -i /data/demo.txt -v
```

`-v` shows the live telemetry dashboard; omit it for plain, log-friendly
output. The final result — including the route audit — prints in both modes.

## Which case are you in?

| Your situation | What to do | What to expect |
|---|---|---|
| reused nonce / LCG nonces | just run it | closed-form, instant |
| 7+ biased nonce bits | just run it | fast (LLL) |
| 4–6 bits | just run it | give it a time budget (`--max-time`) |
| modulo window / shared prefix | just run it | lattice, no hint needed |
| biased data with unbiased noise | just run it | RANSAC resampling (light–moderate noise) |
| 3 bits | sieve route (setup below) | minutes; one-time setup |
| 2 bits | sieve route, on a server | tens of GB RAM, days |

Unsure of the cost? `./build/ecdsa_nonce_recovery --dry-run --leaked-bits 2`
prints a RAM/time estimate for your machine (no setup needed), and
`./build/ecdsa_nonce_recovery --check` reports which routes are ready.

## Deep leakage (L ≤ 3): the sieve route

The 2–3 bit cases are past what plain LLL/BKZ can reach and need lattice sieving
(g6k). Set it up once:

```bash
worker/bootstrap.sh                    # detects/builds g6k, writes worker/sieve-env.sh
./build/ecdsa_nonce_recovery --check   # confirms the sieve route is ready
./build/ecdsa_nonce_recovery -i data/leak.txt --method sieve --leaked-bits 3
```

Or just use the Docker image, which has it prebuilt. The tool prints the cost
estimate and warns before a heavy run; it never blocks you.

## How it works

- **One routing decision path.** All route selection and escalation lives in a
  single planner + executor (`src/route_planner.cpp`): closed-form pre-scans, a
  profile-driven lattice/sieve dispatch with an MSB↔LSB retry, and the
  last-resort ladder. A public key present at the input is the correctness gate
  at every step.
- **Safe parallelism.** fplll mutates process-global precision state, so lattice
  reductions run strictly serially *per process*; parallelism (e.g. RANSAC
  trials) uses fork-based process isolation, never threads.
- **Verified-only results.** A recovered key is emitted only after it passes the
  standard ECDSA equation check against the signatures (and the public key when
  present). Without a public key, `--allow-no-pubkey` enables an explicitly
  best-effort mode whose result is labeled unverified.

## Limitations

- Weaker leakage costs more: 4-bit lattice cases can take minutes, and the 2-bit
  sieve regime needs a large server (tens of GB RAM, potentially days).
- Heavy contamination (majority-outlier / sparse-needle sets) can exhaust the
  RANSAC budget without recovering — it fails cleanly, never with a wrong key.
- The sieve route requires a public key (the predicate *is* the pubkey check)
  and a one-time g6k setup, or the Docker image.
- secp256k1 only.

## More

- [COMMANDS.md](COMMANDS.md) — full CLI, build/test presets, fixtures, troubleshooting.
- [worker/README.md](worker/README.md) — sieve worker internals and bootstrap.

## License

Released under the GNU General Public License, version 2 — see [LICENSE](LICENSE).
The sieving recovery path links G6K and fpylll (both GPL-2.0), so the project is
distributed under GPL-2.0. Copyright (c) 2026 zee-cpu.
