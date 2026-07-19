# ECDSA Nonce-Bias Recovery Tool

[![CI](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml/badge.svg)](https://github.com/zee-cpu/ECDSA-Bazooka/actions/workflows/ci.yml)

Recovers an ECDSA private key from signatures whose nonces have an exploitable
structure (biased high bits, reused nonces, modular windows, or linear/LCG
relations). Every candidate is verified against the public key, so it reports
failure rather than a wrong key.

## Quickstart

**Native:**
```bash
sudo apt-get install -y cmake g++ libgmp-dev libgmpxx4ldbl libfplll-dev
cmake --preset release && cmake --build --preset release -j"$(nproc)"
python3 scripts/generate_mock_signatures.py --count 500 --bias msb --bias-bits 12 \
  --output data/demo.txt --seed 1
./build/ecdsa_nonce_recovery -i data/demo.txt -q
```

**Docker (everything prebuilt, incl. the sieve):**
```bash
docker run --rm -v "$PWD/data:/data" ghcr.io/zee-cpu/ecdsa-bazooka -i /data/demo.txt -q
```

## Which case are you in?

| Your situation | What to do | What to expect |
|---|---|---|
| 7+ known nonce bits | just run it | fast (LLL) |
| 4–6 bits | just run it | give it a time budget (`--max-time`) |
| 3 bits | sieve route (setup below) | minutes; one-time setup |
| 2 bits | sieve route, on a server | tens of GB RAM, days |
| reused nonce / modulo window / LCG nonces | just run it | closed-form, instant |

Not sure of the cost? `./build/ecdsa_nonce_recovery --dry-run --leaked-bits 2`
prints the RAM/time estimate for your machine (no setup needed).

## Deep leakage (L ≤ 3): the sieve route

The 2-3 bit cases need lattice sieving (g6k). Set it up once:

```bash
worker/bootstrap.sh                    # detects/builds g6k, writes worker/sieve-env.sh
./build/ecdsa_nonce_recovery --check   # confirms the sieve route is ready
./build/ecdsa_nonce_recovery -i data/leak.txt --method sieve --leaked-bits 3
```

Or just use the Docker image, which has it prebuilt. The tool shows the cost
estimate and warns before a heavy run; it never blocks you.

## More

- [COMMANDS.md](COMMANDS.md) — full CLI, options, fixtures, troubleshooting.
- [worker/README.md](worker/README.md) — sieve worker internals and bootstrap.

## License

Released under the GNU General Public License, version 2. See [LICENSE](LICENSE).

The sieving recovery path links G6K and fpylll (both GPL-2.0); the project is
therefore distributed under GPL-2.0. Earlier releases were MIT — this project
was relicensed to GPL-2.0 to permit that linkage. Copyright (c) 2026 zee-cpu.
