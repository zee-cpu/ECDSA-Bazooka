#!/usr/bin/env python3
"""M1: measure the norm-rank at which the verified key is found, over the FAST
MSB/LSB corpus (the cases this single-block lattice path is believed to solve).

Runs on the PUBKEY path (fixtures ship a PubKey), which is uncapped and does not
read TOP_N_ROWS -- so this measures WHERE the answer lands, i.e. how deep harvest
must reach. Evidence that informs TOP_N_ROWS; not proof (see M2)."""
import os, re, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import catalog, runner

BINARY = os.environ.get("BAZOOKA_BINARY")
if not (BINARY and os.path.exists(BINARY)):
    sys.exit("set BAZOOKA_BINARY to the built ecdsa_nonce_recovery")

# MSB/LSB FAST cases only -- the path this item targets, that resolve quickly.
SOLVABLE = [c for c in catalog.CASES
            if c.tag == "FAST" and c.family in ("contiguous_msb", "contiguous_lsb")]

ranks = []
with tempfile.TemporaryDirectory() as td:
    for case in SOLVABLE:
        txt_path, _ = runner.write_case(case, Path(td))
        try:
            # NOTE: the brief's literal "-t 1" (a 1s internal --max-time budget)
            # was verified to force every FAST case to FAILURE before the lattice
            # search could finish (observed runtimes 2-23s) -- an internal-cap bug,
            # not a real MISS. Use a generous internal budget (170s) so the search
            # runs to completion, while the outer subprocess timeout (180s) still
            # bounds genuinely slow cases (e.g. msb_L4_500) as a TIMEOUT/MISS.
            proc = subprocess.run([BINARY, "-i", str(txt_path), "-q", "-t", "170"],
                                  capture_output=True, text=True, timeout=180)
            out = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            out = ""
            print(f"{case.name:32s} TIMEOUT")
            continue
        d = re.search(r"d = 0x([0-9a-fA-F]+)", out)
        rank = re.search(r"Norm-rank:\s*(-?\d+)\s*/\s*(\d+)", out)
        status = "MISS"
        if d and rank:
            ranks.append(int(rank.group(1)))
            status = f"rank={rank.group(1)}/{rank.group(2)}"
        print(f"{case.name:32s} {status}")

if ranks:
    print(f"\nrecovered {len(ranks)}/{len(SOLVABLE)} | "
          f"min={min(ranks)} max={max(ranks)} "
          f"-> TOP_N_ROWS must exceed {max(ranks)} (add margin)")
else:
    print("\nNO recoveries -- investigate before setting TOP_N_ROWS")
