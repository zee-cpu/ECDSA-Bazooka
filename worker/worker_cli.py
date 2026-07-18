#!/usr/bin/env python3
"""Subprocess seam for the sieve worker.

The C++ tool spawns this, writes a JSON problem spec on stdin, and reads the
recovered private key (lowercase hex, no 0x) on stdout. On failure it prints
FAIL and exits non-zero. This is a batch operation: no interactive timeouts
here -- the parent enforces --max-time by killing the child.

Spec (stdin JSON):
  {
    "pubkey": "<x||y hex, optionally 04-prefixed uncompressed SEC1>",
    "signatures": [[klen, h_hex, r_hex, s_hex], ...],   # h/r/s hex, no 0x
    "solver": "sieve_pred"                               # optional
  }
"""
import json
import sys

from worker import SieveWorker


def _normalize_pubkey(pk):
    pk = pk.strip().lower()
    if len(pk) == 130 and pk.startswith("04"):
        pk = pk[2:]
    if len(pk) != 128:
        raise ValueError("pubkey must be uncompressed x||y (128 hex, optional 04 prefix)")
    return pk


def main():
    spec = json.load(sys.stdin)
    pubkey_hex = _normalize_pubkey(spec["pubkey"])
    signatures = [
        (int(klen), int(h, 16), int(r, 16), int(s, 16))
        for (klen, h, r, s) in spec["signatures"]
    ]
    solver = spec.get("solver", "sieve_pred")

    worker = SieveWorker(signatures, pubkey_hex)
    d = worker.solve(solver=solver, use_c_predicate=True)

    if d is None:
        print("FAIL")
        return 1
    print("%x" % d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
