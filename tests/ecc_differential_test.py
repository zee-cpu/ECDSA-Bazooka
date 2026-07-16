#!/usr/bin/env python3
"""Differential test (Phase 4): cross-check this project's hand-rolled
secp256k1 point arithmetic against the trusted `ecdsa` library.

For a set of edge-case and random private scalars d, compute d*G two ways --
via the C++ `ecc_diff_tool` shim (this project's implementation) and via the
`ecdsa` library -- and assert the uncompressed public keys match exactly. This
catches any discrepancy in point_add / point_double / scalar_mult that unit
invariants alone might miss.

Usage: ecc_differential_test.py <path-to-ecc_diff_tool>
Exits nonzero on any mismatch.
"""
import secrets
import subprocess
import sys

try:
    from ecdsa import SigningKey, SECP256k1
except ImportError:
    print("SKIP: python `ecdsa` library not installed (pip install ecdsa)")
    sys.exit(0)  # skip rather than fail if the reference lib is unavailable

N = SECP256k1.order


def ref_pubkey(d: int) -> str:
    """Uncompressed SEC1 pubkey (04||X||Y, lowercase hex) of d*G per `ecdsa`."""
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    return "04" + sk.get_verifying_key().to_string().hex()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: ecc_differential_test.py <ecc_diff_tool>")
        return 2
    tool = sys.argv[1]

    # Edge cases first, then random scalars across the whole [1, n-1] range.
    edge = [1, 2, 3, 7, 8, 0x1000, 1 << 128, 1 << 200, 1 << 255,
            N - 1, N - 2, N - 3, N >> 1]
    rand = [secrets.randbelow(N - 1) + 1 for _ in range(250)]
    ds = edge + rand

    inp = "".join(format(d, "x") + "\n" for d in ds)
    proc = subprocess.run([tool], input=inp, capture_output=True,
                          text=True, timeout=180)
    if proc.returncode != 0:
        print(f"FAIL: tool exited {proc.returncode}\n{proc.stderr}")
        return 1

    got = proc.stdout.split()
    if len(got) != len(ds):
        print(f"FAIL: expected {len(ds)} outputs, got {len(got)}")
        return 1

    fails = 0
    for d, g in zip(ds, got):
        exp = ref_pubkey(d).lower()
        if g.lower() != exp:
            fails += 1
            if fails <= 5:
                print(f"MISMATCH d={hex(d)}\n  ref={exp}\n  got={g}")

    if fails:
        print(f"=== ecc differential: {fails}/{len(ds)} MISMATCH ===")
        return 1
    print(f"=== ecc differential: {len(ds)}/{len(ds)} match "
          f"({len(edge)} edge + {len(rand)} random d*G vs `ecdsa` library) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
