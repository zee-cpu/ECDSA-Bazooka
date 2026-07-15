#!/usr/bin/env python3
"""
Mock ECDSA Signature Generator for Nonce-Bias Key Recovery Engine.
Produces files in exact project-specified format.

Usage:
  python generate_mock_signatures.py \
      --count 2000 \
      --bias msb \
      --bias-bits 16 \
      --output data/test_msb_16b_2k.txt \
      --privkey 0x123... (optional)

Bias modes:
  msb     : top N bits biased toward 0 (k < 2^(256 - bias_bits))
  lsb     : bottom N bits fixed to 0 (k % 2**bias_bits == 0)
  modulo  : k mod Omega in [0, bound)   (Omega = 2**bias_bits typically)
  none    : full uniform random k

Prints ground-truth d at end for verification.
"""

import argparse
import hashlib
import os
import random
import sys
import time
from typing import Optional, Tuple

try:
    from ecdsa import SigningKey, SECP256k1
    from ecdsa.ellipticcurve import Point
    from ecdsa.numbertheory import inverse_mod
except ImportError:
    print("ERROR: ecdsa not installed. Run: pip install ecdsa", file=sys.stderr)
    sys.exit(1)

# secp256k1 parameters
CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order  # curve order n
P = CURVE.curve.p  # field prime

def int_to_hex(i: int, width: Optional[int] = None) -> str:
    """Convert int to lowercase hex without 0x prefix, optional zero-pad."""
    h = hex(i)[2:].lower()
    if width:
        h = h.zfill(width)
    return h

def generate_random_z() -> int:
    """Generate a random 256-bit message hash z."""
    return random.getrandbits(256)

def compute_k_biased(bias_mode: str, bias_bits: int, omega: Optional[int] = None) -> int:
    """
    Generate biased nonce k according to mode and magnitude.
    Returns k in [1, n-1].
    """
    if bias_mode == "none":
        k = random.randint(1, N - 1)
        return k

    if bias_mode == "msb":
        # Top 'bias_bits' bits are zero: k < 2^(256 - bias_bits)
        max_k = (1 << (256 - bias_bits)) - 1
        k = random.randint(1, min(max_k, N - 1))
        return k

    if bias_mode == "lsb":
        # Bottom 'bias_bits' bits fixed to 0 (predictable)
        step = 1 << bias_bits
        # Choose random multiple of step, in range
        max_mult = (N - 1) // step
        mult = random.randint(0, max_mult)
        k = mult * step
        if k == 0:
            k = step
        if k >= N:
            k -= step
        return k % N or step

    if bias_mode == "modulo":
        # k mod Omega is in [0, bound)
        # bias_bits typically gives Omega = 2**bias_bits or similar
        if omega is None:
            omega = 1 << bias_bits
        bound = max(1, omega // (1 << max(0, 8)))  # heuristic, e.g. bound ~16 for ~8 bits
        # but allow override via bias_bits meaning leaked bits
        # For simplicity, use bound = max(1, 1 << (bias_bits // 2)) or fixed
        # Project example: period Omega=4096, bound=16 (~8 leaked bits)
        # Here bias_bits is 'leaked bits' so bound ~ omega / 2**bias_bits
        if omega is None:
            omega = 1 << 12   # default 4096 for modulo example
        bound = max(2, omega >> bias_bits)  # approx leaked
        if bound >= omega:
            bound = omega // 2
        k_mod = random.randint(0, bound - 1)
        # pick random multiple
        max_m = (N - 1) // omega
        m = random.randint(0, max_m)
        k = m * omega + k_mod
        if k == 0:
            k = k_mod or 1
        return k % N or 1

    raise ValueError(f"Unknown bias_mode: {bias_mode}")

def sign_with_biased_k(d: int, z: int, k: int) -> Tuple[int, int, int, int]:
    """
    Compute ECDSA signature with a given (biased) nonce k.
    Returns (r, s, z, pubkey_int) where pubkey_int is the uncompressed pubkey int.
    """
    # r = (k * G).x mod n
    kG = k * G
    r = kG.x() % N
    if r == 0:
        # retry not needed in practice for mock
        r = 1

    # s = k^{-1} * (z + r * d) mod n
    kinv = inverse_mod(k, N)
    s = (kinv * (z + (r * d) % N)) % N
    if s == 0:
        s = 1

    # pubkey = d * G
    pub_point = d * G
    pubkey_x = pub_point.x()
    pubkey_y = pub_point.y()
    # uncompressed: 0x04 || x(32B) || y(32B)
    pubkey_bytes = b'\x04' + pubkey_x.to_bytes(32, 'big') + pubkey_y.to_bytes(32, 'big')
    pubkey_int = int.from_bytes(pubkey_bytes, 'big')

    return r, s, z, pubkey_int

def format_signature_block(idx: int, r: int, s: int, z: int, pubkey_int: int, txid: str, ts: int) -> str:
    """Format exactly to project spec."""
    r_hex = int_to_hex(r)
    s_hex = int_to_hex(s)
    z_hex = int_to_hex(z)
    pub_hex = int_to_hex(pubkey_int)
    # Ensure pubkey is always 130 hex chars (04 + 128)
    pub_hex = pub_hex.zfill(130)

    block = f"""Signature #{idx}
R = {r_hex}
S = {s_hex}
Z = {z_hex}
PubKey: {pub_hex}
TXID: {txid}
Timestamp: {ts}
"""
    return block

def main():
    parser = argparse.ArgumentParser(description="Generate biased ECDSA signature mock data.")
    parser.add_argument("--count", type=int, default=2000, help="Number of signatures")
    parser.add_argument("--bias", choices=["msb", "lsb", "modulo", "none"], default="msb",
                        help="Bias type")
    parser.add_argument("--bias-bits", type=int, default=16,
                        help="Bias magnitude in bits (leaked bits estimate)")
    parser.add_argument("--output", type=str, default="data/mock_signatures.txt",
                        help="Output .txt file path")
    parser.add_argument("--privkey", type=str, default=None,
                        help="Optional hex private key (without 0x). If omitted, random.")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--omega", type=int, default=None, help="For modulo mode: period")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # Determine private key d
    if args.privkey:
        d = int(args.privkey, 16)
        if not (1 <= d < N):
            print("ERROR: privkey out of range", file=sys.stderr)
            sys.exit(1)
    else:
        d = random.randint(1, N - 1)

    print(f"[+] Generating {args.count} signatures with bias='{args.bias}' (magnitude ~{args.bias_bits} bits)")
    print(f"[+] Private key (ground truth): {hex(d)}")
    print(f"[+] Output: {args.output}")

    # Derive pubkey once for logging
    pub_point = d * G
    pub_x = hex(pub_point.x())[2:].zfill(64)
    pub_y = hex(pub_point.y())[2:].zfill(64)
    print(f"[+] PubKey (uncompressed): 04{pub_x}{pub_y}")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    signatures = []
    for i in range(1, args.count + 1):
        z = generate_random_z()
        k = compute_k_biased(args.bias, args.bias_bits, args.omega)
        r, s, z, pubkey_int = sign_with_biased_k(d, z, k)

        # metadata
        txid = hashlib.sha256(f"tx-{i}-{int(time.time())}".encode()).hexdigest()
        ts = int(time.time()) - random.randint(0, 86400 * 365)

        block = format_signature_block(i, r, s, z, pubkey_int, txid, ts)
        signatures.append(block)

        if i % max(1, args.count // 10) == 0:
            print(f"  ... generated {i}/{args.count}")

    with open(args.output, "w") as f:
        f.write("\n".join(signatures))

    print(f"\n[+] Wrote {args.count} signatures to {args.output}")
    print(f"[+] Ground-truth private key (exact for verification): {hex(d)}")
    print("[+] Done.")

if __name__ == "__main__":
    main()
