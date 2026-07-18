"""Generate ECDSA-with-biased-nonce test instances, Sage-free.

Nonces are drawn with the top `leaked_bits` MSBs forced to zero (k < 2**(256-L)),
the MSB-leakage model the sieve worker targets. `leaked_bits` may be fractional
(e.g. 2.5): the average leakage is realized as a per-signature mix of the two
bracketing integer nonce lengths (make_klen_list distribution).
"""
import math
import random
from dataclasses import dataclass, field

from ecdsa import SECP256k1

G = SECP256k1.generator
N = SECP256k1.order


def make_klen_list(klen, m):
    """Per-signature nonce bit lengths whose average is `klen`. Integer klen ->
    uniform; fractional -> a mix of floor(klen) and ceil(klen)."""
    if float(klen).is_integer():
        return [int(klen)] * m
    nz = int(round((math.ceil(klen) - klen) * m))
    return [math.floor(klen)] * nz + [math.ceil(klen)] * (m - nz)


@dataclass
class Instance:
    d: int                      # private key
    pubkey_hex: str             # x||y, 64 hex chars each
    signatures: list            # list of (klen, h, r, s)
    nonces: list                # true nonces (test/ground-truth only)
    leaked_bits: int
    n: int = N
    G: object = field(default_factory=lambda: G)


def generate_instance(leaked_bits, m, seed=0):
    rng = random.Random(seed)
    d = rng.randrange(1, N)
    # Per-signature nonce bit lengths (average = 256 - leaked_bits). Shuffle so
    # the two lengths are interleaved rather than blocked, mirroring real data.
    klen_list = make_klen_list(256 - leaked_bits, m)
    rng.shuffle(klen_list)

    signatures, nonces = [], []
    i = 0
    while len(signatures) < m:
        klen = klen_list[i]
        k = rng.randrange(1, 2 ** klen)
        R = k * G
        r = R.x() % N
        if r == 0:
            continue
        h = rng.randrange(1, N)
        s = pow(k, -1, N) * (h + r * d) % N
        if s == 0:
            continue
        signatures.append((klen, h, r, s))
        nonces.append(k)
        i += 1

    P = d * G
    pubkey_hex = "%064x%064x" % (P.x(), P.y())
    return Instance(
        d=d,
        pubkey_hex=pubkey_hex,
        signatures=signatures,
        nonces=nonces,
        leaked_bits=leaked_bits,
    )
