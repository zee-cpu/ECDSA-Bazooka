"""Per-nonce leak shapes for the fixture corpus.

Each function returns (k, label) where `label` is the per-signature record of
the sidecar schema. No signing, no I/O -- these are pure nonce shapers. Bit 0
is the LSB; a window [lo, hi) is a half-open range of forced-zero bit positions.
"""
from ecdsa import SECP256k1

N = SECP256k1.order
BITS = 256

def _label(k, structure, windows):
    return {
        "nonce": hex(k),
        "structure": structure,
        "leaked_bits": sum(hi - lo for lo, hi in windows),
        "zero_windows": [[lo, hi] for lo, hi in windows],
        "reuse_group": None,
        "shared_window": None,
        "is_outlier": False,
    }

def _from_windows(windows, structure, rng):
    k = rng.randrange(1, N)
    for lo, hi in windows:
        for b in range(lo, hi):
            k &= ~(1 << b)
    if k == 0:            # degenerate; astronomically unlikely with free high bits
        k = 1
    return k, _label(k, structure, windows)

def contiguous_msb(L, rng):
    return _from_windows([(BITS - L, BITS)], "msb", rng)

def contiguous_lsb(L, rng):
    return _from_windows([(0, L)], "lsb", rng)

def modulo_window(omega, bound, rng):
    a = omega.bit_length() - 1
    c = bound.bit_length() - 1
    return _from_windows([(c, a)], "modulo", rng)

def fragmented(windows, rng):
    return _from_windows([tuple(w) for w in windows], "fragmented", rng)

def clean(rng):
    k = rng.randrange(1, N)
    return k, _label(k, "clean", [])
