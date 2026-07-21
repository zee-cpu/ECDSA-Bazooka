"""Signs biased nonces and emits the .txt wire format + sidecar labels.

build_case(family, params, count, seed) is the single entry point. Determinism:
one random.Random(seed) drives d, every message hash z, and every nonce draw, in
a fixed order, so regeneration is byte-identical.
"""
import hashlib
import random

from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod

from fixtures import primitives

CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

def sign(d, z, k):
    r = (k * G).x() % N or 1
    s = (inverse_mod(k, N) * (z + r * d)) % N or 1
    return r, s

def pubkey_hex(d):
    P = d * G
    raw = b"\x04" + P.x().to_bytes(32, "big") + P.y().to_bytes(32, "big")
    return format(int.from_bytes(raw, "big"), "x").zfill(130)

def _block(idx, r, s, z, pub_hex, txid, ts):
    return (
        f"Signature #{idx}\n"
        f"R = {r:x}\n"
        f"S = {s:x}\n"
        f"Z = {z:x}\n"
        f"PubKey: {pub_hex}\n"
        f"TXID: {txid}\n"
        f"Timestamp: {ts}\n"
    )

def _default_params():
    return {"omega": None, "bound": None, "outlier_frac": 0.0, "reuse_groups": 0}

def _nonces_uniform(family, params, count, rng):
    """Return a list of (k, label) for the families whose every nonce shares one
    shape. Set-level families (mixed/noisy/partial_reuse) override this."""
    out = []
    for _ in range(count):
        if family == "contiguous_msb":
            out.append(primitives.contiguous_msb(params["L"], rng))
        elif family == "contiguous_lsb":
            out.append(primitives.contiguous_lsb(params["L"], rng))
        elif family == "modulo":
            out.append(primitives.modulo_window(params["omega"], params["bound"], rng))
        elif family == "fragmented":
            out.append(primitives.fragmented(params["windows"], rng))
        else:
            raise NotImplementedError(f"set-level family '{family}' arrives in Task 3")
    return out

def _build_nonces(family, params, count, rng):
    # Task 3 replaces this dispatch with mixed/noisy/partial_reuse branches.
    return _nonces_uniform(family, params, count, rng)

def build_case(family, params, count, seed):
    rng = random.Random(seed)
    d = rng.randrange(1, N)
    pub_hex = pubkey_hex(d)
    base_ts = 1_600_000_000

    nonces = _build_nonces(family, params, count, rng)

    blocks, sig_labels = [], []
    for i, (k, label) in enumerate(nonces, start=1):
        z = rng.getrandbits(256)
        r, s = sign(d, z, k)
        txid = hashlib.sha256(f"{seed}-{i}".encode()).hexdigest()
        blocks.append(_block(i, r, s, z, pub_hex, txid, base_ts + i * 60))
        rec = {"index": i}
        rec.update(label)
        sig_labels.append(rec)

    out_params = _default_params()
    if family == "modulo":
        out_params["omega"] = params["omega"]
        out_params["bound"] = params["bound"]

    sidecar = {
        "schema_version": 1,
        "case": params.get("_name", f"{family}_{count}"),
        "curve": "secp256k1",
        "private_key": hex(d),
        "pubkey_uncompressed": pub_hex,
        "seed": seed,
        "count": count,
        "composition": {"family": family, "params": out_params},
        "signatures": sig_labels,
    }
    return "\n".join(blocks), sidecar
