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
            raise ValueError(f"unknown uniform family {family}")
    return out

def _mixed(params, count, rng):
    out = []
    if params["mode"] == "msblsb":
        L = params["L"]
        for i in range(count):
            if i < count // 2:
                out.append(primitives.contiguous_msb(L, rng))
            else:
                out.append(primitives.contiguous_lsb(L, rng))
    elif params["mode"] == "strength":
        for _ in range(count):
            L = rng.randint(params["lo"], params["hi"])
            out.append(primitives.contiguous_msb(L, rng))
    else:
        raise ValueError(f"unknown mixed mode {params['mode']}")
    return out

def _noisy(params, count, rng):
    n_out = round(params["outlier_frac"] * count)
    out = []
    for i in range(count):
        if i < n_out:
            k, label = primitives.clean(rng)
            label["is_outlier"] = True
        else:
            k, label = primitives.contiguous_msb(params["L"], rng)
        out.append((k, label))
    return out

def _partial_reuse(params, count, rng):
    out = [primitives.clean(rng) for _ in range(count)]   # clean background
    if params["mode"] == "full":
        groups, size = params["groups"], params["group_size"]
        idx = 0
        for g in range(groups):
            shared_k = rng.randrange(1, N)
            for _ in range(size):
                _, label = primitives.clean(rng)   # advance rng identically
                label = {
                    "nonce": hex(shared_k), "structure": "reuse", "leaked_bits": 0,
                    "zero_windows": [], "reuse_group": g,
                    "shared_window": [0, 256], "is_outlier": False,
                }
                out[idx] = (shared_k, label)
                idx += 1
    elif params["mode"] == "prefix":
        P = params["prefix_bits"]
        prefix = rng.randrange(1, N) >> (256 - P) << (256 - P)   # fixed top-P bits
        for i in range(count):
            low = rng.getrandbits(256 - P)
            k = prefix | low
            if k == 0:
                k = 1
            out[i] = (k, {
                "nonce": hex(k), "structure": "reuse", "leaked_bits": 0,
                "zero_windows": [], "reuse_group": 0,
                "shared_window": [256 - P, 256], "is_outlier": False,
            })
    else:
        raise ValueError(f"unknown partial_reuse mode {params['mode']}")
    return out

def _build_nonces(family, params, count, rng):
    if family in ("contiguous_msb", "contiguous_lsb", "modulo", "fragmented"):
        return _nonces_uniform(family, params, count, rng)
    if family == "mixed":
        return _mixed(params, count, rng)
    if family == "noisy":
        return _noisy(params, count, rng)
    if family == "partial_reuse":
        return _partial_reuse(params, count, rng)
    raise ValueError(f"unknown family {family}")

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
    elif family == "noisy":
        out_params["outlier_frac"] = params["outlier_frac"]
    elif family == "partial_reuse":
        out_params["reuse_groups"] = params.get("groups", 1)

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
