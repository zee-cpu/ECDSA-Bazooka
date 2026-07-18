"""TDD suite for the C predicate shim (bazooka_predicate) via cffi.

Validates the shim against the same semantics as utils::verify_pubkey:
d in (0, n) with d*G == pubkey  ->  1, else 0.
"""
import os
import subprocess
import sys

import pytest
from ecdsa import SECP256k1, SigningKey

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

N = SECP256k1.order
G = SECP256k1.generator


@pytest.fixture(scope="module")
def predicate():
    # Build the shared library, then load the worker-facing binding.
    subprocess.run(
        [os.path.join(HERE, "build_shim.sh")],
        check=True, capture_output=True, text=True,
    )
    from predicate_shim import predicate as p
    return p


def _d_bytes(d):
    return d.to_bytes(32, "big")


def _compressed_pubkey(d):
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    return sk.get_verifying_key().to_string("compressed")  # 33 bytes SEC1


def test_accepts_matching_key_and_pubkey(predicate):
    d = 0xC0FFEE123456789ABCDEF
    assert predicate(_d_bytes(d), _compressed_pubkey(d)) is True


def test_rejects_wrong_key(predicate):
    d = 0xC0FFEE123456789ABCDEF
    assert predicate(_d_bytes(d + 1), _compressed_pubkey(d)) is False


def test_matches_verify_pubkey_over_random_keys(predicate):
    import random
    rng = random.Random(1234)
    for _ in range(200):
        d = rng.randrange(1, N)
        pk = _compressed_pubkey(d)
        assert predicate(_d_bytes(d), pk) is True
        wrong = rng.randrange(1, N)
        assert predicate(_d_bytes(wrong), pk) is (wrong == d)


def test_rejects_out_of_range_scalar(predicate):
    pk = _compressed_pubkey(12345)
    assert predicate((0).to_bytes(32, "big"), pk) is False   # d = 0
    assert predicate(int(N).to_bytes(32, "big"), pk) is False  # d = n
