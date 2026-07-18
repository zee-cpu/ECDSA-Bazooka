"""TDD suite for the standalone sieve worker (Sage-free L=5 proof)."""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ecdsa_fixture import generate_instance  # noqa: E402
from worker import SieveWorker  # noqa: E402


def test_fixture_generates_verifiable_biased_signatures():
    """L=5 instance: every signature verifies under the pubkey and every
    nonce respects the 5-bit MSB-zero bias (k < 2**(256-5))."""
    inst = generate_instance(leaked_bits=5, m=40, seed=1)

    assert inst.n.bit_length() == 256
    assert len(inst.signatures) == 40
    assert 1 < inst.d < inst.n

    bound = 2 ** (256 - 5)
    for (klen, h, r, s), k in zip(inst.signatures, inst.nonces):
        assert klen == 256 - 5
        assert 0 < k < bound, "nonce must respect the 5-bit MSB bias"
        # recompute the ECDSA relation with the *known* key and nonce
        assert r == (k * inst.G).x() % inst.n
        assert s == pow(k, -1, inst.n) * (h + r * inst.d) % inst.n

    # the pubkey line matches d*G
    P = inst.d * inst.G
    assert inst.pubkey_hex == "%064x%064x" % (P.x(), P.y())


def test_harness_recovers_key_with_exact_solver():
    """Basis + predicate + recover_key round-trip: the exact enum_pred solver
    recovers the true private key for an easy L=5 instance."""
    inst = generate_instance(leaked_bits=5, m=70, seed=2)
    worker = SieveWorker.from_instance(inst)
    d = worker.solve(solver="enum_pred")
    assert d == inst.d


def test_sieve_pred_recovers_l5_key():
    """The flagship path: g6k progressive sieve + public-key predicate recovers
    the private key for an L=5 instance. This is the method that scales to L=2."""
    inst = generate_instance(leaked_bits=5, m=60, seed=3)
    worker = SieveWorker.from_instance(inst)
    d = worker.solve(solver="sieve_pred")
    assert d == inst.d


def test_sieve_pred_recovers_l5_with_c_shim(tmp_path):
    """End-to-end: the g6k sieve recovers an L=5 key while the predicate's
    pubkey check runs through the compiled C shim (bazooka_predicate) via cffi."""
    import subprocess
    subprocess.run([os.path.join(HERE, "build_shim.sh")],
                   check=True, capture_output=True, text=True)
    inst = generate_instance(leaked_bits=5, m=60, seed=5)
    worker = SieveWorker.from_instance(inst)
    d = worker.solve(solver="sieve_pred", use_c_predicate=True)
    assert d == inst.d


def test_cli_recovers_l5_via_subprocess():
    """The C++-facing seam: worker_cli reads a JSON problem spec (signatures +
    pubkey) on stdin and prints the recovered private key hex on stdout."""
    import json
    import subprocess

    inst = generate_instance(leaked_bits=5, m=60, seed=9)
    spec = {
        "pubkey": inst.pubkey_hex,
        "solver": "sieve_pred",
        "signatures": [[klen, "%x" % h, "%x" % r, "%x" % s]
                       for (klen, h, r, s) in inst.signatures],
    }
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "worker_cli.py")],
        input=json.dumps(spec), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "%x" % inst.d


def test_fractional_fixture_has_mixed_klen():
    """L=5.5 -> average klen 250.5, realized as a mix of klen 250 and 251
    across signatures (make_klen_list distribution). Each nonce respects its
    own per-signature bound and every signature verifies."""
    inst = generate_instance(leaked_bits=5.5, m=40, seed=1)
    klens = [klen for (klen, *_rest) in inst.signatures]
    assert set(klens) == {250, 251}
    assert abs(sum(klens) / len(klens) - 250.5) < 1e-9
    for (klen, h, r, s), k in zip(inst.signatures, inst.nonces):
        assert 0 < k < 2 ** klen
        assert r == (k * inst.G).x() % inst.n
        assert s == pow(k, -1, inst.n) * (h + r * inst.d) % inst.n


def test_sieve_recovers_fractional_l():
    """Non-uniform klen: the sieve recovers a fractional-average-L instance
    (proves the per-signature klen / f_list generalization). Run at a fast
    average L; the math is identical at L=2.5-3, only slower."""
    inst = generate_instance(leaked_bits=5.5, m=60, seed=4)
    worker = SieveWorker.from_instance(inst)
    d = worker.solve(solver="sieve_pred")
    assert d == inst.d
