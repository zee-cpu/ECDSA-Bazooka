from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
from fixtures import composer

N = SECP256k1.order

def test_every_signature_verifies_and_pubkey_matches():
    txt, sc = composer.build_case("contiguous_msb", {"L": 8}, 20, seed=101)
    d = int(sc["private_key"], 16)
    assert sc["schema_version"] == 1
    assert sc["count"] == 20 and len(sc["signatures"]) == 20
    assert sc["pubkey_uncompressed"] == composer.pubkey_hex(d)
    for rec in sc["signatures"]:
        k = int(rec["nonce"], 16)
        # reconstruct r, s from the labeled nonce and check the ECDSA relation
        # by re-signing with the same (d, z, k) is circular; instead verify the
        # core identity s*k == z + r*d (mod n) using the block's r, s, z.
    # pull r,s,z back out of the txt blocks and check the identity
    blocks = [b for b in txt.split("\n\n") if b.strip()]
    assert len(blocks) == 20
    for rec, block in zip(sc["signatures"], blocks):
        vals = dict(
            line.split(" = ", 1) if " = " in line else line.split(": ", 1)
            for line in block.splitlines() if (" = " in line or ": " in line)
        )
        r = int(vals["R"], 16); s = int(vals["S"], 16); z = int(vals["Z"], 16)
        k = int(rec["nonce"], 16)
        assert (s * k) % N == (z + r * d) % N          # ECDSA identity
        assert (k * SECP256k1.generator).x() % N == r  # r reproduces from nonce

def test_txt_index_aligns_with_sidecar():
    txt, sc = composer.build_case("contiguous_lsb", {"L": 8}, 5, seed=102)
    for i, block in enumerate([b for b in txt.split("\n\n") if b.strip()], start=1):
        assert block.splitlines()[0] == f"Signature #{i}"
        assert sc["signatures"][i - 1]["index"] == i

def test_pubkey_hex_is_130_chars_uncompressed():
    txt, sc = composer.build_case("contiguous_msb", {"L": 4}, 3, seed=103)
    assert len(sc["pubkey_uncompressed"]) == 130
    assert sc["pubkey_uncompressed"].startswith("04")

def test_modulo_records_omega_and_bound_in_params():
    txt, sc = composer.build_case("modulo", {"omega": 1 << 20, "bound": 1 << 4}, 4, seed=104)
    assert sc["composition"]["family"] == "modulo"
    assert sc["composition"]["params"]["omega"] == (1 << 20)
    assert sc["composition"]["params"]["bound"] == (1 << 4)
    assert all(rec["structure"] == "modulo" for rec in sc["signatures"])

def test_deterministic_same_seed_same_bytes():
    a = composer.build_case("fragmented", {"windows": [[0, 2], [128, 130]]}, 6, seed=105)
    b = composer.build_case("fragmented", {"windows": [[0, 2], [128, 130]]}, 6, seed=105)
    assert a == b
