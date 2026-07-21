import random
from fixtures import primitives

def _bit(x, b):
    return (x >> b) & 1

def test_contiguous_msb_zeroes_top_bits():
    rng = random.Random(1)
    k, label = primitives.contiguous_msb(8, rng)
    assert label["structure"] == "msb"
    assert label["zero_windows"] == [[248, 256]]
    assert label["leaked_bits"] == 8
    for b in range(248, 256):
        assert _bit(k, b) == 0
    assert int(label["nonce"], 16) == k
    assert 1 <= k < primitives.N

def test_contiguous_lsb_zeroes_bottom_bits():
    rng = random.Random(2)
    k, label = primitives.contiguous_lsb(12, rng)
    assert label["structure"] == "lsb"
    assert label["zero_windows"] == [[0, 12]]
    assert label["leaked_bits"] == 12
    assert k % (1 << 12) == 0

def test_modulo_window_zeroes_middle_window():
    rng = random.Random(3)
    k, label = primitives.modulo_window(1 << 20, 1 << 4, rng)  # a=20, c=4
    assert label["structure"] == "modulo"
    assert label["zero_windows"] == [[4, 20]]
    assert label["leaked_bits"] == 16
    assert (k % (1 << 20)) < (1 << 4)   # low 20 bits confined to [0, 16)

def test_fragmented_multiple_windows():
    rng = random.Random(4)
    k, label = primitives.fragmented([[0, 2], [128, 130]], rng)
    assert label["structure"] == "fragmented"
    assert label["zero_windows"] == [[0, 2], [128, 130]]
    assert label["leaked_bits"] == 4
    for lo, hi in [[0, 2], [128, 130]]:
        for b in range(lo, hi):
            assert _bit(k, b) == 0

def test_clean_has_no_leak():
    rng = random.Random(5)
    k, label = primitives.clean(rng)
    assert label["structure"] == "clean"
    assert label["zero_windows"] == []
    assert label["leaked_bits"] == 0
    assert label["is_outlier"] is False
