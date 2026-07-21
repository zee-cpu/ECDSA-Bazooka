"""The named fixture corpus, as pure data. Parameters are anchored to documented
real-world ECDSA nonce-bias incidents -- see the design spec's Real-World
Anchoring section. Each case carries a distinct fixed seed."""
from collections import namedtuple

Case = namedtuple("Case", "name family params count seed tag")

CASES = [
    # --- Contiguous MSB (real bit-widths: PuTTY=9, TPM-Fail=8) ---
    Case("msb_L9_putty_58",      "contiguous_msb", {"L": 9},  58,   1101, "FAST"),
    Case("msb_L8_tpmfail_1000",  "contiguous_msb", {"L": 8},  1000, 1102, "FAST"),
    Case("msb_L4_500",           "contiguous_msb", {"L": 4},  500,  1103, "FAST"),
    Case("msb_L8_lowcount_40",   "contiguous_msb", {"L": 8},  40,   1104, "FAST"),
    # --- Contiguous LSB ---
    Case("lsb_L8_500",           "contiguous_lsb", {"L": 8},  500,  1201, "FAST"),
    Case("lsb_L12_400",          "contiguous_lsb", {"L": 12}, 400,  1202, "FAST"),
    # --- Modulo / Extended-HNP (bound = omega >> L) ---
    Case("mod_a20_L16_250",      "modulo", {"omega": 1 << 20, "bound": 1 << 4}, 250, 1301, "FAST"),
    Case("mod_a12_L8_400",       "modulo", {"omega": 1 << 12, "bound": 1 << 4}, 400, 1302, "FAST"),
    # --- Fragmented / multi-block ("fixed bits need not be the MSBs") ---
    Case("frag_2blk_L4_600",     "fragmented", {"windows": [[0, 2], [128, 130]]}, 600, 1401, "FAST"),
    Case("frag_3blk_L6_900",     "fragmented", {"windows": [[0, 2], [100, 102], [200, 202]]}, 900, 1402, "FAST"),
    # --- Mixed (multi-platform data) ---
    Case("mix_msblsb_600",       "mixed", {"mode": "msblsb", "L": 8}, 600, 1501, "FAST"),
    Case("mix_strength_L4to10_800", "mixed", {"mode": "strength", "lo": 4, "hi": 10}, 800, 1502, "FAST"),
    # --- Partial reuse (Bitcoin sparse needle; fixed-prefix RNG) ---
    Case("reuse_full_needle_2000", "partial_reuse", {"mode": "full", "groups": 3, "group_size": 2}, 2000, 1601, "FAST"),
    Case("reuse_shared_prefix_64", "partial_reuse", {"mode": "prefix", "prefix_bits": 64}, 64, 1602, "FAST"),
    # --- Noisy (typical 5%; majority-outlier 50%; TPM-Fail-style 3% needle) ---
    Case("msb_L8_noise5_800",    "noisy", {"L": 8,  "outlier_frac": 0.05}, 800,  1701, "FAST"),
    Case("msb_L8_noise50_1200",  "noisy", {"L": 8,  "outlier_frac": 0.50}, 1200, 1702, "FAST"),
    Case("msb_L12_needle3pct_1500", "noisy", {"L": 12, "outlier_frac": 0.97}, 1500, 1703, "FAST"),
    # --- Count extreme ---
    Case("msb_L6_highcount_3000", "contiguous_msb", {"L": 6}, 3000, 1801, "FAST"),
    # --- Frontier (SLOW / opt-in) ---
    Case("msb_L3_90",            "contiguous_msb", {"L": 3},  90,   1901, "SLOW"),
    Case("msb_L2_1500",          "contiguous_msb", {"L": 2},  1500, 1902, "SLOW"),
    Case("msb_L1_minerva_2100",  "contiguous_msb", {"L": 1},  2100, 1903, "SLOW"),
]
