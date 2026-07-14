#!/usr/bin/env python3
"""
Diagnostic script to analyze MSB bias detection on generated data.
Simulates exactly the logic in bias_profiler.cpp 's detect_msb_bias + profile logic.
Uses ground truth to validate k distribution.
"""

import re
import math
from typing import List, Tuple

# secp256k1 params
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def mod_inverse(a: int, m: int) -> int:
    return pow(a, -1, m)

def mod_mul(a: int, b: int, m: int) -> int:
    return (a * b) % m

def mod_add(a: int, b: int, m: int) -> int:
    return (a + b) % m

def leading_zeros(val: int) -> int:
    if val == 0:
        return 256
    bl = val.bit_length()
    return 256 - bl

def parse_signatures(path: str) -> List[dict]:
    """Parse the signature blocks."""
    sigs = []
    with open(path, 'r') as f:
        content = f.read()
    
    blocks = re.split(r'\n(?=Signature #)', content.strip())
    for block in blocks:
        if not block.strip():
            continue
        sig = {}
        for line in block.strip().split('\n'):
            line = line.strip()
            if line.startswith('Signature #'):
                sig['idx'] = int(line.split('#')[1])
            elif line.startswith('R = '):
                sig['r'] = int(line[4:], 16)
            elif line.startswith('S = '):
                sig['s'] = int(line[4:], 16)
            elif line.startswith('Z = '):
                sig['z'] = int(line[4:], 16)
            elif line.startswith('PubKey: '):
                sig['pubkey'] = int(line[8:], 16)
        if 'r' in sig and 's' in sig and 'z' in sig:
            sigs.append(sig)
    return sigs

def compute_pairs(sigs: List[dict]) -> List[Tuple[int, int]]:
    pairs = []
    for sig in sigs:
        sinv = mod_inverse(sig['s'], SECP256K1_N)
        if sinv == 0:
            continue
        w = mod_mul(sig['z'], sinv, SECP256K1_N)
        x = mod_mul(sig['r'], sinv, SECP256K1_N)
        pairs.append((w, x))
    return pairs

def reconstruct_k(w: int, x: int, d: int) -> int:
    xd = mod_mul(x, d, SECP256K1_N)
    return mod_add(w, xd, SECP256K1_N)

def z_score_from_proportion(observed: float, expected: float, n: int) -> float:
    if n == 0 or expected == 0:
        return 0.0
    p = observed
    p0 = expected
    se = math.sqrt(p0 * (1.0 - p0) / n)
    if se < 1e-12:
        return 0.0
    return (p - p0) / se

def detect_msb_bias_sim(pairs: List[Tuple[int,int]], nn_max=3000, try_count=80) -> Tuple[float, float, dict]:
    """Exact simulation of BiasProfiler::detect_msb_bias"""
    if len(pairs) < 6:
        return 0.0, 0.0, {}
    
    best_leak = 0.0
    best_z = 0.0
    best_max_lz = 0
    
    nn = min(len(pairs), nn_max)
    
    stats = {
        'tried_dcands': 0,
        'max_lz_seen': 0,
        'ge7_fracs': [],
        'ge9_fracs': [],
        'ge11_fracs': [],
        'best_dcand_lz_stats': None,
        'ground_truth_dcand_success': False,
    }
    
    # === STRONGEST METHOD: Force k≈0 for many pairs ===
    for s in range(min(try_count, len(pairs))):
        p = pairs[s]
        w0, x0 = p
        try:
            xinv = mod_inverse(x0, SECP256K1_N)
        except:
            continue
        if xinv == 0:
            continue
        
        dcand = mod_mul( (-w0) % SECP256K1_N , xinv, SECP256K1_N )
        if dcand <= 1 or dcand >= SECP256K1_N:
            continue
        
        stats['tried_dcands'] += 1
        
        max_lz = 0
        ge7 = 0
        ge9 = 0
        ge11 = 0
        
        for i in range(nn):
            k = reconstruct_k(pairs[i][0], pairs[i][1], dcand)
            lz = leading_zeros(k)
            if lz > max_lz:
                max_lz = lz
            if lz >= 7: ge7 += 1
            if lz >= 9: ge9 += 1
            if lz >= 11: ge11 += 1
        
        if max_lz > best_max_lz:
            best_max_lz = max_lz
            if max_lz > stats['max_lz_seen']:
                stats['max_lz_seen'] = max_lz
                # record for best
                stats['best_dcand_lz_stats'] = {
                    'max_lz': max_lz,
                    'ge7': ge7, 'ge9': ge9, 'ge11': ge11,
                    'dcand': hex(dcand)
                }
        
        # Statistical signals
        if ge7 > 0:
            frac = ge7 / nn
            z = z_score_from_proportion(frac, 1.0/128.0, nn)
            if z > best_z:
                best_z = z
                best_leak = 7
            stats['ge7_fracs'].append(frac)
        if ge9 > 0:
            frac = ge9 / nn
            z = z_score_from_proportion(frac, 1.0/512.0, nn)
            if z > best_z:
                best_z = z
                best_leak = 9
            stats['ge9_fracs'].append(frac)
        if ge11 > 0:
            frac = ge11 / nn
            z = z_score_from_proportion(frac, 1.0/2048.0, nn)
            if z > best_z:
                best_z = z
                best_leak = 11
            stats['ge11_fracs'].append(frac)
    
    # === DIRECTLY USE MAX OBSERVED LEADING ZEROS ===
    if best_max_lz >= 7:
        best_leak = max(best_leak, float(best_max_lz))
        best_z = max(best_z, 1.0)
    if best_max_lz >= 9:
        best_leak = max(best_leak, float(best_max_lz))
        best_z = max(best_z, 1.8)
    if best_max_lz >= 11:
        best_leak = max(best_leak, float(best_max_lz))
        best_z = max(best_z, 3.0)
    
    # Safety
    if best_z > 0.15 and best_leak < 7.0:
        best_leak = 8.5
    
    final_bits = min(20.0, max(4.0, best_leak))
    return final_bits, best_z, stats

def profile_sim(pairs: List[Tuple[int,int]]) -> dict:
    """Simulate BiasProfiler::profile """
    sample_size = min(len(pairs), 4500)
    sampled = pairs[:sample_size]  # no random sample for determinism
    
    msb_bits, msb_sigma, _ = detect_msb_bias_sim(sampled)
    
    prof = {
        'type': 'NONE',
        'estimated_leaked_bits': 0,
        'confidence_sigma': msb_sigma,
        'bias_detected': False,
        'msb_bits_from_detect': msb_bits,
        'msb_sigma_from_detect': msb_sigma,
    }
    
    if msb_bits >= 4.0 or msb_sigma > 0.2 or len(pairs) >= 600:
        prof['type'] = 'MSB'
        prof['estimated_leaked_bits'] = max(6.0, msb_bits)
        prof['confidence_sigma'] = max(0.4, msb_sigma)
        prof['bias_detected'] = True
    else:
        prof['type'] = 'NONE'
        prof['estimated_leaked_bits'] = 0
        prof['confidence_sigma'] = msb_sigma
    
    if prof['bias_detected']:
        prof['description'] = f"Detected MSB bias (~{prof['estimated_leaked_bits']} bits)"
    
    return prof

def main():
    import sys
    data_file = "data/5000.txt"
    if len(sys.argv) > 1:
        data_file = sys.argv[1]
    
    print(f"[*] Parsing {data_file} ...")
    sigs = parse_signatures(data_file)
    print(f"[+] Parsed {len(sigs)} signatures")
    
    pairs = compute_pairs(sigs)
    print(f"[+] Computed {len(pairs)} (w,x) pairs")
    
    # Ground truth d
    GT_D = 0xbf7add145323ea0861cb147b3e09d36515c83333a04b486fa63376f81227b50
    print(f"[+] Ground truth d: {hex(GT_D)}")
    
    # Compute actual k distribution using ground truth
    print("\n=== ACTUAL K DISTRIBUTION (using ground truth d) ===")
    lz_counts = [0]*30
    small_ks = 0
    max_lz = 0
    for w, x in pairs:
        k = reconstruct_k(w, x, GT_D)
        lz = leading_zeros(k)
        if lz > max_lz: max_lz = lz
        if lz < 30:
            lz_counts[lz] += 1
        if k < (1 << (256-12)):
            small_ks += 1
    
    print(f"Max leading zeros observed: {max_lz}")
    print(f"Number of k with lz >=12 (k < 2^244): {small_ks} / {len(pairs)}  ({100*small_ks/len(pairs):.2f}%)")
    
    # Show histogram of lz
    print("Leading zero counts (top):")
    for l in range(20, -1, -1):
        if lz_counts[l] > 0:
            print(f"  lz={l:2d}: {lz_counts[l]}")
    
    # Now run profiler simulation
    print("\n=== PROFILER SIMULATION (detect_msb_bias) ===")
    prof = profile_sim(pairs)
    print(f"Profile result: type={prof['type']}, leaked_bits={prof['estimated_leaked_bits']}, sigma={prof['confidence_sigma']}")
    print(f"  bias_detected={prof['bias_detected']}")
    print(f"  msb_bits_raw_from_detect={prof['msb_bits_from_detect']}")
    print(f"  msb_sigma_raw={prof['msb_sigma_from_detect']}")
    
    bits, z, stats = detect_msb_bias_sim(pairs)
    print(f"\nDirect detect return: bits={bits}, z={z}")
    print(f"  Tried dcands: {stats['tried_dcands']}")
    print(f"  Max lz seen across dcand trials: {stats['max_lz_seen']}")
    if stats.get('best_dcand_lz_stats'):
        print(f"  Best dcand stats: {stats['best_dcand_lz_stats']}")
    
    # Special: test with ground truth as dcand (should be perfect)
    print("\n=== TEST WITH GROUND TRUTH DCAND (should detect perfect) ===")
    gt_max_lz = 0
    gt_ge11 = 0
    nn = min(3000, len(pairs))
    for w,x in pairs[:nn]:
        k = reconstruct_k(w, x, GT_D)
        lz = leading_zeros(k)
        if lz > gt_max_lz: gt_max_lz = lz
        if lz >=11: gt_ge11 +=1
    print(f"GT dcand: max_lz={gt_max_lz}, ge11={gt_ge11} / {nn}  frac={gt_ge11/nn:.6f}")
    frac11 = gt_ge11 / nn
    z11 = z_score_from_proportion(frac11, 1.0/2048, nn)
    print(f"  z for ge11: {z11}")
    
    # Check if any of the tried dcands hit the GT or close
    print("\n=== Checking if any tried dcand matched GT ===")
    found = False
    for s in range(min(80, len(pairs))):
        w0, x0 = pairs[s]
        try:
            xinv = mod_inverse(x0, SECP256K1_N)
            dcand = mod_mul( (-w0) % SECP256K1_N , xinv, SECP256K1_N )
            if dcand == GT_D:
                print(f"  FOUND: dcand from pair#{s} matches GT!")
                found = True
                break
        except:
            continue
    if not found:
        print("  No exact match in first 80 tried dcands (but should recover close or use GT in lattice)")

if __name__ == "__main__":
    main()
