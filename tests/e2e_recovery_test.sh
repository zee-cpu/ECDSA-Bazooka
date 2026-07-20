#!/usr/bin/env bash
# True end-to-end integration test.
#
# Unlike a self-test that checks a component in isolation (or, worse, checks
# that a function returns *something* without checking it's *correct*), this
# generates real synthetic signature data with a known ground-truth private
# key, runs the actual compiled binary against it exactly as a user would,
# and asserts the reported result against that ground truth. This is the
# only kind of test that would have caught the bugs found in this session:
# - Phase B claiming "~20 bits of bias" on every input regardless of content
# - Phase C's lattice embedding never producing a genuinely short vector
# - PubKey verification unconditionally rejecting even the correct key
#
# Exit code: 0 if every case behaves correctly, 1 otherwise.
set -uo pipefail

BINARY="${1:?usage: e2e_recovery_test.sh /path/to/ecdsa_nonce_recovery [/path/to/generate_mock_signatures.py]}"
GEN="${2:-scripts/generate_mock_signatures.py}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

FAILS=0

check() {
    local desc="$1" cond="$2"
    if [ "$cond" -eq 0 ]; then
        echo "  [PASS] $desc"
    else
        echo "  [FAIL] $desc"
        FAILS=$((FAILS + 1))
    fi
}

echo "=== E2E: genuinely biased data must actually recover the correct key ==="
for case in "msb:12:500:11" "msb:16:400:12" "msb:8:1200:13" "lsb:12:500:31" "lsb:8:400:32"; do
    IFS=: read -r mode bits count seed <<< "$case"
    f="$WORKDIR/${mode}_${bits}b.txt"
    gen_out=$(python3 "$GEN" --count "$count" --bias "$mode" --bias-bits "$bits" \
                    --output "$f" --seed "$seed" 2>&1)
    gt=$(echo "$gen_out" | grep -oE '0x[0-9a-fA-F]+' | head -1)

    # Pass an explicit -t, same as the unbiased case below. Without a budget,
    # remaining_budget_seconds() returns the unlimited sentinel and the budget-
    # fit guards go inert, so the sweep over-explores (higher L, BKZ escalation)
    # chasing more confidence than a strong-bias recovery needs -- which made
    # these cases run *longer* than a bounded run and get killed by the outer
    # timeout on slower machines, reported as a spurious FAIL. With -t the binary
    # converges in ~30-35s. Outer timeout stays larger as a safety net (a single
    # fplll reduction can't be interrupted mid-call).
    run_out=$(timeout 130 "$BINARY" -i "$f" -q -t 90 2>&1)
    recovered=$(echo "$run_out" | grep -oE '^\s*d = 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+')

    echo "$run_out" | grep -q '\[SUCCESS\]'
    success=$?
    check "${mode^^} ${bits}-bit bias (${count} sigs): reports SUCCESS" "$success"

    if [ -n "$recovered" ] && [ "$recovered" = "$gt" ]; then
        match=0
    else
        match=1
    fi
    check "${mode^^} ${bits}-bit bias: recovered key matches ground truth" "$match"
done

echo
echo "=== E2E: modulo / Extended-HNP (windowed-zero) bias ==="
# k mod 2^16 in [0, 2^4): a 12-bit zero window in the MIDDLE of the nonce --
# neither MSB (k is full-width) nor LSB (low bits free) -- so the single-block
# lattice can't touch it. Recovered via the two-block EHNP lattice, given the
# (omega, bound) hint the generator prints. A 12-bit window resolves under LLL
# in ~15s; a narrow ~8-bit window is heavy-BKZ best-effort (like MSB L=4) and is
# deliberately not asserted here. Outer timeout stays above -t as a safety net.
f="$WORKDIR/modulo_12b.txt"
gen_out=$(python3 "$GEN" --count 250 --bias modulo --bias-bits 12 --omega 65536 \
                --output "$f" --seed 41 2>&1)
gt=$(echo "$gen_out" | grep -oE '0x[0-9a-fA-F]+' | head -1)
run_out=$(timeout 160 "$BINARY" -i "$f" -q -t 120 --modulo-omega 65536 --modulo-bound 16 2>&1)
recovered=$(echo "$run_out" | grep -oE '^\s*d = 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+')
echo "$run_out" | grep -q '\[SUCCESS\]'
check "MODULO 12-bit window (250 sigs): reports SUCCESS" "$?"
if [ -n "$recovered" ] && [ "$recovered" = "$gt" ]; then match=0; else match=1; fi
check "MODULO 12-bit window: recovered key matches ground truth" "$match"

echo
echo "=== E2E: linearly-related (LCG) nonces ==="
# k_{i+1} = a*k_i + b (mod n). Recovered by closed-form algebra -- a small modular
# linear solve over consecutive signatures -- with a,b UNKNOWN, no lattice and no
# hint. Fast (well under a second); the outer timeout is just a safety net.
f="$WORKDIR/linear.txt"
gen_out=$(python3 "$GEN" --count 40 --bias linear --output "$f" --seed 44 2>&1)
gt=$(echo "$gen_out" | grep -oE '0x[0-9a-fA-F]+' | head -1)
run_out=$(timeout 60 "$BINARY" -i "$f" -q -t 40 2>&1)
recovered=$(echo "$run_out" | grep -oE '^\s*d = 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+')
echo "$run_out" | grep -q '\[SUCCESS\]'
check "LINEAR (LCG) unknown a,b (40 sigs): reports SUCCESS" "$?"
if [ -n "$recovered" ] && [ "$recovered" = "$gt" ]; then match=0; else match=1; fi
check "LINEAR (LCG): recovered key matches ground truth" "$match"
echo "$run_out" | grep -q 'Method: LINEAR'
check "LINEAR (LCG): reported method is LINEAR (closed-form, not lattice)" "$?"

echo
echo "=== E2E: unbiased data must NOT produce a false recovery ==="
f="$WORKDIR/none.txt"
python3 "$GEN" --count 800 --bias none --bias-bits 0 --output "$f" --seed 21 > /dev/null 2>&1
# Must pass an explicit -t: without a time budget the budget-fit guards are
# inert (remaining_budget_seconds() returns the unlimited sentinel), so the
# sweep runs unbounded looking for a key that isn't there and gets killed by
# the outer timeout before it can print [FAILURE]. With -t the binary enforces
# its own budget and reports FAILURE cleanly. Outer timeout is kept larger than
# -t as a safety net (a single fplll call can't be interrupted mid-reduction).
run_out=$(timeout 130 "$BINARY" -i "$f" -q -t 90 2>&1)
echo "$run_out" | grep -q '\[FAILURE\]'
check "unbiased data: reports FAILURE (no false positive)" "$?"

echo
echo "=== E2E: blind AUTO recovers a modulo-biased set via the last-resort stage ==="
# omega=2^20 with a 16-bit window -> bound=2^4, matching the blind sweep's first
# candidate {a=20,c=4}. NO -m/--modulo hint and NO -t: the profiler reports NONE,
# the capped fallback fails, and the last-resort modulo sweep recovers. This
# exercises the whole blind-auditor path and needs no g6k (modulo is a lattice).
mf="$WORKDIR/modulo_blind.txt"
gen_out=$(python3 "$GEN" --count 250 --bias modulo --bias-bits 16 --omega 1048576 \
                --output "$mf" --seed 71 2>&1)
gt=$(echo "$gen_out" | grep -oE '0x[0-9a-fA-F]+' | head -1)
run_out=$(timeout 320 "$BINARY" -i "$mf" -m auto -q 2>&1)
recovered=$(echo "$run_out" | grep -oE '^\s*d = 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+')
echo "$run_out" | grep -q '\[SUCCESS\]'
check "blind AUTO modulo set: reports SUCCESS" "$?"
if [ -n "$recovered" ] && [ "$recovered" = "$gt" ]; then match=0; else match=1; fi
check "blind AUTO modulo set: recovered key matches ground truth (via last-resort)" "$match"

echo
if [ "${BAZOOKA_E2E_SLOW:-0}" = "1" ] && "$BINARY" --check 2>/dev/null | grep -qi 'sieve route.*ready'; then
  echo "=== E2E [SLOW]: blind AUTO recovers a deep-MSB set via the sieve ladder ==="
  # No --leaked-bits hint: the profiler can't detect L=3, so recovery comes from
  # the last-resort sieve ladder. The L=3 rung is dim-89 (~1h) -- opt-in only.
  sf="$WORKDIR/msb_deep.txt"
  gen_out=$(python3 "$GEN" --count 90 --bias msb --bias-bits 3 --output "$sf" --seed 73 2>&1)
  gt=$(echo "$gen_out" | grep -oE '0x[0-9a-fA-F]+' | head -1)
  run_out=$(timeout 5400 "$BINARY" -i "$sf" -m auto -q 2>&1)
  recovered=$(echo "$run_out" | grep -oE '^\s*d = 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+')
  if [ -n "$recovered" ] && [ "$recovered" = "$gt" ]; then match=0; else match=1; fi
  check "blind AUTO deep-MSB set: recovered via sieve ladder" "$match"
else
  echo "  [SKIP] deep-MSB sieve-ladder e2e (set BAZOOKA_E2E_SLOW=1 with g6k to run; ~1h)"
fi

echo
if [ "$FAILS" -eq 0 ]; then
    echo "ALL E2E CHECKS PASSED"
    exit 0
else
    echo "$FAILS E2E CHECK(S) FAILED"
    exit 1
fi
