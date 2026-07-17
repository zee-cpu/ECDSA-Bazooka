#!/usr/bin/env bash
set -uo pipefail

BINARY="${1:?usage: cli_validation_test.sh /path/to/ecdsa_nonce_recovery}"
MISSING_INPUT="/tmp/ecdsa_cli_validation_missing_input.txt"
FAILS=0

expect_error() {
    local description="$1"
    local expected="$2"
    shift 2

    local output status
    output=$("$BINARY" "$@" --input "$MISSING_INPUT" 2>&1)
    status=$?

    if [ "$status" -eq 1 ] && [[ "$output" == *"$expected"* ]]; then
        echo "  [PASS] $description"
    else
        echo "  [FAIL] $description (exit=$status, expected message: $expected)"
        echo "$output"
        FAILS=$((FAILS + 1))
    fi
}

echo "=== CLI validation ==="
expect_error "invalid --max-sigs" "invalid --max-sigs" --max-sigs nope
expect_error "negative --max-sigs" "invalid --max-sigs" --max-sigs=-1
expect_error "invalid --max-time" "invalid --max-time" --max-time nan
expect_error "invalid --seed" "invalid --seed" --seed nope
expect_error "unknown --method" "unknown --method" --method typo
expect_error "negative modulo hints" "modulo hints must be positive" --modulo-omega=-4 --modulo-bound=-2
expect_error "oversized modulo period" "--modulo-omega must be smaller than the curve order" \
    --modulo-omega=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 \
    --modulo-bound=1
expect_error "--lcg-b without --lcg-a" "--lcg-b requires --lcg-a" --lcg-b 7
expect_error "negative --lcg-a" "--lcg-a must be in [1, n)" --lcg-a=-1
expect_error "negative --lcg-b" "--lcg-b must be in [0, n)" --lcg-a=1 --lcg-b=-1

if [ "$FAILS" -eq 0 ]; then
    echo "ALL CLI VALIDATION CHECKS PASSED"
    exit 0
fi

echo "$FAILS CLI VALIDATION CHECK(S) FAILED"
exit 1
