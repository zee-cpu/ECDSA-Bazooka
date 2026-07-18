#!/usr/bin/env bash
# Standalone build of libbazooka_predicate.so from the repo's secp256k1/utils
# sources + the C predicate shim. The preferred path is the CMake target
# `bazooka_predicate`; this script is a dependency-light equivalent (no CMake).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/worker/build"
mkdir -p "$OUT"

g++ -O2 -fPIC -shared -std=c++17 \
    -I"$REPO/include" \
    "$REPO/src/predicate_shim.cpp" \
    "$REPO/src/secp256k1.cpp" \
    "$REPO/src/utils.cpp" \
    -lgmpxx -lgmp \
    -o "$OUT/libbazooka_predicate.so"

echo "built $OUT/libbazooka_predicate.so"
