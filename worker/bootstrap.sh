#!/usr/bin/env bash
#
# One-shot setup for the sieving-with-predicate route (deep MSB leakage, L<=3).
# Automates everything Tier-2 needs, then writes worker/sieve-env.sh to source.
#
# What it does:
#   1. Find a Python with G6K + fpylll importable (or build G6K if asked).
#   2. Clone the upstream bdd-predicate into third_party/ (only usvp.py is used).
#   3. Install cffi + ecdsa into that Python.
#   4. Build the predicate shim (CMake target, or worker/build_shim.sh fallback).
#   5. Write worker/sieve-env.sh with the env vars the C++ tool needs.
#   6. Verify the whole chain imports and the shim loads.
#
# Usage:
#   worker/bootstrap.sh [--python PATH] [--build-g6k] [--force-build]
#                       [--max-sieving-dim N] [--jobs N] [--skip-shim]
#
#   --force-build  ignore any G6K already installed and build a fresh one into
#                  third_party/g6k (useful for testing the from-source path).
#
# The common case is fully automatic: if a G6K-enabled Python is already on PATH
# (or in $BAZOOKA_SIEVE_PYTHON) it is detected and used. Building G6K from source
# (--build-g6k) is heavy and needs a C/C++ toolchain, autotools and libtool.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
THIRD_PARTY="$REPO/third_party"
BDD_DIR="$THIRD_PARTY/bdd-predicate"
G6K_DIR="$THIRD_PARTY/g6k"

PY_ARG=""
BUILD_G6K=0
FORCE_BUILD=0
MAX_SIEVING_DIM=""
JOBS="$(nproc 2>/dev/null || echo 4)"
SKIP_SHIM=0
# A from-source G6K is built in-place and imported via this on PYTHONPATH
# (that is what G6K's own `source activate` does). Empty for an installed G6K.
G6K_PYTHONPATH=""
# A from-source G6K also builds its own libfplll.so.* into g6k-env/lib only;
# that dir must be on LD_LIBRARY_PATH for `import fpylll` to find it. Empty
# for an installed G6K.
G6K_LD_LIBRARY_PATH=""

log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --python)           PY_ARG="$2"; shift 2 ;;
        --build-g6k)        BUILD_G6K=1; shift ;;
        --force-build)      FORCE_BUILD=1; BUILD_G6K=1; shift ;;
        --max-sieving-dim)  MAX_SIEVING_DIM="$2"; BUILD_G6K=1; shift 2 ;;
        --jobs)             JOBS="$2"; shift 2 ;;
        --skip-shim)        SKIP_SHIM=1; shift ;;
        -h|--help)          grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                  die "unknown argument: $1" ;;
    esac
done

has_g6k() {
    LD_LIBRARY_PATH="${G6K_LD_LIBRARY_PATH:+$G6K_LD_LIBRARY_PATH:}${LD_LIBRARY_PATH:-}" \
        PYTHONPATH="${G6K_PYTHONPATH:+$G6K_PYTHONPATH:}${PYTHONPATH:-}" \
        "$1" -c "import g6k, fpylll" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# 1. Locate a Python with G6K.
# ---------------------------------------------------------------------------
PYTHON=""
if [ "$FORCE_BUILD" -eq 1 ]; then
    log "--force-build: skipping detection, building G6K from source"
else
    for cand in "$PY_ARG" "${BAZOOKA_SIEVE_PYTHON:-}" \
                "$G6K_DIR/g6k-env/bin/python" python3 python; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 && has_g6k "$cand"; then
            PYTHON="$(command -v "$cand")"
            log "found G6K in: $PYTHON"
            break
        fi
    done
fi

if [ -z "$PYTHON" ]; then
    if [ "$BUILD_G6K" -eq 1 ]; then
        # Fail early (before the long clone/build) if the autotools toolchain
        # G6K's fplll build needs is incomplete.
        missing=""
        # autotools bootstrap needs libtoolize (from the 'libtool' package), not
        # the standalone /usr/bin/libtool binary (which is 'libtool-bin').
        for tool in git make autoconf automake libtoolize g++ pkg-config; do
            command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
        done
        [ -f /usr/include/mpfr.h ] || missing="$missing libmpfr-dev(mpfr.h)"
        if [ -n "$missing" ]; then
            die "missing build prerequisites:$missing
       Install them first, e.g. on Debian/Ubuntu:
         sudo apt-get install -y git build-essential autoconf automake libtool pkg-config libmpfr-dev libgmp-dev
       then re-run this script."
        fi
        mkdir -p "$THIRD_PARTY"
        if [ ! -d "$G6K_DIR/.git" ]; then
            git clone --depth 1 https://github.com/fplll/g6k "$G6K_DIR"
        fi
        G6K_PYTHONPATH="$G6K_DIR"           # in-place build -> import via PYTHONPATH
        G6K_LD_LIBRARY_PATH="$G6K_DIR/g6k-env/lib"  # freshly-built libfplll.so.9 lives here
        PYTHON="$G6K_DIR/g6k-env/bin/python"
        pushd "$G6K_DIR" >/dev/null
        # Full fplll+fpylll+g6k build. Idempotent: skip if g6k-env already imports.
        if [ -x "$PYTHON" ] && has_g6k "$PYTHON"; then
            log "reusing existing G6K build in $G6K_DIR/g6k-env"
        else
            log "building G6K from source (fplll + fpylll + g6k, slow)..."
            ./bootstrap.sh -j "$JOBS" || die "G6K build failed -- check the log above (fplll/fpylll/g6k build)."
        fi
        # MAX_SIEVING_DIM lives in G6K's OWN configure (not fplll's / not
        # setup.py), so set it here and rebuild just the g6k kernel if needed.
        if [ -n "$MAX_SIEVING_DIM" ]; then
            cur="$(grep -oP 'define MAX_SIEVING_DIM \K[0-9]+' kernel/g6k_config.h 2>/dev/null || echo 0)"
            if [ "$cur" != "$MAX_SIEVING_DIM" ]; then
                log "setting MAX_SIEVING_DIM=$MAX_SIEVING_DIM (was $cur) and rebuilding g6k kernel"
                [ -x ./configure ] || ./autogen.sh
                # Configure with the dim first so setup.py (which only runs
                # ./configure when no Makefile exists) preserves it; make clean
                # forces the kernel .o's to rebuild against the new g6k_config.h.
                ./configure --with-max-sieving-dim="$MAX_SIEVING_DIM"
                make clean >/dev/null 2>&1 || true
                "$PYTHON" setup.py build_ext -j "$JOBS" --inplace \
                    || "$PYTHON" setup.py build_ext --inplace \
                    || die "g6k kernel rebuild for MAX_SIEVING_DIM=$MAX_SIEVING_DIM failed"
            else
                log "MAX_SIEVING_DIM already $MAX_SIEVING_DIM"
            fi
        fi
        popd >/dev/null
        has_g6k "$PYTHON" || die "G6K built but not importable from $PYTHON (with PYTHONPATH=$G6K_PYTHONPATH)"
        log "using freshly built G6K: $PYTHON  (PYTHONPATH+=$G6K_PYTHONPATH)"
    else
        die "no Python with G6K found. Either activate one and set \$BAZOOKA_SIEVE_PYTHON,
       pass --python /path/to/python, or re-run with --build-g6k (slow, from source).
       For the L=2 case also pass --max-sieving-dim 192."
    fi
fi

# ---------------------------------------------------------------------------
# 2. bdd-predicate (upstream; only usvp.py is used, Sage-free).
# ---------------------------------------------------------------------------
if [ -f "$BDD_DIR/usvp.py" ]; then
    log "bdd-predicate present: $BDD_DIR"
else
    log "cloning bdd-predicate into $BDD_DIR"
    mkdir -p "$THIRD_PARTY"
    git clone --depth 1 https://github.com/malb/bdd-predicate "$BDD_DIR"
fi

# ---------------------------------------------------------------------------
# 3. Python deps for the worker.
# ---------------------------------------------------------------------------
log "installing worker Python deps (cffi, ecdsa) into the G6K Python"
"$PYTHON" -m pip install --quiet cffi ecdsa || warn "pip install failed; ensure cffi and ecdsa are available in $PYTHON"

# ---------------------------------------------------------------------------
# 4. Build the predicate shim (libbazooka_predicate.so).
# ---------------------------------------------------------------------------
SHIM_SO=""
if [ "$SKIP_SHIM" -eq 0 ]; then
    if command -v cmake >/dev/null 2>&1; then
        log "building predicate shim via CMake target bazooka_predicate"
        cmake --preset release >/dev/null 2>&1 || cmake -S "$REPO" -B "$REPO/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
        cmake --build "$REPO/build" --target bazooka_predicate -j "$JOBS" >/dev/null
        SHIM_SO="$REPO/build/libbazooka_predicate.so"
    fi
    if [ ! -f "$SHIM_SO" ]; then
        log "falling back to worker/build_shim.sh"
        "$REPO/worker/build_shim.sh"
        SHIM_SO="$REPO/worker/build/libbazooka_predicate.so"
    fi
    [ -f "$SHIM_SO" ] || die "shim build produced no libbazooka_predicate.so"
    log "shim: $SHIM_SO"
fi

# ---------------------------------------------------------------------------
# 5. Write the env file to source.
# ---------------------------------------------------------------------------
ENV_FILE="$REPO/worker/sieve-env.sh"
{
    echo "# Generated by worker/bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo "# Source this before running the sieve route:  source worker/sieve-env.sh"
    echo "export BAZOOKA_SIEVE_PYTHON=\"$PYTHON\""
    echo "export BAZOOKA_SIEVE_WORKER=\"$REPO/worker/worker_cli.py\""
    echo "export BDD_PREDICATE_DIR=\"$BDD_DIR\""
    [ -n "$SHIM_SO" ] && echo "export BAZOOKA_PREDICATE_SO=\"$SHIM_SO\""
    # A from-source G6K is in-place; put it on PYTHONPATH (inherited by the
    # worker subprocess the C++ tool spawns).
    [ -n "$G6K_PYTHONPATH" ] && \
        echo "export PYTHONPATH=\"$G6K_PYTHONPATH\${PYTHONPATH:+:\$PYTHONPATH}\""
    [ -n "$G6K_LD_LIBRARY_PATH" ] && echo "export LD_LIBRARY_PATH=\"$G6K_LD_LIBRARY_PATH\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\""
} > "$ENV_FILE"
log "wrote $ENV_FILE"

# ---------------------------------------------------------------------------
# 6. Verify the whole chain.
# ---------------------------------------------------------------------------
log "verifying imports..."
# shellcheck disable=SC1090
source "$ENV_FILE"
"$PYTHON" - <<PY || die "verification failed -- see the traceback above"
import os, sys
sys.path.insert(0, os.environ["BDD_PREDICATE_DIR"])
sys.path.insert(0, os.path.join("$REPO", "worker"))
import g6k, fpylll, usvp            # sieve stack
import ecdsa, cffi                  # worker deps
if "$SKIP_SHIM" == "0":
    import predicate_shim           # loads libbazooka_predicate.so
print("  OK: g6k, fpylll, usvp, ecdsa, cffi" + (", predicate_shim" if "$SKIP_SHIM"=="0" else ""))
PY

cat <<EOF

$(printf '\033[1;32m[bootstrap] Sieve route ready.\033[0m')

  source worker/sieve-env.sh
  ./build/ecdsa_nonce_recovery -i <input> --method sieve --leaked-bits <L>

For the L=2 case, G6K must be built with MAX_SIEVING_DIM >= 192:
  worker/bootstrap.sh --build-g6k --max-sieving-dim 192
EOF
