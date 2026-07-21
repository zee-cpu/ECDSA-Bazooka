#!/usr/bin/env python3
"""CTest entry point for the fixtures pytest suite.

Exits 77 (CTest's SKIP_RETURN_CODE) when pytest or the optional `ecdsa` module
is unavailable, so a machine without the optional test dependencies skips this
suite gracefully instead of failing -- mirroring tests/ecc_differential_test.py.
Otherwise it runs pytest over fixtures/tests and propagates its exit code.

Run from the scripts/ directory (CTest sets WORKING_DIRECTORY accordingly)."""
import importlib.util
import subprocess
import sys

if importlib.util.find_spec("pytest") is None or importlib.util.find_spec("ecdsa") is None:
    print("SKIP: fixtures_tests requires pytest and ecdsa")
    sys.exit(77)

sys.exit(subprocess.call([sys.executable, "-m", "pytest", "fixtures/tests", "-q"]))
