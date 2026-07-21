import json, os, re, subprocess
import pytest
from fixtures import catalog, runner, composer

BINARY = os.environ.get("BAZOOKA_BINARY")
pytestmark = pytest.mark.skipif(not (BINARY and os.path.exists(BINARY)),
                                reason="BAZOOKA_BINARY not set / not built")

def _key(out):
    m = re.search(r"d = 0x([0-9a-fA-F]+)", out)
    return int(m.group(1), 16) if m else None

def test_noise5_recovers(tmp_path):
    case = next(c for c in catalog.CASES if c.name == "msb_L8_noise5_800")
    txt_path, _ = runner.write_case(case, tmp_path)
    d_true = int(json.loads((tmp_path / f"{case.name}.labels.json").read_text())["private_key"], 16)
    proc = subprocess.run([BINARY, "-i", str(txt_path), "-q", "-t", "500"],
                          capture_output=True, text=True, timeout=560)
    assert _key(proc.stdout + proc.stderr) == d_true

def test_noise10_recovers(tmp_path):
    txt, sc = composer.build_case("noisy", {"L": 8, "outlier_frac": 0.10}, 800, 4242)
    p = tmp_path / "noise10.txt"; p.write_text(txt)
    d_true = int(sc["private_key"], 16)
    proc = subprocess.run([BINARY, "-i", str(p), "-q", "-t", "500"],
                          capture_output=True, text=True, timeout=560)
    assert _key(proc.stdout + proc.stderr) == d_true

def test_noise50_fails_gracefully(tmp_path):
    case = next(c for c in catalog.CASES if c.name == "msb_L8_noise50_1200")
    txt_path, _ = runner.write_case(case, tmp_path)
    # Bounded budget so heavy noise can't hang; it must never emit a wrong key.
    # Kept short: this is a pure negative check (no recovery), so a tight budget
    # confirms graceful failure without inflating the suite runtime.
    proc = subprocess.run([BINARY, "-i", str(txt_path), "-q", "-t", "90"],
                          capture_output=True, text=True, timeout=150)
    assert "[SUCCESS]" not in (proc.stdout + proc.stderr)
