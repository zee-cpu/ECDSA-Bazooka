import json, os, re, subprocess
import pytest
from fixtures import catalog, runner

BINARY = os.environ.get("BAZOOKA_BINARY")
pytestmark = pytest.mark.skipif(not (BINARY and os.path.exists(BINARY)),
                                reason="BAZOOKA_BINARY not set / not built")

def test_shared_prefix_64_recovers(tmp_path):
    case = next(c for c in catalog.CASES if c.name == "reuse_shared_prefix_64")
    txt_path, _ = runner.write_case(case, tmp_path)
    d_true = json.loads((tmp_path / f"{case.name}.labels.json").read_text())["private_key"]
    proc = subprocess.run(
        [BINARY, "-i", str(txt_path), "-q", "-t", "170"],
        capture_output=True, text=True, timeout=200)
    out = proc.stdout + proc.stderr
    m = re.search(r"d = 0x([0-9a-fA-F]+)", out)
    assert m, f"no key recovered:\n{out[:2000]}"
    assert int(m.group(1), 16) == int(d_true, 16), "recovered key != ground truth"
