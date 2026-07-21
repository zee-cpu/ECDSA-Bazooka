import os
import re
import subprocess
import pytest
from fixtures import runner, catalog

BINARY = os.environ.get("BAZOOKA_BINARY")

pytestmark = pytest.mark.skipif(
    not (BINARY and os.path.exists(BINARY)),
    reason="BAZOOKA_BINARY not set / not built",
)

@pytest.mark.parametrize("name", ["msb_L8_lowcount_40", "msb_L6_highcount_3000"])
def test_binary_parses_generated_fixture(name, tmp_path):
    case = next(c for c in catalog.CASES if c.name == name)
    txt_path, _ = runner.write_case(case, tmp_path)
    proc = subprocess.run(
        [BINARY, "-i", str(txt_path), "-q", "-t", "1"],
        capture_output=True, text=True, timeout=120,
    )
    out = proc.stdout + proc.stderr
    assert "No signatures parsed" not in out
    m = re.search(r"\[\+\] Parsed (\d+) signatures \((\d+) valid\)", out)
    assert m, f"no parse line in output:\n{out[:2000]}"
    assert int(m.group(1)) == case.count
    assert int(m.group(2)) == case.count      # every generated signature is valid
