import json, os, re, subprocess
import pytest
from fixtures import catalog, runner

BINARY = os.environ.get("BAZOOKA_BINARY")
pytestmark = pytest.mark.skipif(not (BINARY and os.path.exists(BINARY)),
                                reason="BAZOOKA_BINARY not set / not built")

# Strong-bias FAST MSB cases that resolve under LLL -- recoverable WITHOUT a
# pubkey via the capped scoring path. This is the only test that exercises
# TOP_N_ROWS + the scoring selection directly.
NOPUBKEY_CASES = ["msb_L9_putty_58", "msb_L8_tpmfail_1000"]

def _strip_pubkey(txt: str) -> str:
    return "\n".join(l for l in txt.splitlines() if not l.startswith("PubKey:"))

@pytest.mark.parametrize("name", NOPUBKEY_CASES)
def test_nopubkey_capped_path_recovers(name, tmp_path):
    case = next(c for c in catalog.CASES if c.name == name)
    txt, sidecar = runner.generate(case)
    d_true = json.loads(sidecar)["private_key"] if isinstance(sidecar, str) \
             else sidecar["private_key"]
    stripped = tmp_path / f"{name}.nopub.txt"
    stripped.write_text(_strip_pubkey(txt), encoding="utf-8")
    proc = subprocess.run(
        # NOTE: -t is --max-time SECONDS, not a row/candidate count. -t 1 forces
        # every case here to fail before the lattice search finishes (same bug
        # found in Task 2's M1 script); -t 170 leaves a 10s margin under the
        # 180s outer subprocess timeout so the search runs to completion.
        [BINARY, "-i", str(stripped), "-q", "-t", "170", "--allow-no-pubkey"],
        capture_output=True, text=True, timeout=180)
    out = proc.stdout + proc.stderr
    m = re.search(r"d = 0x([0-9a-fA-F]+)", out)
    assert m, f"no key line in output:\n{out[:2000]}"
    assert int(m.group(1), 16) == int(d_true, 16), "recovered key != ground truth"
