import json
from fixtures import runner, catalog

def test_generate_is_byte_deterministic():
    case = next(c for c in catalog.CASES if c.name == "msb_L8_lowcount_40")
    a = runner.generate(case)
    b = runner.generate(case)
    assert a == b                              # identical txt AND json bytes

def test_sidecar_json_parses_and_carries_case_name():
    case = next(c for c in catalog.CASES if c.name == "frag_2blk_L4_600")
    _, js = runner.generate(case)
    doc = json.loads(js)
    assert doc["case"] == "frag_2blk_L4_600"
    assert doc["schema_version"] == 1
    assert doc["count"] == 600

def test_write_case_emits_txt_and_labels(tmp_path):
    case = next(c for c in catalog.CASES if c.name == "msb_L8_lowcount_40")
    txt_path, json_path = runner.write_case(case, tmp_path)
    assert txt_path.name == "msb_L8_lowcount_40.txt"
    assert json_path.name == "msb_L8_lowcount_40.labels.json"
    assert txt_path.read_text().startswith("Signature #1")
    json.loads(json_path.read_text())          # valid JSON

def test_main_only_writes_single_case(tmp_path):
    rc = runner.main(["--only", "msb_L8_lowcount_40", "--out", str(tmp_path)])
    assert rc == 0
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["msb_L8_lowcount_40.labels.json", "msb_L8_lowcount_40.txt"]

def test_main_fast_default_excludes_slow(tmp_path):
    runner.main(["--out", str(tmp_path)])
    stems = {p.stem for p in tmp_path.glob("*.txt")}
    assert "msb_L8_lowcount_40" in stems
    assert "msb_L1_minerva_2100" not in stems  # SLOW excluded without --slow
