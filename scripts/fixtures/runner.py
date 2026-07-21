"""Regenerate the labeled fixture corpus deterministically.

    cd scripts && python3 -m fixtures.runner [--only NAME] [--slow] [--out DIR]

FAST cases regenerate by default; --slow adds the frontier cases. Output goes to
tests/fixtures/generated/ (gitignored) unless --out is given."""
import argparse
import json
import sys
from pathlib import Path

from fixtures import catalog, composer

def default_out_dir():
    # scripts/fixtures/runner.py -> parents[2] == repo root
    return Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "generated"

def generate(case):
    txt, sidecar = composer.build_case(
        case.family, dict(case.params, _name=case.name), case.count, case.seed
    )
    js = json.dumps(sidecar, indent=2, sort_keys=True) + "\n"
    return txt, js

def write_case(case, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    txt, js = generate(case)
    txt_path = out_dir / f"{case.name}.txt"
    json_path = out_dir / f"{case.name}.labels.json"
    txt_path.write_text(txt, encoding="utf-8")
    json_path.write_text(js, encoding="utf-8")
    return txt_path, json_path

def main(argv=None):
    ap = argparse.ArgumentParser(description="Regenerate the labeled fixture corpus.")
    ap.add_argument("--only", help="regenerate a single case by name")
    ap.add_argument("--slow", action="store_true", help="include SLOW frontier cases")
    ap.add_argument("--out", default=None, help="output directory")
    args = ap.parse_args(argv)

    out_dir = Path(args.out) if args.out else default_out_dir()
    cases = catalog.CASES
    if args.only:
        cases = [c for c in cases if c.name == args.only]
        if not cases:
            print(f"no such case: {args.only}", file=sys.stderr)
            return 1
    elif not args.slow:
        cases = [c for c in cases if c.tag == "FAST"]

    for c in cases:
        write_case(c, out_dir)
    print(f"wrote {len(cases)} case(s) to {out_dir}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
