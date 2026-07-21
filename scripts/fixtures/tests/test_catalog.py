from fixtures import catalog, composer

def test_case_count_and_tag_split():
    assert len(catalog.CASES) == 21
    fast = [c for c in catalog.CASES if c.tag == "FAST"]
    slow = [c for c in catalog.CASES if c.tag == "SLOW"]
    assert len(fast) == 18 and len(slow) == 3

def test_names_and_seeds_unique():
    names = [c.name for c in catalog.CASES]
    seeds = [c.seed for c in catalog.CASES]
    assert len(set(names)) == len(names)
    assert len(set(seeds)) == len(seeds)

def test_tags_valid():
    assert all(c.tag in ("FAST", "SLOW") for c in catalog.CASES)

def test_expected_anchor_cases_present():
    names = {c.name for c in catalog.CASES}
    for expected in (
        "msb_L9_putty_58", "msb_L8_tpmfail_1000", "reuse_full_needle_2000",
        "msb_L12_needle3pct_1500", "msb_L1_minerva_2100",
    ):
        assert expected in names

def test_every_case_builds_a_small_slice():
    # Build a small slice of each case to prove params are well-formed (cheap:
    # does not generate the full count). The slice must be >= the largest
    # structural minimum across the corpus: reuse_full_needle needs
    # groups*group_size = 3*2 = 6 signatures, so use 8.
    SLICE_N = 8
    for c in catalog.CASES:
        txt, sc = composer.build_case(c.family, dict(c.params, _name=c.name), SLICE_N, c.seed)
        assert sc["count"] == SLICE_N
        assert len(sc["signatures"]) == SLICE_N
        assert sc["composition"]["family"] == c.family
