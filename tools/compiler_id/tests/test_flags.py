from __future__ import annotations

import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from tools.compiler_id import report


def _load_module():
    return report


def test_script_entrypoint_prints_help():
    repo_root = Path(__file__).resolve().parents[3]
    mod_path = repo_root / "scripts" / "report_compiler_matches.py"
    result = subprocess.run(
        [sys.executable, str(mod_path), "--help"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout
    assert "--catalog" in result.stdout


def test_legacy_import_is_the_canonical_module():
    import tools.compiler_id.report as report_compiler_matches

    assert report_compiler_matches is report


def test_package_entrypoint_preserves_help():
    result = subprocess.run(
        [sys.executable, "-m", "tools.compiler_id", "--help"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0
    assert "--catalog" in result.stdout


def test_score_flag_combos_prefers_matching_combo():
    mod = _load_module()
    profiles = {
        "Oa Od": {
            "op:mov": 40.0,
            "shape:bp": 20.0,
            "op:push": 5.0,
            "op:pop": 4.0,
            "op:cmp": 3.0,
            "shape:mem": 3.0,
            "shape:ptr": 2.0,
            "shape:short": 1.0,
            "b4:01020304": 6.0,
        },
        "Ot Oi": {
            "op:imul": 40.0,
            "shape:index": 20.0,
            "op:lea": 5.0,
            "op:shl": 4.0,
            "op:adc": 3.0,
            "shape:sp": 3.0,
            "shape:ptr": 2.0,
            "shape:short": 1.0,
            "b4:aabbccdd": 6.0,
        },
    }
    obs = Counter(
        {
            "op:mov": 20,
            "shape:bp": 8,
            "op:push": 8,
            "op:pop": 8,
            "op:cmp": 6,
            "shape:mem": 6,
            "shape:ptr": 5,
            "shape:short": 2,
            "b4:01020304": 3,
        }
    )
    ranked = mod._score_flag_combos(obs, profiles)
    assert ranked
    assert ranked[0][0] == "Oa Od"
    if len(ranked) > 1:
        assert ranked[0][1] >= ranked[1][1]


def test_flag_marginals_collects_flags_from_top_combos():
    mod = _load_module()
    scores = [("Oa Od", 0.80), ("Oa Ot", 0.70), ("Oi Ot", 0.60)]
    marg = mod._flag_marginals(scores, top_k=3)
    as_dict = dict(marg)
    assert "Oa" in as_dict
    assert "Ot" in as_dict
    assert as_dict["Oa"] > as_dict["Oi"]


def test_build_per_function_flag_report_has_rows(monkeypatch):
    mod = _load_module()

    def fake_capstone(_img: bytes, _offs: list[int]):
        return Counter({"op:mov": 10, "shape:bp": 4}), True

    monkeypatch.setattr(mod, "_extract_capstone_features", fake_capstone)

    profiles = {
        "Oa Od": {
            "op:mov": 30.0,
            "shape:bp": 10.0,
            "op:push": 5.0,
            "op:pop": 5.0,
            "op:cmp": 4.0,
            "shape:mem": 3.0,
            "shape:ptr": 2.0,
            "shape:short": 1.0,
            "b4:11223344": 2.0,
        },
        "Ot Oi": {
            "op:imul": 30.0,
            "shape:index": 10.0,
            "op:lea": 5.0,
            "op:shl": 5.0,
            "op:adc": 4.0,
            "shape:sp": 3.0,
            "shape:ptr": 2.0,
            "shape:short": 1.0,
            "b4:aabbccdd": 2.0,
        },
    }
    image = bytes([0x90] * 512)

    def fake_ngrams(_blob: bytes, _start: int, size: int = 256):
        _ = size
        return Counter(
            {
                "b4:11223344": 20,
                "op:push": 8,
                "op:pop": 8,
                "op:cmp": 6,
                "shape:mem": 6,
                "shape:ptr": 5,
                "shape:short": 2,
            }
        )

    monkeypatch.setattr(mod, "_extract_byte_ngram_features_window", fake_ngrams)
    raw = bytes([0x11, 0x22, 0x33, 0x44] * 200)
    function_entries = [
        {"function": "fn_a", "offset": 32, "module_length": 128, "compilers": ["unknown"]},
        {"function": "fn_b", "offset": 120, "module_length": 128, "compilers": ["unknown"]},
    ]
    report = mod._build_per_function_flag_report(
        image_bytes=image,
        raw_bytes=raw,
        function_entries=function_entries,
        flag_profiles=profiles,
        limit=10,
    )
    assert report
    assert report[0]["function"] in {"fn_a", "fn_b"}
    assert isinstance(report[0]["top_combos"], list)
    assert isinstance(report[0]["top_flags"], list)


def test_aggregate_flag_sets_uses_marginal_flags_not_exact_top_combo():
    mod = _load_module()
    report = [
        {
            "confidence": "medium",
            "gap": 0.08,
            "top_combos": [("Gs Oa Od Zi", 0.86), ("Gs Oa Od On", 0.78)],
            "top_flags": [("Gs", 1.0), ("Oa", 1.0), ("Od", 1.0), ("Zi", 0.45), ("On", 0.35)],
        },
        {
            "confidence": "medium",
            "gap": 0.07,
            "top_combos": [("Gs Oa Od Zi", 0.84), ("Gs Oa Od On", 0.77)],
            "top_flags": [("Gs", 1.0), ("Oa", 1.0), ("Od", 1.0), ("Zi", 0.46), ("On", 0.34)],
        },
    ]
    agg = mod._aggregate_flag_sets(report)
    assert agg
    assert agg[0][0] == "Gs Oa Od"


def test_load_rc_extract_functions_jsonc_and_shift_map():
    mod = _load_module()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "egame_rc.json"
        p.write_text(
            "{\n"
            '  "extract": [\n'
            "    // comment\n"
            '    {"seg":"seg000","begin":"0x13922","from":"sub_13922"},\n'
            '    {"seg":"seg000","begin":"0x15540","from":"sub_15540"},\n'
            '    {"seg":"seg000","begin":"0x0","from":"padding"}\n'
            "  ]\n"
            "}\n",
            encoding="utf-8",
        )
        rows = mod._load_rc_extract_functions(p)
        assert (0x13922, "sub_13922") in rows
        assert (0x15540, "sub_15540") in rows
        assert all(name != "padding" for _, name in rows)

    function_rows = [
        {"offset": 0x3922, "top_combos": [("Gs Oa Od Ol Or", 0.9)], "confidence": "medium", "gap": 0.05},
        {"offset": 0x5540, "top_combos": [("Gs Oa Od Ol Zi", 0.9)], "confidence": "medium", "gap": 0.06},
    ]
    rc_entries = [(0x13922, "sub_13922"), (0x15540, "sub_15540")]
    shift, hits, mapped = mod._map_flags_to_rc_functions(function_rows, rc_entries)
    assert shift == 0x10000
    assert hits == 2
    assert len(mapped) == 2
    assert mapped[0]["rc_name"] == "sub_13922"
