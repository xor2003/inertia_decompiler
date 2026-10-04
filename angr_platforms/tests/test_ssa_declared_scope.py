"""Layer: tests. Responsibility: keep declared candidate-region boundaries closed."""
from pathlib import Path

from test_dosunit_tool import _edge_catalog, _mz_exe

from tools.dosunit import straightline_ssa as S


def _lower(tmp_path: Path, body: bytes, size: int, *, declared: bool) -> dict:
    """Lower exact real16 bytes under the requested boundary policy."""
    exe = tmp_path / "scope.exe"
    exe.write_bytes(_mz_exe(body))
    catalog = _edge_catalog("scope:entry", "entry", offset=0, size=size)
    options = {"successor_range_policy": S.SuccessorRangePolicy.DECLARED_ONLY} if declared else {}
    return S.lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog,
        max_blocks_per_function=8, scan_limit=32, **options)


def test_declared_scope_records_external_edge_without_following(tmp_path: Path) -> None:
    """A proposed boundary cannot authorize expansion into the external tail."""
    body = bytes.fromhex("e902009090b80100c3")
    document = _lower(tmp_path, body, 3, declared=True)
    assert len(document["functions"]) == 1
    assert any(row["reason"] == "successor_outside_declared_scope" for row in document["refusals"])
    assert document["functions"][0]["source"]["transfer"]["kind"] == "direct_successors"
    assert document["parameters"]["successor_range_policy"] == "declared_only"


def test_default_scope_still_discovers_external_successor(tmp_path: Path) -> None:
    document = _lower(tmp_path, bytes.fromhex("e902009090b80100c3"), 3, declared=False)
    assert document["refusals"] == []
    assert any(part["source"]["jumpkind"] == "Ijk_Ret" for part in document["functions"])


def test_declared_scope_keeps_both_internal_branch_arms(tmp_path: Path) -> None:
    document = _lower(tmp_path, bytes.fromhex("83f8007401c3c3"), 7, declared=True)
    assert document["refusals"] == []
    assert sum(part["source"]["jumpkind"] == "Ijk_Ret" for part in document["functions"]) == 2


def test_declared_scope_cannot_grow_split_instruction(tmp_path: Path) -> None:
    document = _lower(tmp_path, bytes.fromhex("d1d2c3"), 1, declared=True)
    assert document["refusals"]
    assert not any(part["source"]["jumpkind"] == "Ijk_Ret" for part in document["functions"])


def test_declared_scope_requires_an_explicit_positive_size(tmp_path: Path) -> None:
    document = _lower(tmp_path, b"\xc3", 0, declared=True)
    assert document["functions"] == []
    assert document["refusals"][0]["reason"] == "declared_candidate_range_missing"


def test_exact_declared_ranges_do_not_admit_extent_holes(tmp_path: Path) -> None:
    """A source extent used for identity cannot authorize execution in its gaps."""
    exe = tmp_path / "gap.exe"
    exe.write_bytes(_mz_exe(bytes.fromhex("eb029090c3c3")))
    project = S._load_lifter_project(exe)
    function = _edge_catalog("gap:entry", "entry", offset=0, size=6)["functions"][0]
    common = {
        'project': project,
        'linked_base': 0x1000,
        'exe_path': exe,
        'exe_digest': S._file_sha256(exe),
        'cache_document': None,
        'cache_stats': {"hits": 0, "misses": 0, "writes": 0, "errors": 0},
        'function': function,
        'segment_paragraphs': {},
        'output_regs': tuple(S.INTERNAL_STATE_REGS),
        'source_ir': "vex",
        'max_blocks_per_function': 8,
        'max_insns_per_function': 16,
        'max_assignments_per_function': 512,
        'scan_limit': 6,
        'follow_call_fallthrough': False,
        'max_lift_block_ms': 10000,
        'successor_range_policy': S.SuccessorRangePolicy.DECLARED_ONLY
    }
    extent_parts, extent_refusals, _ = S._lower_function(**common)
    exact_parts, exact_refusals, _ = S._lower_function(**common,
        declared_linear_ranges=((0x1000, 0x1002), (0x1005, 0x1006)))
    assert len(extent_parts) == 2 and not extent_refusals
    assert len(exact_parts) == 1
    assert any(row["reason"] == "successor_outside_declared_scope" for row in exact_refusals)
