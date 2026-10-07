"""Binary-only caller obligations with omitted direct-call leaf catalogs."""

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe
from tools.dosunit.tests.test_real16_loop_calls import _fixture as _loop_fixture

from tools.dosunit.compare.real16_binary_compare import compare_binary16
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_replay import compare_executions, replay
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    Real16Agreement,
    Real16ReplayStatus,
    Real16Vector,
    SegOffset,
)


def _uncatalogued_image(target, leaf):
    """Keep the actual CALL continuation fixed while moving its omitted leaf."""
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xe8" + (target - 0x203).to_bytes(2, "little") + b"\xc3"
    image[target:target + len(leaf)] = leaf
    return _mz_exe(bytes(image))


@pytest.mark.parametrize("leaf,expected", [
    ("b83412c3", "proved"),
    ("b87856c3", "counterexample"),
    ("b8341285c0c3", "counterexample"),
    ("eb00b83412c3", "proved"),
    ("eb00b87856c3", "counterexample"),
    ("eb00c3", "counterexample"),
])
def test_public_uncatalogued_direct_leaf(tmp_path, leaf, expected):
    """Real CALL/body evidence must prove relocation and expose value/flags edits."""
    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(_uncatalogued_image(0x230, bytes.fromhex("b83412c3")))
    candidate.write_bytes(_uncatalogued_image(0x260, bytes.fromhex(leaf)))
    catalog = {
        "schema": "dosunit.functions.v1", "id": "functions:test",
        "module": "demo.exe", "program_kind": "mz_exe", "diagnostics": [],
        "functions": [_edge_function("demo.exe:caller", "caller", offset=0x200, size=4)],
    }
    images = [image_from_mz_bytes(path.read_bytes()) for path in (original, candidate)]
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(
        registers=(("ax", 0), ("sp", 0x100), ("flags", 3)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)),
    )
    executions = [replay(image, entry, vector, instruction_limit=32) for image in images]
    assert all(execution.status is Real16ReplayStatus.RETURNED for execution in executions)
    agreement = compare_executions(*executions).agreement
    assert agreement is (Real16Agreement.AGREED if expected == "proved" else Real16Agreement.MISMATCHED)
    report = compare_binary16(original, candidate, catalog, catalog, selected=("caller",))
    assert report["status"] == expected, report["proof"]["verdicts"]
    assert report["proof"]["verdicts"][0]["method"] == "ssa_z3_complete_call_inlining"
    for side in ("oracle", "candidate"):
        intake = report["callee_intake"][side]
        assert intake["counters"] == {
            "raw_fact_count": 1, "normalized_fact_count": 1,
            "classified_fact_count": 1, "materialized_count": 1, "failure_count": 0,
        }
        request = intake["requests"][0]
        if request.get("intake_kind") == "source_bound_region":
            assert request["candidate"]["scan"]["status"] == "completed"
            assert request["size_origin"] == "source_region_extent"
            assert request["leaf_attempt"]["status"] == "refused"
            assert len(request["part_ids"]) == 2
        else:
            receipt = request["receipt"]
            assert receipt["size_origin"] == "terminal_control_closure"
            assert receipt["leaf_complete"]


@pytest.mark.parametrize("leaf", ["ebfe", "e8fdffc3", "cd21c3", "cb", "c7040000c3", "f7f3c3"])
def test_public_uncatalogued_leaf_requires_body_and_return_proof(tmp_path, leaf):
    """Intake cannot waive branch closure, external effects or saved-return aliasing."""
    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(_uncatalogued_image(0x230, bytes.fromhex("b83412c3")))
    candidate.write_bytes(_uncatalogued_image(0x260, bytes.fromhex(leaf)))
    catalog = {
        "schema": "dosunit.functions.v1", "id": "functions:test",
        "module": "demo.exe", "program_kind": "mz_exe", "diagnostics": [],
        "functions": [_edge_function("demo.exe:caller", "caller", offset=0x200, size=4)],
    }
    report = compare_binary16(original, candidate, catalog, catalog, selected=("caller",))
    assert report["status"] == "unknown", report["proof"]["verdicts"]


def test_public_uncatalogued_leaf_rejects_physical_low_word_collision(tmp_path):
    """Matching low words cannot redirect a real CALL to a different physical body."""
    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(_uncatalogued_image(0x230, bytes.fromhex("b83412c3")))
    image = bytearray(0x10300)
    image[0x200:0x204] = bytes.fromhex("e82d00c3")
    image[0x230:0x232] = bytes.fromhex("ebfe")
    image[0x10230:0x10234] = bytes.fromhex("b83412c3")
    candidate.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1", "id": "functions:test",
        "module": "demo.exe", "program_kind": "mz_exe", "diagnostics": [],
        "functions": [_edge_function("demo.exe:caller", "caller", offset=0x200, size=4)],
    }
    report = compare_binary16(original, candidate, catalog, catalog, selected=("caller",))
    assert report["status"] == "unknown", report["proof"]["verdicts"]


def test_public_loop_composes_omitted_equivalent_leaf(tmp_path):
    """Full loop induction consumes recovered leaf effects and saved-return proofs."""
    original_bytes, catalog = _loop_fixture(bytes.fromhex("43c3"))
    candidate_bytes, other_catalog = _loop_fixture(bytes.fromhex("9043c3"))
    catalog = {**catalog, "functions": catalog["functions"][:1]}
    other_catalog = {**other_catalog, "functions": other_catalog["functions"][:1]}
    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(original_bytes)
    candidate.write_bytes(candidate_bytes)
    report = compare_binary16(original, candidate, catalog, other_catalog, selected=("loop",))
    assert report["status"] == "proved", report["proof"]["verdicts"]
    assert report["proof"]["verdicts"][0]["method"] == "ssa_z3_closed_call_loop_induction"
    assert all(side["counters"]["failure_count"] == 0 for side in report["callee_intake"].values())


def test_public_mapped_caller_discovers_candidate_leaf(tmp_path):
    """An explicit caller-ID proposal must select candidate intake, then prove bytes."""
    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(_uncatalogued_image(0x230, bytes.fromhex("b83412c3")))
    candidate.write_bytes(_uncatalogued_image(0x260, bytes.fromhex("b83412c3")))
    catalog = {
        "schema": "dosunit.functions.v1", "id": "functions:test",
        "module": "demo.exe", "program_kind": "mz_exe", "diagnostics": [],
        "functions": [_edge_function("demo.exe:caller", "caller", offset=0x200, size=4)],
    }
    other = {**catalog, "functions": [_edge_function("demo.exe:renamed", "renamed", offset=0x200, size=4)]}
    mapping = {"schema": "dosunit.mapping.v1", "functions": [
        {"oracle_id": "demo.exe:caller", "candidate_id": "demo.exe:renamed"},
    ]}
    report = compare_binary16(original, candidate, catalog, other, selected=("caller",), mapping=mapping)
    assert report["status"] == "proved", report["proof"]["verdicts"]
    assert report["callee_intake"]["candidate"]["attempted"] == 1


@pytest.mark.parametrize("second_value,expected", [("3412", "proved"), ("7856", "counterexample")])
def test_public_uncatalogued_branch_region(tmp_path, second_value, expected):
    """Full caller comparison accounts for both callee branch arms and flags."""
    original, candidate = tmp_path / "branch-original.exe", tmp_path / "branch-candidate.exe"
    original.write_bytes(_uncatalogued_image(0x230, bytes.fromhex("85c0b83412c3")))
    body = bytes.fromhex("85c07404b83412c3b8" + second_value + "c3")
    candidate.write_bytes(_uncatalogued_image(0x260, body))
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test",
        "module": "demo.exe", "program_kind": "mz_exe", "diagnostics": [],
        "functions": [_edge_function("demo.exe:caller", "caller", offset=0x200, size=4)]}
    report = compare_binary16(original, candidate, catalog, catalog, selected=("caller",))
    assert report["status"] == expected, report
    request = report["callee_intake"]["candidate"]["requests"][0]
    assert request["intake_kind"] == "source_bound_region"
    assert len(request["part_ids"]) == 3
    images = [image_from_mz_bytes(path.read_bytes()) for path in (original, candidate)]
    entry = SegOffset(images[0].load_segment, 0x200)
    vector = Real16Vector(registers=(("ax", 0), ("sp", 0x100), ("flags", 3)),
        segments=(("ss", 0x7000), ("ds", entry.segment), ("es", entry.segment)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(entry.segment, 0x8000)))
    executions = [replay(image, entry, vector, instruction_limit=32) for image in images]
    assert all(item.status is Real16ReplayStatus.RETURNED for item in executions)
    assert compare_executions(*executions).agreement is (
        Real16Agreement.AGREED if expected == "proved" else Real16Agreement.MISMATCHED)
