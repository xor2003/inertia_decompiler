"""Actual-MZ caller-bound region candidate intake acceptance and refusals."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
from test_binary_callee_intake import CALLEE_LINEAR, CALLER_OFFSET, _image, _lower, _request
from test_dosunit_tool import _edge_function

from tools.dosunit.binary_callee_intake import IntakeRefusalReason
from tools.dosunit.binary_callee_region_contracts import RegionScanBudget, RegionScanRefusalReason, ScanWindow
from tools.dosunit.binary_callee_region_intake import RegionIntakeStatus, intake_uncatalogued_region_candidate

_BUDGET = RegionScanBudget(8, 32, 64, 64)


def _case(tmp_path: Path, body: bytes):
    return _lower(tmp_path, _image(body),
                  [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
                  "region")


def test_actual_branched_callee_candidate(tmp_path: Path) -> None:
    """Both source-derived branch arms close on verified near returns."""
    # test ax,ax ; jz second ; mov ax,1 ; ret ; mov ax,2 ; ret
    body = bytes.fromhex("85c07404b80100c3b80200c3")
    project, document = _case(tmp_path, body)
    result = intake_uncatalogued_region_candidate(
        _request(project, document), window=ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + len(body)),
        budget=_BUDGET)
    assert result.status is RegionIntakeStatus.CANDIDATE, result.to_dict()
    assert len(result.scan.blocks) == 3
    assert len(result.scan.terminals) == 2
    assert result.call_site.computed_target == CALLEE_LINEAR
    assert result.scan.source_bytes == body
    assert result.image_sha256 and result.semantic_sha256
    assert result.to_dict()["status"] == "candidate"


def test_region_rejects_fabricated_call_target(tmp_path: Path) -> None:
    project, document = _case(tmp_path, bytes.fromhex("c3"))
    result = intake_uncatalogued_region_candidate(
        _request(project, copy.deepcopy(document), target=CALLEE_LINEAR + 1),
        window=ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + 16), budget=_BUDGET)
    assert result.status is RegionIntakeStatus.REFUSED
    assert result.source_refusal.reason is IntakeRefusalReason.TARGET_NOT_SOURCE_BOUND
    assert result.scan is None


def test_actual_external_arm_retains_refusal(tmp_path: Path) -> None:
    body = bytes.fromhex("85c07410c3")
    project, document = _case(tmp_path, body)
    result = intake_uncatalogued_region_candidate(
        _request(project, document), window=ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + len(body)),
        budget=_BUDGET)
    assert result.status is RegionIntakeStatus.REFUSED
    assert result.scan.refusal.reason is RegionScanRefusalReason.EXTERNAL_EDGE
    assert result.scan.blocks[0].edges
    assert result.source_refusal is None


def test_candidate_rechecks_bytes_before_publication(tmp_path: Path, monkeypatch) -> None:
    """A changed decoded span cannot publish even after scan completion."""
    from tools.dosunit import binary_callee_region_intake as owner
    project, document = _case(tmp_path, bytes.fromhex("c3"))
    original = owner.scan_candidate_region

    def mutate_after_scan(request):
        scan = original(request)
        project.loader.memory.store(CALLEE_LINEAR, bytes.fromhex("90"))
        return scan

    monkeypatch.setattr(owner, "scan_candidate_region", mutate_after_scan)
    result = owner.intake_uncatalogued_region_candidate(
        _request(project, document), window=ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + 1),
        budget=_BUDGET)
    assert result.status is RegionIntakeStatus.REFUSED
    assert result.source_refusal.reason is IntakeRefusalReason.SOURCE_CHANGED
    assert result.scan.blocks[0].bytes_hex == "c3"


def test_actual_candidate_lowers_full_state_region(tmp_path: Path) -> None:
    """All branched source blocks lower inside the declared exact intervals."""
    from tools.dosunit.binary_callee_region_lowering import RegionLoweringStatus, lower_region_candidate
    from tools.dosunit.real16_call_evidence import group_functions
    body = bytes.fromhex("85c07404b80100c3b80200c3")
    project, document = _case(tmp_path, body)
    request = _request(project, document)
    candidate = intake_uncatalogued_region_candidate(
        request, window=ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + len(body)), budget=_BUDGET)
    result = lower_region_candidate(request, candidate)
    assert result.status is RegionLoweringStatus.LOWERED, result.to_dict()
    assert len(result.parts) == 3
    assert result.function["size"] == len(body)
    assert all(part["source"]["successor_range_policy"] == "declared_only" for part in result.parts)
    assert len(group_functions({"functions": list(result.parts)})) == 1


def test_discovery_publishes_branched_region_without_leaf_claim(tmp_path: Path) -> None:
    """Discovery retains the leaf refusal and publishes complete region parts."""
    from tools.dosunit.binary_callee_discovery import discover_uncatalogued_leaves
    from tools.dosunit.binary_callee_intake import IntakeBudget
    body = bytes.fromhex("85c07404b80100c3b80200c3")
    project, document = _case(tmp_path, body)
    report = discover_uncatalogued_leaves(project, document,
        root_ids=frozenset({"demo.exe:caller"}), leaf_budget=IntakeBudget())
    row = report["requests"][0]
    assert row["status"] == "admitted", row
    assert row["intake_kind"] == "source_bound_region"
    assert row["leaf_attempt"]["status"] == "refused"
    assert row["candidate"]["status"] == "candidate"
    assert len(row["part_ids"]) == 3
    assert report["counters"]["failure_count"] == 0
    assert sum(part["function"]["id"].startswith("demo.exe:binary_intake_")
               for part in document["functions"]) == 3


def test_lowering_keeps_gap_outside_execution_ranges(tmp_path: Path) -> None:
    """Whole-body identity includes a gap while execution admits only spans."""
    from tools.dosunit.binary_callee_region_lowering import RegionLoweringStatus, lower_region_candidate
    body = bytes.fromhex("85c07406c39090909090c3")
    project, document = _case(tmp_path, body)
    request = _request(project, document)
    candidate = intake_uncatalogued_region_candidate(request,
        window=ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + len(body)), budget=_BUDGET)
    result = lower_region_candidate(request, candidate)
    assert result.status is RegionLoweringStatus.LOWERED, result.to_dict()
    assert result.function["size"] == len(body)
    assert sum(part["source"]["machine_code_size"] for part in result.parts) == 6
    assert all(part["source"]["function_machine_code_size"] == len(body) for part in result.parts)
