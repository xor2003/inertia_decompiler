from __future__ import annotations

from types import SimpleNamespace

from inertia.ir.segment_contract import SegmentFunctionContract
from inertia.semantics.segment_function_summary import SegmentFunctionSummary8616
from inertia.semantics.segment_program_layout_contract import (
    SegmentProgramLayoutAspect8616,
    SegmentProgramLayoutVerdict8616,
)

from inertia.cli.discovery_cache_contract import SourceRegionCatalogEvidence8616
from inertia.cli.segment_program_layout_reporting import (
    attach_segment_program_layout_8616,
    segment_program_function_evidence_matches_item_8616,
    with_segment_program_function_evidence_8616,
)
from inertia.cli.work_items import FunctionWorkItem, FunctionWorkResult

_CLOSED_COUNTS = {
    "raw_fact_count": 0,
    "normalized_fact_count": 0,
    "classified_fact_count": 0,
    "materialized_count": 0,
    "failure_count": 0,
}


def _project() -> SimpleNamespace:
    local = SegmentFunctionContract(function_addr=0x100, summary=dict(_CLOSED_COUNTS))
    summary = SegmentFunctionSummary8616(
        function_addr=0x100,
        local_contract=local,
        summary=dict(_CLOSED_COUNTS),
    )
    return SimpleNamespace(_inertia_segment_function_summaries_8616={0x100: summary})


def _result() -> FunctionWorkResult:
    return FunctionWorkResult(
        index=1,
        status="ok",
        payload="void sub_100(void) {}",
        debug_output="",
        function=SimpleNamespace(addr=0x100),
        function_cfg=None,
    )


def test_worker_result_carries_owned_function_evidence() -> None:
    result = with_segment_program_function_evidence_8616(_result(), _project())

    assert result.segment_program_function_evidence is not None
    assert result.segment_program_function_evidence.function_addr == 0x100
    mismatched_item = FunctionWorkItem(1, None, SimpleNamespace(addr=0x200), recovery_addr=0x200)
    assert not segment_program_function_evidence_matches_item_8616(
        result.segment_program_function_evidence,
        mismatched_item,
    )


def test_parent_attaches_closed_program_contract_without_cli_inference(capsys) -> None:
    project = _project()
    result = with_segment_program_function_evidence_8616(_result(), project)
    item = FunctionWorkItem(1, None, result.function, recovery_addr=0x100)
    discovery = SourceRegionCatalogEvidence8616(1, 1, 1, 1, 0, ())

    contract = attach_segment_program_layout_8616(project, (item,), (result,), discovery)

    assert project._inertia_segment_program_layout_8616 is contract
    assert contract.fact(SegmentProgramLayoutAspect8616.DISCOVERY).verdict is (
        SegmentProgramLayoutVerdict8616.PROVEN
    )
    assert contract.fact(SegmentProgramLayoutAspect8616.PRIMARY_STATIC_DATA).verdict is (
        SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE
    )
    assert "functions=1/1" in capsys.readouterr().err
