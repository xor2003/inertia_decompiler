from __future__ import annotations

import pytest
from inertia.ir.segment_contract import SegmentFactVerdict
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.segment_function_summary import (
    SegmentControlTransferDistance8616,
    SegmentControlTransferFact8616,
    SegmentControlTransferKind8616,
)
from inertia.semantics.segment_program_layout import build_x86_16_segment_program_layout
from inertia.semantics.segment_program_layout_codec import (
    segment_program_function_evidence_from_record_8616,
)
from inertia.semantics.segment_program_layout_contract import (
    SegmentProgramAccessEvidence8616,
    SegmentProgramDiscoveryEvidence8616,
    SegmentProgramEvidenceCoverage8616,
    SegmentProgramFunctionEvidence8616,
    SegmentProgramLayoutAspect8616,
    SegmentProgramLayoutVerdict8616,
    SegmentProgramSupplementalEvidence8616,
)

_CLOSED_COUNTS = {
    "raw_fact_count": 0,
    "normalized_fact_count": 0,
    "classified_fact_count": 0,
    "materialized_count": 0,
    "failure_count": 0,
}


def _discovery(*addrs: int) -> SegmentProgramDiscoveryEvidence8616:
    count = len(addrs)
    return SegmentProgramDiscoveryEvidence8616(tuple(addrs), count, count, count, count, 0)


def _transfer(
    site: int,
    target: int | None,
    *,
    distance: SegmentControlTransferDistance8616 = SegmentControlTransferDistance8616.NEAR,
    verdict: SegmentFactVerdict = SegmentFactVerdict.PROVEN,
) -> SegmentControlTransferFact8616:
    return SegmentControlTransferFact8616(
        instruction_addr=site,
        kind=SegmentControlTransferKind8616.CALL,
        distance=distance,
        target_addr=target,
        return_addr=site + 3,
        verdict=verdict,
    )


def _function(
    addr: int,
    *,
    transfers: tuple[SegmentControlTransferFact8616, ...] = (),
    accesses: tuple[SegmentProgramAccessEvidence8616, ...] = (),
) -> SegmentProgramFunctionEvidence8616:
    return SegmentProgramFunctionEvidence8616(
        function_addr=addr,
        entry_requirements=("ds",),
        accesses=accesses,
        local_clobbered_registers=(),
        restored_registers=(),
        control_transfers=transfers,
        summary=dict(_CLOSED_COUNTS),
    )


def _complete_supplemental() -> SegmentProgramSupplementalEvidence8616:
    complete = SegmentProgramEvidenceCoverage8616.COMPLETE
    return SegmentProgramSupplementalEvidence8616(
        indirect_control_coverage=complete,
        overlay_coverage=complete,
        primary_static_data_coverage=complete,
        primary_static_data_region="image:primary-ds",
        far_data_coverage=complete,
        huge_pointer_coverage=complete,
        entry_relation_coverage=complete,
        cs_ds_entry_relation="distinct",
        ss_ds_entry_relation="distinct",
    )


def test_program_layout_closes_all_independent_facts_deterministically() -> None:
    caller = _function(0x100, transfers=(_transfer(0x110, 0x200),))
    callee = _function(0x200)

    first = build_x86_16_segment_program_layout(
        _discovery(0x100, 0x200),
        (callee, caller),
        _complete_supplemental(),
    )
    second = build_x86_16_segment_program_layout(
        _discovery(0x100, 0x200),
        (caller, callee),
        _complete_supplemental(),
    )

    assert first.to_dict() == second.to_dict()
    assert first.function_addrs == (0x100, 0x200)
    assert first.summary["classified_fact_count"] == len(first.facts)
    assert first.summary["materialized_count"] == len(first.facts)
    assert first.summary["failure_count"] == 0
    assert first.fact(SegmentProgramLayoutAspect8616.FAR_CODE).verdict is (
        SegmentProgramLayoutVerdict8616.PROVEN_ABSENT
    )


def test_program_layout_refuses_incomplete_discovery_and_missing_function_summary() -> None:
    discovery = SegmentProgramDiscoveryEvidence8616((0x100, 0x200), 2, 2, 2, 1, 1, (0x200,))

    contract = build_x86_16_segment_program_layout(discovery, (_function(0x100),), _complete_supplemental())

    assert contract.fact(SegmentProgramLayoutAspect8616.DISCOVERY).verdict is (
        SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE
    )
    assert contract.fact(SegmentProgramLayoutAspect8616.FUNCTION_SUMMARIES).evidence_sites == (0x200,)
    assert contract.fact(SegmentProgramLayoutAspect8616.CONTROL_FLOW).verdict is (
        SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE
    )


def test_program_layout_refuses_unresolved_control_external_clobber_and_overlap() -> None:
    supplemental = _complete_supplemental()
    supplemental = SegmentProgramSupplementalEvidence8616(
        indirect_control_coverage=supplemental.indirect_control_coverage,
        unresolved_indirect_control_sites=(0x130,),
        overlay_coverage=supplemental.overlay_coverage,
        overlap_sites=(0x20,),
        primary_static_data_coverage=supplemental.primary_static_data_coverage,
        primary_static_data_region=supplemental.primary_static_data_region,
        far_data_coverage=supplemental.far_data_coverage,
        huge_pointer_coverage=supplemental.huge_pointer_coverage,
        entry_relation_coverage=supplemental.entry_relation_coverage,
        cs_ds_entry_relation=supplemental.cs_ds_entry_relation,
        ss_ds_entry_relation=supplemental.ss_ds_entry_relation,
    )
    caller = _function(
        0x100,
        transfers=(
            _transfer(
                0x110,
                0x999,
                distance=SegmentControlTransferDistance8616.FAR,
            ),
        ),
    )

    contract = build_x86_16_segment_program_layout(_discovery(0x100), (caller,), supplemental)

    assert contract.fact(SegmentProgramLayoutAspect8616.CONTROL_FLOW).evidence_sites == (0x130,)
    assert contract.fact(SegmentProgramLayoutAspect8616.SEGMENT_EFFECTS).evidence_sites == (0x110,)
    assert contract.fact(SegmentProgramLayoutAspect8616.OVERLAY_FREE).evidence_sites == (0x20,)
    assert contract.fact(SegmentProgramLayoutAspect8616.PRIMARY_STATIC_DATA).verdict is (
        SegmentProgramLayoutVerdict8616.UNKNOWN_REFUSE
    )
    assert contract.fact(SegmentProgramLayoutAspect8616.FAR_CODE).verdict is (
        SegmentProgramLayoutVerdict8616.PROVEN_PRESENT
    )


def test_program_layout_refuses_unknown_segment_access() -> None:
    access = SegmentProgramAccessEvidence8616(
        block_addr=0x100,
        instruction_addr=0x106,
        segment_register="ds",
        physical_source=None,
        verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
    )

    contract = build_x86_16_segment_program_layout(
        _discovery(0x100),
        (_function(0x100, accesses=(access,)),),
        _complete_supplemental(),
    )

    assert contract.fact(SegmentProgramLayoutAspect8616.SEGMENT_EFFECTS).evidence_sites == (0x106,)


def test_transport_refuses_classified_evidence_without_materialization() -> None:
    record = _function(0x100).to_dict()
    record["summary"] = {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 0,
    }

    with pytest.raises(PipelineHardError, match="not fully materialized"):
        segment_program_function_evidence_from_record_8616(record)


@pytest.mark.parametrize("schema", [True, 1.0, "1", None, 2])
def test_transport_requires_integer_schema_version(schema) -> None:
    record = _function(0x100).to_dict()
    record["schema"] = schema
    with pytest.raises(ValueError, match="schema"):
        segment_program_function_evidence_from_record_8616(record)


@pytest.mark.parametrize("container,field,label", [
    ("accesses", "verdict", "access verdict"),
    ("control_transfers", "kind", "transfer kind"),
    ("control_transfers", "distance", "transfer distance"),
    ("control_transfers", "verdict", "transfer verdict"),
])
@pytest.mark.parametrize("value", [None, 1, ""])
def test_transport_identifies_invalid_enum_field(container, field, label, value) -> None:
    evidence = _function(
        0x100,
        transfers=(_transfer(0x110, 0x200),),
        accesses=(SegmentProgramAccessEvidence8616(0x100, 0x106, "ds", "entry:ds", SegmentFactVerdict.PROVEN),),
    )
    record = evidence.to_dict()
    record[container][0][field] = value
    with pytest.raises(ValueError, match=label):
        segment_program_function_evidence_from_record_8616(record)
