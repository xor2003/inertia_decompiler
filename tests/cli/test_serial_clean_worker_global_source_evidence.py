from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)
from inertia.lowering.callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
    attach_project_global_object_source_evidence_8616,
    project_global_object_source_evidence_8616,
)
from inertia.lowering.callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
)

from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from inertia.cli.project_evidence_transport import (
    attach_project_global_object_layout_evidence_8616,
)
from inertia.cli.serial_clean_worker_evidence import (
    _SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616,
    _hydrate_serial_clean_worker_evidence_8616,
    _read_serial_clean_worker_evidence_8616,
    _write_serial_clean_worker_evidence_8616,
)


def _layout() -> GlobalObjectLayoutEvidence8616:
    return GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)


def _pointer() -> CalleePointerArgumentEvidence8616:
    return CalleePointerArgumentEvidence8616(
        target_addr=0x107B8,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        pointer_stack_offsets=(4,),
        pointer_argument_indices=(0,),
        ambiguous_displaced_stack_offsets=(),
    )


def _source(layout: GlobalObjectLayoutEvidence8616) -> GlobalObjectSourceEvidence8616:
    return GlobalObjectSourceEvidence8616(
        scope_addr=None,
        source_facts=(),
        raw_fact_count=0,
        normalized_fact_count=0,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=0,
        pointer_target_addrs=(0x107B8,),
        layout_evidence=layout,
    )


def test_serial_worker_round_trips_and_hydrates_global_source_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "evidence.json"
    source_project = SimpleNamespace()
    layout = _layout()
    attach_project_global_object_layout_evidence_8616(source_project, layout)
    record_callee_pointer_argument_evidence_8616(source_project, _pointer())
    attach_project_global_object_source_evidence_8616(source_project, _source(layout))

    assert _write_serial_clean_worker_evidence_8616(source_project, evidence_path) == 0
    transported = _read_serial_clean_worker_evidence_8616(evidence_path)

    assert transported.callee_pointer_by_addr == {0x107B8: _pointer()}
    assert transported.global_object_sources == _source(layout)
    destination_project = SimpleNamespace()
    monkeypatch.setenv(_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616, str(evidence_path))
    assert _hydrate_serial_clean_worker_evidence_8616(destination_project) == 0
    assert callee_pointer_argument_evidence_by_addr_8616(destination_project) == {
        0x107B8: _pointer()
    }
    assert project_global_object_source_evidence_8616(destination_project) == _source(
        layout
    )


def test_serial_worker_refuses_global_source_pointer_census_mismatch(
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "evidence.json"
    source_project = SimpleNamespace()
    layout = _layout()
    attach_project_global_object_layout_evidence_8616(source_project, layout)
    attach_project_global_object_source_evidence_8616(source_project, _source(layout))

    with pytest.raises(ValueError, match="pointer census"):
        _write_serial_clean_worker_evidence_8616(source_project, evidence_path)


def test_serial_worker_rebinds_complete_callee_callsite_census(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "evidence.json"
    source_project = SimpleNamespace()
    summary = CallsiteSummary8616(
        0x1110,
        0x2200,
        0x1113,
        "direct_near",
        1,
        (2,),
        2,
        None,
        False,
        push_arg_sources=(("imm", 7),),
        push_arg_instruction_addrs=(0x110E,),
    )
    census = CalleeCallsiteCensus8616(
        0x2200,
        (
            CalleeCallsiteFact8616(
                source_project,
                SimpleNamespace(addr=0x1100),
                0x2200,
                0x1100,
                0x1110,
                summary,
            ),
        ),
        1,
        1,
        0,
    )
    attach_callee_callsite_censuses_8616(source_project, {0x2200: census})
    _write_serial_clean_worker_evidence_8616(source_project, evidence_path)
    destination_project = SimpleNamespace()
    monkeypatch.setenv(_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616, str(evidence_path))

    _hydrate_serial_clean_worker_evidence_8616(destination_project)

    transported = callee_callsite_censuses_by_addr_8616(destination_project)
    assert transported[0x2200].facts[0].evidence_project is destination_project
    assert transported[0x2200].facts[0].summary == summary
