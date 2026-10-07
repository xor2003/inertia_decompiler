from __future__ import annotations

from types import SimpleNamespace

import pytest
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
    transfer_project_global_source_evidence_8616,
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


def test_project_global_source_transfer_copies_coherent_bundle() -> None:
    source_project = SimpleNamespace()
    destination_project = SimpleNamespace()
    layout = _layout()
    attach_project_global_object_layout_evidence_8616(source_project, layout)
    attach_project_global_object_layout_evidence_8616(destination_project, layout)
    record_callee_pointer_argument_evidence_8616(source_project, _pointer())
    attach_project_global_object_source_evidence_8616(source_project, _source(layout))

    assert transfer_project_global_source_evidence_8616(
        source_project,
        destination_project,
    ) == (1, 1)
    assert callee_pointer_argument_evidence_by_addr_8616(destination_project) == {
        0x107B8: _pointer()
    }
    assert project_global_object_source_evidence_8616(destination_project) == _source(
        layout
    )


def test_project_global_source_transfer_refuses_missing_pointer_dependency() -> None:
    source_project = SimpleNamespace()
    destination_project = SimpleNamespace()
    layout = _layout()
    attach_project_global_object_layout_evidence_8616(source_project, layout)
    attach_project_global_object_layout_evidence_8616(destination_project, layout)
    attach_project_global_object_source_evidence_8616(source_project, _source(layout))

    with pytest.raises(ValueError, match="pointer census"):
        transfer_project_global_source_evidence_8616(
            source_project,
            destination_project,
        )
