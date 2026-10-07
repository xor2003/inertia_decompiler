from __future__ import annotations

from types import SimpleNamespace

import pytest
import inertia.lowering.project_global_object_source_collection as collection
from inertia.lowering.callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
)
from inertia.lowering.callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
)

from inertia.lowering.analysis_helpers import CallTargetKind8616, CallTargetSeed
from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)


def _layout() -> GlobalObjectLayoutEvidence8616:
    return GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)


def _pointer_evidence(target_addr: int) -> CalleePointerArgumentEvidence8616:
    return CalleePointerArgumentEvidence8616(
        target_addr=target_addr,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        pointer_stack_offsets=(4,),
        pointer_argument_indices=(0,),
        ambiguous_displaced_stack_offsets=(),
    )


def test_complete_project_source_collection_closes_unique_target_census(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_function = SimpleNamespace()

    class Manager:
        def function(self, *, addr: int, create: bool = False) -> object | None:
            assert not create
            return target_function if addr == 0x100 else None

    project = SimpleNamespace(kb=SimpleNamespace(functions=Manager()))
    functions = (SimpleNamespace(addr=1), SimpleNamespace(addr=2))
    targets = {
        1: (
            CallTargetSeed(0x10, 0x100, 0x13, CallTargetKind8616.DIRECT_NEAR_CALL),
            CallTargetSeed(0x20, 0x200, 0x23, CallTargetKind8616.DIRECT_NEAR_CALL),
        ),
        2: (
            CallTargetSeed(0x30, 0x100, 0x33, CallTargetKind8616.CFG_RESOLVED_CALL),
        ),
    }
    monkeypatch.setattr(
        collection,
        "collect_neighbor_call_targets",
        lambda function: targets[function.addr],
    )

    def apply(project_value: object, _function: object, target_addr: int) -> bool:
        record_callee_pointer_argument_evidence_8616(
            project_value,
            _pointer_evidence(target_addr),
        )
        return True

    monkeypatch.setattr(
        collection,
        "apply_callee_pointer_argument_evidence_at_address_8616",
        apply,
    )

    def collect_sources(
        project_value: object,
        layout: GlobalObjectLayoutEvidence8616,
    ) -> GlobalObjectSourceEvidence8616:
        proven = tuple(
            sorted(
                target_addr
                for target_addr, evidence in callee_pointer_argument_evidence_by_addr_8616(
                    project_value
                ).items()
                if evidence.closes_classification
            )
        )
        return GlobalObjectSourceEvidence8616(
            scope_addr=None,
            source_facts=(),
            raw_fact_count=0,
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
            pointer_target_addrs=proven,
            layout_evidence=layout,
        )

    monkeypatch.setattr(
        collection,
        "collect_project_global_object_source_evidence_8616",
        collect_sources,
    )

    result = collection.collect_complete_project_global_object_sources_8616(
        project,
        functions,
        _layout(),
    )

    assert result.call_target_addrs == (0x100, 0x200)
    assert result.raw_fact_count == 3
    assert result.normalized_fact_count == 2
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 1
    assert result.source_evidence.pointer_target_addrs == (0x100,)
