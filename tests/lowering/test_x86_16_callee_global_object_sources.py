from __future__ import annotations

from types import SimpleNamespace

import inertia.lowering.callee_global_object_sources as sources_module
from inertia.lowering.callee_global_object_evidence import (
    CalleeGlobalObjectSourceFamilyFact8616,
)
from inertia.lowering.callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
    collect_project_global_object_source_evidence_8616,
    join_global_object_source_facts_8616,
)
from inertia.lowering.callee_pointer_evidence import (
    CalleePointerArgumentEvidence8616,
)
from inertia.lowering.indexed_global_evidence import (
    IndexedSegmentedGlobalEvidence8616,
    merge_global_object_source_evidence_8616,
)

from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)


def _fact(family_base_offset: int = 0x08F0) -> CalleeGlobalObjectSourceFamilyFact8616:
    return CalleeGlobalObjectSourceFamilyFact8616(
        target_addr=0x107B8,
        callsite_addr=0x10929,
        argument_index=0,
        base_offset=0x0B4E,
        canonical_base_offset=0x0B4C,
        index_identity=(("stack", "bp", -2), ("shl", 1)),
        family_base_offset=family_base_offset,
        element_width=2,
        field_offsets=(0, 1),
    )


def test_caller_source_join_refuses_conflicting_families_for_one_base() -> None:
    evidence = join_global_object_source_facts_8616(
        0x108D0,
        (_fact(0x08F0), _fact(0x1200)),
    )

    assert evidence.raw_fact_count == evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == evidence.materialized_count == 0
    assert evidence.failure_count == 2
    assert evidence.source_facts == ()


def test_caller_source_merge_retains_symbol_name_and_adds_family_type() -> None:
    source_evidence = GlobalObjectSourceEvidence8616(
        scope_addr=0x108D0,
        source_facts=(_fact(),),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
    )
    existing = IndexedSegmentedGlobalEvidence8616(
        base_offset=0x0B4E,
        name="existing_symbol",
        relative_disp=0,
        width=1,
    )

    merged, census = merge_global_object_source_evidence_8616(
        (existing,),
        source_evidence,
    )
    by_key = {(item.base_offset, item.width): item for item in merged}

    assert census.materialized_count == 1
    assert census.failure_count == 0
    assert by_key[(0x0B4E, 1)].name == "g_0B4C"
    assert by_key[(0x0B4E, 1)].relative_disp == 2
    assert by_key[(0x0B4E, 1)].aggregate_type_name == "g_08F0"
    assert by_key[(0x0B4E, 2)].aggregate_type_name == "g_08F0"
    assert by_key[(0x0B4F, 1)].aggregate_type_name == "g_08F0"


def test_caller_source_merge_refuses_existing_incompatible_aggregate() -> None:
    source_evidence = GlobalObjectSourceEvidence8616(
        scope_addr=0x108D0,
        source_facts=(_fact(),),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
    )
    existing = IndexedSegmentedGlobalEvidence8616(
        base_offset=0x0B4E,
        name="existing_symbol",
        relative_disp=0,
        width=2,
        aggregate_type_name="g_1200",
    )

    merged, census = merge_global_object_source_evidence_8616(
        (existing,),
        source_evidence,
    )

    assert merged == (existing,)
    assert census.materialized_count == 0
    assert census.failure_count == 1


def test_project_source_collection_caches_proven_pointer_targets(monkeypatch) -> None:
    pointer_evidence = CalleePointerArgumentEvidence8616(
        target_addr=0x107B8,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        pointer_stack_offsets=(4, 6),
        pointer_argument_indices=(0, 1),
        ambiguous_displaced_stack_offsets=(),
    )
    project = SimpleNamespace(
        _inertia_callee_pointer_argument_evidence_8616={0x107B8: pointer_evidence},
    )
    layout_evidence = GlobalObjectLayoutEvidence8616(
        layouts=(),
        raw_fact_count=0,
        normalized_fact_count=0,
        classified_fact_count=0,
        materialized_count=0,
    )
    calls: list[int] = []

    def collect(_project: object, target_addr: int, _layouts: object) -> SimpleNamespace:
        calls.append(target_addr)
        return SimpleNamespace(
            source_facts=(_fact(),),
            family_base_offset=0x08F0,
            callsite_addrs=(0x10929,),
        )

    monkeypatch.setattr(
        sources_module,
        "collect_callee_global_object_interface_evidence_8616",
        collect,
    )

    first = collect_project_global_object_source_evidence_8616(
        project,
        layout_evidence,
    )
    second = collect_project_global_object_source_evidence_8616(
        project,
        layout_evidence,
    )

    assert first is second
    assert first.pointer_target_addrs == (0x107B8,)
    assert first.source_facts == (_fact(),)
    assert calls == [0x107B8]
