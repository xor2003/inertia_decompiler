from __future__ import annotations

from types import SimpleNamespace

import pytest
from inertia.lowering.callee_global_object_evidence import (
    CalleeGlobalObjectSourceFamilyFact8616,
)
from inertia.lowering.callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
    attach_project_global_object_source_evidence_8616,
    project_global_object_source_evidence_8616,
)
from inertia.lowering.global_object_source_codec import (
    global_object_source_evidence_from_record_8616,
    global_object_source_evidence_record_8616,
)

from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)


def _layout() -> GlobalObjectLayoutEvidence8616:
    return GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)


def _evidence() -> GlobalObjectSourceEvidence8616:
    fact = CalleeGlobalObjectSourceFamilyFact8616(
        target_addr=0x107B8,
        callsite_addr=0x10929,
        argument_index=0,
        base_offset=0x0B4E,
        canonical_base_offset=0x0B4C,
        index_identity=(("stack", "bp", -2), ("shl", 1)),
        family_base_offset=0x08F0,
        element_width=2,
        field_offsets=(0, 1),
    )
    return GlobalObjectSourceEvidence8616(
        scope_addr=None,
        source_facts=(fact,),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        pointer_target_addrs=(0x107B8,),
        layout_evidence=_layout(),
    )


def test_global_object_source_codec_round_trips_exact_evidence() -> None:
    evidence = _evidence()

    assert global_object_source_evidence_from_record_8616(
        global_object_source_evidence_record_8616(evidence)
    ) == evidence


def test_project_global_object_source_attachment_requires_project_scope() -> None:
    project = SimpleNamespace()
    evidence = _evidence()

    attach_project_global_object_source_evidence_8616(project, evidence)

    assert project_global_object_source_evidence_8616(project) == evidence
    with pytest.raises(ValueError, match="local-scope"):
        attach_project_global_object_source_evidence_8616(
            project,
            GlobalObjectSourceEvidence8616(
                scope_addr=0x108D0,
                source_facts=(),
                raw_fact_count=0,
                normalized_fact_count=0,
                classified_fact_count=0,
                materialized_count=0,
                failure_count=0,
            ),
        )


def test_global_object_source_codec_refuses_open_counters() -> None:
    record = global_object_source_evidence_record_8616(_evidence())
    record["classified_fact_count"] = 0

    with pytest.raises(ValueError, match="classified count"):
        global_object_source_evidence_from_record_8616(record)


def test_global_object_source_codec_refuses_untyped_identity_atom() -> None:
    evidence = _evidence()
    fact = evidence.source_facts[0]
    invalid = GlobalObjectSourceEvidence8616(
        scope_addr=None,
        source_facts=(
            CalleeGlobalObjectSourceFamilyFact8616(
                target_addr=fact.target_addr,
                callsite_addr=fact.callsite_addr,
                argument_index=fact.argument_index,
                base_offset=fact.base_offset,
                canonical_base_offset=fact.canonical_base_offset,
                index_identity=(object(),),
                family_base_offset=fact.family_base_offset,
                element_width=fact.element_width,
                field_offsets=fact.field_offsets,
            ),
        ),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        pointer_target_addrs=(fact.target_addr,),
        layout_evidence=evidence.layout_evidence,
    )

    with pytest.raises(TypeError, match="unsupported atom"):
        global_object_source_evidence_record_8616(invalid)


def test_global_object_source_codec_rejects_missing_project_layout() -> None:
    evidence = _evidence()
    invalid = GlobalObjectSourceEvidence8616(
        scope_addr=None,
        source_facts=evidence.source_facts,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=0,
        pointer_target_addrs=evidence.pointer_target_addrs,
    )

    with pytest.raises(ValueError, match="layout dependency"):
        global_object_source_evidence_record_8616(invalid)
