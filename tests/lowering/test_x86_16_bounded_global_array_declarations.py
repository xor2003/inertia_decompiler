from __future__ import annotations

from types import SimpleNamespace

import pytest
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.indexed_address_contracts import (
    IndexedAddressAccessKind8616,
)
from inertia.ir.indexed_address_range_witnesses import (
    IndexedLoopProofSite8616,
)
from inertia.lowering.bounded_global_array_declarations import (
    BoundedGlobalArrayLoweringFailureKind8616,
    BoundedGlobalArrayLoweringStatus8616,
    materialize_project_bounded_global_arrays_8616,
)
from inertia.lowering.global_declaration_extents import (
    GlobalDeclarationExtentApplicationStatus8616,
)
from inertia.lowering.indexed_global_evidence import (
    IndexedSegmentedGlobalEvidence8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.lowering.codegen_metadata import GlobalDeclarationArrayExtent8616
from inertia.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
    ProjectBoundedGlobalObjectRangeSource8616,
    ProjectBoundedGlobalObjectRangeSourceKind8616,
    ProjectBoundedGlobalObjectRangeSourceStatus8616,
)
from inertia.widening.indexed_global_object_ranges import (
    BoundedGlobalObjectRange8616,
    BoundedGlobalObjectRangeFailureKind8616,
    BoundedGlobalObjectRangeRefusal8616,
    BoundedGlobalObjectRangeStats8616,
    IndexedGlobalAccessKey8616,
)


def _layout() -> GlobalObjectLayoutEvidence8616:
    return GlobalObjectLayoutEvidence8616(
        (
            GlobalObjectLayout8616(
                IRAddress(
                    MemSpace.DS,
                    offset=0x200,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
                2,
                (0, 1),
                0x200,
            ),
        ),
        1,
        1,
        1,
        1,
    )


def _source() -> ProjectBoundedGlobalObjectRangeSource8616:
    return ProjectBoundedGlobalObjectRangeSource8616(
        ProjectBoundedGlobalObjectRangeSourceKind8616.LIVE_ALIAS_PROGRAM,
        ProjectBoundedGlobalObjectRangeSourceStatus8616.COMPLETE,
        1,
        1,
        0,
        1,
    )


def _access_key() -> IndexedGlobalAccessKey8616:
    return IndexedGlobalAccessKey8616(
        0x1000,
        0x1010,
        2,
        0x1014,
        IndexedAddressAccessKind8616.LOAD,
    )


def _accepted_evidence() -> ProjectBoundedGlobalObjectRangeEvidence8616:
    object_range = BoundedGlobalObjectRange8616(
        MemSpace.DS,
        0x200,
        0,
        4,
        2,
        4,
        8,
        (_access_key(),),
        (IndexedLoopProofSite8616(0x1010, 2, 0x1014),),
    )
    return ProjectBoundedGlobalObjectRangeEvidence8616(
        (object_range,),
        (),
        BoundedGlobalObjectRangeStats8616(1, 1, 1, 1, 0),
        _source(),
        _layout(),
    )


def _refused_evidence() -> ProjectBoundedGlobalObjectRangeEvidence8616:
    refusal = BoundedGlobalObjectRangeRefusal8616(
        MemSpace.DS,
        0x200,
        BoundedGlobalObjectRangeFailureKind8616.UNCOVERED_ACCESS,
        "dynamic loop bound leaves the object extent uncovered",
        (_access_key(),),
        (),
    )
    return ProjectBoundedGlobalObjectRangeEvidence8616(
        (),
        (refusal,),
        BoundedGlobalObjectRangeStats8616(1, 1, 1, 0, 1),
        _source(),
        _layout(),
    )


def _indexed_name() -> tuple[IndexedSegmentedGlobalEvidence8616, ...]:
    return (IndexedSegmentedGlobalEvidence8616(0x200, "g_0200", 0, 2),)


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            (
                "unsigned short",
                "g_0200",
                GlobalDeclarationArrayExtent8616.UNKNOWN,
            ),
        )
    )


def test_exact_range_strengthens_existing_declaration_extent_idempotently() -> None:
    project = SimpleNamespace(
        _inertia_project_bounded_global_object_ranges_8616=_accepted_evidence()
    )
    codegen = _codegen()

    assert materialize_project_bounded_global_arrays_8616(
        project, codegen, _indexed_name()
    )
    first = codegen._inertia_bounded_global_array_lowering_evidence_8616
    assert first.closed
    assert first.status is BoundedGlobalArrayLoweringStatus8616.AVAILABLE
    assert first.facts[0].application.status is GlobalDeclarationExtentApplicationStatus8616.APPLIED
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned short", "g_0200", 4),
    )

    assert not materialize_project_bounded_global_arrays_8616(
        project, codegen, _indexed_name()
    )
    second = codegen._inertia_bounded_global_array_lowering_evidence_8616
    assert second.facts[0].application.status is GlobalDeclarationExtentApplicationStatus8616.ALREADY_PRESENT


def test_accepted_range_without_exact_name_hard_fails_with_typed_refusal() -> None:
    project = SimpleNamespace(
        _inertia_project_bounded_global_object_ranges_8616=_accepted_evidence()
    )
    codegen = _codegen()

    with pytest.raises(PipelineHardError, match="were not materialized"):
        materialize_project_bounded_global_arrays_8616(project, codegen, ())

    result = codegen._inertia_bounded_global_array_lowering_evidence_8616
    assert result.closed
    assert result.facts == ()
    assert (
        result.refusals[0].failure
        is BoundedGlobalArrayLoweringFailureKind8616.GLOBAL_NAME_UNPROVEN
    )


def test_refused_dynamic_extent_never_changes_unknown_declaration() -> None:
    project = SimpleNamespace(
        _inertia_project_bounded_global_object_ranges_8616=_refused_evidence()
    )
    codegen = _codegen()
    before = codegen._inertia_global_declaration_specs_8616

    assert not materialize_project_bounded_global_arrays_8616(
        project, codegen, _indexed_name()
    )

    result = codegen._inertia_bounded_global_array_lowering_evidence_8616
    assert result.closed
    assert result.facts == ()
    assert result.refusals == ()
    assert len(result.upstream_refusals) == 1
    assert codegen._inertia_global_declaration_specs_8616 == before
