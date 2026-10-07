from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

from inertia.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from inertia.lowering.callee_global_object_collection import (
    collect_callee_global_object_interface_evidence_8616,
)
from inertia.lowering.callee_global_object_evidence import (
    CalleeGlobalObjectInterfaceVerdict8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    FunctionStorageContract8616,
    FunctionStorageResolution8616,
    ProgramStorageResolution8616,
    StorageTrialStats8616,
    StorageTrialVerdict8616,
)
from inertia.lowering.pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTarget8616,
)
from inertia.lowering.pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputObject8616,
    PointerParameterMemoryOutputView8616,
)
from inertia.lowering.pointer_parameter_object_type_contracts import (
    PointerParameterObjectTypeFailure8616,
)
from inertia.lowering.pointer_parameter_object_types import (
    recover_pointer_parameter_object_types_8616,
)
from inertia.lowering.pointer_parameter_output_contracts import (
    PointerParameterOutputContract8616,
)

from inertia.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)

SWAPS_ADDR = 0x107B8


def _layout(
    offset: int,
    *,
    family_base_offset: int = 0x08F0,
) -> GlobalObjectLayout8616:
    return GlobalObjectLayout8616(
        address=IRAddress(
            space=MemSpace.DS,
            offset=offset,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        element_width=2,
        field_offsets=(0, 1),
        family_base_offset=family_base_offset,
    )


def _layouts(
    *items: GlobalObjectLayout8616,
) -> GlobalObjectLayoutEvidence8616:
    count = len(items)
    return GlobalObjectLayoutEvidence8616(
        layouts=items,
        raw_fact_count=count,
        normalized_fact_count=count,
        classified_fact_count=count,
        materialized_count=count,
    )


def _source(logical_index: int) -> PointerParameterOutputContract8616:
    output_view = SimpleNamespace(
        segment=MemSpace.DS,
        relative_offset=0,
        width=2,
        alias_outputs=(
            SimpleNamespace(
                terminal_output=SimpleNamespace(relative_offset=0),
            ),
            SimpleNamespace(
                terminal_output=SimpleNamespace(relative_offset=1),
            ),
        ),
    )
    return cast(
        PointerParameterOutputContract8616,
        SimpleNamespace(
            logical_index=logical_index,
            output_view=output_view,
            complete=True,
        ),
    )


def _object(
    logical_index: int,
    *,
    offsets: tuple[int, ...] = (0x0B4C, 0x0B4E),
    coefficient: int = 2,
) -> PointerParameterMemoryOutputObject8616:
    source = _source(logical_index)
    views: list[PointerParameterMemoryOutputView8616] = []
    for position, offset in enumerate(offsets):
        caller_addr = 0x1100 + position * 0x100
        callsite_addr = caller_addr + 0x10
        term = SimpleNamespace(
            source=IRAddress(
                space=MemSpace.SS,
                base=("bp",),
                offset=-2 - logical_index * 2,
                size=2,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
            coefficient=coefficient,
        )
        effect = cast(
            PointerParameterCallerTarget8616,
            SimpleNamespace(
                callee_addr=SWAPS_ADDR,
                caller_addr=caller_addr,
                callsite_addr=callsite_addr,
                logical_index=logical_index,
                segment=MemSpace.DS,
                near_offset=SimpleNamespace(width=2, terms=(term,)),
                relative_offset=0,
                width=2,
                source=source,
                target_base_offset=offset,
                complete=True,
            ),
        )
        views.append(
            PointerParameterMemoryOutputView8616(
                caller_addr,
                SWAPS_ADDR,
                callsite_addr,
                effect,
            )
        )
    return PointerParameterMemoryOutputObject8616(source, tuple(views))


def _project_with_contract(
    objects: tuple[PointerParameterMemoryOutputObject8616, ...],
) -> SimpleNamespace:
    contract = FunctionStorageContract8616(
        function_addr=SWAPS_ADDR,
        inputs=(),
        outputs=(),
        stack_delta=0,
        callsites=(),
        pointer_memory_outputs=objects,
    )
    function_resolution = FunctionStorageResolution8616(
        SWAPS_ADDR,
        StorageTrialVerdict8616.ACCEPTED,
        contract,
        (),
        StorageTrialStats8616(),
    )
    program = ProgramStorageResolution8616(
        (),
        (function_resolution,),
        ((SWAPS_ADDR,),),
        (1,),
        StorageTrialStats8616(),
    )
    return SimpleNamespace(
        _inertia_interprocedural_storage_resolution_8616=program,
    )


def test_pointer_output_objects_drive_complete_codegen_type_projection() -> None:
    objects = (_object(0), _object(1))
    layouts = _layouts(_layout(0x08F0), _layout(0x0B4C))
    typed = recover_pointer_parameter_object_types_8616(
        SWAPS_ADDR,
        objects,
        layouts,
    )

    assert typed.complete
    assert typed.failure is None
    assert typed.stats.raw_fact_count == typed.stats.materialized_count == 4
    assert tuple(fact.logical_index for fact in typed.facts) == (0, 1)
    assert {fact.family_base_offset for fact in typed.facts} == {0x08F0}

    projected = collect_callee_global_object_interface_evidence_8616(
        _project_with_contract(objects),
        SWAPS_ADDR,
        layouts,
    )
    assert projected.verdict is CalleeGlobalObjectInterfaceVerdict8616.COMPLETE
    assert projected.family_base_offset == 0x08F0
    assert projected.pointer_argument_indices == (0, 1)
    assert projected.raw_fact_count == projected.normalized_fact_count == 4
    assert projected.classified_fact_count == 2
    assert projected.failure_count == 0
    assert tuple(
        (fact.callsite_addr, fact.argument_index, fact.base_offset)
        for fact in projected.source_facts
    ) == (
        (0x1110, 0, 0x0B4C),
        (0x1210, 0, 0x0B4E),
        (0x1110, 1, 0x0B4C),
        (0x1210, 1, 0x0B4E),
    )


def test_pointer_object_typing_refuses_open_anchor_family_and_alignment() -> None:
    source = _object(0)
    layouts = _layouts(_layout(0x0B4C))

    open_layouts = replace(layouts, raw_fact_count=2)
    open_result = recover_pointer_parameter_object_types_8616(
        SWAPS_ADDR,
        (source,),
        open_layouts,
    )
    assert open_result.facts == ()
    assert (
        open_result.failure
        is PointerParameterObjectTypeFailure8616.LAYOUT_EVIDENCE_OPEN
    )

    unanchored = recover_pointer_parameter_object_types_8616(
        SWAPS_ADDR,
        (_object(0, offsets=(0x0B4E, 0x0B50)),),
        layouts,
    )
    assert unanchored.facts == ()
    assert (
        unanchored.failure
        is PointerParameterObjectTypeFailure8616.LAYOUT_ANCHOR_UNMATCHED
    )

    conflicting = recover_pointer_parameter_object_types_8616(
        SWAPS_ADDR,
        (source,),
        _layouts(
            _layout(0x0B4C),
            _layout(0x0B4E, family_base_offset=0x09F0),
        ),
    )
    assert conflicting.facts == ()
    assert (
        conflicting.failure
        is PointerParameterObjectTypeFailure8616.LAYOUT_FAMILY_CONFLICT
    )

    unaligned_object = _object(0, coefficient=1)
    unaligned = recover_pointer_parameter_object_types_8616(
        SWAPS_ADDR,
        (unaligned_object,),
        layouts,
    )
    assert unaligned.facts == ()
    assert (
        unaligned.failure
        is PointerParameterObjectTypeFailure8616.TARGET_ALIGNMENT_UNPROVEN
    )

    projected = collect_callee_global_object_interface_evidence_8616(
        _project_with_contract((unaligned_object,)),
        SWAPS_ADDR,
        layouts,
    )
    assert projected.verdict is CalleeGlobalObjectInterfaceVerdict8616.UNKNOWN
    assert projected.family_base_offset is None
    assert projected.pointer_argument_indices == ()
    assert projected.failure_count == 1
