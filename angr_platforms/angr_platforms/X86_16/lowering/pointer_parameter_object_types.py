"""Prove pointee-object families for accepted pointer-output contracts.

Layer: Types/Lowering.
Responsibility: join complete interprocedural pointer-output objects with exact
Widening-owned global layouts. An exact target must anchor each object family;
scaled targets may then share that family only with proven modular alignment.
This module does not mutate codegen, infer bounds, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..ir import MemSpace
from ..widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from .pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputObject8616,
)
from .pointer_parameter_object_type_contracts import (
    PointerParameterObjectTypeEvidence8616,
    PointerParameterObjectTypeFact8616,
    PointerParameterObjectTypeFailure8616,
    PointerParameterObjectTypeStats8616,
    PointerParameterObjectTypeView8616,
)


def _refused_8616(
    function_addr: int,
    raw_count: int,
    normalized_count: int,
    failure: PointerParameterObjectTypeFailure8616,
    *,
    logical_index: int | None = None,
    callsite_addr: int | None = None,
) -> PointerParameterObjectTypeEvidence8616:
    """Build one atomic refusal without publishing partial type facts."""
    return PointerParameterObjectTypeEvidence8616(
        function_addr,
        (),
        failure,
        PointerParameterObjectTypeStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
        logical_index=logical_index,
        callsite_addr=callsite_addr,
    )


def _output_field_offsets_8616(
    source: PointerParameterMemoryOutputObject8616,
) -> tuple[int, ...]:
    """Return exact relative STORE starts retained by one output view."""
    return tuple(
        sorted(
            {
                alias_output.terminal_output.relative_offset
                for alias_output in source.source.output_view.alias_outputs
            }
        )
    )


def _anchor_layouts_8616(
    source: PointerParameterMemoryOutputObject8616,
    layouts: Sequence[GlobalObjectLayout8616],
) -> tuple[GlobalObjectLayout8616, ...]:
    """Return exact-address layouts matching this output object's full shape."""
    output = source.source.output_view
    target_offsets = {view.effect.target_base_offset for view in source.views}
    field_offsets = _output_field_offsets_8616(source)
    return tuple(
        layout
        for layout in layouts
        if layout.complete
        and layout.address.space is output.segment is MemSpace.DS
        and output.relative_offset == 0
        and layout.element_width == output.width
        and layout.field_offsets == field_offsets
        and layout.address.offset in target_offsets
    )


def _object_type_fact_8616(
    source: PointerParameterMemoryOutputObject8616,
    layout_evidence: GlobalObjectLayoutEvidence8616,
    function_addr: int,
    raw_count: int,
    normalized_count: int,
) -> PointerParameterObjectTypeFact8616 | PointerParameterObjectTypeEvidence8616:
    """Join one accepted pointer output to its proven object-family fact."""
    output = source.source.output_view
    if (
        output.segment is not MemSpace.DS
        or output.relative_offset != 0
        or output.width <= 0
        or not _output_field_offsets_8616(source)
    ):
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.OUTPUT_SHAPE_UNSUPPORTED,
            logical_index=source.source.logical_index,
        )
    anchors = _anchor_layouts_8616(
        source,
        layout_evidence.layouts,
    )
    if not anchors:
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.LAYOUT_ANCHOR_UNMATCHED,
            logical_index=source.source.logical_index,
        )
    families = {layout.family_base_offset for layout in anchors}
    if len(families) != 1:
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.LAYOUT_FAMILY_CONFLICT,
            logical_index=source.source.logical_index,
        )
    layout = min(
        anchors,
        key=lambda item: (
            item.address.offset,
            item.element_width,
            item.field_offsets,
        ),
    )
    views = tuple(
        PointerParameterObjectTypeView8616(view, layout)
        for view in source.views
    )
    failed_view = next((view for view in views if not view.complete), None)
    if failed_view is not None:
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.TARGET_ALIGNMENT_UNPROVEN,
            logical_index=source.source.logical_index,
            callsite_addr=failed_view.source.callsite_addr,
        )
    fact = PointerParameterObjectTypeFact8616(source, layout, views)
    if not fact.complete:
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.UPSTREAM_CONTRACT_REFUSED,
            logical_index=source.source.logical_index,
        )
    return fact


def recover_pointer_parameter_object_types_8616(
    function_addr: int,
    objects: Sequence[PointerParameterMemoryOutputObject8616],
    layout_evidence: GlobalObjectLayoutEvidence8616,
) -> PointerParameterObjectTypeEvidence8616:
    """Join every accepted pointer-output target to one proven object family."""
    raw_count = sum(len(source.views) for source in objects)
    if not objects:
        return PointerParameterObjectTypeEvidence8616(
            function_addr,
            (),
            None,
            PointerParameterObjectTypeStats8616(),
        )
    if not all(source.complete for source in objects):
        return _refused_8616(
            function_addr,
            raw_count,
            0,
            PointerParameterObjectTypeFailure8616.UPSTREAM_CONTRACT_REFUSED,
        )
    normalized_count = raw_count
    if not layout_evidence.closed:
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.LAYOUT_EVIDENCE_OPEN,
        )
    logical_indices = tuple(source.source.logical_index for source in objects)
    if len(set(logical_indices)) != len(logical_indices):
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.DUPLICATE_LOGICAL_INDEX,
        )

    facts: list[PointerParameterObjectTypeFact8616] = []
    for source in sorted(objects, key=lambda item: item.source.logical_index):
        outcome = _object_type_fact_8616(
            source,
            layout_evidence,
            function_addr,
            raw_count,
            normalized_count,
        )
        if isinstance(outcome, PointerParameterObjectTypeEvidence8616):
            return outcome
        facts.append(outcome)

    evidence = PointerParameterObjectTypeEvidence8616(
        function_addr,
        tuple(facts),
        None,
        PointerParameterObjectTypeStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=raw_count,
        ),
    )
    if not evidence.complete:
        return _refused_8616(
            function_addr,
            raw_count,
            normalized_count,
            PointerParameterObjectTypeFailure8616.UPSTREAM_CONTRACT_REFUSED,
        )
    return evidence


__all__ = ["recover_pointer_parameter_object_types_8616"]
