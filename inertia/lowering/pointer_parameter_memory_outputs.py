# cython: language_level=3, infer_types=True
"""Group exact pointer-parameter caller effects under callee outputs.

Layer: Types/Lowering.
Responsibility: validate complete dynamic effects and group them by their
callee-owned pointer-output contract. This module does not infer pointee types,
create direct memory identities, fabricate LIVE_OUT trials, mutate codegen, or
render C. Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from .interprocedural_storage_contracts import CallsiteStorageTrials8616
from .pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputFailure8616,
    PointerParameterMemoryOutputJoin8616,
    PointerParameterMemoryOutputObject8616,
    PointerParameterMemoryOutputStats8616,
    PointerParameterMemoryOutputView8616,
)
from .pointer_parameter_output_contracts import PointerParameterOutputContract8616
import operator
import builtins


@cython.ccall
def _refused_8616(
    failure: PointerParameterMemoryOutputFailure8616,
    raw_count: cython.longlong,
    normalized_count: cython.longlong,
) -> PointerParameterMemoryOutputJoin8616:
    """Build one atomic refusal without retaining partial dynamic objects."""
    return PointerParameterMemoryOutputJoin8616(
        (),
        failure,
        PointerParameterMemoryOutputStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


@cython.ccall
def _source_order_8616(source: PointerParameterOutputContract8616) -> tuple[object, ...]:
    """Return a deterministic primitive key for one callee output source."""
    view = source.output_view
    return (
        source.logical_index,
        source.argument_storage.offset,
        source.argument_storage.size,
        view.segment.value,
        view.relative_offset,
        view.width,
    )


def join_pointer_parameter_memory_outputs_8616(
    callsites: object,
) -> PointerParameterMemoryOutputJoin8616:
    """Group every exact dynamic caller effect under one callee source."""
    previous: object
    callsite: object
    effect: object
    raw_count = sum(len(callsite.pointer_effects) for callsite in iter(callsites))
    normalized_count = 0
    grouped: dict[
        tuple[object, ...],
        tuple[PointerParameterOutputContract8616, list[PointerParameterMemoryOutputView8616]],
    ] = {}
    for callsite in sorted(callsites, key=lambda item: (item.callsite_addr, item.caller_addr)):
        seen: set[cython.longlong] = set()
        for effect in sorted(callsite.pointer_effects, key=lambda item: item.logical_index):
            if not effect.complete:
                return _refused_8616(
                    PointerParameterMemoryOutputFailure8616.INCOMPLETE_EFFECT,
                    raw_count,
                    normalized_count,
                )
            normalized_count += 1
            if (
                operator.ne(effect.callee_addr, callsite.callee_addr)
                or operator.ne(effect.caller_addr, callsite.caller_addr)
                or operator.ne(effect.callsite_addr, callsite.callsite_addr)
            ):
                return _refused_8616(
                    PointerParameterMemoryOutputFailure8616.CALLSITE_CONFLICT,
                    raw_count,
                    normalized_count,
                )
            if effect.logical_index in seen:
                return _refused_8616(
                    PointerParameterMemoryOutputFailure8616.DUPLICATE_EFFECT,
                    raw_count,
                    normalized_count,
                )
            seen.add(effect.logical_index)
            source = effect.source
            source_key = _source_order_8616(source)
            view = PointerParameterMemoryOutputView8616(
                callsite.caller_addr,
                callsite.callee_addr,
                callsite.callsite_addr,
                effect,
            )
            previous = grouped.get(source_key)
            if previous is None:
                grouped[source_key] = (source, [view])
            elif operator.ne(previous[0], source):
                return _refused_8616(
                    PointerParameterMemoryOutputFailure8616.SOURCE_CONFLICT,
                    raw_count,
                    normalized_count,
                )
            else:
                previous[1].append(view)
    objects = tuple(
        PointerParameterMemoryOutputObject8616(source, tuple(views))
        for _key, (source, views) in builtins.iter(sorted(tuple(grouped.items())))
    )
    return PointerParameterMemoryOutputJoin8616(
        objects,
        None,
        PointerParameterMemoryOutputStats8616(
            raw_count,
            raw_count,
            raw_count,
            raw_count,
        ),
    )


__all__ = ["join_pointer_parameter_memory_outputs_8616"]
