"""Publish direct-stack invalidation generations for covered owner scopes.

Layer: Types/Lowering.
Responsibility: expose a cheap typed generation only while every mutation that
can invalidate direct-stack replay is published by the enclosing owner.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic boundary: generation state is attached to third-party angr codegen.
"""

from __future__ import annotations

import contextlib
from typing import Any, Protocol, cast

from .direct_stack_replay_contracts import (
    DirectStackConsumerGeneration8616,
    DirectStackConsumerGenerationScope8616,
)

__all__ = [
    "advance_direct_stack_consumer_generation_8616",
    "begin_direct_stack_consumer_generation_scope_8616",
    "current_direct_stack_consumer_generation_8616",
    "end_direct_stack_consumer_generation_scope_8616",
]


class _ConsumerGenerationBoundary8616(Protocol):
    """Dynamic codegen fields owned by direct-stack invalidation tracking."""

    _inertia_direct_stack_consumer_generation_8616: DirectStackConsumerGeneration8616
    _inertia_direct_stack_consumer_generation_counter_8616: int


def current_direct_stack_consumer_generation_8616(
    codegen: object,
) -> DirectStackConsumerGeneration8616 | None:
    """Read the active authoritative generation from the codegen boundary."""
    try:
        generation = cast(
            _ConsumerGenerationBoundary8616,
            codegen,
        )._inertia_direct_stack_consumer_generation_8616
    except AttributeError:
        return None
    return generation if isinstance(generation, DirectStackConsumerGeneration8616) else None


def begin_direct_stack_consumer_generation_scope_8616(
    codegen: object,
) -> DirectStackConsumerGenerationScope8616:
    """Begin one scope whose owners publish every direct-stack invalidation."""
    boundary = cast(_ConsumerGenerationBoundary8616, codegen)
    previous = current_direct_stack_consumer_generation_8616(codegen)
    try:
        counter = boundary._inertia_direct_stack_consumer_generation_counter_8616
    except AttributeError:
        counter = 0
    boundary._inertia_direct_stack_consumer_generation_counter_8616 = counter + 1
    boundary._inertia_direct_stack_consumer_generation_8616 = (
        DirectStackConsumerGeneration8616(counter + 1)
    )
    return DirectStackConsumerGenerationScope8616(previous=previous)


def advance_direct_stack_consumer_generation_8616(
    codegen: object,
) -> DirectStackConsumerGeneration8616 | None:
    """Advance the active generation after a covered owner invalidates replay."""
    if current_direct_stack_consumer_generation_8616(codegen) is None:
        return None
    boundary = cast(_ConsumerGenerationBoundary8616, codegen)
    counter = boundary._inertia_direct_stack_consumer_generation_counter_8616 + 1
    generation = DirectStackConsumerGeneration8616(counter)
    boundary._inertia_direct_stack_consumer_generation_counter_8616 = counter
    boundary._inertia_direct_stack_consumer_generation_8616 = generation
    return generation


def end_direct_stack_consumer_generation_scope_8616(
    codegen: object,
    scope: DirectStackConsumerGenerationScope8616,
) -> None:
    """Restore the generation active before one covered owner scope began."""
    if scope.previous is None:
        with contextlib.suppress(AttributeError):
            del cast(Any, codegen)._inertia_direct_stack_consumer_generation_8616
        return
    cast(
        _ConsumerGenerationBoundary8616,
        codegen,
    )._inertia_direct_stack_consumer_generation_8616 = scope.previous
