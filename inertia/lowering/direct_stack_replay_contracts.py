# cython: language_level=3, infer_types=True
"""Define immutable contracts for direct-stack replay scheduling.

Layer: Types/Lowering.
Responsibility: represent direct-stack replay inputs, policy, stable state, and
closed execution accounting without inspecting or mutating third-party ASTs.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.pipeline.structured_ast_generation import StructuredAstGeneration8616

from .consumed_call_push_evidence import ConsumedCallPushEvidenceResult8616
import dataclasses
import operator

__all__ = [
    "DirectStackCallsiteProjection8616",
    "DirectStackConsumerGeneration8616",
    "DirectStackConsumerGenerationScope8616",
    "DirectStackMaterializationResult8616",
    "DirectStackReplayGeneration8616",
    "DirectStackReplayOptions8616",
    "DirectStackReplayRequest8616",
    "DirectStackReplayState8616",
    "DirectStackReplayStats8616",
]


@dataclasses.dataclass(frozen=True, )
class DirectStackCallsiteProjection8616:
    """Callsite fields consumed by direct-stack fact and cleanup lowering."""

    inventory_addr: cython.longlong
    callsite_addr: cython.longlong
    target_addr: int | None
    return_addr: int | None
    arg_count: int | None
    arg_widths: object
    stack_cleanup: int | None
    stack_cleanup_instruction_addr: int | None
    consumed_push_evidence: ConsumedCallPushEvidenceResult8616


@dataclasses.dataclass(frozen=True, )
class DirectStackConsumerGeneration8616:
    """Authoritative invalidation generation inside one covered owner scope."""

    value: cython.longlong


@dataclasses.dataclass(frozen=True, )
class DirectStackConsumerGenerationScope8616:
    """Previous active generation restored when one covered scope closes."""

    previous: DirectStackConsumerGeneration8616 | None


@dataclasses.dataclass(frozen=True, )
class DirectStackMaterializationResult8616:
    """Closed direct-stack owner result that needs no whole-AST witness."""

    changed: cython.bint
    evidence_closed: cython.bint = True


@dataclasses.dataclass(frozen=True, )
class DirectStackReplayGeneration8616:
    """AST and typed evidence consumed by direct-stack lowering."""

    ast: StructuredAstGeneration8616 | None
    callsites: object
    attached_facts: object
    function_facts: object
    function_addr: int | None
    consumer_generation: DirectStackConsumerGeneration8616 | None = None

    def __post_init__(self) -> None:
        """Require exactly one authoritative structured-surface generation."""
        if (self.ast is None) == (self.consumer_generation is None):
            raise ValueError(
                "direct-stack replay requires exactly one AST or consumer generation"
            )


@dataclasses.dataclass(frozen=True, )
class DirectStackReplayOptions8616:
    """Every public option that changes direct-stack materialization behavior."""

    allow_stack_slot_fallback: cython.bint
    source_kind_values: object
    materialize_reloads: cython.bint


@dataclasses.dataclass(frozen=True, )
class DirectStackReplayRequest8616:
    """One exact direct-stack generation and execution policy."""

    generation: DirectStackReplayGeneration8616
    options: DirectStackReplayOptions8616


@dataclasses.dataclass(frozen=True, )
class DirectStackReplayStats8616:
    """Closed accounting for executed, changed, stable, skipped, and failed work."""

    attempt_count: cython.longlong = 0
    changed_count: cython.longlong = 0
    stable_count: cython.longlong = 0
    skipped_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def closed(self) -> cython.bint:
        """Return whether every attempted execution has one terminal outcome."""
        return bool(
            operator.eq(self.attempt_count, self.changed_count + self.stable_count + self.failure_count)
            and min(
                self.attempt_count,
                self.changed_count,
                self.stable_count,
                self.skipped_count,
                self.failure_count,
            )
            >= 0
        )


@dataclasses.dataclass(frozen=True, )
class DirectStackReplayState8616:
    """Completed stable request and closed replay accounting for one codegen."""

    stable_request: DirectStackReplayRequest8616 | None = None
    stats: DirectStackReplayStats8616 = DirectStackReplayStats8616()
