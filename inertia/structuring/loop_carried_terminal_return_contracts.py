"""Typed contracts for loop-carried terminal return materialization.

Layer: Structuring.
Responsibility: define stable outcomes, refusal reasons, and closed evidence
accounting for the loop-carried AX Structuring owner.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from archinfo import Arch

__all__ = [
    "LoopCarriedTerminalReturnEvidence8616",
    "LoopCarriedTerminalReturnRefusal8616",
    "LoopCarriedTerminalReturnResult8616",
    "LoopCarriedTerminalReturnStatus8616",
]


class LoopCarriedTerminalReturnStatus8616(Enum):
    """Typed outcome of one loop-carried terminal-return decision."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED = "refused"
    ALREADY_MATERIALIZED = "already_materialized"
    MATERIALIZED = "materialized"


class LoopCarriedTerminalReturnRefusal8616(Enum):
    """Reason one candidate was conservatively retained without projection."""

    NONE = "none"
    NOT_APPLICABLE = "not_applicable"
    MISSING_FUNCTION = "missing_function"
    TERMINAL_STORAGE_NOT_AX = "terminal_storage_not_ax"
    INCOMPLETE_STRUCTURED_SHAPE = "incomplete_structured_shape"
    AMBIGUOUS_AX_DEFINITION = "ambiguous_ax_definition"
    UNSAFE_AX_FLOW = "unsafe_ax_flow"
    MISSING_TYPED_WORD = "missing_typed_word"
    MISSING_INSTRUCTION_IDENTITY = "missing_instruction_identity"


@dataclass(frozen=True, slots=True)
class LoopCarriedTerminalReturnEvidence8616:
    """Closed evidence accounting for one loop-carried AX projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class LoopCarriedTerminalReturnResult8616:
    """Result of preserving one loop-carried terminal AX value."""

    changed: bool
    status: LoopCarriedTerminalReturnStatus8616
    refusal: LoopCarriedTerminalReturnRefusal8616
    evidence: LoopCarriedTerminalReturnEvidence8616


class _FunctionSurface8616(Protocol):
    """angr function fields consumed by terminal-storage Semantics."""

    addr: int
    block_addrs_set: set[int]


class _FunctionManagerSurface8616(Protocol):
    """Function-manager lookup used at the third-party project boundary."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return one existing function without creating it."""


class _KnowledgeBaseSurface8616(Protocol):
    """Knowledge-base fields consumed by the Structuring owner."""

    functions: _FunctionManagerSurface8616


class _ProjectSurface8616(Protocol):
    """Project fields consumed by the Structuring owner."""

    arch: Arch
    kb: _KnowledgeBaseSurface8616


class _CFunctionSurface8616(Protocol):
    """Structured function fields inspected and updated by the owner."""

    addr: int
    functy: object
    statements: object


class _CodegenSurface8616(Protocol):
    """Structured-codegen fields consumed and updated by the owner."""

    cfunc: _CFunctionSurface8616
    _inertia_loop_carried_terminal_return_result_8616: LoopCarriedTerminalReturnResult8616
