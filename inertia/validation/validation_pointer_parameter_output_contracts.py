"""Typed contracts for final pointer-parameter output validation.

Layer: Tail validation.
Responsibility: represent normalized pointer-write obligations, deterministic
failures, and closed evidence counts. This module performs no AST traversal,
semantic recovery, mutation, or rendering.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PointerParameterOutputIssueKind8616(StrEnum):
    """Stable reasons one proven pointer output is absent from final C."""

    INTERFACE_UNAVAILABLE = "interface_unavailable"
    MISSING_WRITE = "missing_write"


@dataclass(frozen=True, slots=True)
class PointerParameterWriteRequirement8616:
    """One normalized byte range written through a logical pointer input."""

    logical_index: int
    stack_offset: int
    relative_offset: int
    width: int


@dataclass(frozen=True, slots=True)
class PointerParameterOutputIssue8616:
    """One final-AST failure for an exact pointer-output requirement."""

    kind: PointerParameterOutputIssueKind8616
    requirement: PointerParameterWriteRequirement8616

    def token(self) -> str:
        """Return a deterministic diagnostic token."""
        requirement = self.requirement
        return (
            f"{self.kind.value}-pointer-parameter-write:"
            f"arg={requirement.logical_index}:bp={requirement.stack_offset}:"
            f"offset={requirement.relative_offset}:width={requirement.width}"
        )


@dataclass(frozen=True, slots=True)
class PointerParameterOutputValidationReport8616:
    """Closed evidence result for final pointer-parameter writes."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[PointerParameterOutputIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every proven pointer output remains materialized."""
        return self.failure_count == 0 and not self.issues

    def issue_tokens(self) -> tuple[str, ...]:
        """Return stable tokens for canonical validation snapshots."""
        return tuple(issue.token() for issue in self.issues)


__all__ = [
    "PointerParameterOutputIssue8616",
    "PointerParameterOutputIssueKind8616",
    "PointerParameterOutputValidationReport8616",
    "PointerParameterWriteRequirement8616",
]
