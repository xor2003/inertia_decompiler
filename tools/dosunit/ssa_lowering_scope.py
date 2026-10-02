"""Typed scope boundaries for binary-derived SSA candidate regions.

Layer: dosunit IR lowering contract.
Responsibility: distinguish open function discovery from a declared region
whose external edges must remain explicit refused obligations.
"""
from __future__ import annotations

from enum import StrEnum


class SuccessorRangePolicy(StrEnum):
    """Whether source-derived successors may extend declared machine-code ranges."""

    DISCOVER = "discover"
    DECLARED_ONLY = "declared_only"


class ScopeBoundaryReason(StrEnum):
    """Typed lowering refusal at a declared machine-code boundary."""

    EXTERNAL_SUCCESSOR = "successor_outside_declared_scope"
    DECLARED_RANGE_MISSING = "declared_candidate_range_missing"
