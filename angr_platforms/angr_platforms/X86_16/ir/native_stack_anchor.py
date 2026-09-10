"""Preserve native address coordinates through SSA conversion.

Layer: IR.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
Responsibility: carry an exact entry-SP address origin, not stack ownership.
Only the native StackBaseOffset conversion may publish this tag. Consumers
must additionally prove their frame coordinate; apparent variable offsets
and names are not substitutes for source provenance.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

NATIVE_ENTRY_SP_ANCHOR_TAG8616: str = "inertia_native_entry_sp_anchor_8616"


@dataclass(frozen=True, slots=True)
class NativeStackAnchor8616:
    """Exact source address before native SSA replaces it with a reference."""

    entry_sp_offset: int


@dataclass(slots=True)
class NativeStackAnchorStats8616:
    """SSA-boundary census of exact publications and refused replacements."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def record(self, published: bool) -> None:
        """Account for one native source and its publication or refusal."""
        self.raw_fact_count += 1
        self.normalized_fact_count += 1
        self.classified_fact_count += 1
        self.materialized_count += int(published)
        self.failure_count += int(not published)


def native_stack_anchor_8616(tags: Mapping[str, object] | None) -> NativeStackAnchor8616 | None:
    """Read a primitive, cache-serializable coordinate; refuse malformed tags."""
    value = tags.get(NATIVE_ENTRY_SP_ANCHOR_TAG8616) if tags is not None else None
    return NativeStackAnchor8616(value) if type(value) is int else None
