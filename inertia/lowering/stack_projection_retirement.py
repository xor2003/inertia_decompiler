# cython: language_level=3, infer_types=True
"""Retain the legacy stack-projection retirement result contract.

Layer: Types/Lowering.
Responsibility: preserve serialized compatibility for older Lowering artifacts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

Do not retire an angr stack variable merely because its entry-SP coordinate
differs from a machine-BP offset. Angr's C-variable surface owns the entry-SP
coordinate, so offset-only retirement can delete the authoritative variable.
New Lowering code must materialize the proven entry-SP projection directly.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from inertia.ir.core import IRAddress
import dataclasses
import operator

__all__ = [
    "StackProjectionRetirementArtifact8616",
    "StackProjectionRetirementStats8616",
    "retire_materialized_entry_sp_projections_8616",
]


class _BPProjectionCandidate8616(Protocol):
    """Exact machine-BP object and its proven entry-SP projection."""

    @property
    def address(self) -> IRAddress:
        """Return the exact machine-BP storage identity."""
        ...

    @property
    def entry_sp_offset(self) -> cython.longlong:
        """Return the proven equivalent angr entry-SP offset."""
        ...


@dataclasses.dataclass(frozen=True, )
class StackProjectionRetirementStats8616:
    """Closed evidence accounting for retired declaration projections."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every exact projected declaration was retired."""
        return (
            operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
        )

    def to_dict(self) -> dict[str, cython.longlong]:
        """Return the mandatory five evidence counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclasses.dataclass(frozen=True, )
class StackProjectionRetirementArtifact8616:
    """Exact obsolete declaration identities removed from angr surfaces."""

    retired: tuple[tuple[cython.longlong, cython.longlong], ...] = ()
    stats: StackProjectionRetirementStats8616 = StackProjectionRetirementStats8616()

    @property
    def complete(self) -> cython.bint:
        """Return whether retirement evidence closes without failure."""
        return self.stats.complete and self.stats.failure_count == 0

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic diagnostic representation."""
        return {
            "retired": [{"offset": offset, "size": size} for offset, size in iter(self.retired)],
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


@cython.ccall
def retire_materialized_entry_sp_projections_8616(
    codegen,
    candidates,
    materialized_bp_offsets,
) -> StackProjectionRetirementArtifact8616:
    """Return a no-op compatibility artifact without deleting owned variables."""
    del codegen, candidates, materialized_bp_offsets
    return StackProjectionRetirementArtifact8616()
