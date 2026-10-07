"""Project angr entry-SP coordinates into Alias-owned machine-BP ranges.

Layer: Alias.
Responsibility: select one machine-BP offset from complete stack Alias evidence
and a proven typed frame relation. Consumers in Widening and Types/Lowering use
this owner instead of interpreting numerically overlapping coordinate domains.
Do not infer coordinates from names, source, COD, assembly, or rendered C.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.analysis.stack_frame_ir import FrameAccessArtifact, FrameCoordinateStatus8616

from inertia.ir.core import AddressStatus, IRAddress, MemSpace

from .stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616


class StackCoordinateProjectionStatus8616(StrEnum):
    """Typed outcome of one raw stack-coordinate classification."""

    RAW_MACHINE_BP = "raw-machine-bp"
    PROJECTED_ENTRY_SP = "projected-entry-sp"
    AMBIGUOUS = "ambiguous"
    UNPROVEN = "unproven"
    INVALID_RANGE = "invalid-range"


@dataclass(frozen=True, slots=True)
class StackCoordinateProjectionStats8616:
    """Closed evidence accounting for one coordinate classification."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether the single candidate has one explicit outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class StackCoordinateProjection8616:
    """One selected machine-BP offset or an evidence-backed refusal."""

    status: StackCoordinateProjectionStatus8616
    bp_offset: int | None
    stats: StackCoordinateProjectionStats8616

    @property
    def materialized(self) -> bool:
        """Return whether this projection selected one machine-BP offset."""
        return self.bp_offset is not None


def _contains_range_8616(address: IRAddress, offset: int, size: int) -> bool:
    """Return whether one stable Alias address contains the requested range."""
    return (
        address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.offset <= offset
        and address.offset + address.size >= offset + size
    )


def _alias_proves_range_8616(
    source: StackMemorySSAAliasArtifact8616,
    offset: int,
    size: int,
) -> bool:
    """Return whether current complete Alias evidence contains one BP range."""
    if not source.complete:
        return False
    return any(
        _contains_range_8616(fact.address, offset, size) for fact in source.facts
    ) or any(
        _contains_range_8616(access.source.address, offset, size)
        for access in source.accesses
    ) or any(
        _contains_range_8616(access.source.address, offset, size)
        for access in source.logical_accesses
    )


def _result_8616(
    status: StackCoordinateProjectionStatus8616,
    bp_offset: int | None,
) -> StackCoordinateProjection8616:
    """Build one closed single-fact outcome."""
    materialized = int(bp_offset is not None)
    return StackCoordinateProjection8616(
        status,
        bp_offset,
        StackCoordinateProjectionStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=materialized,
            failure_count=1 - materialized,
        ),
    )


def project_stack_offset_to_machine_bp_8616(
    source: StackMemorySSAAliasArtifact8616,
    frame: FrameAccessArtifact | None,
    raw_offset: int,
    size: int,
) -> StackCoordinateProjection8616:
    """Select raw-BP or projected entry-SP identity from typed evidence."""
    if size <= 0:
        return _result_8616(StackCoordinateProjectionStatus8616.INVALID_RANGE, None)
    raw_proven = _alias_proves_range_8616(source, raw_offset, size)
    projected_offset: int | None = None
    if (
        isinstance(frame, FrameAccessArtifact)
        and frame.bp_coordinate.complete
        and frame.bp_coordinate.status is FrameCoordinateStatus8616.PROVEN
        and isinstance(frame.bp_coordinate.bp_entry_sp_delta, int)
    ):
        projected_offset = raw_offset - frame.bp_coordinate.bp_entry_sp_delta
    projected_proven = bool(
        projected_offset is not None
        and _alias_proves_range_8616(source, projected_offset, size)
    )
    if projected_proven and raw_proven and projected_offset != raw_offset:
        return _result_8616(StackCoordinateProjectionStatus8616.AMBIGUOUS, None)
    if projected_proven and not raw_proven:
        return _result_8616(
            StackCoordinateProjectionStatus8616.PROJECTED_ENTRY_SP,
            projected_offset,
        )
    if raw_proven:
        return _result_8616(
            StackCoordinateProjectionStatus8616.RAW_MACHINE_BP,
            raw_offset,
        )
    return _result_8616(StackCoordinateProjectionStatus8616.UNPROVEN, None)


__all__ = [
    "StackCoordinateProjection8616",
    "StackCoordinateProjectionStats8616",
    "StackCoordinateProjectionStatus8616",
    "project_stack_offset_to_machine_bp_8616",
]
