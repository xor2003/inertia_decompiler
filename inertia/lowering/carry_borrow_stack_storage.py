"""Project wide carry-result storage into stack-object Lowering candidates.

Layer: Types/Lowering.
Responsibility: classify Alias/Widening-proven four-byte stack destinations as
locals that the canonical stack-variable materializer can consume. Refused
wide candidates retain their original word-level stack representation.
Consumes alias, widening, and typed facts without rediscovering semantics.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.alias_model_impl import AliasStorageFacts
from inertia.ir.core import IRAddress, MemSpace
from inertia.widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616
from inertia.widening.carry_borrow_storage import WideCarryBorrowStorage8616


class WideCarryBorrowStackRole8616(StrEnum):
    """C storage role proven for one wide destination."""

    LOCAL = "local"


class WideCarryBorrowStackFailure8616(StrEnum):
    """Stable reason a wide destination cannot become one stack object."""

    ARGUMENT_STORAGE_TRIAL_REQUIRED = "argument_storage_trial_required"
    FRAME_CONTROL_SLOT = "frame_control_slot"
    FRAME_COORDINATE_UNPROVEN = "frame_coordinate_unproven"
    SOURCE_WIDENING_REFUSAL = "source_widening_refusal"
    STORAGE_IDENTITY_MISMATCH = "storage_identity_mismatch"


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStackCandidate8616:
    """One exact wide stack range ready for canonical C-variable Lowering."""

    role: WideCarryBorrowStackRole8616
    address: IRAddress
    entry_sp_offset: int
    storage: AliasStorageFacts
    source: WideCarryBorrowStorage8616

    @property
    def source_ranges(self) -> tuple[IRAddress, IRAddress]:
        """Return the exact low/high ranges superseded by this candidate."""
        destination = self.source.destination
        return (destination.low_store.address, destination.high_store.address)


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStackRefusal8616:
    """One retained refusal that leaves narrow storage available."""

    kind: WideCarryBorrowStackFailure8616
    detail: str
    address: IRAddress | None = None


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStackStats8616:
    """Closed evidence accounting for wide stack Lowering projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether each Widening outcome has one Lowering outcome."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStackArtifact8616:
    """Function-level wide stack candidates and refusals."""

    function_addr: int
    candidates: tuple[WideCarryBorrowStackCandidate8616, ...]
    refusals: tuple[WideCarryBorrowStackRefusal8616, ...]
    stats: WideCarryBorrowStackStats8616

    @property
    def complete(self) -> bool:
        """Return whether projection count and evidence accounting are closed."""
        return self.stats.complete


def _refusal(
    kind: WideCarryBorrowStackFailure8616,
    detail: str,
    address: IRAddress | None = None,
) -> WideCarryBorrowStackRefusal8616:
    return WideCarryBorrowStackRefusal8616(kind, detail, address)


def _candidate_or_refusal(
    source: WideCarryBorrowStorage8616,
    bp_entry_sp_delta: int | None,
) -> WideCarryBorrowStackCandidate8616 | WideCarryBorrowStackRefusal8616:
    address = source.address
    if (
        address.space is not MemSpace.SS
        or address.base != ("bp",)
        or address.size != 4
        or source.storage.needs_synthesis()
    ):
        return _refusal(
            WideCarryBorrowStackFailure8616.STORAGE_IDENTITY_MISMATCH,
            "wide carry destination is not one exact SS:BP four-byte range",
            address,
        )
    if address.offset < 4 and address.offset + address.size > 0:
        return _refusal(
            WideCarryBorrowStackFailure8616.FRAME_CONTROL_SLOT,
            "wide destination overlaps saved-frame or return-address storage",
            address,
        )
    if address.offset >= 4:
        return _refusal(
            WideCarryBorrowStackFailure8616.ARGUMENT_STORAGE_TRIAL_REQUIRED,
            "positive BP storage requires argument storage trials",
            address,
        )
    if bp_entry_sp_delta is None:
        return _refusal(
            WideCarryBorrowStackFailure8616.FRAME_COORDINATE_UNPROVEN,
            "wide local has no proven BP-to-entry-SP coordinate",
            address,
        )
    return WideCarryBorrowStackCandidate8616(
        role=WideCarryBorrowStackRole8616.LOCAL,
        address=address,
        entry_sp_offset=address.offset + bp_entry_sp_delta,
        storage=source.storage,
        source=source,
    )


def project_wide_carry_borrow_stack_storage_8616(
    pipeline: CarryBorrowWideningPipeline8616,
    bp_entry_sp_delta: int | None,
) -> WideCarryBorrowStackArtifact8616:
    """Project every wide destination into a local candidate or typed refusal."""
    outcomes: list[WideCarryBorrowStackCandidate8616 | WideCarryBorrowStackRefusal8616] = []
    for resolution in pipeline.storage_widening.resolutions:
        if resolution.value is None:
            outcomes.append(
                _refusal(
                    WideCarryBorrowStackFailure8616.SOURCE_WIDENING_REFUSAL,
                    f"storage Widening refused destination: {resolution.failure}",
                )
            )
        else:
            outcomes.append(_candidate_or_refusal(resolution.value, bp_entry_sp_delta))
    candidates = tuple(item for item in outcomes if isinstance(item, WideCarryBorrowStackCandidate8616))
    refusals = tuple(item for item in outcomes if isinstance(item, WideCarryBorrowStackRefusal8616))
    return WideCarryBorrowStackArtifact8616(
        function_addr=pipeline.function_addr,
        candidates=candidates,
        refusals=refusals,
        stats=WideCarryBorrowStackStats8616(
            raw_fact_count=len(outcomes),
            normalized_fact_count=len(candidates),
            classified_fact_count=len(candidates),
            materialized_count=len(candidates),
            failure_count=len(refusals),
        ),
    )


__all__ = [
    "WideCarryBorrowStackArtifact8616",
    "WideCarryBorrowStackCandidate8616",
    "WideCarryBorrowStackFailure8616",
    "WideCarryBorrowStackRefusal8616",
    "WideCarryBorrowStackRole8616",
    "WideCarryBorrowStackStats8616",
    "project_wide_carry_borrow_stack_storage_8616",
]
