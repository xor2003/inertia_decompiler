"""Named logical pair type and per-operation legality contracts.

Layer: Widening.
Responsibility: own the immutable named pair type projected from exact
Alias-proven carry/borrow halves plus the typed per-operation pair/split
legality evidence retained on each wide value for later passes.
Consumes alias-proven storage identity before joining values or propagating widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.

A named bit-pair is a logical value contract only. It is not proof of a
recovered program struct, union, or flat far pointer, and it never rewrites
segmented SS/DS/ES identities or the proven scalar call/argument ABI. A
``SPLIT`` or ``UNPAIRED`` state never authorizes combining halves or
retiring carrier statements; original code must survive it unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from inertia.ir.core import MemSpace

if TYPE_CHECKING:
    from inertia.alias.domains import DomainKey
    from inertia.ir.core import IRValue
    from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616

    from .carry_borrow_values import (
        WideCarryBorrowValue8616,
        WideRegisterSlice8616,
        WideValueSignedness8616,
    )


class WidePairOrder8616(StrEnum):
    """Canonical position of one half inside a named logical pair."""

    LOW = "low"
    HIGH = "high"


class WidePairState8616(StrEnum):
    """Pairing state retained for one owning wide operation.

    ``PAIRED`` authorizes combining the proven halves into one wide entity.
    ``SPLIT`` authorizes consuming the halves independently but never a
    combine. ``UNPAIRED`` authorizes neither: the halves are not a coherent
    pair and every transform must keep the original statements.
    """

    PAIRED = "paired"
    SPLIT = "split"
    UNPAIRED = "unpaired"


class WidePairIllegality8616(StrEnum):
    """Typed reason retained pair evidence cannot authorize a transform."""

    COMBINE_NOT_AUTHORIZED = "combine_not_authorized"
    HALF_DOMAIN_COLLISION = "half_domain_collision"
    HALF_IDENTITY_MISMATCH = "half_identity_mismatch"
    HALF_ORDER_MISMATCH = "half_order_mismatch"
    HALF_STORAGE_MISMATCH = "half_storage_mismatch"
    HALF_WIDTH_MISMATCH = "half_width_mismatch"
    KIND_MISMATCH = "kind_mismatch"
    PAIR_EVIDENCE_MISSING = "pair_evidence_missing"
    SIGNEDNESS_MISMATCH = "signedness_mismatch"
    SOURCE_SPACE_MISMATCH = "source_space_mismatch"
    TOTAL_WIDTH_MISMATCH = "total_width_mismatch"
    TYPE_NAME_MISMATCH = "type_name_mismatch"
    TYPE_WIDTH_MISMATCH = "type_width_mismatch"
    VALUE_WIDTH_MISMATCH = "value_width_mismatch"


@dataclass(frozen=True, slots=True)
class WidePairType8616:
    """Immutable named logical pair type retained from proven halves.

    Type identity covers proven width, half layout, and signedness only;
    the arithmetic kind and the segmented source space belong to the
    per-operation evidence, not to the type. ``name`` is derived
    deterministically from the proven total width; it identifies the
    logical pair type and is never a recovered program structure name.
    """

    name: str
    signedness: WideValueSignedness8616
    total_size: int
    low_size: int
    high_size: int


@dataclass(frozen=True, slots=True)
class WidePairHalf8616:
    """One ordered half of a named pair retaining its exact proven slice."""

    order: WidePairOrder8616
    slice: WideRegisterSlice8616

    @property
    def result(self) -> IRValue:
        """Return the exact half result value including its version."""
        return self.slice.result

    @property
    def domain(self) -> DomainKey:
        """Return the proven Alias domain of this half result."""
        return self.slice.result_domain

    @property
    def size(self) -> int:
        """Return the proven byte width of this half result."""
        return int(self.slice.result.size)


@dataclass(frozen=True, slots=True)
class WidePairEvidence8616:
    """Named pair type plus typed transform legality for one wide operation.

    ``kind`` and ``address_space`` are per-operation provenance kept on the
    evidence, not on the shared type identity; ``address_space`` preserves
    the exact segmented source space (``None`` for register/constant
    sources) and is authenticated against the owning value.
    """

    type: WidePairType8616
    kind: CarryBorrowKind8616
    address_space: MemSpace | None
    low: WidePairHalf8616
    high: WidePairHalf8616
    state: WidePairState8616
    illegality: WidePairIllegality8616 | None = None

    @property
    def ordered_halves(self) -> tuple[WidePairHalf8616, WidePairHalf8616]:
        """Return the retained halves in canonical low-to-high order."""
        return (self.low, self.high)

    @property
    def combine_authorized(self) -> bool:
        """Return whether the halves may be consumed as one wide entity."""
        return (
            self.state is WidePairState8616.PAIRED
            and self.illegality is None
            and _pair_invariant_illegality_8616(self) is None
        )

    @property
    def split_authorized(self) -> bool:
        """Return whether the halves may be consumed independently."""
        return (
            self.state is not WidePairState8616.UNPAIRED
            and self.illegality is None
            and _pair_invariant_illegality_8616(self) is None
        )


def wide_pair_type_name_8616(total_size: int) -> str:
    """Return the deterministic logical pair-type name from proven width."""
    return f"wide_pair{total_size * 8}"


def _pair_half_legality_8616(
    low: WidePairHalf8616,
    high: WidePairHalf8616,
) -> WidePairIllegality8616 | None:
    """Return the typed reason two retained halves cannot form one pair."""
    if low.result.space is not MemSpace.REG or high.result.space is not MemSpace.REG:
        return WidePairIllegality8616.HALF_STORAGE_MISMATCH
    if low.size <= 0 or high.size <= 0 or low.size != high.size:
        return WidePairIllegality8616.HALF_WIDTH_MISMATCH
    if low.result == high.result:
        return WidePairIllegality8616.HALF_IDENTITY_MISMATCH
    if low.domain == high.domain:
        return WidePairIllegality8616.HALF_DOMAIN_COLLISION
    return None


def _pair_legality_8616(
    *,
    claimed_size: int,
    low: WidePairHalf8616,
    high: WidePairHalf8616,
) -> WidePairIllegality8616 | None:
    """Return the typed reason proven halves cannot form one claimed pair."""
    illegality = _pair_half_legality_8616(low, high)
    if illegality is not None:
        return illegality
    if low.size + high.size != claimed_size:
        return WidePairIllegality8616.TOTAL_WIDTH_MISMATCH
    return None


def materialize_wide_pair_evidence_8616(
    *,
    kind: CarryBorrowKind8616,
    claimed_size: int,
    signedness: WideValueSignedness8616,
    address_space: MemSpace | None,
    low: WideRegisterSlice8616,
    high: WideRegisterSlice8616,
) -> WidePairEvidence8616:
    """Project proven result slices into one named pair with typed legality."""
    low_half = WidePairHalf8616(WidePairOrder8616.LOW, low)
    high_half = WidePairHalf8616(WidePairOrder8616.HIGH, high)
    total_size = low_half.size + high_half.size
    pair_type = WidePairType8616(
        name=wide_pair_type_name_8616(total_size),
        signedness=signedness,
        total_size=total_size,
        low_size=low_half.size,
        high_size=high_half.size,
    )
    illegality = _pair_legality_8616(
        claimed_size=claimed_size,
        low=low_half,
        high=high_half,
    )
    return WidePairEvidence8616(
        type=pair_type,
        kind=kind,
        address_space=address_space,
        low=low_half,
        high=high_half,
        state=(
            WidePairState8616.PAIRED
            if illegality is None
            else WidePairState8616.UNPAIRED
        ),
        illegality=illegality,
    )


def _pair_invariant_illegality_8616(
    pair: WidePairEvidence8616,
) -> WidePairIllegality8616 | None:
    """Return the typed illegality when evidence violates its own invariants."""
    pair_type = pair.type
    if (
        pair.low.order is not WidePairOrder8616.LOW
        or pair.high.order is not WidePairOrder8616.HIGH
    ):
        return WidePairIllegality8616.HALF_ORDER_MISMATCH
    half = _pair_half_legality_8616(pair.low, pair.high)
    if half is not None:
        return half
    if (
        pair_type.low_size != pair.low.size
        or pair_type.high_size != pair.high.size
        or pair_type.total_size != pair_type.low_size + pair_type.high_size
    ):
        return WidePairIllegality8616.TYPE_WIDTH_MISMATCH
    if pair_type.name != wide_pair_type_name_8616(pair_type.total_size):
        return WidePairIllegality8616.TYPE_NAME_MISMATCH
    return None


def _pair_value_field_illegality_8616(
    value: WideCarryBorrowValue8616,
    pair: WidePairEvidence8616,
) -> WidePairIllegality8616 | None:
    """Return the typed illegality when live fields disagree with the pair."""
    pair_type = pair.type
    if value.kind is not pair.kind:
        return WidePairIllegality8616.KIND_MISMATCH
    if value.signedness is not pair_type.signedness:
        return WidePairIllegality8616.SIGNEDNESS_MISMATCH
    if value.size != pair_type.total_size:
        return WidePairIllegality8616.VALUE_WIDTH_MISMATCH
    source_space = (
        value.source_memory.space if value.source_memory is not None else None
    )
    if source_space is not pair.address_space:
        return WidePairIllegality8616.SOURCE_SPACE_MISMATCH
    if value.address_space is not pair.address_space:
        return WidePairIllegality8616.SOURCE_SPACE_MISMATCH
    if value.low != pair.low.slice or value.high != pair.high.slice:
        return WidePairIllegality8616.HALF_IDENTITY_MISMATCH
    return None


def wide_pair_value_consistent_8616(
    value: WideCarryBorrowValue8616,
) -> WidePairIllegality8616 | None:
    """Return the typed illegality when a live value breaks its retained pair."""
    pair = value.pair
    if not isinstance(pair, WidePairEvidence8616):
        return WidePairIllegality8616.PAIR_EVIDENCE_MISSING
    if pair.illegality is not None:
        return pair.illegality
    if pair.state is not WidePairState8616.PAIRED:
        return WidePairIllegality8616.COMBINE_NOT_AUTHORIZED
    invariant = _pair_invariant_illegality_8616(pair)
    if invariant is not None:
        return invariant
    return _pair_value_field_illegality_8616(value, pair)


__all__ = [
    "WidePairEvidence8616",
    "WidePairHalf8616",
    "WidePairIllegality8616",
    "WidePairOrder8616",
    "WidePairState8616",
    "WidePairType8616",
    "materialize_wide_pair_evidence_8616",
    "wide_pair_type_name_8616",
    "wide_pair_value_consistent_8616",
]
