"""Layer: Analysis.

Responsibility: derive storage overlap facts from typed IR values and addresses.
Forbidden: owning alias state, lowering objects, or using rendered text as alias proof.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.ir.core import IRAddress, IRValue, MemSpace

__all__ = ["MemRange", "Storage", "may_alias", "overlap", "storage_of"]


@dataclass(frozen=True, slots=True)
class Storage:
    """Typed memory storage span derived from IR value/address evidence."""

    space: MemSpace
    base: tuple[str, ...]
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class MemRange:
    """Comparable memory interval inside one segmented storage space."""

    space: MemSpace
    base: tuple[str, ...]
    offset: int
    size: int


def storage_of(value: IRValue | IRAddress) -> Storage | None:
    """Return storage identity for a typed IR value or address when evidence is sufficient."""
    if isinstance(value, IRAddress):
        if value.space == MemSpace.UNKNOWN:
            return None
        return Storage(
            space=value.space,
            base=value.base,
            offset=value.offset,
            size=max(int(value.size or 0), 1),
        )
    if value.space in {MemSpace.CONST, MemSpace.TMP, MemSpace.UNKNOWN}:
        return None
    return Storage(
        space=value.space,
        base=() if value.name is None else (value.name,),
        offset=value.offset,
        size=max(int(value.size or 0), 1),
    )


def overlap(left: MemRange, right: MemRange) -> bool:
    """Return whether two memory ranges overlap in the same segmented space."""
    if left.space != right.space or left.base != right.base:
        return False
    return not (left.offset + left.size <= right.offset or right.offset + right.size <= left.offset)


def may_alias(left: Storage, right: Storage) -> bool:
    """Return whether two storage spans may refer to overlapping memory."""
    return overlap(
        MemRange(left.space, left.base, left.offset, left.size),
        MemRange(right.space, right.base, right.offset, right.size),
    )
