# cython: language_level=3, infer_types=True
"""Layer: Analysis.

Responsibility: derive storage overlap facts from typed IR values and addresses.
Forbidden: owning alias state, lowering objects, or using rendered text as alias proof.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.ir.core import IRAddress, IRValue, MemSpace
import dataclasses
import operator

__all__ = ["MemRange", "Storage", "may_alias", "overlap", "storage_of"]


@dataclasses.dataclass(frozen=True, )
class Storage:
    """Typed memory storage span derived from IR value/address evidence."""

    space: MemSpace
    base: object
    offset: cython.longlong
    size: cython.longlong


@dataclasses.dataclass(frozen=True, )
class MemRange:
    """Comparable memory interval inside one segmented storage space."""

    space: MemSpace
    base: object
    offset: cython.longlong
    size: cython.longlong


@cython.ccall
def storage_of(value: IRValue | IRAddress) -> Storage | None:
    """Return storage identity for a typed IR value or address when evidence is sufficient."""
    if isinstance(value, IRAddress):
        if operator.eq(value.space, MemSpace.UNKNOWN):
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
        base=tuple(()) if value.name is None else tuple((value.name,)),
        offset=value.offset,
        size=max(int(value.size or 0), 1),
    )


@cython.ccall
def overlap(left: MemRange, right: MemRange) -> cython.bint:
    """Return whether two memory ranges overlap in the same segmented space."""
    if operator.ne(left.space, right.space) or operator.ne(left.base, right.base):
        return False
    return not (left.offset + left.size <= right.offset or right.offset + right.size <= left.offset)


@cython.ccall
def may_alias(left: Storage, right: Storage) -> cython.bint:
    """Return whether two storage spans may refer to overlapping memory."""
    return overlap(
        MemRange(left.space, left.base, left.offset, left.size),
        MemRange(right.space, right.base, right.offset, right.size),
    )
