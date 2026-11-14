# cython: language_level=3, infer_types=True
"""Constant-size receipts for ordinary, closed census stage sets.

Layer: IR.
Responsibility: preserve separate stage ledgers while proving their equality
through owned row transitions and detecting subsequent mutation without scans.

The contract covers pinned owned producers using normal set methods. Calling
builtin base descriptors directly bypasses subclass accounting and is outside
this ownership contract. Receipts never replace native or source admission.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, Set
from dataclasses import dataclass, field
from typing import Self, cast
import dataclasses
import operator
import builtins

CensusFact8616 = typing.TypeAliasType("CensusFact8616", tuple[int, int])


@cython.dataclasses.dataclass()
class _FactOwner8616:
    """Track nested rows independently; callbacks may interleave row completion."""

    pending: object = field(default_factory=dict)
    dirty: cython.bint = False
    sets: tuple[_OwnedFacts8616, ...] = ()

    @cython.ccall
    def advance(self, stage: cython.longlong, row: CensusFact8616) -> None:
        """Accept only the canonical four additions for each completed row."""
        if self.dirty:
            return
        if operator.ne(self.pending.get(row, 0), stage):
            self.dirty = True
        elif stage == 3:
            del self.pending[row]
        else:
            self.pending[row] = stage + 1


class _OwnedFacts8616(set[CensusFact8616]):
    """A genuine set with mutation accounting; bulk edits decline receipts."""

    owner: _FactOwner8616
    stage: cython.longlong
    version: cython.longlong

    def __init__(self, owner: _FactOwner8616, stage: cython.longlong) -> None:
        prior_owner: object
        try:
            prior_owner = self.owner
        except AttributeError:
            prior_owner = None
        if prior_owner is not None:
            self._edit()
            raise RuntimeError("owned census ledgers cannot be reinitialized")
        super().__init__()
        self.owner = owner
        self.stage = stage
        self.version = 0

    def add(self, element: CensusFact8616) -> None:
        """Record the row transition even when its set membership is unchanged."""
        self.version += 1
        self.owner.advance(self.stage, element)
        super().add(element)

    def _edit(self) -> None:
        """Invalidate receipts before an arbitrary bulk or destructive operation."""
        self.version += 1
        self.owner.dirty = True

    def discard(self, element: object) -> None:
        """Preserve ordinary discard behavior and invalidate closed ownership."""
        self._edit()
        super().discard(element)

    def remove(self, element: CensusFact8616) -> None:
        """Preserve missing-element errors; mutation attempts invalidate receipts."""
        self._edit()
        super().remove(element)

    def clear(self) -> None:
        """Clear the ledger without retaining its former equality certificate."""
        self._edit()
        super().clear()

    def pop(self) -> CensusFact8616:
        """Remove one arbitrary row, preserving the builtin empty-set error."""
        self._edit()
        return super().pop()

    def update(self, *others: Iterable[CensusFact8616]) -> None:
        """Keep bulk updates legal for census consumers but never certifiable."""
        self._edit()
        super().update(*others)

    def difference_update(self, *others: Iterable[object]) -> None:
        """Apply the ordinary difference and discard closed ownership."""
        self._edit()
        super().difference_update(*others)

    def intersection_update(self, *others: Iterable[object]) -> None:
        """Apply the ordinary intersection and discard closed ownership."""
        self._edit()
        super().intersection_update(*others)

    def symmetric_difference_update(self, other: Iterable[CensusFact8616]) -> None:
        """Apply the ordinary symmetric difference and discard ownership."""
        self._edit()
        super().symmetric_difference_update(other)

    # Builtin in-place operators return this same instance. MyPy additionally
    # compares them with the widening non-mutating operators, whose generic
    # result cannot describe that identity. Preserve the runtime set contract.
    def __ior__(self, other: Set[object]) -> Self:  # type: ignore[override]
        """Preserve builtin operator admission and invalidate on mutation."""
        self._edit()
        result = super().__ior__(cast(Set[CensusFact8616], other))
        if result is NotImplemented:
            return result
        return self

    def __iand__(self, other: Set[object]) -> Self:
        """Preserve builtin intersection semantics and invalidate ownership."""
        self._edit()
        result = super().__iand__(other)
        if result is NotImplemented:
            return result
        return self

    def __isub__(self, other: Set[object]) -> Self:
        """Preserve builtin subtraction semantics and invalidate ownership."""
        self._edit()
        result = super().__isub__(other)
        if result is NotImplemented:
            return result
        return self

    def __ixor__(self, other: Set[object]) -> Self:  # type: ignore[override]
        """Preserve builtin symmetric difference and invalidate ownership."""
        self._edit()
        result = super().__ixor__(cast(Set[CensusFact8616], other))
        if result is NotImplemented:
            return result
        return self


@cython.ccall
def _fact_producers_8616() -> tuple[object, ...]:
    """Pin the owned transition and every supported mutation entry point."""
    return (
        _fact_producers_8616, new_census_fact_sets_8616,
        census_fact_ownership_8616, census_fact_ownership_current_8616,
        _FactOwner8616.advance, _OwnedFacts8616.__init__, _OwnedFacts8616.add,
        _OwnedFacts8616._edit, _OwnedFacts8616.discard, _OwnedFacts8616.remove,
        _OwnedFacts8616.clear, _OwnedFacts8616.pop, _OwnedFacts8616.update,
        _OwnedFacts8616.difference_update, _OwnedFacts8616.intersection_update,
        _OwnedFacts8616.symmetric_difference_update, _OwnedFacts8616.__ior__,
        _OwnedFacts8616.__iand__, _OwnedFacts8616.__isub__, _OwnedFacts8616.__ixor__,
    )


@dataclasses.dataclass(frozen=True, eq=False)
class CensusFactOwnership8616:
    """A bounded ownership receipt, not native or semantic proof authority."""

    sets: object
    versions: object


def new_census_fact_sets_8616() -> object:
    """Create four empty, distinct ordinary sets sharing transition ownership."""
    owner = _FactOwner8616()
    owner.sets = tuple(_OwnedFacts8616(owner, stage) for stage in range(4))
    return owner.sets


def census_fact_ownership_8616(
    sets: object,
) -> CensusFactOwnership8616 | None:
    """Certify complete owned additions in constant work; plain sets decline."""
    index: object
    item: object
    if len(sets) != 4 or any(type(item) is not _OwnedFacts8616 for item in iter(sets)):
        return None
    actual = _fact_producers_8616()
    if any(a is not b for a, b in builtins.iter(zip(actual, _CANONICAL_FACT_PRODUCERS_8616, strict=True))):
        return None
    raw = sets[0]
    assert isinstance(raw, _OwnedFacts8616)
    owner = raw.owner
    if owner.dirty or owner.pending:
        return None
    for index, item in enumerate(sets):
        assert isinstance(item, _OwnedFacts8616)
        if item.owner is not owner or operator.ne(item.stage, index) or owner.sets[index] is not item:
            return None
    return CensusFactOwnership8616(sets, tuple(item.version for item in iter(owner.sets)))


def census_fact_ownership_current_8616(
    receipt: CensusFactOwnership8616, sets: object,
) -> cython.bint:
    """Reject replacement, partial rows and same-cardinality in-place changes."""
    current: object
    current = census_fact_ownership_8616(sets)
    return (
        current is not None and operator.eq(current.versions, receipt.versions)
        and all(a is b for a, b in builtins.iter(zip(current.sets, receipt.sets, strict=True)))
    )


_CANONICAL_FACT_PRODUCERS_8616: object = _fact_producers_8616()
