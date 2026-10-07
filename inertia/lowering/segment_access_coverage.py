"""Normalize exact split-access evidence for segment lowering.

Layer: Types/Lowering.
Responsibility: consume IR-owned segment access facts and join only complete,
unambiguous byte coverage for one typed lowering query.
Consumes alias, widening, and typed facts without owning their proof.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections import defaultdict

from inertia.ir.core import MemSpace
from inertia.ir.segment_contract import SegmentAccessFact, SegmentAccessKind

__all__ = [
    "segment_access_matches_query_8616",
    "select_contiguous_segment_access_facts_8616",
]

_AccessIdentity8616 = tuple[
    int,
    SegmentAccessKind,
    MemSpace,
    tuple[str, ...],
    tuple[str, ...] | None,
    str | None,
]


def segment_access_matches_query_8616(
    fact: SegmentAccessFact,
    *,
    access_kind: SegmentAccessKind | None,
    segment_register: str | None,
    offset: int | None,
    width: int | None,
) -> bool:
    """Return whether one typed access matches every exact known query field."""
    if access_kind is not None and fact.kind is not access_kind:
        return False
    if segment_register is not None and fact.segment_register != segment_register:
        return False
    if isinstance(offset, int) and (fact.address.offset & 0xFFFF) != (offset & 0xFFFF):
        return False
    return not (isinstance(width, int) and width > 0 and fact.address.size != width)


def _access_identity_8616(fact: SegmentAccessFact) -> _AccessIdentity8616 | None:
    """Return the address identity shared by fragments of one machine access."""
    if not isinstance(fact.instruction_addr, int):
        return None
    return (
        fact.instruction_addr,
        fact.kind,
        fact.address.space,
        fact.address.base,
        fact.address.expr,
        fact.segment_register,
    )


def _covered_offsets_8616(facts: tuple[SegmentAccessFact, ...]) -> frozenset[int]:
    """Return every 16-bit byte offset covered by a fragment group."""
    return frozenset(
        (fact.address.offset + byte_offset) & 0xFFFF
        for fact in facts
        for byte_offset in range(max(fact.address.size, 0))
    )


def _has_exact_coverage_8616(
    facts: tuple[SegmentAccessFact, ...],
    *,
    offset: int | None,
    width: int,
) -> bool:
    """Return whether fragments cover exactly one requested-width interval."""
    covered = _covered_offsets_8616(facts)
    starts = ((offset & 0xFFFF),) if isinstance(offset, int) else tuple(sorted(covered))
    return any(
        covered == frozenset((start + byte_offset) & 0xFFFF for byte_offset in range(width))
        for start in starts
    )


def select_contiguous_segment_access_facts_8616(
    facts: tuple[SegmentAccessFact, ...],
    *,
    instruction_addrs: frozenset[int],
    offset: int | None,
    width: int,
) -> tuple[SegmentAccessFact, ...]:
    """Select unambiguous complete split-access groups for one query."""
    if width <= 1:
        return ()
    groups: dict[_AccessIdentity8616, list[SegmentAccessFact]] = defaultdict(list)
    for fact in facts:
        identity = _access_identity_8616(fact)
        if identity is not None and (not instruction_addrs or identity[0] in instruction_addrs):
            groups[identity].append(fact)

    complete: dict[int, list[tuple[SegmentAccessFact, ...]]] = defaultdict(list)
    for identity, group in groups.items():
        ordered = tuple(
            sorted(
                group,
                key=lambda fact: (
                    fact.block_addr,
                    fact.address.offset,
                    fact.address.size,
                    fact.physical_source or "",
                    fact.verdict.value,
                ),
            )
        )
        if _has_exact_coverage_8616(ordered, offset=offset, width=width):
            complete[identity[0]].append(ordered)

    if instruction_addrs:
        if set(complete) != set(instruction_addrs) or any(
            len(groups_at_addr) != 1 for groups_at_addr in complete.values()
        ):
            return ()
    elif sum(len(groups_at_addr) for groups_at_addr in complete.values()) != 1:
        return ()
    return tuple(fact for instruction_addr in sorted(complete) for fact in complete[instruction_addr][0])
