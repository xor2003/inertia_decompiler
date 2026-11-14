# cython: language_level=3, infer_types=True
"""Join already-proven adjacent Alias storage facts.

Layer: Alias.
Responsibility: own construction of a canonical combined Alias identity after a
consumer has selected exact adjacent views. Segmented joins retain every
original IR address because the legacy generic memory identity alone does not
distinguish DS from ES. This module does not discover candidates, infer widths,
mutate codegen, or inspect rendered text. Owns storage identity and exact
Alias-domain joins.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

import itertools
from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

from .alias_model_impl import AliasStorageFacts, _StackSlotIdentity
import dataclasses
import operator
import builtins


class SegmentedAccessRelation8616(StrEnum):
    """Alias relationship between two typed segmented memory ranges."""

    DISJOINT = "disjoint"
    EXACT = "exact"
    CONTAINED = "contained"
    CONTAINS = "contains"
    CROSSING = "crossing"
    UNPROVEN = "unproven"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True, )
class SegmentedAliasRange8616:
    """Canonical Alias storage derived from exact adjacent segmented addresses."""

    space: MemSpace
    addresses: object
    source_facts: object
    storage: AliasStorageFacts

    @property
    def size(self) -> cython.longlong:
        """Return the proven byte width of this segmented range."""
        return sum(address.size for address in iter(self.addresses))

    @property
    def offset(self) -> cython.longlong:
        """Return the first byte offset of this segmented range."""
        return int(self.addresses[0].offset)

    def overlaps(self, other: SegmentedAliasRange8616) -> cython.bint:
        """Return whether two proven ranges overlap in one segmented space."""
        return (
            self.space is other.space
            and self.offset < other.offset + other.size
            and other.offset < self.offset + self.size
        )

    def contains(self, other: SegmentedAliasRange8616) -> cython.bint:
        """Return whether this proven segmented range contains another view."""
        return (
            self.space is other.space
            and self.offset <= other.offset
            and other.offset + other.size <= self.offset + self.size
        )


@cython.ccall
def segmented_access_relation_8616(
    access: IRAddress,
    target: IRAddress,
) -> SegmentedAccessRelation8616:
    """Classify one typed access range against exact segmented storage."""
    spaces = {MemSpace.SS, MemSpace.DS, MemSpace.ES}
    if access.space not in spaces or target.space not in spaces:
        return SegmentedAccessRelation8616.UNKNOWN
    if access.space is not target.space:
        return SegmentedAccessRelation8616.DISJOINT
    if access.base or target.base or access.size <= 0 or target.size <= 0:
        return SegmentedAccessRelation8616.UNKNOWN
    overlaps = (
        access.offset < target.offset + target.size
        and target.offset < access.offset + access.size
    )
    if not overlaps:
        return SegmentedAccessRelation8616.DISJOINT
    if (
        access.status is not AddressStatus.STABLE
        or target.status is not AddressStatus.STABLE
        or access.segment_origin is not SegmentOrigin.PROVEN
        or target.segment_origin is not SegmentOrigin.PROVEN
    ):
        return SegmentedAccessRelation8616.UNPROVEN
    if operator.eq(access.offset, target.offset) and operator.eq(access.size, target.size):
        return SegmentedAccessRelation8616.EXACT
    if target.offset <= access.offset and access.offset + access.size <= target.offset + target.size:
        return SegmentedAccessRelation8616.CONTAINED
    if access.offset <= target.offset and target.offset + target.size <= access.offset + access.size:
        return SegmentedAccessRelation8616.CONTAINS
    return SegmentedAccessRelation8616.CROSSING

@cython.ccall
def join_adjacent_stack_alias_facts_8616(
    low: AliasStorageFacts,
    high: AliasStorageFacts,
) -> AliasStorageFacts | None:
    """Return one canonical stack Alias fact for a proven adjacent pair."""
    domain: object
    high_identity: object
    low_identity: object
    slot: object
    if not low.can_join(high):
        return None
    low_identity = low.identity
    high_identity = high.identity
    if low_identity is None or high_identity is None:
        return None
    if low_identity[0] != "stack" or high_identity[0] != "stack":
        return None
    if not isinstance(low_identity[1], _StackSlotIdentity) or not isinstance(
        high_identity[1], _StackSlotIdentity
    ):
        return None
    domain = low.domain.join(high.domain)
    slot = low_identity[1].join(high_identity[1])
    if domain is None or slot is None:
        return None
    return AliasStorageFacts(domain=domain, identity=("stack", slot))


@cython.ccall
def _memory_fact_matches_address_8616(
    address: IRAddress,
    fact: AliasStorageFacts,
) -> cython.bint:
    view: object
    view = fact.domain.view
    return (
        fact.domain.space == "memory"
        and operator.eq(fact.domain.width, address.size)
        and operator.eq(fact.identity, ("memory", address.offset))
        and view is not None
        and operator.eq(view.bit_offset, address.offset * 8)
        and operator.eq(view.bit_width, address.size * 8)
        and not fact.needs_synthesis()
    )


@cython.ccall
def _stack_fact_matches_address_8616(
    address: IRAddress,
    fact: AliasStorageFacts,
) -> cython.bint:
    identity: object
    view: object
    identity = fact.identity
    view = fact.domain.view
    return (
        address.base in {("bp",), ("sp",)}
        and fact.domain.space == "stack"
        and operator.eq(fact.domain.width, address.size)
        and identity is not None
        and identity[0] == "stack"
        and isinstance(identity[1], _StackSlotIdentity)
        and operator.eq(identity[1].base, address.base[0])
        and operator.eq(identity[1].offset, address.offset)
        and operator.eq(identity[1].width, address.size)
        and view is not None
        and operator.eq(view.bit_width, address.size * 8)
        and not fact.needs_synthesis()
    )


@cython.ccall
def _first_segmented_address_valid_8616(first: IRAddress) -> cython.bint:
    """Gate the range's head address to stable proven segmented storage."""
    if first.space not in {MemSpace.SS, MemSpace.DS, MemSpace.ES}:
        return False
    if first.status is not AddressStatus.STABLE:
        return False
    if first.segment_origin is not SegmentOrigin.PROVEN:
        return False
    if first.size <= 0:
        return False
    return not (first.space in {MemSpace.DS, MemSpace.ES} and first.offset < 0)


@cython.ccall
def _address_matches_range_head_8616(current: IRAddress, first: IRAddress) -> cython.bint:
    """Require one address to share the head address's identity fields."""
    if current.space is not first.space:
        return False
    if operator.ne(current.base, first.base):
        return False
    if current.status is not first.status:
        return False
    if current.segment_origin is not first.segment_origin:
        return False
    if operator.ne(current.expr, first.expr):
        return False
    return bool(operator.eq(current.version, first.version))


@cython.ccall
def _addresses_contiguous_uniform_8616(addresses: object, first: IRAddress) -> cython.bint:
    """Require all addresses to share identity fields and be gap-free."""
    current: object
    previous: object
    for previous, current in itertools.pairwise(addresses):
        if not _address_matches_range_head_8616(current, first):
            return False
        if current.size <= 0 or operator.ne(current.offset, previous.offset + previous.size):
            return False
    return True


def _join_stack_alias_facts_8616(
    addresses: object, facts: object
) -> AliasStorageFacts | None:
    """Join stack-lane facts after every fact matches its address."""
    joined: object
    fact: object
    if not all(
        _stack_fact_matches_address_8616(address, fact)
        for address, fact in builtins.iter(zip(addresses, facts, strict=True))
    ):
        return None
    combined = facts[0]
    for fact in facts[1:]:
        joined = join_adjacent_stack_alias_facts_8616(combined, fact)
        if joined is None:
            return None
        combined = joined
    return combined


def _join_memory_alias_facts_8616(
    addresses: object, facts: object, first: IRAddress
) -> AliasStorageFacts | None:
    """Join non-stack memory-lane facts into a merged domain identity."""
    joined_domain: object
    fact: object
    if not all(
        _memory_fact_matches_address_8616(address, fact)
        for address, fact in builtins.iter(zip(addresses, facts, strict=True))
    ):
        return None
    domain = facts[0].domain
    for fact in facts[1:]:
        joined_domain = domain.join(fact.domain)
        if joined_domain is None:
            return None
        domain = joined_domain
    return AliasStorageFacts(
        domain=domain,
        identity=(
            "memory",
            (first.space.value, first.offset, sum(address.size for address in iter(addresses))),
        ),
    )


@cython.ccall
def build_segmented_alias_range_8616(
    addresses: object,
    facts: object,
) -> SegmentedAliasRange8616 | None:
    """Build a range from one or more original adjacent segmented Alias facts."""
    combined: object
    if not addresses or operator.ne(len(addresses), len(facts)):
        return None
    first = addresses[0]
    if not _first_segmented_address_valid_8616(first):
        return None
    if not _addresses_contiguous_uniform_8616(addresses, first):
        return None
    if addresses[-1].offset + addresses[-1].size > 0x10000:
        return None

    if first.space is MemSpace.SS:
        combined = _join_stack_alias_facts_8616(addresses, facts)
        if combined is None:
            return None
    else:
        combined = _join_memory_alias_facts_8616(addresses, facts, first)
        if combined is None:
            return None
    return SegmentedAliasRange8616(
        space=first.space,
        addresses=addresses,
        source_facts=facts,
        storage=combined,
    )


@cython.ccall
def join_adjacent_segmented_alias_facts_8616(
    addresses: object,
    facts: object,
) -> SegmentedAliasRange8616 | None:
    """Join at least two original adjacent segmented Alias facts."""
    if len(addresses) < 2:
        return None
    return build_segmented_alias_range_8616(addresses, facts)


__all__ = [
    "SegmentedAccessRelation8616",
    "SegmentedAliasRange8616",
    "build_segmented_alias_range_8616",
    "join_adjacent_segmented_alias_facts_8616",
    "join_adjacent_stack_alias_facts_8616",
    "segmented_access_relation_8616",
]
