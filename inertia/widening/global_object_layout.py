# cython: language_level=3, infer_types=True
"""Recover project-wide object layouts from typed segmented storage views.

Layer: Widening.
Responsibility: join exact segmented direct or indexed views into stable object
extents. C type materialization remains owned by Types/Lowering.
Consumes alias-proven storage identity and typed access widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRefusal8616,
)
from inertia.alias.indexed_address_copy_contracts import (
    IndexedAliasCopyFact8616,
    IndexedAliasCopyRefusal8616,
)
from inertia.alias.indexed_address_program import (
    IndexedAliasFunctionRefusal8616,
)
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
import dataclasses
import operator
import builtins


class GlobalObjectLayoutFailureKind8616(StrEnum):
    """Stable reason one Alias input did not support a Widening layout."""

    PROGRAM_CENSUS_INCOMPLETE = "program_census_incomplete"
    UPSTREAM_FUNCTION_REFUSAL = "upstream_function_refusal"
    UPSTREAM_ACCESS_REFUSAL = "upstream_access_refusal"
    UPSTREAM_COPY_REFUSAL = "upstream_copy_refusal"
    NON_GLOBAL_ACCESS = "non_global_access"
    LAYOUT_NOT_PROVEN = "layout_not_proven"
    COPY_ENDPOINT_NOT_LAYOUT = "copy_endpoint_not_layout"


class GlobalObjectLayoutSourceKind8616(StrEnum):
    """Typed Alias source category retained across worker transport."""

    FUNCTION_REFUSAL = "function_refusal"
    ACCESS_FACT = "access_fact"
    ACCESS_REFUSAL = "access_refusal"
    COPY_FACT = "copy_fact"
    COPY_REFUSAL = "copy_refusal"


@dataclasses.dataclass(frozen=True, )
class TransportedGlobalObjectLayoutSource8616:
    """Reduced source identity for already-classified Widening evidence."""

    kind: GlobalObjectLayoutSourceKind8616
    summary: object

    @property
    def complete(self) -> cython.bint:
        """Return whether the transported source keeps a typed category."""
        return bool(self.summary)


GlobalObjectLayoutRefusalSource8616 = typing.TypeAliasType("GlobalObjectLayoutRefusalSource8616", (
    IndexedAliasFunctionRefusal8616
    | IndexedAliasAccessFact8616
    | IndexedAliasAccessRefusal8616
    | IndexedAliasCopyFact8616
    | IndexedAliasCopyRefusal8616
    | TransportedGlobalObjectLayoutSource8616
))


@dataclasses.dataclass(frozen=True, )
class GlobalObjectLayoutRefusal8616:
    """One retained Alias input not consumed by project layout Widening."""

    function_addr: cython.longlong
    failure: GlobalObjectLayoutFailureKind8616
    detail: object
    source: GlobalObjectLayoutRefusalSource8616

    @property
    def complete(self) -> cython.bint:
        """Return whether the refusal has one typed source and stable reason."""
        return self.function_addr >= 0 and bool(self.detail) and self.source.complete


@dataclasses.dataclass(frozen=True, )
class GlobalObjectLayout8616:
    """One stable segmented object extent with byte field boundaries."""

    address: IRAddress
    element_width: cython.longlong
    field_offsets: object
    family_base_offset: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether the materialized extent is exact and byte-bounded."""
        return bool(
            self.address.space is MemSpace.DS
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
            and self.address.size == self.element_width > 0
            and operator.eq(self.field_offsets, tuple(sorted(tuple(set(self.field_offsets)))))
            and self.field_offsets
            and all(0 <= offset < self.element_width for offset in iter(self.field_offsets))
            and 0 <= self.family_base_offset <= 0xFFFF
        )


@dataclasses.dataclass(frozen=True, )
class GlobalObjectLayoutEvidence8616:
    """Closed census where materialized count measures consumed Alias inputs."""

    layouts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong = 0
    refusals: tuple[GlobalObjectLayoutRefusal8616, ...] = ()

    @property
    def closed(self) -> cython.bint:
        """Return whether every Alias input was consumed or explicitly refused."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in iter(counts))
            and operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and operator.eq(len(self.refusals), self.failure_count)
            and all(layout.complete for layout in iter(self.layouts))
            and all(refusal.complete for refusal in iter(self.refusals))
        )


@dataclasses.dataclass(frozen=True, )
class DirectGlobalStorageView8616:
    """One exact direct DS storage view observed in a recovered function."""

    function_addr: cython.longlong
    address: IRAddress


@dataclasses.dataclass(frozen=True, )
class DirectGlobalObjectLayout8616:
    """One unambiguous direct global object extent proven across the program."""

    address: IRAddress
    proof_function_addrs: object


@dataclasses.dataclass(frozen=True, )
class DirectGlobalObjectLayoutEvidence8616:
    """Closed evidence census for project-wide direct global object extents."""

    layouts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong = 0


def recover_direct_global_object_layout_evidence_8616(
    views: Sequence[DirectGlobalStorageView8616],
) -> DirectGlobalObjectLayoutEvidence8616:
    """Join exact wide DS views by base and refuse overlapping object bases."""
    view: object
    normalized = tuple(dict.fromkeys(views))
    wide_views = tuple(
        view
        for view in iter(normalized)
        if view.address.space is MemSpace.DS
        and view.address.size >= 4
        and view.address.status is AddressStatus.STABLE
        and view.address.segment_origin is SegmentOrigin.PROVEN
    )
    widest_by_base: dict[cython.longlong, cython.longlong] = {}
    proof_functions_by_base: dict[cython.longlong, set[cython.longlong]] = {}
    for view in wide_views:
        base = view.address.offset & 0xFFFF
        widest_by_base[base] = max(widest_by_base.get(base, 0), view.address.size)
        proof_functions_by_base.setdefault(base, set()).add(view.function_addr)

    covered_offsets_by_base = {
        base: frozenset((base + delta) & 0xFFFF for delta in range(width))
        for base, width in builtins.iter(widest_by_base.items())
    }
    ambiguous_bases = {
        left_base
        for left_base, left_offsets in builtins.iter(covered_offsets_by_base.items())
        for right_base, right_offsets in builtins.iter(covered_offsets_by_base.items())
        if left_base != right_base and not left_offsets.isdisjoint(right_offsets)
    }
    layouts = tuple(
        DirectGlobalObjectLayout8616(
            address=IRAddress(
                space=MemSpace.DS,
                offset=base,
                size=width,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            ),
            proof_function_addrs=tuple(sorted(proof_functions_by_base[base])),
        )
        for base, width in builtins.iter(sorted(tuple(widest_by_base.items())))
        if base not in ambiguous_bases
    )
    invalid_fact_count = len(normalized) - len(wide_views)
    return DirectGlobalObjectLayoutEvidence8616(
        layouts=layouts,
        raw_fact_count=len(views),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(wide_views),
        materialized_count=len(layouts),
        failure_count=invalid_fact_count + len(ambiguous_bases),
    )


__all__ = [
    "DirectGlobalObjectLayout8616",
    "DirectGlobalObjectLayoutEvidence8616",
    "DirectGlobalStorageView8616",
    "GlobalObjectLayout8616",
    "GlobalObjectLayoutEvidence8616",
    "GlobalObjectLayoutFailureKind8616",
    "GlobalObjectLayoutRefusal8616",
    "GlobalObjectLayoutSourceKind8616",
    "TransportedGlobalObjectLayoutSource8616",
    "recover_direct_global_object_layout_evidence_8616",
]
