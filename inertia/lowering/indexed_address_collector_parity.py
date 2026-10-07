"""Measure migration parity for indexed-address evidence producers.

Layer: Types/Lowering diagnostics.
Responsibility: compare Alias-projected indexed access identities with the
current instruction-backed Lowering collectors and publish exact matched and
unmatched keys. This module is a migration census only: it does not produce
semantic evidence, select a winner, infer types or bounds, or mutate C.
Consumes alias, widening, and typed facts; do not recover new semantics here.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not perform structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

from inertia.alias.indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
)
from inertia.ir.core import MemSpace
from inertia.ir.indexed_address_contracts import IndexedAddressAccessKind8616

from .segmented_global_loads import (
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    IndexedSegmentedGlobalStoreEvidence8616,
    recover_indexed_segmented_global_load_site_evidence_8616,
    recover_indexed_segmented_global_store_evidence_8616,
)


class IndexedAddressCollectorParityStatus8616(StrEnum):
    """Relationship between Alias and legacy indexed-address key sets."""

    EMPTY = "empty"
    EXACT = "exact"
    ALIAS_SUPERSET = "alias_superset"
    LEGACY_SUPERSET = "legacy_superset"
    DIVERGED = "diverged"


@dataclass(frozen=True, slots=True)
class IndexedAddressCollectorKey8616:
    """Common identity represented by both indexed-address collectors."""

    kind: IndexedAddressAccessKind8616
    space: MemSpace
    base_offset: int
    width: int
    index_stack_offset: int
    index_shift: int
    instr_addr: int

    @property
    def complete(self) -> bool:
        """Return whether this key has an exact segmented machine identity."""
        return bool(
            self.space in {MemSpace.DS, MemSpace.ES}
            and 0 <= self.base_offset <= 0xFFFF
            and self.width > 0
            and 0 <= self.index_shift <= 4
            and self.instr_addr >= 0
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressCollectorParityStats8616:
    """Closed accounting for both compared key multisets."""

    raw_key_count: int
    normalized_key_count: int
    matched_key_count: int
    alias_only_count: int
    legacy_only_count: int
    duplicate_key_count: int

    @property
    def closed(self) -> bool:
        """Return whether all raw and normalized keys are accounted."""
        return bool(
            self.raw_key_count == self.normalized_key_count + self.duplicate_key_count
            and self.normalized_key_count
            == self.matched_key_count * 2
            + self.alias_only_count
            + self.legacy_only_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressCollectorParity8616:
    """Exact migration census for one function."""

    function_addr: int
    status: IndexedAddressCollectorParityStatus8616
    matched: tuple[IndexedAddressCollectorKey8616, ...]
    alias_only: tuple[IndexedAddressCollectorKey8616, ...]
    legacy_only: tuple[IndexedAddressCollectorKey8616, ...]
    stats: IndexedAddressCollectorParityStats8616

    @property
    def closed(self) -> bool:
        """Return whether keys, counts, and status agree."""
        expected_status = _parity_status_8616(
            bool(self.matched),
            bool(self.alias_only),
            bool(self.legacy_only),
        )
        return bool(
            self.stats.closed
            and len(self.matched) == self.stats.matched_key_count
            and len(self.alias_only) == self.stats.alias_only_count
            and len(self.legacy_only) == self.stats.legacy_only_count
            and self.status is expected_status
            and all(key.complete for key in (*self.matched, *self.alias_only, *self.legacy_only))
        )

    @property
    def exact(self) -> bool:
        """Return whether both collectors publish exactly the same unique keys."""
        return bool(
            self.status in {
                IndexedAddressCollectorParityStatus8616.EMPTY,
                IndexedAddressCollectorParityStatus8616.EXACT,
            }
            and self.stats.duplicate_key_count == 0
        )


class _CFuncBoundary8616(Protocol):
    """Minimal dynamic angr C-function surface used to resolve a function."""

    addr: object


class _CodegenBoundary8616(Protocol):
    """Typed artifacts carried across the dynamic angr codegen boundary."""

    cfunc: _CFuncBoundary8616 | None
    _inertia_indexed_address_alias_evidence_8616: IndexedAddressAliasEvidence8616
    _inertia_indexed_address_collector_parity_8616: IndexedAddressCollectorParity8616


class _FunctionManagerBoundary8616(Protocol):
    """Minimal dynamic angr function lookup surface."""

    function: Callable[..., object | None]


class _KnowledgeBaseBoundary8616(Protocol):
    """Minimal dynamic angr knowledge-base surface."""

    functions: _FunctionManagerBoundary8616


class _ProjectBoundary8616(Protocol):
    """Minimal dynamic angr project surface for parity collection."""

    kb: _KnowledgeBaseBoundary8616


def _alias_key_8616(fact: IndexedAddressAliasFact8616) -> IndexedAddressCollectorKey8616:
    """Normalize one Alias fact to the shared migration identity."""
    return IndexedAddressCollectorKey8616(
        fact.source.kind,
        fact.storage.space,
        fact.storage.base_offset,
        fact.storage.width,
        fact.source.index_source.offset,
        fact.storage.index_shift,
        fact.source.instr_addr,
    )


def _load_key_8616(
    fact: IndexedSegmentedGlobalLoadSiteEvidence8616,
) -> IndexedAddressCollectorKey8616:
    """Normalize one instruction-backed load to the shared identity."""
    return IndexedAddressCollectorKey8616(
        IndexedAddressAccessKind8616.LOAD,
        MemSpace.DS,
        fact.base_offset & 0xFFFF,
        fact.width,
        fact.index_stack_offset,
        fact.index_shift,
        fact.ins_addr,
    )


def _store_key_8616(
    fact: IndexedSegmentedGlobalStoreEvidence8616,
) -> IndexedAddressCollectorKey8616:
    """Normalize one instruction-backed store to the shared identity."""
    return IndexedAddressCollectorKey8616(
        IndexedAddressAccessKind8616.STORE,
        MemSpace.DS,
        fact.base_offset & 0xFFFF,
        fact.width,
        fact.index_stack_offset,
        fact.index_shift,
        fact.ins_addr,
    )


def _parity_status_8616(
    matched: bool,
    alias_only: bool,
    legacy_only: bool,
) -> IndexedAddressCollectorParityStatus8616:
    """Classify one exact set relationship without text matching."""
    if not matched and not alias_only and not legacy_only:
        return IndexedAddressCollectorParityStatus8616.EMPTY
    if not alias_only and not legacy_only:
        return IndexedAddressCollectorParityStatus8616.EXACT
    if alias_only and not legacy_only:
        return IndexedAddressCollectorParityStatus8616.ALIAS_SUPERSET
    if legacy_only and not alias_only:
        return IndexedAddressCollectorParityStatus8616.LEGACY_SUPERSET
    return IndexedAddressCollectorParityStatus8616.DIVERGED


def _key_sort_8616(key: IndexedAddressCollectorKey8616) -> tuple[object, ...]:
    """Return deterministic primitive fields for parity report ordering."""
    return (
        key.kind.value,
        key.space.value,
        key.base_offset,
        key.width,
        key.index_stack_offset,
        key.index_shift,
        key.instr_addr,
    )


def compare_indexed_address_collectors_8616(
    alias_evidence: IndexedAddressAliasEvidence8616,
    legacy_loads: tuple[IndexedSegmentedGlobalLoadSiteEvidence8616, ...],
    legacy_stores: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
) -> IndexedAddressCollectorParity8616:
    """Compare Alias and instruction-backed keys without selecting a producer."""
    if not alias_evidence.closed:
        raise PipelineHardError(
            "indexed-address Alias evidence is incomplete before parity census",
            layer="lowering",
        )
    alias_keys = tuple(_alias_key_8616(fact) for fact in alias_evidence.facts)
    legacy_keys = (*(_load_key_8616(fact) for fact in legacy_loads), *(_store_key_8616(fact) for fact in legacy_stores))
    alias_set = frozenset(alias_keys)
    legacy_set = frozenset(legacy_keys)
    matched = tuple(sorted(alias_set & legacy_set, key=_key_sort_8616))
    alias_only = tuple(sorted(alias_set - legacy_set, key=_key_sort_8616))
    legacy_only = tuple(sorted(legacy_set - alias_set, key=_key_sort_8616))
    normalized = len(alias_set) + len(legacy_set)
    raw = len(alias_keys) + len(legacy_keys)
    duplicate_count = sum(count - 1 for count in Counter(alias_keys).values()) + sum(
        count - 1 for count in Counter(legacy_keys).values()
    )
    result = IndexedAddressCollectorParity8616(
        alias_evidence.function_addr,
        _parity_status_8616(bool(matched), bool(alias_only), bool(legacy_only)),
        matched,
        alias_only,
        legacy_only,
        IndexedAddressCollectorParityStats8616(
            raw,
            normalized,
            len(matched),
            len(alias_only),
            len(legacy_only),
            duplicate_count,
        ),
    )
    if not result.closed:
        raise PipelineHardError(
            "indexed-address collector parity accounting is incomplete",
            layer="lowering",
        )
    return result


def collect_indexed_address_collector_parity_8616(
    project: object,
    codegen: object,
) -> IndexedAddressCollectorParity8616 | None:
    """Collect legacy facts and attach the typed migration census."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return None
    if cfunc is None or not isinstance(cfunc.addr, int):
        return None
    try:
        alias_evidence = boundary._inertia_indexed_address_alias_evidence_8616
    except AttributeError as error:
        raise PipelineHardError(
            "indexed-address Alias evidence is missing before Lowering parity census",
            layer="lowering",
        ) from error
    if not isinstance(alias_evidence, IndexedAddressAliasEvidence8616):
        raise PipelineHardError(
            "indexed-address Alias evidence has the wrong pipeline contract",
            layer="lowering",
        )
    project_boundary = cast(_ProjectBoundary8616, project)
    function = project_boundary.kb.functions.function(addr=cfunc.addr, create=False)
    if function is None:
        return None
    result = compare_indexed_address_collectors_8616(
        alias_evidence,
        recover_indexed_segmented_global_load_site_evidence_8616(project, function),
        recover_indexed_segmented_global_store_evidence_8616(project, function),
    )
    boundary._inertia_indexed_address_collector_parity_8616 = result
    return result


__all__ = [
    "IndexedAddressCollectorKey8616",
    "IndexedAddressCollectorParity8616",
    "IndexedAddressCollectorParityStats8616",
    "IndexedAddressCollectorParityStatus8616",
    "collect_indexed_address_collector_parity_8616",
    "compare_indexed_address_collectors_8616",
]
