# cython: language_level=3, infer_types=True
"""Project immutable entry-address tags from one structured-C subtree.

Layer: Structuring.
Responsibility: collect instruction and VEX-block entry tags in one read-only
walk so Structuring consumers do not independently traverse the same subtree.
Dynamic boundary: angr structured-C nodes expose version-dependent tag fields.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.lowering.c_ast_utils import (
    _iter_c_node_children_8616,
    _iter_c_nodes_deep_8616,
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)
from inertia.lowering.structured_tags import copy_structured_tags_8616
import dataclasses
import operator
import builtins


class _TaggedStructuredNode8616(Protocol):
    """Minimal third-party structured-C tag surface."""

    tags: object


@dataclasses.dataclass(frozen=True, )
class StructuredSubtreeEntryTags8616:
    """Immutable instruction and block entry tags for one subtree."""

    first_instruction_addr: int | None
    block_addrs: object

    @property
    def first_block_addr(self) -> int | None:
        """Return the lowest represented VEX block address."""
        return self.block_addrs[0] if self.block_addrs else None


@dataclasses.dataclass(frozen=True, )
class StructuredSubtreeEntryTagIndexStats8616:
    """Closed accounting for one bottom-up subtree-tag index build."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether every current structured node was indexed."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count + self.failure_count
            and operator.eq(self.classified_fact_count, self.materialized_count)
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class StructuredSubtreeEntryTagIndex8616:
    """Exact entry-tag projections for every acyclic subtree in one C-AST."""

    root: object
    _entries: object
    stats: StructuredSubtreeEntryTagIndexStats8616

    @classmethod
    def build(cls, root: object) -> StructuredSubtreeEntryTagIndex8616:
        """Build bottom-up projections and refuse cyclic unresolved subtrees."""
        node: object
        nodes = tuple(_iter_c_nodes_deep_8616(root))
        node_ids = frozenset(id(node) for node in iter(nodes))
        children_by_id = {
            id(node): tuple(
                child
                for child in builtins.iter(_direct_structured_children_8616(node))
                if id(child) in node_ids
            )
            for node in iter(nodes)
        }
        entries: dict[cython.longlong, tuple[object, StructuredSubtreeEntryTags8616]] = {}
        remaining = list(reversed(nodes))
        while remaining:
            unresolved: list[object] = []
            materialized_before = len(entries)
            for node in remaining:
                children = children_by_id[id(node)]
                if any(id(child) not in entries for child in iter(children)):
                    unresolved.append(node)
                    continue
                entries[id(node)] = (
                    node,
                    _merge_structured_entry_tags_8616(
                        node,
                        tuple(entries[id(child)][1] for child in iter(children)),
                    ),
                )
            if operator.eq(len(entries), materialized_before):
                break
            remaining = unresolved
        materialized_count = len(entries)
        stats = StructuredSubtreeEntryTagIndexStats8616(
            raw_fact_count=len(nodes),
            normalized_fact_count=len(nodes),
            classified_fact_count=materialized_count,
            materialized_count=materialized_count,
            failure_count=len(nodes) - materialized_count,
        )
        return cls(root=root, _entries=entries, stats=stats)

    def for_node(self, node: object) -> StructuredSubtreeEntryTags8616 | None:
        """Return one exact indexed projection by identity, if classified."""
        entry: object
        entry = self._entries.get(id(node))
        return entry[1] if entry is not None and entry[0] is node else None


@dataclasses.dataclass(frozen=True, )
class StructuredSubtreeEntryTagQueryStats8616:
    """Closed accounting for one mutation-aware indexed query session."""

    request_count: cython.longlong
    index_build_count: cython.longlong
    indexed_hit_count: cython.longlong
    fallback_count: cython.longlong
    invalidation_count: cython.longlong

    @property
    def closed(self) -> cython.bint:
        """Return whether every request hit the index or exact fallback."""
        return bool(
            operator.eq(self.request_count, self.indexed_hit_count + self.fallback_count)
            and min(
                self.request_count,
                self.index_build_count,
                self.indexed_hit_count,
                self.fallback_count,
                self.invalidation_count,
            )
            >= 0
        )


@cython.dataclasses.dataclass()
class StructuredSubtreeEntryTagQuerySession8616:
    """Reuse one bottom-up index until its caller reports an AST mutation."""

    root: object
    _index: StructuredSubtreeEntryTagIndex8616 | None = None
    _request_count: cython.longlong = 0
    _index_build_count: cython.longlong = 0
    _indexed_hit_count: cython.longlong = 0
    _fallback_count: cython.longlong = 0
    _invalidation_count: cython.longlong = 0

    @cython.ccall
    def current(self, node: object) -> StructuredSubtreeEntryTags8616:
        """Return an indexed projection or the exact cycle-safe fallback."""
        projection: object
        self._request_count += 1
        if self._index is None:
            self._index = StructuredSubtreeEntryTagIndex8616.build(self.root)
            self._index_build_count += 1
        projection = self._index.for_node(node)
        if projection is not None:
            self._indexed_hit_count += 1
            return projection
        self._fallback_count += 1
        return collect_structured_subtree_entry_tags_8616(node)

    @cython.ccall
    def record_mutation(self) -> None:
        """Discard the entire index after one accepted AST mutation."""
        self._index = None
        self._invalidation_count += 1

    @cython.ccall
    def stats(self) -> StructuredSubtreeEntryTagQueryStats8616:
        """Return closed immutable accounting for this query session."""
        result = StructuredSubtreeEntryTagQueryStats8616(
            request_count=self._request_count,
            index_build_count=self._index_build_count,
            indexed_hit_count=self._indexed_hit_count,
            fallback_count=self._fallback_count,
            invalidation_count=self._invalidation_count,
        )
        if not result.closed:
            raise ValueError("subtree-tag index query accounting is not closed")
        return result


@cython.ccall
def _direct_structured_children_8616(node: object) -> tuple[object, ...]:
    """Return deterministic direct structured children across container fields."""
    value: object
    child: object
    field_name: object
    children: list[object] = []
    seen_children: set[cython.longlong] = set()
    seen_values: set[cython.longlong] = set()
    for field_name in _structured_slot_names_8616(node):
        try:
            value = getattr(node, field_name)
        except (AttributeError, TypeError, ValueError):
            continue
        candidates = (
            (value,)
            if _structured_codegen_node_8616(value)
            else tuple(_iter_c_node_children_8616(value, seen_values))
        )
        for child in candidates:
            child_id = id(child)
            if child_id in seen_children:
                continue
            seen_children.add(child_id)
            children.append(child)
    return tuple(children)


@cython.ccall
def _merge_structured_entry_tags_8616(
    node: object,
    child_projections: object,
) -> StructuredSubtreeEntryTags8616:
    """Merge own exact tags with already-classified direct child projections."""
    block_addr: object
    child_instruction_addr: object
    first_instruction_addr: object
    instruction_addr: object
    tags: object
    projection: object
    first_instruction_addr = None
    block_addrs: set[cython.longlong] = set()
    boundary = cast(_TaggedStructuredNode8616, node)
    try:
        tags = copy_structured_tags_8616(boundary.tags)
    except AttributeError:
        tags = None
    if tags is not None:
        instruction_addr = tags.get("ins_addr")
        if isinstance(instruction_addr, int):
            first_instruction_addr = instruction_addr
        block_addr = tags.get("vex_block_addr")
        if isinstance(block_addr, int):
            block_addrs.add(block_addr)
    for projection in child_projections:
        child_instruction_addr = projection.first_instruction_addr
        if child_instruction_addr is not None and (
            first_instruction_addr is None
            or child_instruction_addr < first_instruction_addr
        ):
            first_instruction_addr = child_instruction_addr
        block_addrs.update(projection.block_addrs)
    return StructuredSubtreeEntryTags8616(
        first_instruction_addr=first_instruction_addr,
        block_addrs=tuple(sorted(block_addrs)),
    )


@cython.ccall
def collect_structured_subtree_entry_tags_8616(
    node: object,
) -> StructuredSubtreeEntryTags8616:
    """Collect instruction and block tags in one deterministic subtree walk."""
    block_addr: object
    copied_tags: object
    first_instruction_addr: object
    instruction_addr: object
    current: object
    first_instruction_addr = None
    block_addrs: set[cython.longlong] = set()
    for current in _iter_c_nodes_deep_8616(node):
        boundary = cast(_TaggedStructuredNode8616, current)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        copied_tags = copy_structured_tags_8616(tags)
        if copied_tags is None:
            continue
        instruction_addr = copied_tags.get("ins_addr")
        if isinstance(instruction_addr, int) and (
            first_instruction_addr is None
            or instruction_addr < first_instruction_addr
        ):
            first_instruction_addr = instruction_addr
        block_addr = copied_tags.get("vex_block_addr")
        if isinstance(block_addr, int):
            block_addrs.add(block_addr)
    return StructuredSubtreeEntryTags8616(
        first_instruction_addr=first_instruction_addr,
        block_addrs=tuple(sorted(block_addrs)),
    )


__all__ = [
    "StructuredSubtreeEntryTagIndex8616",
    "StructuredSubtreeEntryTagIndexStats8616",
    "StructuredSubtreeEntryTagQuerySession8616",
    "StructuredSubtreeEntryTagQueryStats8616",
    "StructuredSubtreeEntryTags8616",
    "collect_structured_subtree_entry_tags_8616",
]
