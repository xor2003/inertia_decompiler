# cython: language_level=3, infer_types=True
"""Resolve exact segment-access provenance from structured-codegen tags.

Layer: Types/Lowering.
Responsibility: map dynamic angr C-AST instruction and block ownership tags to
unique machine-access instructions already proven by the IR segment contract.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not infer storage identity or inspect assembly/rendered C.
"""

from __future__ import annotations
import cython

from typing import Any, cast

from inertia.ir.segment_contract import (
    SegmentAccessKind,
    SegmentFunctionContract,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616
import operator

__all__ = [
    "instruction_addrs_from_node_8616",
    "unique_access_instruction_in_tagged_blocks_8616",
]


def instruction_addrs_from_node_8616(node: object) -> frozenset[cython.longlong]:
    """Collect exact instruction provenance from a dynamic angr C subtree."""
    candidate: object

    def collect_owner_tags(owner: object, addresses: object) -> None:
        """Collect exact tags from one dynamic AST or wrapped dirty owner."""
        source_addrs: object
        tags: object
        value: object
        key: object
        dynamic_owner = cast(Any, owner)
        try:
            tags = copy_structured_tags_8616(dynamic_owner.tags)
        except AttributeError:
            return
        if tags is None:
            return
        for key in ("ins_addr", "inertia_relocated_from_ins_addr"):
            value = tags.get(key)
            if isinstance(value, int):
                addresses.add(value)
        source_addrs = tags.get("inertia_source_instruction_addrs", ())
        if isinstance(source_addrs, tuple):
            addresses.update(value for value in iter(source_addrs) if isinstance(value, int))

    addresses: set[cython.longlong] = set()
    for candidate in _iter_c_nodes_deep_8616(node):
        collect_owner_tags(candidate, addresses)
        try:
            dirty_payload = cast(Any, candidate).dirty
        except AttributeError:
            continue
        collect_owner_tags(dirty_payload, addresses)
    return frozenset(addresses)


@cython.ccall
def unique_access_instruction_in_tagged_blocks_8616(
    contract: SegmentFunctionContract,
    node: object,
    *,
    access_kind: object,
    segment_register: object,
    offset: int | None,
    width: int | None,
) -> object:
    """Resolve one unique matching access instruction from exact block tags."""
    tags: object
    candidate: object
    if not isinstance(offset, int) or not isinstance(width, int) or width <= 0:
        return frozenset()
    block_addrs: set[cython.longlong] = set()
    for candidate in _iter_c_nodes_deep_8616(node):
        dynamic_candidate = cast(Any, candidate)
        try:
            tags = copy_structured_tags_8616(dynamic_candidate.tags)
        except AttributeError:
            continue
        block_addr = tags.get("vex_block_addr") if tags is not None else None
        if isinstance(block_addr, int):
            block_addrs.add(block_addr)
    if not block_addrs:
        return frozenset()
    requested_offsets = {
        (offset + byte_offset) & 0xFFFF
        for byte_offset in range(width)
    }
    instruction_addrs = {
        fact.instruction_addr
        for fact in iter(contract.accesses)
        if isinstance(fact.instruction_addr, int)
        and fact.block_addr in block_addrs
        and operator.eq(fact.segment_register, segment_register)
        and (access_kind is None or fact.kind is access_kind)
        and fact.address.size > 0
        and {
            (fact.address.offset + byte_offset) & 0xFFFF
            for byte_offset in range(fact.address.size)
        }.issubset(requested_offsets)
    }
    return frozenset(instruction_addrs) if len(instruction_addrs) == 1 else frozenset()
