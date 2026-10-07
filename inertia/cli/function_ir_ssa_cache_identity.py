"""Build exact function identities for persisted raw IR and SSA.

Layer: CLI/fallback/reporting orchestration.
Responsibility: fingerprint concrete function block bytes, CFG edges, frontend
configuration, and implementation sources without lifting a VEX block.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Iterable
from typing import Protocol, cast

from .cache import _cache_runtime_environment, _cache_source_digest
from .cache_runtime_contract import cache_runtime_contract_8616
from .cache_source_manifest import FUNCTION_IR_SSA_CACHE_SOURCE_FILES

_FUNCTION_IR_SSA_CACHE_SCHEMA_8616: int = 2


class _MemorySurface8616(Protocol):
    """Third-party loader memory needed for exact block bytes."""

    def load(self, addr: int, size: int) -> bytes | bytearray | memoryview:
        """Read concrete loaded bytes."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader surface used only for cache identity."""

    memory: _MemorySurface8616


class _ArchSurface8616(Protocol):
    """Third-party architecture identity used by the raw IR cache."""

    name: str
    bits: int
    memory_endness: object


class _ProjectSurface8616(Protocol):
    """Third-party project inputs needed for function identity."""

    arch: _ArchSurface8616
    loader: _LoaderSurface8616


class _BlockNode8616(Protocol):
    """Third-party CFG block identity without lifting the block."""

    addr: int
    size: int


class _GraphSurface8616(Protocol):
    """Third-party function graph needed for exact CFG identity."""

    nodes: Iterable[object]
    edges: Iterable[tuple[object, object]]


class _FunctionSurface8616(Protocol):
    """Third-party recovered function boundary used for cache identity."""

    addr: int
    block_addrs_set: set[int]
    graph: _GraphSurface8616


def function_addr_from_boundary_8616(function: object) -> int:
    """Return one exact function address or the refusal sentinel."""
    try:
        addr = cast(_FunctionSurface8616, function).addr
    except AttributeError:
        return -1
    return addr if isinstance(addr, int) and addr >= 0 else -1


def _block_byte_identities_8616(
    project_surface: _ProjectSurface8616,
    raw_nodes: tuple[object, ...],
    expected_addrs: tuple[int, ...],
) -> dict[int, tuple[int, str]] | None:
    """Return per-block size+byte digests, or None on incomplete evidence."""
    nodes: dict[int, tuple[int, str]] = {}
    for raw_node in raw_nodes:
        node = cast(_BlockNode8616, raw_node)
        try:
            addr, size = node.addr, node.size
        except AttributeError:
            continue
        if not isinstance(addr, int) or not isinstance(size, int) or size <= 0:
            return None
        try:
            block_bytes = bytes(project_surface.loader.memory.load(addr, size))
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
        if len(block_bytes) != size:
            return None
        nodes[addr] = (size, hashlib.sha256(block_bytes).hexdigest())
    if tuple(sorted(nodes)) != expected_addrs:
        return None
    return nodes


def _block_edge_identities_8616(
    raw_edges: tuple[object, ...],
    nodes: dict[int, tuple[int, str]],
) -> set[tuple[int, int]]:
    """Return exact CFG edges whose endpoints both materialized blocks."""
    edges: set[tuple[int, int]] = set()
    for raw_source, raw_target in raw_edges:
        source = cast(_BlockNode8616, raw_source)
        target = cast(_BlockNode8616, raw_target)
        try:
            edge = (source.addr, target.addr)
        except AttributeError:
            continue
        if edge[0] in nodes and edge[1] in nodes:
            edges.add(edge)
    return edges


def function_ir_ssa_cache_key_8616(
    project: object,
    function: object,
) -> dict[str, object] | None:
    """Build exact function-byte and CFG identity without lifting VEX."""
    if not cache_runtime_contract_8616().allows_semantic_cache:
        return None
    function_addr = function_addr_from_boundary_8616(function)
    if function_addr < 0:
        return None
    project_surface = cast(_ProjectSurface8616, project)
    function_surface = cast(_FunctionSurface8616, function)
    try:
        expected_addrs = tuple(sorted(function_surface.block_addrs_set))
        raw_nodes = tuple(function_surface.graph.nodes)
        raw_edges = tuple(function_surface.graph.edges)
    except (AttributeError, TypeError):
        return None
    nodes = _block_byte_identities_8616(project_surface, raw_nodes, expected_addrs)
    if nodes is None:
        return None
    edges = _block_edge_identities_8616(raw_edges, nodes)
    try:
        arch = project_surface.arch
        arch_identity = {
            "name": arch.name,
            "bits": arch.bits,
            "memory_endness": str(arch.memory_endness),
        }
    except AttributeError:
        return None
    return {
        "schema": _FUNCTION_IR_SSA_CACHE_SCHEMA_8616,
        "function_addr": function_addr,
        "blocks": [
            {"addr": addr, "size": nodes[addr][0], "sha256": nodes[addr][1]}
            for addr in sorted(nodes)
        ],
        "edges": [[source, target] for source, target in sorted(edges)],
        "arch": arch_identity,
        "runtime": _cache_runtime_environment(),
        "source_sha256": _cache_source_digest(FUNCTION_IR_SSA_CACHE_SOURCE_FILES),
        "python_cache_tag": sys.implementation.cache_tag,
    }


__all__ = [
    "function_addr_from_boundary_8616",
    "function_ir_ssa_cache_key_8616",
]
