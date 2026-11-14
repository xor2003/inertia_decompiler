# cython: language_level=3, infer_types=True
"""Build exact function identities for persisted raw IR and SSA.

Layer: CLI/fallback/reporting orchestration.
Responsibility: fingerprint concrete function block bytes, CFG edges, frontend
configuration, and implementation sources without lifting a VEX block.
"""

from __future__ import annotations
import typing
import cython

import hashlib
import sys
from collections.abc import Iterable
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir.function_readiness_contracts import (
    FunctionSourceScope8616,
    observed_function_source_revision_8616,
)

from .cache import _cache_runtime_environment, _cache_source_digest
from .cache_runtime_contract import cache_runtime_contract_8616
from .cache_source_manifest import FUNCTION_IR_SSA_CACHE_SOURCE_FILES
import operator
import builtins

_FUNCTION_IR_SSA_CACHE_SCHEMA_8616: cython.longlong = 3


class _MemorySurface8616(Protocol):
    """Third-party loader memory needed for exact block bytes."""

    def load(self, addr: cython.longlong, size: cython.longlong) -> object:
        """Read concrete loaded bytes."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader surface used only for cache identity."""

    memory: _MemorySurface8616


class _ArchSurface8616(Protocol):
    """Third-party architecture identity used by the raw IR cache."""

    name: object
    bits: cython.longlong
    memory_endness: object


class _ProjectSurface8616(Protocol):
    """Third-party project inputs needed for function identity."""

    arch: _ArchSurface8616
    loader: _LoaderSurface8616


class _BlockNode8616(Protocol):
    """Third-party CFG block identity without lifting the block."""

    addr: cython.longlong
    size: cython.longlong


class _GraphSurface8616(Protocol):
    """Third-party function graph needed for exact CFG identity."""

    nodes: Iterable[object]
    edges: Iterable[tuple[object, object]]


class _FunctionSurface8616(Protocol):
    """Third-party recovered function boundary used for cache identity."""

    addr: cython.longlong
    block_addrs_set: object
    graph: _GraphSurface8616


@cython.ccall
def function_addr_from_boundary_8616(function: object) -> cython.longlong:
    """Return one exact function address or the refusal sentinel."""
    try:
        addr = cast(_FunctionSurface8616, function).addr
    except AttributeError:
        return -1
    return addr if isinstance(addr, int) and addr >= 0 else -1


@cython.ccall
def _block_byte_identities_8616(
    project_surface: _ProjectSurface8616,
    raw_nodes: object,
    expected_addrs: object,
) -> object:
    """Return per-block size+byte digests, or None on incomplete evidence."""
    raw_node: object
    nodes: dict[cython.longlong, tuple[cython.longlong, str]] = {}
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
        if operator.ne(len(block_bytes), size):
            return None
        nodes[addr] = (size, hashlib.sha256(block_bytes).hexdigest())
    if operator.ne(tuple(sorted(nodes)), expected_addrs):
        return None
    return nodes


@cython.ccall
def _block_edge_identities_8616(
    raw_edges: object,
    nodes: object,
) -> object:
    """Return exact CFG edges whose endpoints both materialized blocks."""
    raw_source: object
    raw_target: object
    edges: set[tuple[cython.longlong, cython.longlong]] = set()
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


@cython.ccall
def _function_block_identities_8616(
    project: object,
    function: object,
) -> object:
    """Read exact native range inventory or the existing graph-backed identity."""
    nodes: object
    revision: object
    if isinstance(function, ExactFunctionRangeBoundary8616):
        revision = observed_function_source_revision_8616(
            project, function.addr, boundary=function,
        )
        if revision is None:
            return None
        return (
            {block.addr: (block.size, block.sha256) for block in iter(revision.blocks)},
            set(revision.edges),
        )
    surface = cast(_FunctionSurface8616, function)
    try:
        expected = tuple(sorted(surface.block_addrs_set))
        raw_nodes = tuple(surface.graph.nodes)
        raw_edges = tuple(surface.graph.edges)
    except (AttributeError, TypeError):
        return None
    nodes = _block_byte_identities_8616(cast(_ProjectSurface8616, project), raw_nodes, expected)
    if nodes is None:
        return None
    return nodes, _block_edge_identities_8616(raw_edges, nodes)


@cython.ccall
def function_ir_ssa_cache_key_8616(
    project: object,
    function: object,
) -> object:
    """Build exact function-byte and CFG identity without lifting VEX."""
    identities: object
    if not cache_runtime_contract_8616().allows_semantic_cache:
        return None
    function_addr = function_addr_from_boundary_8616(function)
    if function_addr < 0:
        return None
    project_surface = cast(_ProjectSurface8616, project)
    identities = _function_block_identities_8616(project, function)
    if identities is None:
        return None
    nodes, edges = identities
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
        "source_scope": (
            {"kind": FunctionSourceScope8616.EXACT_RANGE.value, "end": function.addr + function.size}
            if isinstance(function, ExactFunctionRangeBoundary8616)
            else {"kind": FunctionSourceScope8616.CURRENT_FUNCTION.value}
        ),
        "blocks": [
            {"addr": addr, "size": nodes[addr][0], "sha256": nodes[addr][1]}
            for addr in builtins.iter(sorted(nodes))
        ],
        "edges": [[source, target] for source, target in builtins.iter(sorted(edges))],
        "arch": arch_identity,
        "runtime": _cache_runtime_environment(),
        "source_sha256": _cache_source_digest(FUNCTION_IR_SSA_CACHE_SOURCE_FILES),
        "python_cache_tag": sys.implementation.cache_tag,
    }


__all__ = [
    "function_addr_from_boundary_8616",
    "function_ir_ssa_cache_key_8616",
]
