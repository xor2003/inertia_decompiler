# cython: language_level=3, infer_types=True
"""Retain immutable CFG inputs for register-source recovery.

Layer: traits/summaries/confidence.
Responsibility: cache exact decoded block instructions and predecessor topology
under a binary/CFG surface generation without classifying register effects.
Do not own Alias joins, semantic CALL effects, lowering, structuring, or rewrite.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.errors import SimEngineError

from .function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "RegisterSourceBlockEvidence8616",
    "RegisterSourceBlockInventory8616",
    "collect_register_source_block_inventory_8616",
]


class _InstructionBlock8616(Protocol):
    """Decoded Capstone instruction container at the angr boundary."""

    insns: Sequence[object]


class _DecodedBlock8616(Protocol):
    """Decoded block fields consumed by the inventory builder."""

    capstone: _InstructionBlock8616


class _Factory8616(Protocol):
    """angr block factory boundary used for exact-size decoding."""

    def block(self, addr: cython.longlong, *, size: cython.longlong, opt_level: cython.longlong) -> _DecodedBlock8616:
        """Decode one exact CFG block."""


class _Project8616(Protocol):
    """Project surface needed to decode immutable instruction evidence."""

    factory: _Factory8616


class _GraphNode8616(Protocol):
    """Function graph node bounds used by the inventory."""

    addr: cython.longlong
    size: cython.longlong


class _Graph8616(Protocol):
    """Directed function graph surface consumed by the inventory."""

    nodes: Iterable[_GraphNode8616]

    def predecessors(self, node: _GraphNode8616) -> Iterable[_GraphNode8616]:
        """Return direct in-function predecessors of ``node``."""


class _Function8616(Protocol):
    """angr function fields defining one exact CFG surface."""

    addr: cython.longlong
    project: _Project8616
    graph: _Graph8616
    block_addrs_set: object


@dataclasses.dataclass(frozen=True, )
class RegisterSourceBlockEvidence8616:
    """Immutable instructions and predecessors for one exact CFG block."""

    block_addr: cython.longlong
    predecessors: object
    instructions: object


@dataclasses.dataclass(frozen=True, )
class RegisterSourceBlockInventory8616:
    """Closed per-function input census for register-source recovery."""

    function_addr: cython.longlong
    blocks: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether every CFG block produced one exact input record."""
        return bool(
            self.function_addr >= 0
            and self.raw_fact_count > 0
            and operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
            and operator.eq(self.materialized_count, len(self.blocks))
            and self.failure_count == 0
        )


@cython.ccall
def _node_addr_8616(node: object) -> int | None:
    """Return an address from an angr node or a NetworkX integer node."""
    if isinstance(node, int):
        return node
    try:
        address = cast(_GraphNode8616, node).addr
    except AttributeError:
        return None
    return address if isinstance(address, int) else None


def _graph_rows_8616(
    function: _Function8616,
) -> tuple[tuple[cython.longlong, cython.longlong, tuple[cython.longlong, ...]], ...]:
    """Project deterministic block bounds and predecessor edges."""
    node: object
    block_addr: object
    try:
        block_addrs = tuple(sorted(function.block_addrs_set))
        graph_nodes = tuple(function.graph.nodes)
    except (AttributeError, TypeError):
        return ()
    nodes = {
        address: node
        for node in iter(graph_nodes)
        if (address := _node_addr_8616(node)) is not None
    }
    rows: list[tuple[cython.longlong, cython.longlong, tuple[cython.longlong, ...]]] = []
    for block_addr in block_addrs:
        node = nodes.get(block_addr)
        if node is None:
            rows.append((block_addr, -1, ()))
            continue
        try:
            size = int(node.size)
            predecessors = tuple(
                sorted(
                    address
                    for predecessor in builtins.iter(function.graph.predecessors(node))
                    if (address := _node_addr_8616(predecessor)) is not None
                )
            )
        except (AttributeError, TypeError, ValueError):
            size = -1
            predecessors = ()
        rows.append((block_addr, size, predecessors))
    return tuple(rows)


@cython.ccall
def _graph_generation_8616(
    rows: object,
) -> bytes:
    """Encode structured CFG coordinates for generic cache invalidation."""
    block_addr: object
    predecessor: object
    predecessors: object
    size: object
    generation = bytearray()
    for block_addr, size, predecessors in rows:
        generation.extend(block_addr.to_bytes(16, "little", signed=True))
        generation.extend(size.to_bytes(16, "little", signed=True))
        generation.extend(len(predecessors).to_bytes(8, "little"))
        for predecessor in predecessors:
            generation.extend(predecessor.to_bytes(16, "little", signed=True))
    return bytes(generation)


@cython.ccall
def _build_inventory_8616(
    project: object,
    function: object,
) -> tuple[RegisterSourceBlockInventory8616]:
    """Build one closed inventory from the current exact CFG surface."""
    block_addr: object
    predecessors: object
    size: object
    boundary = cast(_Function8616, function)
    try:
        function_addr = int(boundary.addr)
    except (AttributeError, TypeError, ValueError):
        function_addr = -1
    rows = _graph_rows_8616(boundary)
    blocks: list[RegisterSourceBlockEvidence8616] = []
    failures = 0
    if project is None:
        failures = len(rows) or 1
    else:
        project_boundary = cast(_Project8616, project)
        for block_addr, size, predecessors in rows:
            if size <= 0:
                failures += 1
                continue
            try:
                instructions = tuple(
                    project_boundary.factory.block(
                        block_addr,
                        size=size,
                        opt_level=0,
                    ).capstone.insns
                )
            except (AttributeError, SimEngineError, TypeError, ValueError):
                failures += 1
                continue
            blocks.append(
                RegisterSourceBlockEvidence8616(
                    block_addr,
                    predecessors,
                    instructions,
                )
            )
    fact_count = len(rows) or failures
    return (
        RegisterSourceBlockInventory8616(
            function_addr,
            tuple(blocks),
            raw_fact_count=fact_count,
            normalized_fact_count=fact_count,
            classified_fact_count=fact_count,
            materialized_count=len(blocks),
            failure_count=failures,
        ),
    )


@cython.ccall
def collect_register_source_block_inventory_8616(
    function: object,
) -> RegisterSourceBlockInventory8616:
    """Return cached immutable inputs for the current function CFG surface."""
    boundary = cast(_Function8616, function)
    try:
        project = boundary.project
    except AttributeError:
        project = None
    rows = _graph_rows_8616(boundary)
    collected = collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.REGISTER_SOURCE_BLOCKS,
        builder=_build_inventory_8616,
        content_identity=_graph_generation_8616(rows),
    )
    if len(collected) == 1 and isinstance(
        collected[0],
        RegisterSourceBlockInventory8616,
    ):
        return collected[0]
    return RegisterSourceBlockInventory8616(-1, (), 1, 1, 1, 0, 1)
