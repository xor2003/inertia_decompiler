# cython: language_level=3, infer_types=True
"""Prove direct stack moves that execute at a pretest-loop body entry.

Layer: Structuring.
Responsibility: project a complete angr function CFG into exact block-address
topology and identify a direct stack move in the unique guarded body-entry
block of a natural loop.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
This module never reads rendered C, symbols, source text, or variable names.
Unknown jumps, ambiguous entries, and non-unique latches refuse evidence.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

import networkx as nx

from .direct_stack_move_loop_evidence import comparable_address_8616
import dataclasses
import operator
import builtins

__all__ = (
    "DirectStackMovePretestBodyEvidence8616",
    "recover_direct_stack_move_pretest_body_evidence_8616",
)


@dataclasses.dataclass(frozen=True, )
class DirectStackMovePretestBodyEvidence8616:
    """One exact pretest loop whose body entry contains the stack move."""

    move_addr: cython.longlong
    header_addr: cython.longlong
    body_entry_addr: cython.longlong
    latch_addr: cython.longlong
    body_block_addrs: object
    entry_edges: object
    exit_edges: object
    header_instruction_addrs: object
    body_entry_instruction_addrs: object


@dataclasses.dataclass(frozen=True, )
class _FunctionCfgSnapshot8616:
    """Complete integer-address projection of one dynamic angr function CFG."""

    graph: nx.DiGraph
    instructions_by_block: object


class _GraphBoundary8616(Protocol):
    """Minimal networkx-compatible surface consumed at the angr boundary."""

    nodes: Iterable[object]

    def successors(self, node: object) -> Iterable[object]:
        """Return direct graph successors for one node."""


class _FunctionBoundary8616(Protocol):
    """Dynamic angr Function fields required by the topology projection."""

    block_addrs_set: object
    blocks: Iterable[object]
    has_unresolved_jumps: cython.bint
    transition_graph: _GraphBoundary8616


@cython.ccall
def _boundary_field_8616(
    value: object | None,
    name: object,
    default: object | None = None,
) -> object | None:
    """Read one optional field from a heterogeneous angr/Capstone object."""
    # Dynamic third-party boundary: block, Capstone, and graph-node shapes vary.
    return getattr(value, name, default)


@cython.ccall
def _node_address_8616(node: object) -> int | None:
    """Return one integer node address without interpreting other identities."""
    if isinstance(node, int) and not isinstance(node, bool):
        return node
    address = _boundary_field_8616(node, "addr")
    return address if isinstance(address, int) and not isinstance(address, bool) else None


@cython.ccall
def _instruction_addresses_8616(
    project: object,
    block: object,
    reference_addr: cython.longlong,
) -> tuple[cython.longlong, ...]:
    """Return exact decoded instruction addresses for one binary block."""
    wrapper: object
    capstone = _boundary_field_8616(block, "capstone")
    wrapped = _boundary_field_8616(capstone, "insns", ()) or ()
    addresses: set[cython.longlong] = set()
    try:
        instructions = tuple(cast(Iterable[object], wrapped))
    except TypeError:
        return ()
    for wrapper in instructions:
        instruction = _boundary_field_8616(wrapper, "insn", wrapper)
        address = _boundary_field_8616(instruction, "address")
        if isinstance(address, int) and not isinstance(address, bool):
            addresses.add(comparable_address_8616(project, address, reference_addr))
    return tuple(sorted(addresses))


@cython.ccall
def _snapshot_nodes_8616(
    graph_nodes: object,
    block_set: object,
    project: object,
    reference_addr: cython.longlong,
) -> object:
    """Index transition-graph nodes by their unique in-function block."""
    address: object
    node: object
    node_by_addr: dict[cython.longlong, object] = {}
    for node in graph_nodes:
        address = _node_address_8616(node)
        if address is None:
            continue
        comparable = comparable_address_8616(project, address, reference_addr)
        if comparable not in block_set:
            continue
        if comparable in node_by_addr:
            return None
        node_by_addr[comparable] = node
    return node_by_addr if operator.eq(frozenset(node_by_addr), block_set) else None


@cython.ccall
def _snapshot_graph_8616(
    block_set: object,
    node_by_addr: object,
    source_graph: nx.DiGraph,
    project: object,
    reference_addr: cython.longlong,
) -> nx.DiGraph | None:
    """Project the transition graph onto in-function block addresses."""
    target_addr: object
    source_addr: object
    source_node: object
    target_node: object
    graph = nx.DiGraph()
    graph.add_nodes_from(sorted(block_set))
    try:
        for source_addr, source_node in sorted(tuple(node_by_addr.items())):
            for target_node in source_graph.successors(source_node):
                target_addr = _node_address_8616(target_node)
                if target_addr is None:
                    continue
                comparable_target = comparable_address_8616(
                    project,
                    target_addr,
                    reference_addr,
                )
                if comparable_target in block_set:
                    graph.add_edge(source_addr, comparable_target)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    return graph


@cython.ccall
def _snapshot_block_instructions_8616(
    blocks: object,
    block_set: object,
    project: object,
    reference_addr: cython.longlong,
) -> object:
    """Decode instruction addresses for each unique in-function block."""
    raw_block_addr: object
    block: object
    instructions_by_block: dict[cython.longlong, tuple[cython.longlong, ...]] = {}
    for block in blocks:
        raw_block_addr = _node_address_8616(block)
        if raw_block_addr is None:
            return None
        block_addr = comparable_address_8616(project, raw_block_addr, reference_addr)
        if block_addr not in block_set or block_addr in instructions_by_block:
            return None
        instructions_by_block[block_addr] = _instruction_addresses_8616(
            project,
            block,
            reference_addr,
        )
    return (
        instructions_by_block
        if operator.eq(frozenset(instructions_by_block), block_set)
        else None
    )


def _function_cfg_snapshot_8616(
    project: object,
    function: object,
    reference_addr: cython.longlong,
) -> _FunctionCfgSnapshot8616 | None:
    """Project a complete in-function CFG and decoded block membership."""
    graph: object
    instructions_by_block: object
    node_by_addr: object
    boundary = cast(_FunctionBoundary8616, function)
    try:
        if boundary.has_unresolved_jumps is not False:
            return None
        raw_block_addrs = tuple(boundary.block_addrs_set)
        blocks = tuple(boundary.blocks)
        source_graph = boundary.transition_graph
        graph_nodes = tuple(source_graph.nodes)
    except (AttributeError, TypeError):
        return None
    if not raw_block_addrs or any(
        not isinstance(address, int) or isinstance(address, bool)
        for address in iter(raw_block_addrs)
    ):
        return None
    block_addrs = tuple(
        comparable_address_8616(project, address, reference_addr)
        for address in iter(raw_block_addrs)
    )
    if operator.ne(len(set(block_addrs)), len(block_addrs)):
        return None
    block_set = frozenset(block_addrs)
    node_by_addr = _snapshot_nodes_8616(graph_nodes, block_set, project, reference_addr)
    if node_by_addr is None:
        return None

    graph = _snapshot_graph_8616(
        block_set, node_by_addr, source_graph, project, reference_addr,
    )
    if graph is None:
        return None

    instructions_by_block = _snapshot_block_instructions_8616(
        blocks, block_set, project, reference_addr,
    )
    if instructions_by_block is None:
        return None
    return _FunctionCfgSnapshot8616(graph, instructions_by_block)


def recover_direct_stack_move_pretest_body_evidence_8616(
    project: object,
    function: object,
    move_addr: cython.longlong,
) -> tuple[DirectStackMovePretestBodyEvidence8616, ...]:
    """Return exact loop-body-entry ownership for one direct stack move."""
    fact: object
    snapshot: object
    raw_component: object
    snapshot = _function_cfg_snapshot_8616(project, function, move_addr)
    if snapshot is None:
        return ()
    move_blocks = tuple(
        block_addr
        for block_addr, instruction_addrs in builtins.iter(snapshot.instructions_by_block.items())
        if move_addr in instruction_addrs
    )
    if len(move_blocks) != 1:
        return ()
    move_block = move_blocks[0]
    evidence: list[DirectStackMovePretestBodyEvidence8616] = []
    for raw_component in nx.strongly_connected_components(snapshot.graph):
        component = frozenset(cast(Iterable[int], raw_component))
        if move_block not in component or (
            len(component) == 1
            and not snapshot.graph.has_edge(move_block, move_block)
        ):
            continue
        fact = _component_evidence_8616(snapshot, move_block, move_addr, component)
        if fact is not None:
            evidence.append(fact)
    return tuple(evidence)


def _component_evidence_8616(
    snapshot: _FunctionCfgSnapshot8616,
    move_block: cython.longlong,
    move_addr: cython.longlong,
    component: object,
) -> DirectStackMovePretestBodyEvidence8616 | None:
    """Prove one SCC's unique header/body-entry/latch structure, or refuse."""
    entry_edges = tuple(
        sorted(
            (source, target)
            for source, target in iter(snapshot.graph.edges)
            if source not in component and target in component
        )
    )
    entry_targets = tuple(sorted({target for _, target in iter(entry_edges)}))
    if len(entry_targets) != 1:
        return None
    header = entry_targets[0]
    internal_successors = tuple(
        sorted(
            target
            for target in builtins.iter(snapshot.graph.successors(header))
            if target in component and target != header
        )
    )
    external_successors = tuple(
        target
        for target in builtins.iter(snapshot.graph.successors(header))
        if target not in component
    )
    if len(internal_successors) != 1 or not external_successors:
        return None
    body_entry = internal_successors[0]
    if body_entry != move_block:
        return None
    internal_body_predecessors = frozenset(
        source
        for source in builtins.iter(snapshot.graph.predecessors(body_entry))
        if source in component
    )
    if internal_body_predecessors != {header}:
        return None
    latches = tuple(
        sorted(
            source
            for source in builtins.iter(snapshot.graph.predecessors(header))
            if source in component
        )
    )
    if len(latches) != 1:
        return None
    exit_edges = tuple(
        sorted(
            (source, target)
            for source, target in iter(snapshot.graph.edges)
            if source in component and target not in component
        )
    )
    if not exit_edges:
        return None
    return DirectStackMovePretestBodyEvidence8616(
        move_addr=move_addr,
        header_addr=header,
        body_entry_addr=body_entry,
        latch_addr=latches[0],
        body_block_addrs=tuple(sorted(component)),
        entry_edges=entry_edges,
        exit_edges=exit_edges,
        header_instruction_addrs=snapshot.instructions_by_block[header],
        body_entry_instruction_addrs=snapshot.instructions_by_block[body_entry],
    )
