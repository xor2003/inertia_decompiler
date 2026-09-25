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

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast

import networkx as nx

from .direct_stack_move_loop_evidence import comparable_address_8616

__all__ = (
    "DirectStackMovePretestBodyEvidence8616",
    "recover_direct_stack_move_pretest_body_evidence_8616",
)


@dataclass(frozen=True, slots=True)
class DirectStackMovePretestBodyEvidence8616:
    """One exact pretest loop whose body entry contains the stack move."""

    move_addr: int
    header_addr: int
    body_entry_addr: int
    latch_addr: int
    body_block_addrs: tuple[int, ...]
    entry_edges: tuple[tuple[int, int], ...]
    exit_edges: tuple[tuple[int, int], ...]
    header_instruction_addrs: tuple[int, ...]
    body_entry_instruction_addrs: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _FunctionCfgSnapshot8616:
    """Complete integer-address projection of one dynamic angr function CFG."""

    graph: nx.DiGraph
    instructions_by_block: dict[int, tuple[int, ...]]


class _GraphBoundary8616(Protocol):
    """Minimal networkx-compatible surface consumed at the angr boundary."""

    nodes: Iterable[object]

    def successors(self, node: object) -> Iterable[object]:
        """Return direct graph successors for one node."""


class _FunctionBoundary8616(Protocol):
    """Dynamic angr Function fields required by the topology projection."""

    block_addrs_set: set[int]
    blocks: Iterable[object]
    has_unresolved_jumps: bool
    transition_graph: _GraphBoundary8616


def _boundary_field_8616(
    value: object | None,
    name: str,
    default: object | None = None,
) -> object | None:
    """Read one optional field from a heterogeneous angr/Capstone object."""
    # Dynamic third-party boundary: block, Capstone, and graph-node shapes vary.
    return getattr(value, name, default)


def _node_address_8616(node: object) -> int | None:
    """Return one integer node address without interpreting other identities."""
    if isinstance(node, int) and not isinstance(node, bool):
        return node
    address = _boundary_field_8616(node, "addr")
    return address if isinstance(address, int) and not isinstance(address, bool) else None


def _instruction_addresses_8616(
    project: object,
    block: object,
    reference_addr: int,
) -> tuple[int, ...]:
    """Return exact decoded instruction addresses for one binary block."""
    capstone = _boundary_field_8616(block, "capstone")
    wrapped = _boundary_field_8616(capstone, "insns", ()) or ()
    addresses: set[int] = set()
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


def _snapshot_nodes_8616(
    graph_nodes: tuple[object, ...],
    block_set: frozenset[int],
    project: object,
    reference_addr: int,
) -> dict[int, object] | None:
    """Index transition-graph nodes by their unique in-function block."""
    node_by_addr: dict[int, object] = {}
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
    return node_by_addr if frozenset(node_by_addr) == block_set else None


def _snapshot_graph_8616(
    block_set: frozenset[int],
    node_by_addr: dict[int, object],
    source_graph: Any,
    project: object,
    reference_addr: int,
) -> nx.DiGraph | None:
    """Project the transition graph onto in-function block addresses."""
    graph = nx.DiGraph()
    graph.add_nodes_from(sorted(block_set))
    try:
        for source_addr, source_node in sorted(node_by_addr.items()):
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


def _snapshot_block_instructions_8616(
    blocks: tuple[object, ...],
    block_set: frozenset[int],
    project: object,
    reference_addr: int,
) -> dict[int, tuple[int, ...]] | None:
    """Decode instruction addresses for each unique in-function block."""
    instructions_by_block: dict[int, tuple[int, ...]] = {}
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
        if frozenset(instructions_by_block) == block_set
        else None
    )


def _function_cfg_snapshot_8616(
    project: object,
    function: object,
    reference_addr: int,
) -> _FunctionCfgSnapshot8616 | None:
    """Project a complete in-function CFG and decoded block membership."""
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
        for address in raw_block_addrs
    ):
        return None
    block_addrs = tuple(
        comparable_address_8616(project, address, reference_addr)
        for address in raw_block_addrs
    )
    if len(set(block_addrs)) != len(block_addrs):
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
    move_addr: int,
) -> tuple[DirectStackMovePretestBodyEvidence8616, ...]:
    """Return exact loop-body-entry ownership for one direct stack move."""
    snapshot = _function_cfg_snapshot_8616(project, function, move_addr)
    if snapshot is None:
        return ()
    move_blocks = tuple(
        block_addr
        for block_addr, instruction_addrs in snapshot.instructions_by_block.items()
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
    move_block: int,
    move_addr: int,
    component: frozenset[int],
) -> DirectStackMovePretestBodyEvidence8616 | None:
    """Prove one SCC's unique header/body-entry/latch structure, or refuse."""
    entry_edges = tuple(
        sorted(
            (source, target)
            for source, target in snapshot.graph.edges
            if source not in component and target in component
        )
    )
    entry_targets = tuple(sorted({target for _, target in entry_edges}))
    if len(entry_targets) != 1:
        return None
    header = entry_targets[0]
    internal_successors = tuple(
        sorted(
            target
            for target in snapshot.graph.successors(header)
            if target in component and target != header
        )
    )
    external_successors = tuple(
        target
        for target in snapshot.graph.successors(header)
        if target not in component
    )
    if len(internal_successors) != 1 or not external_successors:
        return None
    body_entry = internal_successors[0]
    if body_entry != move_block:
        return None
    internal_body_predecessors = frozenset(
        source
        for source in snapshot.graph.predecessors(body_entry)
        if source in component
    )
    if internal_body_predecessors != {header}:
        return None
    latches = tuple(
        sorted(
            source
            for source in snapshot.graph.predecessors(header)
            if source in component
        )
    )
    if len(latches) != 1:
        return None
    exit_edges = tuple(
        sorted(
            (source, target)
            for source, target in snapshot.graph.edges
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
