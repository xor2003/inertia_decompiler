"""Prove CFG exits before introducing structured loop-break guards.

Layer: Structuring.
Responsibility: consume immutable binary CFG evidence and require an exact
natural-loop exit. Missing AST instruction tags are never exit evidence.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
No rendered-text recovery belongs here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

import networkx as nx

from ..ir.function_ssa_registry import registered_function_ssa_artifact_8616
from ..ir.ssa_function import SSAFunctionArtifact
from ..register_source_block_inventory import collect_register_source_block_inventory_8616
from .condition_exit_normalization import transparent_condition_exit_8616
from .natural_loop_topology import (
    LoopTopologyVerdict8616,
    NaturalLoopTopology8616,
    classify_natural_loop_topology_8616,
)


class _Functions(Protocol):
    """Read-only angr function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Find the already-discovered function."""


class _KnowledgeBase(Protocol):
    """angr function inventory boundary."""

    functions: _Functions


class _Project(Protocol):
    """angr project boundary needed for CFG evidence."""

    kb: _KnowledgeBase


class _Function(Protocol):
    """Structured function identity boundary."""

    addr: int


class _Codegen(Protocol):
    """angr codegen function boundary."""

    cfunc: _Function


@dataclass(frozen=True, slots=True)
class LoopBreakTopology8616:
    """Exact natural-loop regions and their source CFG edges."""

    loops: tuple[NaturalLoopTopology8616, ...]
    edges: frozenset[tuple[int, int]]
    resolved_targets: tuple[tuple[int, int], ...] = ()

    def resolve_target(self, target: int) -> int:
        """Project a physical target through SSA-proven empty connectors."""
        return next((resolved for source, resolved in self.resolved_targets if source == target), target)

    def proves_exit(self, branch: int, taken: int, fallthrough: int, destination: int) -> bool:
        """Require one unambiguous loop and its actual fallthrough exit edge."""
        owners = tuple(loop for loop in self.loops if branch in loop.body)
        if len(owners) != 1:
            return False
        loop = owners[0]
        return (
            self.resolve_target(taken) in loop.body
            and self.resolve_target(destination) not in loop.body
            and (branch, taken) in self.edges
            and (branch, fallthrough) in self.edges
            and (branch, self.resolve_target(fallthrough)) in loop.exit_edges
        )


def _back_edges(graph: nx.DiGraph, entry: int) -> tuple[tuple[int, int], ...]:
    """Find latch/header edges using NetworkX's authoritative dominator tree."""
    dominators: dict[int, int] = nx.immediate_dominators(graph, entry)
    # NetworkX omits the root, which has no immediate dominator. Terminate
    # ancestor walks at a local self-parent and retain entry self-loops.
    dominators[entry] = entry
    edges: list[tuple[int, int]] = []
    for latch in sorted(dominators):
        header = latch
        while True:
            if graph.has_edge(latch, header):
                edges.append((header, latch))
            parent = dominators[header]
            if parent == header:
                break
            header = parent
    return tuple(sorted(edges))


def _transparent_topology_8616(
    graph: nx.DiGraph, entry: int, artifact: SSAFunctionArtifact,
) -> tuple[nx.DiGraph, tuple[tuple[int, int], ...]]:
    """Collapse only proven empty connectors in a detached classification view.

    Headers and latches retain their physical identities so loop ownership and
    backedge proofs cannot be manufactured by collapsing an empty loop body.
    The original graph remains authoritative for branch-edge identity.
    """
    retained = frozenset({entry} | {node for pair in _back_edges(graph, entry) for node in pair})
    successors = {node: tuple(sorted(graph.successors(node))) for node in graph}
    targets = {
        node: transparent_condition_exit_8616(
            artifact, node, successors, stop_at=None, retained_targets=retained,
        )
        for node in graph
    }
    projected = nx.DiGraph()
    projected.add_nodes_from(node for node in graph if targets[node] == node)
    projected.add_edges_from((source, targets[target]) for source, target in graph.edges if targets[source] == source)
    reachable = nx.descendants(projected, entry) | {entry}
    resolutions = tuple(sorted((node, target) for node, target in targets.items() if node != target))
    return projected.subgraph(reachable).copy(), resolutions


def collect_loop_break_topology_8616(project: object, codegen: object) -> LoopBreakTopology8616 | None:
    """Collect exact topology, refusing incomplete or unsupported loop regions."""
    try:
        function = cast(_Project, project).kb.functions.function(
            addr=cast(_Codegen, codegen).cfunc.addr, create=False,
        )
    except (AttributeError, TypeError):
        return None
    if function is None:
        return None
    inventory = collect_register_source_block_inventory_8616(function)
    if not inventory.complete:
        return None
    graph = nx.DiGraph()
    graph.add_nodes_from(block.block_addr for block in inventory.blocks)
    graph.add_edges_from((pred, block.block_addr) for block in inventory.blocks for pred in block.predecessors)
    if inventory.function_addr not in graph:
        return None
    reachable = nx.descendants(graph, inventory.function_addr) | {inventory.function_addr}
    graph = graph.subgraph(reachable).copy()
    loops = tuple(
        classify_natural_loop_topology_8616(graph, header=header, latch=latch, entry=inventory.function_addr)
        for header, latch in _back_edges(graph, inventory.function_addr)
    )
    resolved_targets: tuple[tuple[int, int], ...] = ()
    physical_edges = frozenset(graph.edges)
    if any(loop.verdict is not LoopTopologyVerdict8616.PROVEN for loop in loops):
        artifact = registered_function_ssa_artifact_8616(project, inventory.function_addr).artifact
        if artifact is None:
            return None
        graph, resolved_targets = _transparent_topology_8616(graph, inventory.function_addr, artifact)
        loops = tuple(
            classify_natural_loop_topology_8616(graph, header=header, latch=latch, entry=inventory.function_addr)
            for header, latch in _back_edges(graph, inventory.function_addr)
        )
    if any(loop.verdict is not LoopTopologyVerdict8616.PROVEN for loop in loops):
        return None
    return LoopBreakTopology8616(loops, physical_edges, resolved_targets)
