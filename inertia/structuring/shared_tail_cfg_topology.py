"""CFG topology evidence for calls placed at shared structured tails.

Layer: Structuring.
Responsibility: prove an exact callsite belongs to a multi-predecessor CFG block
whose in-function successor is the call's recovered return address.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from inertia.semantics.callsite_summary import CallsiteSummary8616

__all__ = (
    "SharedTailCfgTopology8616",
    "recover_shared_tail_cfg_topology_8616",
    "shared_callsite_tail_is_proven_8616",
)


@dataclass(frozen=True, slots=True)
class SharedTailCfgTopology8616:
    """Exact in-function block topology used by shared-tail ownership."""

    block_addrs: tuple[int, ...]
    successors: dict[int, tuple[int, ...]]
    predecessors: dict[int, tuple[int, ...]]


class _GraphSurface8616(Protocol):
    """Third-party CFG graph operations used for topology proof."""

    nodes: Iterable[object]

    def successors(self, node: object) -> Iterable[object]:
        """Return graph successors for one node."""


class _FunctionSurface8616(Protocol):
    """Third-party function topology consumed by this pass."""

    block_addrs_set: set[int]
    transition_graph: _GraphSurface8616


class _FunctionManagerSurface8616(Protocol):
    """Third-party function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616:
        """Return the function at one exact entry address."""


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party knowledge-base boundary."""

    functions: _FunctionManagerSurface8616


class _ProjectSurface8616(Protocol):
    """Third-party project boundary."""

    kb: _KnowledgeBaseSurface8616


def _cfg_node_addr_8616(node: object) -> int | None:
    """Return an address from an integer or dynamic angr graph node."""
    if isinstance(node, int):
        return node
    try:
        addr = cast(Any, node).addr
    except AttributeError:
        return None
    return addr if isinstance(addr, int) else None


def recover_shared_tail_cfg_topology_8616(
    project: object,
    function_addr: int,
) -> SharedTailCfgTopology8616 | None:
    """Return exact in-function block, successor, and predecessor topology."""
    try:
        function = cast(_ProjectSurface8616, project).kb.functions.function(
            addr=function_addr,
            create=False,
        )
        graph = function.transition_graph
        block_addrs = tuple(sorted(function.block_addrs_set))
        nodes = tuple(graph.nodes)
    except (AttributeError, TypeError):
        return None
    block_set = set(block_addrs)
    node_by_addr = {
        addr: node
        for node in nodes
        if (addr := _cfg_node_addr_8616(node)) in block_set
    }
    successors: dict[int, tuple[int, ...]] = {}
    for block_addr in block_addrs:
        node = node_by_addr.get(block_addr)
        if node is None:
            return None
        try:
            targets = tuple(
                target_addr
                for successor in graph.successors(node)
                if (target_addr := _cfg_node_addr_8616(successor)) in block_set
            )
        except (AttributeError, TypeError):
            return None
        successors[block_addr] = tuple(dict.fromkeys(targets))
    predecessor_lists: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    for source, targets in successors.items():
        for target in targets:
            predecessor_lists[target].append(source)
    predecessors = {
        target: tuple(dict.fromkeys(sources))
        for target, sources in predecessor_lists.items()
    }
    return SharedTailCfgTopology8616(block_addrs, successors, predecessors)


def shared_callsite_tail_is_proven_8616(
    summary: CallsiteSummary8616,
    topology: SharedTailCfgTopology8616,
) -> bool:
    """Prove a call lies in a multi-predecessor block with an exact return edge."""
    candidates = tuple(
        addr for addr in topology.block_addrs if addr <= summary.callsite_addr
    )
    if not candidates or not isinstance(summary.return_addr, int):
        return False
    call_block_addr = max(candidates)
    return (
        summary.return_addr in topology.successors.get(call_block_addr, ())
        and len(topology.predecessors.get(call_block_addr, ())) >= 2
    )
