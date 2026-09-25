"""Project resolved CFG evidence for direct stack move linear prefixes.

Layer: Structuring.
Responsibility: expose complete normalized block membership and immediate
successors needed to prove that one instruction linearly precedes another.
This module does not inspect or mutate structured C and does not recover values,
aliases, types, or rewrite output.

Dynamic boundary: angr function graphs, blocks, and Capstone wrappers expose
version-dependent attributes. Dynamic reads are restricted to those surfaces.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from .direct_stack_move_loop_evidence import (
    boundary_tuple_8616,
    comparable_address_8616,
)


@dataclass(frozen=True, slots=True)
class DirectStackMoveLinearCfgSnapshot8616:
    """Complete in-function block membership and successor projection."""

    instructions_by_block: dict[int, tuple[int, ...]]
    successors_by_block: dict[int, tuple[int, ...]]


class _GraphBoundary8616(Protocol):
    """Typed subset of the dynamic angr graph contract consumed here."""

    nodes: Iterable[object]

    def successors(self, node: object) -> Iterable[object]:
        """Return immediate graph successors for one node."""


class _FunctionBoundary8616(Protocol):
    """Typed subset of the dynamic angr Function contract consumed here."""

    has_unresolved_jumps: bool
    block_addrs_set: Iterable[object]
    blocks: Iterable[object]
    transition_graph: _GraphBoundary8616


def _node_address_8616(node: object) -> int | None:
    """Read one address from a dynamic angr graph or block node."""
    # Dynamic boundary: angr graph nodes and blocks use optional address fields.
    address = getattr(node, "addr", None)
    return address if isinstance(address, int) and not isinstance(address, bool) else None


def _instruction_addresses_8616(
    project: object,
    block: object,
    reference_addr: int,
) -> tuple[int, ...]:
    """Return normalized decoded instruction addresses for one angr block."""
    # Dynamic boundary: angr blocks expose Capstone wrappers dynamically.
    capstone = getattr(block, "capstone", None)
    addresses: list[int] = []
    for wrapper in boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
        instruction = getattr(wrapper, "insn", wrapper)
        address = getattr(instruction, "address", None)
        if isinstance(address, int) and not isinstance(address, bool):
            addresses.append(comparable_address_8616(project, address, reference_addr))
    return tuple(dict.fromkeys(addresses))


def direct_stack_move_linear_cfg_snapshot_8616(
    project: object,
    function: object,
    reference_addr: int,
) -> DirectStackMoveLinearCfgSnapshot8616 | None:
    """Project a complete resolved in-function CFG for one move fact."""
    # Dynamic boundary: this cast documents the angr Function fields consumed.
    boundary = cast(_FunctionBoundary8616, function)
    try:
        unresolved = boundary.has_unresolved_jumps
    except AttributeError:
        return None
    if unresolved is not False:
        return None
    surface = _cfg_surface_8616(boundary)
    if surface is None:
        return None
    raw_block_addrs, blocks, source_graph, graph_nodes = surface
    block_set = _proven_block_set_8616(project, raw_block_addrs, reference_addr)
    if block_set is None:
        return None
    node_by_addr = _node_map_8616(project, graph_nodes, block_set, reference_addr)
    if node_by_addr is None:
        return None
    successors_by_block = _successor_map_8616(
        project, source_graph, node_by_addr, block_set, reference_addr
    )
    if successors_by_block is None:
        return None
    instructions_by_block = _instruction_map_8616(
        project, blocks, block_set, reference_addr
    )
    if instructions_by_block is None:
        return None
    return DirectStackMoveLinearCfgSnapshot8616(
        instructions_by_block,
        successors_by_block,
    )


def _cfg_surface_8616(
    boundary: _FunctionBoundary8616,
) -> (
    tuple[tuple[object, ...], tuple[object, ...], _GraphBoundary8616, tuple[object, ...]]
    | None
):
    """Fetch the raw block/instruction/graph surfaces from the function."""
    try:
        return (
            tuple(boundary.block_addrs_set),
            tuple(boundary.blocks),
            boundary.transition_graph,
            tuple(boundary.transition_graph.nodes),
        )
    except (AttributeError, TypeError):
        return None


def _proven_block_set_8616(
    project: object,
    raw_block_addrs: tuple[object, ...],
    reference_addr: int,
) -> frozenset[int] | None:
    """Return the unique comparable block set or refuse."""
    if not raw_block_addrs or any(
        not isinstance(address, int) or isinstance(address, bool)
        for address in raw_block_addrs
    ):
        return None
    block_addrs = tuple(
        comparable_address_8616(project, cast(int, address), reference_addr)
        for address in raw_block_addrs
    )
    if len(set(block_addrs)) != len(block_addrs):
        return None
    return frozenset(block_addrs)


def _node_map_8616(
    project: object,
    graph_nodes: tuple[object, ...],
    block_set: frozenset[int],
    reference_addr: int,
) -> dict[int, object] | None:
    """Map each proven block address to its unique graph node."""
    node_by_addr: dict[int, object] = {}
    for node in graph_nodes:
        address = _node_address_8616(node)
        if address is None:
            continue
        comparable = comparable_address_8616(project, address, reference_addr)
        if comparable in block_set:
            if comparable in node_by_addr:
                return None
            node_by_addr[comparable] = node
    if frozenset(node_by_addr) != block_set:
        return None
    return node_by_addr


def _successor_map_8616(
    project: object,
    source_graph: _GraphBoundary8616,
    node_by_addr: dict[int, object],
    block_set: frozenset[int],
    reference_addr: int,
) -> dict[int, tuple[int, ...]] | None:
    """Project exact in-set CFG successors per block."""
    successors_by_block: dict[int, tuple[int, ...]] = {}
    try:
        for source_addr, source_node in node_by_addr.items():
            successors = tuple(
                comparable_address_8616(project, target_addr, reference_addr)
                for target in source_graph.successors(source_node)
                if (target_addr := _node_address_8616(target)) is not None
                and comparable_address_8616(project, target_addr, reference_addr)
                in block_set
            )
            successors_by_block[source_addr] = tuple(dict.fromkeys(successors))
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    return successors_by_block


def _instruction_map_8616(
    project: object,
    blocks: tuple[object, ...],
    block_set: frozenset[int],
    reference_addr: int,
) -> dict[int, tuple[int, ...]] | None:
    """Project decoded instruction addresses per proven block."""
    instructions_by_block: dict[int, tuple[int, ...]] = {}
    for block in blocks:
        raw_addr = _node_address_8616(block)
        if raw_addr is None:
            return None
        block_addr = comparable_address_8616(project, raw_addr, reference_addr)
        if block_addr not in block_set or block_addr in instructions_by_block:
            return None
        instructions_by_block[block_addr] = _instruction_addresses_8616(
            project,
            block,
            reference_addr,
        )
    if frozenset(instructions_by_block) != block_set:
        return None
    return instructions_by_block


def _instruction_block_8616(
    snapshot: DirectStackMoveLinearCfgSnapshot8616,
    instruction_addr: int,
) -> int | None:
    """Return the unique block containing one decoded instruction."""
    owners = tuple(
        block_addr
        for block_addr, instructions in snapshot.instructions_by_block.items()
        if instruction_addr in instructions
    )
    return owners[0] if len(owners) == 1 else None


def linear_cfg_successor_proven_8616(
    snapshot: DirectStackMoveLinearCfgSnapshot8616,
    move_addr: int,
    following_addr: int,
) -> bool:
    """Return whether one statement follows in the same or sole successor block."""
    move_block = _instruction_block_8616(snapshot, move_addr)
    following_block = _instruction_block_8616(snapshot, following_addr)
    if move_block is None or following_block is None:
        return False
    if move_block == following_block:
        return move_addr < following_addr
    return snapshot.successors_by_block.get(move_block, ()) == (following_block,)
