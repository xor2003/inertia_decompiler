# cython: language_level=3, infer_types=True
"""Normalize condition exits only through proven empty SSA blocks.

Layer: Structuring.
Responsibility: consume authoritative SSA effects and CFG edges to identify
equivalent condition-chain exits, without moving or discarding effects.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping

from angr.analyses.decompiler.structured_codegen.c import CGoto, CStatements

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.ssa_function import SSAFunctionArtifact
import operator
import builtins


def transparent_condition_exit_8616(
    artifact: object,
    target: cython.longlong,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
    *,
    stop_at: int | None,
    retained_targets: object = frozenset(),
) -> cython.longlong:
    """Follow empty, refusal-free SSA blocks; retain the input on uncertain edges.

    The opposite outcome is a boundary, never an equivalent exit. Instructions,
    bindings and phi nodes stop traversal before their effects, even if those
    destination effects have refusals: only bypassed blocks need that proof. Missing blocks,
    conflicting graphs and cycles invalidate normalization altogether.
    Explicit retained targets are endpoints, never blocks to bypass.
    """
    block: object
    edges: object
    refused_blocks: object
    if artifact is None:
        return target
    refused_blocks = {refusal.block_addr for refusal in iter(artifact.memory_refusals)}
    if None in refused_blocks:
        return target
    blocks = {block.addr: block for block in iter(artifact.blocks)}
    phi_blocks = {phi.block_addr for phi in iter(artifact.phi_nodes)}
    phi_blocks.update(phi.block_addr for phi in iter(artifact.memory_phi_nodes))
    current = target
    visited: set[cython.longlong] = set()
    while current != stop_at:
        if current in retained_targets:
            return current
        if current in visited:
            return target
        visited.add(current)
        block = blocks.get(current)
        if block is None:
            return target
        if block.instrs or block.bindings or current in phi_blocks:
            return current
        if block.refusals or current in refused_blocks:
            return target
        edges = successors.get(current, ())
        ssa_edges = tuple(
            sorted(addr for addr, preds in builtins.iter(artifact.predecessor_map.items()) if current in preds)
        )
        if len(edges) != 1 or operator.ne(tuple(sorted(edges)), ssa_edges):
            return target
        current = edges[0]
    return target


def exact_condition_exit_polarity_8616(
    artifact: SSAFunctionArtifact | None,
    fact: ConditionIR,
    true_target: object,
    false_target: object,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
    *,
    retained_targets: object = frozenset(),
) -> bool | None:
    """Orient two exact bodies without bypassing effects or changing CFG facts.

    Physical edges must match the typed branch before empty connectors may be
    normalized. Both bodies and the branch itself are mandatory boundaries.
    """
    block: object
    fallthrough: object
    taken: object
    taken, fallthrough = fact.taken_target, fact.fallthrough_target
    block = fact.block_addr
    if block is None or taken is None or fallthrough is None:
        return None
    if true_target is None or false_target is None or operator.eq(true_target, false_target):
        return None
    if operator.eq(taken, fallthrough) or operator.ne(set(successors.get(block, ())), {taken, fallthrough}):
        return None
    boundaries = retained_targets | {true_target, false_target, block}
    resolved_taken, resolved_fallthrough = (
        transparent_condition_exit_8616(
            artifact, edge, successors, stop_at=None, retained_targets=boundaries,
        )
        for edge in iter((taken, fallthrough))
    )
    if (true_target, false_target) == (resolved_taken, resolved_fallthrough):
        return True
    if (true_target, false_target) == (resolved_fallthrough, resolved_taken):
        return False
    return None


@cython.ccall
def conditional_goto_polarity_8616(
    body: object,
    artifact: SSAFunctionArtifact | None,
    fact: ConditionIR,
    continuation: int | None,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> bool | None:
    """Prove a plain conditional jump against its immediate continuation.

    A goto's destination is not its source block. Consume its structured target
    directly and require both physical branch paths, without moving the jump.
    """
    while isinstance(body, CStatements) and len(body.statements) == 1:
        body = body.statements[0]
    if not isinstance(body, CGoto) or not isinstance(body.target, int) or isinstance(body.target, bool):
        return None
    return exact_condition_exit_polarity_8616(artifact, fact, body.target, continuation, successors)
