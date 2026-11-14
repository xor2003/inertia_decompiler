# cython: language_level=3, infer_types=True
"""Prove bounded, effect-free structured guard regions.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Use immediate statement ownership to stop before a continuation's later effects.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

import itertools
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CIfElse, CStatements

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import AddressStatus, IRAddress, IRInstr, MemSpace, SegmentOrigin
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.structured_tags import copy_structured_tags_8616

from .multi_arm_condition_ownership import first_statement_block_8616
import dataclasses
import operator
import builtins

_BINARY_ARITY = 2
# An explicit total integer-operation contract, not an Iop-prefix purity guess.
_TOTAL_TEMP_OPS = frozenset({"MOV"}) | frozenset(
    f"Iop_{operation}{width}"
    for operation in iter(("Add", "Sub", "And", "Or", "Xor", "Shl", "Shr", "Sar"))
    for width in iter((8, 16, 32, 64))
) | frozenset(
    f"Iop_Cmp{relation}{width}{signedness}"
    for relation in iter(("LT", "LE", "GT", "GE"))
    for width in iter((8, 16, 32, 64))
    for signedness in iter(("S", "U"))
)


@dataclasses.dataclass(frozen=True, )
class LocalConditionRegion8616:
    """Retain the exact condition inventory and both non-bypassed boundaries."""

    conditions: object
    body_target: cython.longlong
    continuation: cython.longlong


@cython.ccall
def _statement_entry(statement: object, facts: Mapping[cython.longlong, ConditionIR]) -> int | None:
    """Resolve direct ownership only; operand and container tags are not entries."""
    fact: object
    instruction: object
    while isinstance(statement, CStatements) and statement.statements:
        statement = statement.statements[0]
    if isinstance(statement, CIfElse):
        tags = copy_structured_tags_8616(statement.tags) or {}
        instruction = tags.get("ins_addr")
        if not isinstance(instruction, int) or isinstance(instruction, bool):
            return None
        fact = facts.get(instruction)
        return fact.block_addr if fact is not None else None
    return first_statement_block_8616(statement)


@cython.ccall
def local_condition_continuations_8616(
    nodes: Iterable[object], facts: Mapping[cython.longlong, ConditionIR],
) -> dict[cython.longlong, cython.longlong]:
    """Index unique no-else guards by their immediate sibling's proven entry."""
    entry: object
    container: object
    following: object
    statement: object
    candidates: dict[cython.longlong, cython.longlong] = {}
    seen: set[cython.longlong] = set()
    ambiguous: set[cython.longlong] = set()
    for container in nodes:
        if not isinstance(container, CStatements):
            continue
        for statement in container.statements:
            identity = id(statement)
            if identity in seen:
                ambiguous.add(identity)
            seen.add(identity)
        for statement, following in itertools.pairwise(container.statements):
            if not isinstance(statement, CIfElse) or statement.else_node is not None:
                continue
            identity = id(statement)
            entry = _statement_entry(following, facts)
            if entry is not None:
                candidates[identity] = entry
    return {identity: entry for identity, entry in builtins.iter(candidates.items()) if identity not in ambiguous}


@cython.ccall
def _instruction_is_guard_only(instruction: IRInstr) -> cython.bint:
    """Allow only total temporary computations, stable stack reads and branches."""
    if instruction.call_stack_effect is not None:
        return False
    if instruction.op == "CJMP":
        return instruction.dst is None
    if instruction.dst is None or instruction.dst.space is not MemSpace.TMP:
        return False
    if instruction.op in _TOTAL_TEMP_OPS:
        return True
    if instruction.op != "LOAD" or len(instruction.args) != 1:
        return False
    address = instruction.args[0]
    return (
        isinstance(address, IRAddress)
        and address.space is MemSpace.SS
        and address.status is AddressStatus.STABLE
        and address.segment_origin is SegmentOrigin.PROVEN
        and address.base == ("bp",)
    )


def prove_local_condition_region_8616(
    root: ConditionIR,
    body_target: cython.longlong,
    continuation: cython.longlong,
    facts: Mapping[cython.longlong, ConditionIR],
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
    artifact: object,
) -> LocalConditionRegion8616 | None:
    """Refuse effects, unknown branches, cycles and inconsistent SSA/CFG edges."""
    refused: object
    if artifact is None or body_target == continuation or root.block_addr is None or root.block_addr in (body_target, continuation):
        return None
    boundaries = {body_target, continuation}
    blocks = {block.addr: block for block in iter(artifact.blocks)}
    refused = {refusal.block_addr for refusal in iter(artifact.memory_refusals)}
    if None in refused:
        return None
    phi_blocks = {phi.block_addr for phi in iter(artifact.phi_nodes)}
    phi_blocks.update(phi.block_addr for phi in iter(artifact.memory_phi_nodes))
    safe_blocks = {
        block.addr for block in iter(artifact.blocks)
        if all(_instruction_is_guard_only(instruction) for instruction in iter(block.instrs))
    }
    visited: set[cython.longlong] = set()
    active: set[cython.longlong] = set()
    consumed: list[ConditionIR] = []

    def visit(address: cython.longlong) -> cython.bint:
        block: object
        edges: object
        fact: object
        if address in boundaries:
            return True
        if address in active:
            return False
        if address in visited:
            return True
        fact, block = facts.get(address), blocks.get(address)
        blocked = address in refused or address in phi_blocks or address not in safe_blocks
        if fact is None or block is None or block.refusals or blocked:
            return False
        edges = {fact.taken_target, fact.fallthrough_target}
        ssa_edges = {target for target, parents in builtins.iter(artifact.predecessor_map.items()) if address in parents}
        if None in edges or operator.ne(len(edges), _BINARY_ARITY) or operator.ne(edges, set(successors.get(address, ()))) or operator.ne(edges, ssa_edges):
            return False
        active.add(address)
        consumed.append(fact)
        valid = all(visit(target) for target in iter(successors[address]))
        active.remove(address)
        visited.add(address)
        return valid

    if operator.ne(facts.get(root.block_addr), root) or not visit(root.block_addr):
        return None
    return LocalConditionRegion8616(tuple(consumed), body_target, continuation)
