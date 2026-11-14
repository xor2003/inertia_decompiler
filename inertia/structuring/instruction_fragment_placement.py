# cython: language_level=3, infer_types=True
"""Restore split instruction statements before logical storage materialization.

Layer: Structuring.
Responsibility: move an iterator fragment back to its unique conditional
instruction group using VEX provenance, typed conditions and CFG reachability.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

No statement is synthesized or deleted. Lowering remains responsible for
merging storage fragments after their original execution scope is restored.
Ambiguous provenance or paths leave the tree unchanged for the lowering guard.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CForLoop, CIfElse, CStatements

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class InstructionFragmentOrigin8616:
    """Exact statement provenance within one lifted machine instruction."""

    instruction: cython.longlong
    block: cython.longlong
    statement: cython.longlong


class _TaggedNode8616(Protocol):
    """Third-party angr node tag boundary."""

    tags: object


class _FunctionBoundary8616(Protocol):
    """Third-party structured function body boundary."""

    statements: object


class _CodegenBoundary8616(Protocol):
    """Typed evidence and statistics carried on the active codegen object."""

    cfunc: _FunctionBoundary8616
    _inertia_typed_conditions: object
    _inertia_instruction_fragment_placement_8616: InstructionFragmentPlacementStats8616


@cython.dataclasses.dataclass()
class InstructionFragmentPlacementStats8616:
    """Evidence accounting for restored instruction scopes."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


def _origin(node: object) -> InstructionFragmentOrigin8616 | None:
    """Require complete original VEX provenance, never operand-derived tags."""
    tags = cast(_TaggedNode8616, node).tags
    if not isinstance(tags, dict):
        return None
    values = tuple(tags.get(key) for key in iter(("ins_addr", "vex_block_addr", "vex_stmt_idx")))
    if not all(type(value) is int for value in iter(values)):
        return None
    instruction, block, statement = cast(tuple[int, int, int], values)
    return InstructionFragmentOrigin8616(instruction, block, statement)


@cython.ccall
def _reaches_before(
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]], start: cython.longlong, target: cython.longlong, stops: object,
) -> bool | None:
    """Test reachability without traversing the next loop/condition evaluation."""
    current: object
    pending = [start]
    seen = set(stops)
    incomplete = False
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        if operator.eq(current, target):
            return True
        seen.add(current)
        incomplete = incomplete or current not in successors
        pending.extend(successors.get(current, ()))
    return None if incomplete else False


@cython.ccall
def _conditional_block(
    condition: ConditionIR, block: cython.longlong, header: cython.longlong, successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> cython.bint:
    """Require exactly one binary branch edge to reach this instruction group."""
    fallthrough: object
    fallthrough_reaches: object
    source: object
    taken: object
    taken_reaches: object
    source = condition.block_addr
    taken, fallthrough = condition.taken_target, condition.fallthrough_target
    if source is None or taken is None or fallthrough is None or operator.eq(taken, fallthrough):
        return False
    if operator.ne(set(successors.get(source, ())), {taken, fallthrough}):
        return False
    stops = frozenset((source, header))
    taken_reaches = _reaches_before(successors, taken, block, stops)
    fallthrough_reaches = _reaches_before(successors, fallthrough, block, stops)
    return taken_reaches is not None and fallthrough_reaches is not None and operator.ne(taken_reaches, fallthrough_reaches)


@cython.ccall
def _ordered_group(body: object, origin: InstructionFragmentOrigin8616) -> cython.bint:
    """Require a contiguous instruction suffix preceding the iterator fragment."""
    candidate: object
    index: object
    statement: object
    if not isinstance(body, CStatements) or not body.statements:
        return False
    indexes: list[cython.longlong] = []
    positions: list[cython.longlong] = []
    for index, statement in enumerate(body.statements):
        if not isinstance(statement, CAssignment):
            continue
        candidate = _origin(statement)
        if candidate is not None and (candidate.instruction, candidate.block) == (origin.instruction, origin.block):
            indexes.append(index)
            positions.append(candidate.statement)
    if not indexes or operator.ne(indexes, list(range(indexes[0], len(body.statements)))):
        return False
    return operator.eq(positions, sorted(tuple(set(positions)))) and positions[-1] < origin.statement


def _branch_sites(
    body: CStatements, origin: InstructionFragmentOrigin8616, header: cython.longlong,
    conditions: object, successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> object:
    """Find exact conditional instruction suffixes in this loop, excluding nested loops."""
    branch_origin: object
    arm: object
    branch: object
    expression: object
    sites: list[CStatements] = []
    for branch in body.statements:
        if not isinstance(branch, CIfElse):
            continue
        for expression, arm in branch.condition_and_nodes:
            branch_origin = _origin(expression)
            if branch_origin is None or not _ordered_group(arm, origin):
                continue
            facts = tuple(fact for fact in iter(conditions) if (
                operator.eq(fact.src_insn, branch_origin.instruction) and operator.eq(fact.block_addr, branch_origin.block)
            ))
            if len(facts) == 1 and _conditional_block(facts[0], origin.block, header, successors):
                sites.append(cast(CStatements, arm))
    return sites


@cython.ccall
def restore_instruction_fragment_placement_8616(
    root: object,
    conditions: object,
    successors: Mapping[cython.longlong, tuple[cython.longlong, ...]],
) -> InstructionFragmentPlacementStats8616:
    """Restore uniquely proven conditional instruction groups without changing values."""
    header: object
    origin: object
    loop: object
    stats = InstructionFragmentPlacementStats8616()
    for loop in _iter_c_nodes_deep_8616(root):
        if not isinstance(loop, CForLoop) or not isinstance(loop.iterator, CAssignment):
            continue
        stats.raw_fact_count += 1
        if not isinstance(loop.body, CStatements) or loop.condition is None:
            continue
        origin, header = _origin(loop.iterator), _origin(loop.condition)
        if origin is None or header is None:
            continue
        stats.normalized_fact_count += 1
        sites = _branch_sites(loop.body, origin, header.block, conditions, successors)
        if sites:
            stats.classified_fact_count += 1
        if len(sites) == 1:
            sites[0].statements.append(loop.iterator)
            loop.iterator = None
            stats.materialized_count += 1
        elif sites:
            stats.failure_count += 1
    return stats


@cython.ccall
def apply_instruction_fragment_placement_8616(project: object, codegen: object) -> cython.bint:
    """Restore instruction scopes before Lowering merges logical storage updates."""
    from .condition_materialization import condition_chain_successors_8616

    surface = cast(_CodegenBoundary8616, codegen)
    try:
        conditions = surface._inertia_typed_conditions
        root = surface.cfunc.statements
    except AttributeError:
        return False
    stats = restore_instruction_fragment_placement_8616(
        root, conditions, condition_chain_successors_8616(project, codegen),
    )
    surface._inertia_instruction_fragment_placement_8616 = stats
    return stats.materialized_count > 0
