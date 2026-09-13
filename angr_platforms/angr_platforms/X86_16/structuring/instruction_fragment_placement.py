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

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CForLoop, CIfElse, CStatements

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.condition_ir import ConditionIR


@dataclass(frozen=True, slots=True)
class InstructionFragmentOrigin8616:
    """Exact statement provenance within one lifted machine instruction."""

    instruction: int
    block: int
    statement: int


class _TaggedNode8616(Protocol):
    """Third-party angr node tag boundary."""

    tags: dict[str, object] | None


class _FunctionBoundary8616(Protocol):
    """Third-party structured function body boundary."""

    statements: object


class _CodegenBoundary8616(Protocol):
    """Typed evidence and statistics carried on the active codegen object."""

    cfunc: _FunctionBoundary8616
    _inertia_typed_conditions: tuple[ConditionIR, ...]
    _inertia_instruction_fragment_placement_8616: InstructionFragmentPlacementStats8616


@dataclass(slots=True)
class InstructionFragmentPlacementStats8616:
    """Evidence accounting for restored instruction scopes."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _origin(node: object) -> InstructionFragmentOrigin8616 | None:
    """Require complete original VEX provenance, never operand-derived tags."""
    tags = cast(_TaggedNode8616, node).tags
    if not isinstance(tags, dict):
        return None
    values = tuple(tags.get(key) for key in ("ins_addr", "vex_block_addr", "vex_stmt_idx"))
    if not all(type(value) is int for value in values):
        return None
    instruction, block, statement = cast(tuple[int, int, int], values)
    return InstructionFragmentOrigin8616(instruction, block, statement)


def _reaches_before(
    successors: Mapping[int, tuple[int, ...]], start: int, target: int, stops: frozenset[int],
) -> bool | None:
    """Test reachability without traversing the next loop/condition evaluation."""
    pending = [start]
    seen = set(stops)
    incomplete = False
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        if current == target:
            return True
        seen.add(current)
        incomplete = incomplete or current not in successors
        pending.extend(successors.get(current, ()))
    return None if incomplete else False


def _conditional_block(
    condition: ConditionIR, block: int, header: int, successors: Mapping[int, tuple[int, ...]],
) -> bool:
    """Require exactly one binary branch edge to reach this instruction group."""
    source = condition.block_addr
    taken, fallthrough = condition.taken_target, condition.fallthrough_target
    if source is None or taken is None or fallthrough is None or taken == fallthrough:
        return False
    if set(successors.get(source, ())) != {taken, fallthrough}:
        return False
    stops = frozenset((source, header))
    taken_reaches = _reaches_before(successors, taken, block, stops)
    fallthrough_reaches = _reaches_before(successors, fallthrough, block, stops)
    return taken_reaches is not None and fallthrough_reaches is not None and taken_reaches != fallthrough_reaches


def _ordered_group(body: object, origin: InstructionFragmentOrigin8616) -> bool:
    """Require a contiguous instruction suffix preceding the iterator fragment."""
    if not isinstance(body, CStatements) or not body.statements:
        return False
    indexes: list[int] = []
    positions: list[int] = []
    for index, statement in enumerate(body.statements):
        if not isinstance(statement, CAssignment):
            continue
        candidate = _origin(statement)
        if candidate is not None and (candidate.instruction, candidate.block) == (origin.instruction, origin.block):
            indexes.append(index)
            positions.append(candidate.statement)
    if not indexes or indexes != list(range(indexes[0], len(body.statements))):
        return False
    return positions == sorted(set(positions)) and positions[-1] < origin.statement


def _branch_sites(
    body: CStatements, origin: InstructionFragmentOrigin8616, header: int,
    conditions: tuple[ConditionIR, ...], successors: Mapping[int, tuple[int, ...]],
) -> list[CStatements]:
    """Find exact conditional instruction suffixes in this loop, excluding nested loops."""
    sites: list[CStatements] = []
    for branch in body.statements:
        if not isinstance(branch, CIfElse):
            continue
        for expression, arm in branch.condition_and_nodes:
            branch_origin = _origin(expression)
            if branch_origin is None or not _ordered_group(arm, origin):
                continue
            facts = tuple(fact for fact in conditions if (
                fact.src_insn == branch_origin.instruction and fact.block_addr == branch_origin.block
            ))
            if len(facts) == 1 and _conditional_block(facts[0], origin.block, header, successors):
                sites.append(cast(CStatements, arm))
    return sites


def restore_instruction_fragment_placement_8616(
    root: object,
    conditions: tuple[ConditionIR, ...],
    successors: Mapping[int, tuple[int, ...]],
) -> InstructionFragmentPlacementStats8616:
    """Restore uniquely proven conditional instruction groups without changing values."""
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


def apply_instruction_fragment_placement_8616(project: object, codegen: object) -> bool:
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
