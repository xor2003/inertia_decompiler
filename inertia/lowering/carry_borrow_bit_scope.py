# cython: language_level=3, infer_types=True
"""Structured scope contracts for proven carry/borrow bit placement.

Layer: Types/Lowering.
Responsibility: index exact C-SSA assignments and prove whether multiple
structured definitions are mutually exclusive alternatives reaching one use.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from inertia.lowering.c_ast_utils import _iter_c_node_occurrences_8616
from inertia.structuring.structuring_cfg_ownership import (
    CFGInstructionReachability8616,
    CFGInstructionSite8616,
    CFGOwnershipArtifact,
)

from .carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616, CarryBorrowBitLoweringFailure8616
import dataclasses
import operator
import builtins

VariableKey8616 = typing.TypeAliasType("VariableKey8616", tuple[str, int])
ControlArm8616 = typing.TypeAliasType("ControlArm8616", tuple[int, str, int])
ControlPath8616 = typing.TypeAliasType("ControlPath8616", tuple[ControlArm8616, ...])


@dataclasses.dataclass(frozen=True)
class CarryBitOccurrence8616:
    """One exact high-instruction carry mask and its mutable statement owner."""

    root: object
    container: structured_c.CStatements
    statement_index: cython.longlong
    node: structured_c.CBinaryOp
    flag_variable: structured_c.CVariable
    mask_depth: cython.longlong


@dataclasses.dataclass(frozen=True)
class InlinedCarryBitOccurrence8616:
    """One low carry projection inlined into an exact high-instruction expression."""

    root: object
    container: structured_c.CStatements
    statement_index: cython.longlong
    node: structured_c.CBinaryOp
    high_node: structured_c.CBinaryOp


@dataclasses.dataclass(frozen=True)
class CarryBitDefinitionSelection8616:
    """Definitions proven to reach one use directly or through exclusive arms."""

    definitions: object
    joined_alternatives: cython.bint


@cython.ccall
def variable_key_8616(variable: structured_c.CVariable) -> VariableKey8616 | None:
    """Return stable SSA identity at the third-party C-AST boundary."""
    carrier: object
    if isinstance(variable.vvar_id, int):
        return "vvar", variable.vvar_id
    carrier = variable.unified_variable if variable.unified_variable is not None else variable.variable
    return ("variable", id(carrier)) if carrier is not None else None


@cython.ccall
def _tagged_instruction_site_8616(
    node: object,
    ownership: CFGOwnershipArtifact,
) -> CFGInstructionSite8616 | CFGInstructionReachability8616:
    """Read one exact instruction tag at the dynamic third-party C-AST boundary."""
    block_addr: object
    ins_addr: object
    if not hasattr(node, "tags"):
        return CFGInstructionReachability8616.OWNER_MISSING
    tags = cast(dict[str, object], node.tags)
    ins_addr = tags.get("ins_addr")
    if not isinstance(ins_addr, int):
        return CFGInstructionReachability8616.OWNER_MISSING
    block_addr = tags.get("vex_block_addr")
    if isinstance(block_addr, int):
        site = CFGInstructionSite8616(block_addr=block_addr, ins_addr=ins_addr)
    else:
        sites = ownership.instruction_sites(ins_addr)
        if not sites:
            return CFGInstructionReachability8616.OWNER_MISSING
        if len(sites) != 1:
            return CFGInstructionReachability8616.OWNER_AMBIGUOUS
        site = sites[0]
    return site


@cython.ccall
def node_instruction_site_8616(
    node: object,
    ownership: CFGOwnershipArtifact,
) -> CFGInstructionSite8616 | CFGInstructionReachability8616:
    """Resolve one dynamic C-AST node to a unique instruction or split-region owner."""
    site = _tagged_instruction_site_8616(node, ownership)
    if isinstance(site, CFGInstructionReachability8616):
        return site
    owner_status = ownership.instruction_reachability(site, site)
    if owner_status is CFGInstructionReachability8616.REACHES:
        return site
    if owner_status is not CFGInstructionReachability8616.OWNER_MISSING:
        return owner_status
    if ownership.instruction_sites(site.ins_addr):
        return owner_status
    region_id = _snapshot_region_id_8616(site.block_addr, ownership)
    return site if isinstance(region_id, int) else region_id


def _snapshot_region_id_8616(
    block_addr: cython.longlong,
    ownership: CFGOwnershipArtifact,
) -> int | CFGInstructionReachability8616:
    """Resolve one block address to a unique published CFG region."""
    owners = tuple(node for node in iter(ownership.snapshot.nodes) if operator.eq(node.block_addr, block_addr))
    if not owners:
        return CFGInstructionReachability8616.OWNER_MISSING
    if len(owners) != 1:
        return CFGInstructionReachability8616.OWNER_AMBIGUOUS
    return owners[0].region_id


@cython.ccall
def _snapshot_region_reachability_8616(
    source_region_id: cython.longlong,
    target_region_id: cython.longlong,
    ownership: CFGOwnershipArtifact,
) -> CFGInstructionReachability8616:
    """Prove reachability through unique immutable CFG region identities."""
    region_id: object
    successor_id: object
    nodes_by_id = {node.region_id: node for node in iter(ownership.snapshot.nodes)}
    if operator.ne(len(nodes_by_id), len(ownership.snapshot.nodes)):
        return CFGInstructionReachability8616.OWNER_AMBIGUOUS
    if source_region_id not in nodes_by_id or target_region_id not in nodes_by_id:
        return CFGInstructionReachability8616.OWNER_MISSING
    if source_region_id == target_region_id:
        return CFGInstructionReachability8616.REACHES

    pending = [source_region_id]
    visited: set[cython.longlong] = set()
    while pending:
        region_id = pending.pop()
        if region_id in visited:
            continue
        visited.add(region_id)
        for successor_id in nodes_by_id[region_id].successor_ids:
            if successor_id == target_region_id:
                return CFGInstructionReachability8616.REACHES
            if successor_id in nodes_by_id and successor_id not in visited:
                pending.append(successor_id)
    return CFGInstructionReachability8616.DOES_NOT_REACH


@cython.ccall
def _instruction_reachability_8616(
    source_site: CFGInstructionSite8616,
    target_site: CFGInstructionSite8616,
    ownership: CFGOwnershipArtifact,
) -> CFGInstructionReachability8616:
    """Prove instruction order, including exact tags projected onto split regions."""
    reachability = ownership.instruction_reachability(source_site, target_site)
    if reachability is not CFGInstructionReachability8616.OWNER_MISSING:
        return reachability
    if ownership.instruction_sites(source_site.ins_addr) or ownership.instruction_sites(target_site.ins_addr):
        return reachability
    source_region_id = _snapshot_region_id_8616(source_site.block_addr, ownership)
    if isinstance(source_region_id, CFGInstructionReachability8616):
        return source_region_id
    target_region_id = _snapshot_region_id_8616(target_site.block_addr, ownership)
    if isinstance(target_region_id, CFGInstructionReachability8616):
        return target_region_id
    if source_region_id == target_region_id:
        if source_site.ins_addr > target_site.ins_addr:
            return CFGInstructionReachability8616.ORDER_CONFLICT
        return CFGInstructionReachability8616.REACHES
    return _snapshot_region_reachability_8616(source_region_id, target_region_id, ownership)


@cython.ccall
def node_matches_instruction_site_8616(
    node: object,
    site: CFGInstructionSite8616,
    ownership: CFGOwnershipArtifact,
) -> cython.bint:
    """Return whether one C-AST node has one exact or proven split-region owner."""
    projected = _tagged_instruction_site_8616(node, ownership)
    if not isinstance(projected, CFGInstructionSite8616) or operator.ne(projected.ins_addr, site.ins_addr):
        return False
    if operator.eq(projected.block_addr, site.block_addr):
        return not isinstance(_snapshot_region_id_8616(site.block_addr, ownership), CFGInstructionReachability8616)
    if ownership.instruction_sites(site.ins_addr) or operator.ne(projected.block_addr, projected.ins_addr):
        return False
    source_region_id = _snapshot_region_id_8616(site.block_addr, ownership)
    if isinstance(source_region_id, CFGInstructionReachability8616):
        return False
    target_region_id = _snapshot_region_id_8616(projected.block_addr, ownership)
    if isinstance(target_region_id, CFGInstructionReachability8616):
        return target_region_id is CFGInstructionReachability8616.OWNER_MISSING
    return (
        _snapshot_region_reachability_8616(source_region_id, target_region_id, ownership)
        is CFGInstructionReachability8616.REACHES
    )


@cython.ccall
def statement_containers_8616(root: object) -> tuple[structured_c.CStatements, ...]:
    """Return each unique mutable statement container in deterministic order."""
    node: object
    containers: list[structured_c.CStatements] = []
    seen: set[cython.longlong] = set()
    for node in _iter_c_node_occurrences_8616(root):
        if isinstance(node, structured_c.CStatements) and id(node) not in seen:
            seen.add(id(node))
            containers.append(node)
    return tuple(containers)


@cython.ccall
def assignment_map_8616(
    occurrence: CarryBitOccurrence8616,
) -> dict[VariableKey8616, tuple[structured_c.CAssignment, ...]]:
    """Index exact SSA definitions function-wide and legacy identities locally."""
    container: object
    statement: object
    statement_index: object
    grouped: dict[VariableKey8616, list[structured_c.CAssignment]] = {}
    for container in statement_containers_8616(occurrence.root):
        for statement_index, statement in enumerate(container.statements):
            if not isinstance(statement, structured_c.CAssignment) or not isinstance(
                statement.lhs, structured_c.CVariable
            ):
                continue
            if (key := variable_key_8616(statement.lhs)) is None:
                continue
            local_predecessor = container is occurrence.container and statement_index < occurrence.statement_index
            if key[0] == "vvar" or local_predecessor:
                grouped.setdefault(key, []).append(statement)
    return {key: tuple(items) for key, items in builtins.iter(grouped.items())}


@cython.ccall
def read_counts_8616(root: object) -> Counter[VariableKey8616]:
    """Count function-wide C-variable reads, excluding assignment lvalues."""
    node: object
    counts: Counter[VariableKey8616] = Counter()
    for node in _iter_c_node_occurrences_8616(root):
        if isinstance(node, structured_c.CVariable) and (key := variable_key_8616(node)) is not None:
            counts[key] += 1
        if (
            isinstance(node, structured_c.CAssignment)
            and isinstance(node.lhs, structured_c.CVariable)
            and (lhs_key := variable_key_8616(node.lhs))
        ):
            counts[lhs_key] -= 1
    return counts


@cython.ccall
def _ifelse_children_8616(
    statement: structured_c.CIfElse,
    path: ControlPath8616,
) -> tuple[tuple[structured_c.CStatements, ControlPath8616], ...]:
    """Return typed branch containers at the dynamic angr C-AST boundary."""
    branch_index: object
    pair: object
    children: list[tuple[structured_c.CStatements, ControlPath8616]] = []
    marker = id(statement)
    pairs = statement.condition_and_nodes
    if isinstance(pairs, (list, tuple)):
        for branch_index, pair in enumerate(pairs):
            if isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[1], structured_c.CStatements):
                children.append((pair[1], (*path, (marker, "if", branch_index))))
    if isinstance(statement.else_node, structured_c.CStatements):
        children.append((statement.else_node, (*path, (marker, "else", 0))))
    return tuple(children)


@cython.ccall
def _child_scopes_8616(
    statement: object,
    path: ControlPath8616,
) -> tuple[tuple[structured_c.CStatements, ControlPath8616], ...]:
    """Return child containers, proving exclusivity only for explicit if arms."""
    cases: object
    child: object
    attr: object
    case: object
    if isinstance(statement, structured_c.CStatements):
        return ((statement, path),)
    children: list[tuple[structured_c.CStatements, ControlPath8616]] = []
    if isinstance(statement, structured_c.CIfElse):
        children.extend(_ifelse_children_8616(statement, path))
    for attr in ("body", "default"):
        child = getattr(statement, attr, None)  # dynamic third-party C-AST boundary
        if isinstance(child, structured_c.CStatements):
            children.append((child, path))
    cases = getattr(statement, "cases", ())  # dynamic third-party C-AST boundary
    if isinstance(cases, (list, tuple)):
        for case in cases:
            if isinstance(case, tuple) and len(case) == 2 and isinstance(case[1], structured_c.CStatements):
                children.append((case[1], path))
    return tuple(children)


@cython.ccall
def _structured_control_paths_8616(
    root: object,
) -> tuple[
    dict[cython.longlong, tuple[ControlPath8616, ...]],
    dict[cython.longlong, tuple[ControlPath8616, ...]],
]:
    """Index container and direct-statement control paths without flattening arms."""
    container: object
    path: object
    statement: object
    if not isinstance(root, structured_c.CStatements):
        return {}, {}
    container_paths: dict[cython.longlong, list[ControlPath8616]] = {}
    statement_paths: dict[cython.longlong, list[ControlPath8616]] = {}
    pending: list[tuple[structured_c.CStatements, ControlPath8616]] = [(root, ())]
    visited: set[tuple[cython.longlong, ControlPath8616]] = set()
    while pending:
        container, path = pending.pop()
        identity = id(container), path
        if identity in visited:
            continue
        visited.add(identity)
        container_paths.setdefault(id(container), []).append(path)
        for statement in container.statements:
            statement_paths.setdefault(id(statement), []).append(path)
            pending.extend(reversed(_child_scopes_8616(statement, path)))
    return (
        {key: tuple(paths) for key, paths in builtins.iter(container_paths.items())},
        {key: tuple(paths) for key, paths in builtins.iter(statement_paths.items())},
    )


def _paths_exclusive_8616(lhs: ControlPath8616, rhs: ControlPath8616) -> cython.bint:
    """Return whether two paths choose different arms of one control owner."""
    lhs_arms = {owner: (kind, index) for owner, kind, index in iter(lhs)}
    return any(owner in lhs_arms and operator.ne(lhs_arms[owner], (kind, index)) for owner, kind, index in iter(rhs))


def select_reaching_definitions_8616(
    occurrence: CarryBitOccurrence8616,
    definitions: object,
) -> CarryBitDefinitionSelection8616 | None:
    """Select one reaching definition or a complete mutually exclusive join."""
    paths: object
    use_paths: object
    definition: object
    container_paths, statement_paths = _structured_control_paths_8616(occurrence.root)
    use_paths = container_paths.get(id(occurrence.container), ())
    if len(use_paths) != 1:
        return None
    use_path = use_paths[0]
    compatible: list[structured_c.CAssignment] = []
    definition_paths: dict[cython.longlong, ControlPath8616] = {}
    for definition in definitions:
        paths = statement_paths.get(id(definition), ())
        if len(paths) != 1:
            return None
        definition_path = paths[0]
        if not _paths_exclusive_8616(definition_path, use_path):
            compatible.append(definition)
            definition_paths[id(definition)] = definition_path
    if len(compatible) == 1:
        return CarryBitDefinitionSelection8616((compatible[0],), False)
    if not compatible or not all(
        _paths_exclusive_8616(definition_paths[id(lhs)], definition_paths[id(rhs)])
        for lhs, rhs in builtins.iter(combinations(compatible, 2))
    ):
        return None
    return CarryBitDefinitionSelection8616(tuple(compatible), True)


@cython.ccall
def _ownership_failure_8616(
    reachability: CFGInstructionReachability8616,
) -> CarryBorrowBitLoweringFailure8616:
    """Map Structuring ownership refusal into the Lowering diagnostic contract."""
    if reachability is CFGInstructionReachability8616.OWNER_MISSING:
        return CarryBorrowBitLoweringFailure8616.EXECUTION_OWNER_MISSING
    if reachability is CFGInstructionReachability8616.ORDER_CONFLICT:
        return CarryBorrowBitLoweringFailure8616.EXECUTION_ORDER_CONFLICT
    return CarryBorrowBitLoweringFailure8616.EXECUTION_OWNER_AMBIGUOUS


@cython.ccall
def select_cfg_reaching_definitions_8616(
    occurrence: CarryBitOccurrence8616,
    definitions: object,
    fact: CarryBorrowBitLoweringFact8616,
    ownership: CFGOwnershipArtifact,
) -> CarryBitDefinitionSelection8616 | CarryBorrowBitLoweringFailure8616:
    """Select exact low-site definitions that can execute before the high use."""
    definition: object
    low_site = CFGInstructionSite8616(fact.low_block_addr, fact.low_ins_addr)
    typed_high_site = CFGInstructionSite8616(fact.high_block_addr, fact.high_ins_addr)
    high_site = node_instruction_site_8616(occurrence.node, ownership)
    if isinstance(high_site, CFGInstructionReachability8616):
        return _ownership_failure_8616(high_site)
    if not node_matches_instruction_site_8616(occurrence.node, typed_high_site, ownership):
        return CarryBorrowBitLoweringFailure8616.EXECUTION_OWNER_AMBIGUOUS
    candidates: list[structured_c.CAssignment] = []
    for definition in definitions:
        site = node_instruction_site_8616(definition, ownership)
        if isinstance(site, CFGInstructionReachability8616):
            if node_matches_instruction_site_8616(definition, low_site, ownership):
                site = low_site
            else:
                return _ownership_failure_8616(site)
        reachability = _instruction_reachability_8616(site, high_site, ownership)
        if reachability is CFGInstructionReachability8616.DOES_NOT_REACH:
            continue
        if reachability is not CFGInstructionReachability8616.REACHES:
            return _ownership_failure_8616(reachability)
        if not node_matches_instruction_site_8616(definition, low_site, ownership):
            return CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_AMBIGUOUS
        candidates.append(definition)
    if not candidates:
        return CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_MISSING
    selection = select_reaching_definitions_8616(occurrence, tuple(candidates))
    return selection or CarryBorrowBitLoweringFailure8616.CARRIER_ASSIGNMENT_AMBIGUOUS


__all__ = [
    "CarryBitDefinitionSelection8616",
    "CarryBitOccurrence8616",
    "InlinedCarryBitOccurrence8616",
    "VariableKey8616",
    "assignment_map_8616",
    "node_instruction_site_8616",
    "node_matches_instruction_site_8616",
    "read_counts_8616",
    "select_cfg_reaching_definitions_8616",
    "select_reaching_definitions_8616",
    "statement_containers_8616",
    "variable_key_8616",
]
