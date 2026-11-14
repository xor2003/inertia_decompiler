# cython: language_level=3, infer_types=True
"""Propagate proven condition-register identities across condition-only CFG edges.

Layer: Alias.
Responsibility: Owns storage identity. Retain exact register-to-storage identity through CFG joins only
when complete predecessor topology and typed ConditionIR instruction addresses
prove that no intervening instruction can clobber the carrier. This module does
not decode instructions, lower types, structure control flow, or inspect text.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass, replace

from inertia.ir.condition_ir import ConditionIR, condition_sort_key_8616
from inertia.ir.core import IRValue, MemSpace

from .condition_register_bindings import condition_semantic_register_operands_8616
import dataclasses
import operator
import builtins

_STORAGE_SPACES_8616 = frozenset({MemSpace.SS, MemSpace.DS, MemSpace.ES})


@dataclasses.dataclass(frozen=True, )
class ConditionRegisterTopology8616:
    """Complete basic-block predecessor sets supplied by the CFG frontend."""

    predecessors_by_block: Mapping[cython.longlong, frozenset[cython.longlong]]
    condition_only_blocks: frozenset[cython.longlong] = frozenset()


@dataclasses.dataclass(frozen=True, )
class ConditionRegisterLivenessStats8616:
    """Closed evidence counters for register-carrier liveness propagation."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class ConditionRegisterLivenessResult8616:
    """Return liveness-normalized conditions and their evidence accounting."""

    conditions: object
    stats: ConditionRegisterLivenessStats8616


@cython.ccall
def _typed_register_name_8616(value: object) -> object:
    """Return the normalized name of one register operand."""
    if (
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and isinstance(value.name, str)
    ):
        return value.name.lower()
    return None


@cython.ccall
def _typed_storage_value_8616(value: object, width_bits: cython.longlong) -> IRValue | None:
    """Return a width-matched segmented storage identity."""
    if (
        isinstance(value, IRValue)
        and value.space in _STORAGE_SPACES_8616
        and operator.eq(value.size, max(1, int(width_bits) // 8))
    ):
        return value
    return None


def _local_bindings_8616(
    condition: ConditionIR,
) -> tuple[dict[str, IRValue], cython.longlong]:
    """Extract exact register identities already proven at one CMP."""
    existing: object
    storage: object
    operand: object
    register_name: object
    bindings: dict[str, IRValue] = {}
    failures = 0
    operands = (
        *((binding.register_name, binding.value) for binding in iter(condition.register_bindings)),
        *condition_semantic_register_operands_8616(condition),
    )
    for register_name, operand in operands:
        storage = _typed_storage_value_8616(operand, condition.width_bits)
        if storage is None:
            continue
        existing = bindings.get(register_name)
        if existing is not None and operator.ne(existing, storage):
            bindings.pop(register_name, None)
            failures += 1
            continue
        bindings[register_name] = storage
    return bindings, failures


def _condition_by_block_8616(
    conditions: object,
) -> tuple[dict[cython.longlong, ConditionIR], cython.longlong]:
    """Build an unambiguous one-condition-per-basic-block view."""
    block_addr: object
    candidates: object
    condition: object
    grouped: dict[cython.longlong, list[ConditionIR]] = {}
    for condition in conditions:
        if isinstance(condition.block_addr, int):
            grouped.setdefault(condition.block_addr, []).append(condition)
    nodes: dict[cython.longlong, ConditionIR] = {}
    failures = 0
    for block_addr, candidates in grouped.items():
        identities = {
            (
                condition.op,
                condition.width_bits,
                condition.source,
                condition.src_insn,
                condition.producer_insn,
                condition.taken_target,
                condition.fallthrough_target,
                condition.operand_bind_insn,
                condition.relative_edge,
            )
            for condition in iter(candidates)
        }
        if len(identities) != 1:
            failures += 1
            continue
        nodes[block_addr] = max(
            candidates,
            key=lambda condition: (
                len(_local_bindings_8616(condition)[0]),
                tuple(-part if isinstance(part, int) else part for part in builtins.iter(condition_sort_key_8616(condition))),
            ),
        )
    return nodes, failures


@cython.ccall
def _is_condition_only_edge_8616(
    predecessor: ConditionIR,
    successor: ConditionIR,
    condition_only_blocks: object,
) -> cython.bint:
    """Prove that the successor block has no register-clobbering prefix."""
    block_addr = successor.block_addr
    if not isinstance(block_addr, int):
        return False
    if block_addr not in {
        predecessor.taken_target,
        predecessor.fallthrough_target,
    }:
        return False
    return block_addr in condition_only_blocks


@cython.ccall
def _intersect_bindings_8616(
    bindings: object,
) -> object:
    """Keep only register identities equal on every incoming edge."""
    candidate: object
    if not bindings:
        return {}
    common = dict(bindings[0])
    for candidate in bindings[1:]:
        common = {
            name: value
            for name, value in builtins.iter(common.items())
            if operator.eq(candidate.get(name), value)
        }
    return common


def _condition_only_components_8616(
    nodes: Mapping[cython.longlong, ConditionIR],
    topology: ConditionRegisterTopology8616,
) -> tuple[frozenset[cython.longlong], ...]:
    """Return components joined only by decoded condition-only blocks."""
    current: object
    predecessor: object
    predecessors: object
    block_addr: object
    condition: object
    predecessor_addr: object
    adjacency: dict[cython.longlong, set[cython.longlong]] = {block_addr: set() for block_addr in iter(nodes)}
    for block_addr, condition in nodes.items():
        predecessors = topology.predecessors_by_block.get(block_addr, frozenset())
        known_edges = tuple(
            predecessor_addr
            for predecessor_addr in iter(predecessors)
            if predecessor_addr in nodes
            and _is_condition_only_edge_8616(
                nodes[predecessor_addr],
                condition,
                topology.condition_only_blocks,
            )
        )
        if operator.ne(len(known_edges), len(predecessors)):
            continue
        for predecessor_addr in known_edges:
            predecessor = nodes.get(predecessor_addr)
            if predecessor is None:
                continue
            adjacency[block_addr].add(predecessor_addr)
            adjacency[predecessor_addr].add(block_addr)

    components: list[frozenset[cython.longlong]] = []
    unseen = set(nodes)
    while unseen:
        root = min(unseen)
        pending = [root]
        component: set[cython.longlong] = set()
        while pending:
            current = pending.pop()
            if current in component:
                continue
            component.add(current)
            unseen.discard(current)
            pending.extend(sorted(adjacency[current] - component, reverse=True))
        components.append(frozenset(component))
    return tuple(components)


def _component_bindings_8616(
    components: object,
    local_by_block: Mapping[cython.longlong, dict[str, IRValue]],
) -> tuple[dict[cython.longlong, dict[str, IRValue]], cython.longlong]:
    """Assign a binding to a component if all local proofs agree."""
    block_addr: object
    component: object
    register_name: object
    storage: object
    bindings_by_block: dict[cython.longlong, dict[str, IRValue]] = {}
    failures = 0
    for component in components:
        by_register: dict[str, set[IRValue]] = {}
        for block_addr in component:
            for register_name, storage in local_by_block.get(block_addr, {}).items():
                by_register.setdefault(register_name, set()).add(storage)
        component_bindings = {
            register_name: next(iter(values))
            for register_name, values in builtins.iter(by_register.items())
            if len(values) == 1
        }
        failures += sum(1 for values in builtins.iter(by_register.values()) if len(values) > 1)
        for block_addr in component:
            bindings_by_block[block_addr] = dict(component_bindings)
    return bindings_by_block, failures


@cython.ccall
def _replace_proven_registers_8616(
    condition: ConditionIR,
    bindings: Mapping[str, IRValue],
) -> tuple[ConditionIR, cython.longlong, cython.longlong]:
    """Replace register operands for which Alias has one exact identity."""
    lhs_name: object
    rhs_name: object
    lhs = condition.lhs
    rhs = condition.rhs
    classified = 0
    materialized = 0
    lhs_name = _typed_register_name_8616(lhs)
    if lhs_name is not None and lhs_name in bindings:
        classified += 1
        lhs = bindings[lhs_name]
        materialized += 1
    rhs_name = _typed_register_name_8616(rhs)
    if rhs_name is not None and rhs_name in bindings:
        classified += 1
        rhs = bindings[rhs_name]
        materialized += 1
    if materialized == 0:
        return condition, classified, materialized
    return replace(condition, lhs=lhs, rhs=rhs), classified, materialized


def normalize_condition_register_liveness_8616(
    conditions: object,
    topology: ConditionRegisterTopology8616,
) -> ConditionRegisterLivenessResult8616:
    """Propagate exact register identities across fully known condition edges."""
    block_addr: object
    condition: object
    ordered = tuple(sorted(conditions, key=condition_sort_key_8616))
    nodes, failures = _condition_by_block_8616(ordered)
    local_by_block: dict[cython.longlong, dict[str, IRValue]] = {}
    for block_addr, condition in nodes.items():
        local, local_failures = _local_bindings_8616(condition)
        local_by_block[block_addr] = local
        failures += local_failures

    output_by_block, component_failures = _component_bindings_8616(
        _condition_only_components_8616(nodes, topology),
        local_by_block,
    )
    failures += component_failures

    normalized: list[ConditionIR] = []
    classified = 0
    materialized = 0
    for condition in ordered:
        bindings = (
            output_by_block.get(condition.block_addr, {})
            if isinstance(condition.block_addr, int)
            else {}
        )
        replacement, condition_classified, condition_materialized = (
            _replace_proven_registers_8616(condition, bindings)
        )
        normalized.append(replacement)
        classified += condition_classified
        materialized += condition_materialized

    return ConditionRegisterLivenessResult8616(
        conditions=tuple(normalized),
        stats=ConditionRegisterLivenessStats8616(
            raw_fact_count=len(ordered),
            normalized_fact_count=sum(len(values) for values in builtins.iter(local_by_block.values())),
            classified_fact_count=classified,
            materialized_count=materialized,
            failure_count=failures,
        ),
    )
