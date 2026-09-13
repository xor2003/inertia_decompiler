"""Materialize proven near-pointer memory idioms.

Layer: Types/Lowering.
Responsibility: own pointer-memory idiom dispatch from proven instruction,
stack-slot, and typed pointer evidence.
Consumes alias, widening, and typed facts; legacy callback providers
may temporarily live in postprocess while their proof helpers are split.
Byte-fill and word-sum body substitution are retired: generic indexed-access and GP storage
lowering preserve the function's surrounding effects. Do not reintroduce a
whole-function replacement to improve a loop's appearance.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CForLoop,
    CIndexedVariable,
    CReturn,
    CStatement,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .authoritative_function_prototypes import publish_codegen_function_prototype_8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616


@dataclass(frozen=True, slots=True)
class PointerMemoryIdiomCallbacks8616:
    """Callbacks needed to consume legacy pointer-memory proof helpers."""

    linear_function_insns: Callable[[object, object], tuple[object, ...]]
    word_pair_pointer_accumulation_loop: Callable[[object, object, tuple[object, ...], dict[int, int]], bool]
    word_pointer_first_gt_loop: Callable[[object, object, tuple[object, ...], dict[int, int]], bool]
    word_pointer_rotate3: Callable[[object, object, tuple[object, ...], dict[int, int]], bool]
    pointer_swap: Callable[[object, object, tuple[object, ...], dict[int, int]], bool]


class _PointerSwapCFunctionBoundary8616(Protocol):
    """Typed view of the mutable angr C-function fields used by this lowering."""

    statements: CStatements


class _PointerSwapProjectBoundary8616(Protocol):
    """Typed view of the angr project fields used by this lowering."""

    arch: Arch


class _PointerSwapCodegenBoundary8616(Protocol):
    """Typed view of dynamic angr codegen state used by pointer-swap lowering."""

    cfunc: _PointerSwapCFunctionBoundary8616
    project: _PointerSwapProjectBoundary8616
    _inertia_pointer_swap_splice_stats_8616: PointerSwapSpliceStats8616


class _PointerMemoryCodegenBoundary8616(Protocol):
    """Typed view of codegen state owned by pointer-memory Lowering."""

    cfunc: _PointerSwapCFunctionBoundary8616
    _inertia_pointer_memory_idiom_facts_8616: tuple[PointerMemoryIdiomMaterializationFact8616, ...]
    _inertia_pointer_memory_materialized_8616: str
    _inertia_pointer_swap_splice_stats_8616: PointerSwapSpliceStats8616


class PointerMemoryIdiomKind8616(StrEnum):
    """Binary-proven pointer-memory idiom selected by Lowering."""

    BYTE_FILL_LOOP = "byte_fill_loop"
    WORD_SUM_LOOP = "word_sum_loop"
    WORD_PAIR_ACCUMULATION_LOOP = "word_pair_accumulation_loop"
    WORD_FIRST_GREATER_LOOP = "word_first_greater_loop"
    WORD_ROTATE3 = "word_rotate3"
    POINTER_SWAP = "pointer_swap"


@dataclass(frozen=True, slots=True)
class PointerMemoryIdiomMaterializationFact8616:
    """Closed evidence counters for one materialized pointer-memory idiom."""

    kind: PointerMemoryIdiomKind8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    counted_loop_normalized: bool
    pointer_stack_offset: int | None
    index_stack_offset: int | None
    element_stride: int | None


def _validation_delta_tokens_8616(
    delta: Mapping[str, object],
    field_name: str,
    direction: str,
) -> tuple[str, ...] | None:
    """Return typed string fingerprints from one validation delta field."""
    field_delta = delta.get(field_name)
    if not isinstance(field_delta, Mapping):
        return None
    values = field_delta.get(direction)
    if not isinstance(values, tuple) or not all(isinstance(value, str) for value in values):
        return None
    return values


def _nonempty_validation_delta_fields_8616(delta: Mapping[str, object]) -> set[str]:
    """Return validation fields containing at least one added or removed token."""
    fields: set[str] = set()
    for field_name, field_delta in delta.items():
        if not isinstance(field_delta, Mapping):
            continue
        if field_delta.get("added") or field_delta.get("removed"):
            fields.add(field_name)
    return fields


def _stack_offsets_in_validation_fingerprint_8616(token: str) -> set[int]:
    """Extract BP-relative storage identities from a validation fingerprint."""
    offsets: set[int] = set()
    for match in re.finditer(r"(?:stack_slot:SS:BP|stack_arg:[^:,]+(?::size[0-9]+)?:bp)([+-])0x([0-9a-fA-F]+)", token):
        magnitude = int(match.group(2), 16)
        offsets.add(magnitude if match.group(1) == "+" else -magnitude)
    return offsets


def _control_write_location_8616(token: str) -> tuple[str, str] | None:
    """Split one loop-body write fingerprint into control prefix and location."""
    marker = ":deref:"
    marker_index = token.find(marker)
    if marker_index < 0:
        return None
    return token[:marker_index], token[marker_index + 1 :]


def pointer_memory_loop_validation_delta_is_precision_only_8616(
    fact: PointerMemoryIdiomMaterializationFact8616,
    validation: Mapping[str, object],
) -> bool:
    """Accept only the exact byte-fill pointer-write representation delta."""
    if (
        fact.kind is not PointerMemoryIdiomKind8616.BYTE_FILL_LOOP
        or fact.raw_fact_count != 1
        or fact.normalized_fact_count != 1
        or fact.classified_fact_count != 1
        or fact.materialized_count != 1
        or fact.failure_count != 0
        or not fact.counted_loop_normalized
        or fact.pointer_stack_offset is None
        or fact.index_stack_offset is None
        or fact.element_stride != 1
    ):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return False
    if _nonempty_validation_delta_fields_8616(delta) != {
        "segmented_writes",
        "control_flow_effects",
    }:
        return False
    segmented_added = _validation_delta_tokens_8616(delta, "segmented_writes", "added")
    segmented_removed = _validation_delta_tokens_8616(delta, "segmented_writes", "removed")
    control_added = _validation_delta_tokens_8616(delta, "control_flow_effects", "added")
    control_removed = _validation_delta_tokens_8616(delta, "control_flow_effects", "removed")
    if (
        segmented_added is None
        or segmented_removed is None
        or control_added is None
        or control_removed is None
        or len(segmented_added) != 1
        or len(segmented_removed) != 1
        or len(control_added) != 1
        or len(control_removed) != 1
    ):
        return False
    added_location = segmented_added[0]
    removed_location = segmented_removed[0]
    expected_offsets = {fact.pointer_stack_offset, fact.index_stack_offset}
    if (
        not added_location.startswith("deref:Add(Mul(reg:ds,const:16),")
        or _stack_offsets_in_validation_fingerprint_8616(added_location) != expected_offsets
        or not removed_location.startswith("deref:Add(")
        or not expected_offsets <= _stack_offsets_in_validation_fingerprint_8616(removed_location)
    ):
        return False
    added_control = _control_write_location_8616(control_added[0])
    removed_control = _control_write_location_8616(control_removed[0])
    if added_control is None or removed_control is None:
        return False
    added_prefix, added_control_location = added_control
    removed_prefix, removed_control_location = removed_control
    return (
        added_prefix == removed_prefix
        and added_prefix.startswith("for-body-writes:")
        and added_control_location.startswith("deref:Add(Mul(reg:ds,const:16),")
        and _stack_offsets_in_validation_fingerprint_8616(added_control_location) == expected_offsets
        and removed_control_location == removed_location
    )


@dataclass(slots=True)
class PointerSwapSpliceStats8616:
    """Closed evidence counters for pointer-swap statement materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    idempotent_count: int = 0
    proven_ins_addrs: tuple[int, ...] = ()
    required_write_ins_addrs: tuple[int, ...] = ()
    observed_ins_addrs: tuple[int, ...] = ()
    statement_ins_addrs: tuple[tuple[int, ...], ...] = ()
    statement_nonvariable_ins_addrs: tuple[tuple[int, ...], ...] = ()
    statement_stack_flows: tuple[tuple[int | None, tuple[int, ...]], ...] = ()
    stale_temp_assignment_count: int = 0
    left_machine_bp_offset: int | None = None
    right_machine_bp_offset: int | None = None


def pointer_swap_validation_delta_is_precision_only_8616(
    stats: PointerSwapSpliceStats8616,
    validation: dict[str, object],
) -> bool:
    """Prove that validation changed only pointer-swap write representation."""
    if (
        stats.raw_fact_count <= 0
        or stats.normalized_fact_count != 1
        or stats.classified_fact_count != 1
        or stats.materialized_count != 1
        or stats.failure_count != 0
        or stats.left_machine_bp_offset is None
        or stats.right_machine_bp_offset is None
        or stats.left_machine_bp_offset == stats.right_machine_bp_offset
    ):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    for field_name, field_delta in delta.items():
        if not isinstance(field_delta, dict):
            return False
        added = tuple(str(item) for item in tuple(field_delta.get("added", ()) or ()))
        removed = tuple(str(item) for item in tuple(field_delta.get("removed", ()) or ()))
        if field_name != "segmented_writes" and (added or removed):
            return False
    writes = delta.get("segmented_writes")
    if not isinstance(writes, dict):
        return False
    added_writes = tuple(str(item) for item in tuple(writes.get("added", ()) or ()))
    removed_writes = tuple(str(item) for item in tuple(writes.get("removed", ()) or ()))
    pointer_prefix = "deref:Add(Mul(reg:ds,const:16),stack_slot:SS:BP+"
    expected_added_offsets = {
        frozenset({stats.left_machine_bp_offset}),
        frozenset({stats.right_machine_bp_offset}),
    }
    return (
        len(added_writes) == 2
        and len(set(added_writes)) == 2
        and all(item.startswith(pointer_prefix) for item in added_writes)
        and {
            frozenset(_stack_offsets_in_validation_fingerprint_8616(item))
            for item in added_writes
        }
        == expected_added_offsets
        and len(removed_writes) >= 2
        and all(item.startswith("deref:") and "stack_slot:SS:BP+" in item for item in removed_writes)
    )


def _stack_slot_offset_8616(cvar: object) -> int | None:
    if not isinstance(cvar, CVariable):
        return None
    variable = cvar.variable
    return variable.offset if isinstance(variable, SimStackVariable) and isinstance(variable.offset, int) else None


def _indexed_stack_slot_offset_8616(expr: object) -> int | None:
    """Return the stack base offset for an exact zero-indexed C expression."""
    if not isinstance(expr, CIndexedVariable):
        return None
    index = expr.index
    if not isinstance(index, CConstant) or index.value != 0:
        return None
    return _stack_slot_offset_8616(expr.variable)


def _materialized_pointer_swap_sequence_8616(
    leaf_positions: list[tuple[list[CStatement], int, CStatement]],
    *,
    left_offset: int | None,
    right_offset: int | None,
    temporary_offset: int | None,
) -> tuple[CAssignment, CAssignment, CAssignment] | None:
    """Return the unique exact pointer-swap sequence among unrelated effects."""
    assignments = [statement for _, _, statement in leaf_positions if isinstance(statement, CAssignment)]
    if left_offset is None or right_offset is None or temporary_offset is None:
        return None
    matches: list[tuple[CAssignment, CAssignment, CAssignment]] = []
    for index in range(len(assignments) - 2):
        temporary_load, left_store, right_store = assignments[index : index + 3]
        if (
            _stack_slot_offset_8616(temporary_load.lhs) == temporary_offset
            and _indexed_stack_slot_offset_8616(temporary_load.rhs) == left_offset
            and _indexed_stack_slot_offset_8616(left_store.lhs) == left_offset
            and _indexed_stack_slot_offset_8616(left_store.rhs) == right_offset
            and _indexed_stack_slot_offset_8616(right_store.lhs) == right_offset
            and _stack_slot_offset_8616(right_store.rhs) == temporary_offset
        ):
            matches.append((temporary_load, left_store, right_store))
    return matches[0] if len(matches) == 1 else None


def _optional_c_node_ins_addr_8616(node: object) -> int | None:
    """Read optional instruction tags at the dynamic third-party C-AST boundary."""
    try:
        tags = cast(Any, node).tags
    except AttributeError:
        return None
    ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
    return int(ins_addr) if isinstance(ins_addr, int) else None


def splice_proven_pointer_swap_statements_8616(
    codegen: object,
    left_expr: CVariable,
    right_expr: CVariable,
    temporary_expr: CVariable,
    proven_ins_addrs: frozenset[int],
    required_write_ins_addrs: frozenset[int],
) -> bool:
    """Replace assignments owned solely by the proven swap instruction region."""
    stats = PointerSwapSpliceStats8616()
    stats.proven_ins_addrs = tuple(sorted(proven_ins_addrs))
    stats.required_write_ins_addrs = tuple(sorted(required_write_ins_addrs))
    typed_codegen = cast(_PointerSwapCodegenBoundary8616, codegen)
    left_variable = left_expr.variable
    right_variable = right_expr.variable
    stats.left_machine_bp_offset = (
        machine_bp_offset_for_stack_variable_8616(codegen, left_variable)
        if isinstance(left_variable, SimStackVariable)
        else None
    )
    stats.right_machine_bp_offset = (
        machine_bp_offset_for_stack_variable_8616(codegen, right_variable)
        if isinstance(right_variable, SimStackVariable)
        else None
    )
    if (
        stats.left_machine_bp_offset is None
        or stats.right_machine_bp_offset is None
        or stats.left_machine_bp_offset == stats.right_machine_bp_offset
    ):
        stats.failure_count = 1
        typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
        return False
    cfunc = typed_codegen.cfunc
    root = cfunc.statements
    statements = root.statements if isinstance(root, CStatements) else None
    if (
        not isinstance(statements, list)
        or not proven_ins_addrs
        or not required_write_ins_addrs
        or not required_write_ins_addrs <= proven_ins_addrs
    ):
        stats.failure_count = 1
        typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
        return False

    leaf_positions: list[tuple[list[CStatement], int, CStatement]] = []

    def collect_leaf_positions(container: CStatements) -> None:
        """Collect replaceable leaves without crossing structured controls."""
        for index, statement in enumerate(container.statements):
            if isinstance(statement, CStatements):
                collect_leaf_positions(statement)
            elif isinstance(statement, CStatement):
                leaf_positions.append((container.statements, index, statement))

    collect_leaf_positions(root)
    affected: list[tuple[list[CStatement], int]] = []
    stale_temp_assignments: list[tuple[list[CStatement], CAssignment]] = []
    mixed_ownership = False
    observed_addrs: set[int] = set()
    statement_addrs: list[tuple[int, ...]] = []
    statement_nonvariable_addrs: list[tuple[int, ...]] = []
    statement_stack_flows: list[tuple[int | None, tuple[int, ...]]] = []
    raw_intersections = 0
    temporary_offset = _stack_slot_offset_8616(temporary_expr)
    left_offset = _stack_slot_offset_8616(left_expr)
    right_offset = _stack_slot_offset_8616(right_expr)
    materialized_sequence = _materialized_pointer_swap_sequence_8616(
        leaf_positions,
        left_offset=left_offset,
        right_offset=right_offset,
        temporary_offset=temporary_offset,
    )
    if materialized_sequence is not None:
        materialized_ids = {id(statement) for statement in materialized_sequence}
        stale_temp_assignments = [
            (parent, statement)
            for parent, _index, statement in leaf_positions
            if isinstance(statement, CAssignment)
            if id(statement) not in materialized_ids
            if _stack_slot_offset_8616(statement.lhs) == temporary_offset
            if _indexed_stack_slot_offset_8616(statement.rhs) == left_offset
            if _optional_c_node_ins_addr_8616(statement) in proven_ins_addrs
        ]
        for stale_parent, stale_statement in stale_temp_assignments:
            stale_parent[:] = [statement for statement in stale_parent if statement is not stale_statement]
        stats.raw_fact_count = len(proven_ins_addrs)
        stats.normalized_fact_count = 1
        stats.classified_fact_count = 1
        stats.materialized_count = 1
        stats.idempotent_count = 1
        stats.stale_temp_assignment_count = len(stale_temp_assignments)
        typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
        return bool(stale_temp_assignments)
    affected_ins_addrs: set[int] = set()
    for parent, index, statement in leaf_positions:
        nonvariable_addrs = {
            ins_addr
            for node in _iter_c_nodes_deep_8616(statement)
            if not isinstance(node, CVariable)
            if isinstance((ins_addr := _optional_c_node_ins_addr_8616(node)), int)
        }
        rhs_stack_offsets = (
            tuple(
                sorted(
                    {
                        offset
                        for node in _iter_c_nodes_deep_8616(statement.rhs)
                        if isinstance(node, CVariable)
                        if isinstance((offset := _stack_slot_offset_8616(node)), int)
                    }
                )
            )
            if isinstance(statement, CAssignment)
            else ()
        )
        statement_nonvariable_addrs.append(tuple(sorted(nonvariable_addrs)))
        statement_stack_flows.append(
            (_stack_slot_offset_8616(statement.lhs), rhs_stack_offsets)
            if isinstance(statement, CAssignment)
            else (None, ())
        )
        if (
            isinstance(statement, CAssignment)
            and _stack_slot_offset_8616(statement.lhs) == temporary_offset
            and any(
                isinstance(node, CVariable) and _stack_slot_offset_8616(node) == left_offset
                for node in _iter_c_nodes_deep_8616(statement.rhs)
            )
        ):
            stale_temp_assignments.append((parent, statement))
        direct_ins_addr = _optional_c_node_ins_addr_8616(statement)
        owned_addrs = (
            {int(direct_ins_addr)}
            if isinstance(direct_ins_addr, int)
            else {
                ins_addr
                for node in _iter_c_nodes_deep_8616(statement)
                if not isinstance(node, CVariable)
                if isinstance((ins_addr := _optional_c_node_ins_addr_8616(node)), int)
            }
        )
        observed_addrs.update(owned_addrs)
        statement_addrs.append(tuple(sorted(owned_addrs)))
        if owned_addrs & proven_ins_addrs:
            raw_intersections += 1
            if not isinstance(statement, CAssignment) or not owned_addrs <= proven_ins_addrs:
                mixed_ownership = True
                continue
            affected.append((parent, index))
            affected_ins_addrs.update(owned_addrs)
    stats.observed_ins_addrs = tuple(sorted(observed_addrs))
    stats.statement_ins_addrs = tuple(statement_addrs)
    stats.statement_nonvariable_ins_addrs = tuple(statement_nonvariable_addrs)
    stats.statement_stack_flows = tuple(statement_stack_flows)
    stats.stale_temp_assignment_count = len(stale_temp_assignments)
    stats.raw_fact_count = raw_intersections
    if not affected or mixed_ownership or not required_write_ins_addrs <= affected_ins_addrs:
        stats.failure_count = 1
        typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
        return False
    stats.normalized_fact_count = 1
    parent = affected[0][0]
    indexes = [index for candidate_parent, index in affected if candidate_parent is parent]
    if len(indexes) != len(affected):
        stats.failure_count = 1
        typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
        return False
    first, last = indexes[0], indexes[-1]
    if indexes != list(range(first, last + 1)):
        stats.failure_count = 1
        typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
        return False
    stats.classified_fact_count = 1

    word_type = SimTypeShort(False)
    word_type = word_type.with_arch(typed_codegen.project.arch)

    def indexed(cvar: CVariable) -> CIndexedVariable:
        return CIndexedVariable(
            copy.copy(cvar),
            CConstant(0, word_type, codegen=codegen),
            variable_type=word_type,
            codegen=codegen,
        )

    replacements = [
        CAssignment(copy.copy(temporary_expr), indexed(left_expr), codegen=codegen),
        CAssignment(indexed(left_expr), indexed(right_expr), codegen=codegen),
        CAssignment(indexed(right_expr), copy.copy(temporary_expr), codegen=codegen),
    ]
    parent[first : last + 1] = replacements
    for stale_parent, stale_statement in stale_temp_assignments:
        stale_parent[:] = [statement for statement in stale_parent if statement is not stale_statement]
    stats.materialized_count = 1
    typed_codegen._inertia_pointer_swap_splice_stats_8616 = stats
    return True


def _instruction_address_8616(insn: object) -> int:
    """Read a Capstone instruction address at the dynamic third-party boundary."""
    return int(cast(Any, insn).address)


def _normalize_materialized_counted_loop_8616(
    codegen: _PointerMemoryCodegenBoundary8616,
    kind: PointerMemoryIdiomKind8616,
) -> bool:
    """Keep proven fill/sum loops in canonical CForLoop form before validation."""
    if kind not in {
        PointerMemoryIdiomKind8616.BYTE_FILL_LOOP,
        PointerMemoryIdiomKind8616.WORD_SUM_LOOP,
    }:
        return True
    root = codegen.cfunc.statements
    statements = root.statements
    if kind is PointerMemoryIdiomKind8616.BYTE_FILL_LOOP:
        if len(statements) != 2:
            return False
        initializer, loop = statements
        prefix: list[CStatement] = []
        suffix: list[CStatement] = [CReturn(None, codegen=cast(Any, codegen))]
    else:
        if len(statements) != 4:
            return False
        total_initializer, initializer, loop, return_statement = statements
        if not isinstance(total_initializer, CStatement) or not isinstance(return_statement, CReturn):
            return False
        prefix = [total_initializer]
        suffix = [return_statement]
    if not isinstance(initializer, CStatement) or not isinstance(loop, CWhileLoop):
        return False
    body = loop.body
    if not isinstance(body, CStatements) or len(body.statements) != 2:
        return False
    body_statement, iterator = body.statements
    if not isinstance(body_statement, CStatement) or not isinstance(iterator, CAssignment):
        return False
    normalized_loop = CForLoop(
        initializer,
        loop.condition,
        iterator,
        CStatements([body_statement], codegen=cast(Any, codegen)),
        codegen=cast(Any, codegen),
    )
    codegen.cfunc.statements = CStatements(
        [*prefix, normalized_loop, *suffix],
        codegen=cast(Any, codegen),
    )
    return True


def materialize_pointer_memory_idioms_from_evidence_8616(
    project: object,
    codegen: object,
    callbacks: PointerMemoryIdiomCallbacks8616,
) -> bool:
    """Materialize the first proven pointer-memory idiom for a function."""
    insns = callbacks.linear_function_insns(project, codegen)
    if not insns:
        return False
    index_by_addr = {_instruction_address_8616(insn): idx for idx, insn in enumerate(insns)}
    attempts = (
        (
            PointerMemoryIdiomKind8616.WORD_PAIR_ACCUMULATION_LOOP,
            callbacks.word_pair_pointer_accumulation_loop,
        ),
        (PointerMemoryIdiomKind8616.WORD_FIRST_GREATER_LOOP, callbacks.word_pointer_first_gt_loop),
        (PointerMemoryIdiomKind8616.WORD_ROTATE3, callbacks.word_pointer_rotate3),
        (PointerMemoryIdiomKind8616.POINTER_SWAP, callbacks.pointer_swap),
    )
    typed_codegen = cast(_PointerMemoryCodegenBoundary8616, codegen)
    typed_codegen._inertia_pointer_swap_splice_stats_8616 = PointerSwapSpliceStats8616()
    for kind, materializer in attempts:
        if not materializer(project, codegen, insns, index_by_addr):
            continue
        publish_codegen_function_prototype_8616(project, codegen)
        counted_loop_normalized = _normalize_materialized_counted_loop_8616(typed_codegen, kind)
        requires_counted_loop = kind in {
            PointerMemoryIdiomKind8616.BYTE_FILL_LOOP,
            PointerMemoryIdiomKind8616.WORD_SUM_LOOP,
        }
        pointer_stack_offset: int | None = None
        index_stack_offset: int | None = None
        element_stride: int | None = None
        if kind is PointerMemoryIdiomKind8616.BYTE_FILL_LOOP:
            pointer_stack_offset, index_stack_offset, element_stride = 4, -2, 1
        elif kind is PointerMemoryIdiomKind8616.WORD_SUM_LOOP:
            pointer_stack_offset, index_stack_offset, element_stride = 4, -4, 2
        typed_codegen._inertia_pointer_memory_idiom_facts_8616 = (
            PointerMemoryIdiomMaterializationFact8616(
                kind=kind,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=int(requires_counted_loop and not counted_loop_normalized),
                counted_loop_normalized=counted_loop_normalized,
                pointer_stack_offset=pointer_stack_offset,
                index_stack_offset=index_stack_offset,
                element_stride=element_stride,
            ),
        )
        return True
    pointer_swap_stats = typed_codegen._inertia_pointer_swap_splice_stats_8616
    if isinstance(pointer_swap_stats, PointerSwapSpliceStats8616) and pointer_swap_stats.idempotent_count == 1:
        typed_codegen._inertia_pointer_memory_idiom_facts_8616 = (
            PointerMemoryIdiomMaterializationFact8616(
                kind=PointerMemoryIdiomKind8616.POINTER_SWAP,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
                counted_loop_normalized=True,
                pointer_stack_offset=4,
                index_stack_offset=None,
                element_stride=2,
            ),
        )
        typed_codegen._inertia_pointer_memory_materialized_8616 = PointerMemoryIdiomKind8616.POINTER_SWAP.value
        return False
    typed_codegen._inertia_pointer_memory_idiom_facts_8616 = ()
    return False
