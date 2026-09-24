"""Materialize proven register-carried direct-global logical updates.

Layer: Types/Lowering.
Responsibility: consume adjacent binary instruction evidence for a direct
global load followed by a logical direct-global update through one register.
No rendered C text, symbol spelling, or corpus address participates in proof; consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from itertools import pairwise
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from capstone.x86_const import X86_INS_AND, X86_INS_MOV, X86_INS_OR, X86_INS_XOR, X86_OP_MEM, X86_OP_REG

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)
from ..pipeline.structured_ast_query_index import StructuredAstQuerySession8616
from .direct_global_register_update_contracts import (
    DirectGlobalRegisterUpdate8616,
    DirectGlobalRegisterUpdateOp8616,
    DirectGlobalRegisterUpdateStats8616,
)
from .real_mode_linear import _capstone_insns_for_direct_global_update_8616, _direct_global_update_blocks_8616
from .segment_access_policy import instruction_addrs_from_node_8616

type ProjectBoundary8616 = Any
type CodegenBoundary8616 = Any


class _FunctionLookupBoundary8616(Protocol):
    """Dynamic angr function-manager lookup used by materialization."""

    def get(self, key: object) -> object | None:
        """Return one function by address without creating it."""


def _boundary_attr_8616(value: object, name: str, default: object = None) -> object:
    """Read one dynamic third-party angr or Capstone boundary attribute."""
    # Dynamic boundary: angr and Capstone objects expose version-dependent fields.
    return getattr(value, name, default)


def _direct_memory_identity_8616(operand: object) -> tuple[int, int] | None:
    """Return an unindexed direct-memory offset and byte width."""
    if _boundary_attr_8616(operand, "type", None) != X86_OP_MEM:
        return None
    memory = _boundary_attr_8616(operand, "mem", None)
    width = _boundary_attr_8616(operand, "size", None)
    if memory is None or not isinstance(width, int) or width not in {1, 2, 4}:
        return None
    base = _boundary_attr_8616(memory, "base", 0)
    index = _boundary_attr_8616(memory, "index", 0)
    displacement = _boundary_attr_8616(memory, "disp", 0)
    if (
        not isinstance(base, int)
        or not isinstance(index, int)
        or not isinstance(displacement, int)
    ):
        return None
    if base != 0 or index != 0:
        return None
    return displacement & 0xFFFF, width


def collect_direct_global_register_updates_8616(
    project: ProjectBoundary8616,
    function: object,
) -> tuple[DirectGlobalRegisterUpdate8616, ...]:
    """Collect exact adjacent MOV-load plus logical-memory-update facts."""
    operations = {
        X86_INS_AND: DirectGlobalRegisterUpdateOp8616.AND,
        X86_INS_OR: DirectGlobalRegisterUpdateOp8616.OR,
        X86_INS_XOR: DirectGlobalRegisterUpdateOp8616.XOR,
    }
    facts: list[DirectGlobalRegisterUpdate8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        wrappers = _capstone_insns_for_direct_global_update_8616(project, block)
        for previous_wrapper, update_wrapper in pairwise(wrappers):
            previous = _boundary_attr_8616(previous_wrapper, "insn", previous_wrapper)
            update = _boundary_attr_8616(update_wrapper, "insn", update_wrapper)
            operation = operations.get(_boundary_attr_8616(update, "id", None))
            previous_operands_value = _boundary_attr_8616(previous, "operands", ())
            update_operands_value = _boundary_attr_8616(update, "operands", ())
            previous_operands: tuple[object, ...] = (
                tuple(previous_operands_value)
                if isinstance(previous_operands_value, Iterable)
                else ()
            )
            update_operands: tuple[object, ...] = (
                tuple(update_operands_value)
                if isinstance(update_operands_value, Iterable)
                else ()
            )
            if not _mov_update_shape_8616(previous, previous_operands, update_operands, operation):
                continue
            source = _direct_memory_identity_8616(previous_operands[1])
            destination = _direct_memory_identity_8616(update_operands[0])
            register_id = _boundary_attr_8616(previous_operands[0], "reg", None)
            previous_address = _boundary_attr_8616(previous, "address", None)
            update_address = _boundary_attr_8616(update, "address", None)
            if not _direct_update_facts_match_8616(
                source,
                destination,
                register_id,
                _boundary_attr_8616(update_operands[1], "reg", None),
                previous_address,
                update_address,
            ):
                continue
            if source is None or destination is None:
                continue
            facts.append(
                DirectGlobalRegisterUpdate8616(
                    source[0], destination[0], source[1], register_id, operation,
                    previous_address, update_address,
                )
            )
    return tuple(dict.fromkeys(facts))


def _mov_update_shape_8616(
    previous: object,
    previous_operands: tuple[object, ...],
    update_operands: tuple[object, ...],
    operation: DirectGlobalRegisterUpdateOp8616 | None,
) -> bool:
    """Check the adjacent pair has the MOV-load plus 2-operand-update shape."""
    return (
        operation is not None
        and _boundary_attr_8616(previous, "id", None) == X86_INS_MOV
        and _update_operand_shape_8616(previous_operands, update_operands)
    )


def _update_operand_shape_8616(
    previous_operands: tuple[object, ...], update_operands: tuple[object, ...]
) -> bool:
    """Check both instructions expose the expected 2-operand register slots."""
    return (
        len(previous_operands) == 2
        and len(update_operands) == 2
        and _boundary_attr_8616(previous_operands[0], "type", None) == X86_OP_REG
        and _boundary_attr_8616(update_operands[1], "type", None) == X86_OP_REG
    )


def _direct_update_facts_match_8616(
    source: tuple[int, int] | None,
    destination: tuple[int, int] | None,
    register_id: object,
    update_register_id: object,
    previous_address: object,
    update_address: object,
) -> bool:
    """Check memory identity, register, and address facts all align."""
    return (
        _mem_identities_align_8616(source, destination)
        and isinstance(register_id, int)
        and register_id == update_register_id
        and isinstance(previous_address, int)
        and isinstance(update_address, int)
    )


def _mem_identities_align_8616(
    source: tuple[int, int] | None, destination: tuple[int, int] | None
) -> bool:
    """Check both memory operands resolved to the same segment space."""
    return source is not None and destination is not None and source[1] == destination[1]


def _source_variable_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
    fact: DirectGlobalRegisterUpdate8616,
    variable_type: object,
) -> structured_c.CExpression | None:
    """Create a named source or an exact segmented-helper fallback."""
    if isinstance(synthetic_globals, dict):
        entry = synthetic_globals.get(fact.source_offset)
        if isinstance(entry, tuple) and len(entry) >= 2 and isinstance(entry[0], str):
            declared_width = entry[1]
            if isinstance(declared_width, int) and declared_width >= fact.width:
                region = _boundary_attr_8616(_boundary_attr_8616(codegen, "cfunc", None), "addr", None)
                return structured_c.CVariable(
                    SimMemoryVariable(fact.source_offset, fact.width, name=entry[0], region=region),
                    variable_type=variable_type,
                    codegen=codegen,
                )
    registers = _boundary_attr_8616(_boundary_attr_8616(project, "arch", None), "registers", None)
    register = registers.get("ds") if isinstance(registers, dict) else None
    if not isinstance(register, tuple) or len(register) < 2:
        return None
    segment = structured_c.CVariable(
        SimRegisterVariable(register[0], register[1], name="ds"),
        codegen=codegen,
    )
    return structured_c.CFunctionCall(
        "SEG_U16",
        None,
        [
            segment,
            structured_c.CConstant(fact.source_offset, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
        tags={"ins_addr": fact.load_insn_addr},
    )


def _replace_unsupported_carrier_8616(
    expression: object,
    replacement: structured_c.CExpression,
) -> int:
    """Replace unsupported leaves while preserving the existing projection tree."""
    if isinstance(expression, structured_c.CDirtyExpression):
        return -1
    changed = 0
    if isinstance(expression, structured_c.CBinaryOp):
        if isinstance(expression.lhs, structured_c.CDirtyExpression):
            expression.lhs = replacement
            changed += 1
        else:
            nested = _replace_unsupported_carrier_8616(expression.lhs, replacement)
            changed += max(0, nested)
        if isinstance(expression.rhs, structured_c.CDirtyExpression):
            expression.rhs = replacement
            changed += 1
        else:
            nested = _replace_unsupported_carrier_8616(expression.rhs, replacement)
            changed += max(0, nested)
    elif isinstance(expression, structured_c.CUnaryOp):
        if isinstance(expression.operand, structured_c.CDirtyExpression):
            expression.operand = replacement
            changed += 1
        else:
            nested = _replace_unsupported_carrier_8616(expression.operand, replacement)
            changed += max(0, nested)
    return changed


def materialize_direct_global_register_updates_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
    *,
    query_session: StructuredAstQuerySession8616 | None = None,
) -> bool:
    """Replace exact tagged update RHSs using one copied assignment projection."""
    cfunc = _boundary_attr_8616(codegen, "cfunc", None)
    function_addr = _boundary_attr_8616(cfunc, "addr", None)
    functions = _boundary_attr_8616(_boundary_attr_8616(project, "kb", None), "functions", None)
    if functions is not None and isinstance(function_addr, int):
        try:
            function = cast(_FunctionLookupBoundary8616, functions).get(function_addr)
        except AttributeError:
            function = None
    else:
        function = None
    root = _boundary_attr_8616(cfunc, "statements", None)
    facts = (
        collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.DIRECT_GLOBAL_REGISTER_UPDATES,
            builder=collect_direct_global_register_updates_8616,
        )
        if function is not None
        else ()
    )
    query_index = query_session.current() if query_session is not None and facts else None
    if query_index is not None:
        query_index.require_root(root)
    all_assignments = (
        query_index.assignments
        if query_index is not None
        else tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, structured_c.CAssignment))
        if facts
        else ()
    )
    if os.environ.get("INERTIA_DEBUG_DIRECT_GLOBAL_UPDATES") == "1":
        _debug_dump_update_candidates_8616(facts, all_assignments)
    materialized = failures = 0
    ast_changed = False
    for fact in facts:
        ok, fact_changed = _apply_update_fact_8616(
            project, codegen, synthetic_globals, fact, all_assignments
        )
        ast_changed |= fact_changed
        if ok:
            materialized += 1
        else:
            failures += 1
    stats = DirectGlobalRegisterUpdateStats8616(len(facts), len(facts), len(facts), materialized, failures)
    codegen._inertia_direct_global_register_update_stats_8616 = stats
    if not stats.complete:
        raise RuntimeError("direct-global register update evidence loop did not close")
    if query_session is not None:
        query_session.record_mutation(ast_changed)
    return ast_changed


def _debug_dump_update_candidates_8616(
    facts: tuple[DirectGlobalRegisterUpdate8616, ...],
    all_assignments: Iterable[structured_c.CAssignment],
) -> None:
    """Emit the fact/assignment census used for debug correlation."""
    candidates = [
        (
            _boundary_attr_8616(_boundary_attr_8616(node, "lhs", None), "variable", None),
            type(_boundary_attr_8616(node, "lhs", None)).__name__,
            sorted(instruction_addrs_from_node_8616(node)),
            type(_boundary_attr_8616(node, "rhs", None)).__name__,
            sum(
                isinstance(item, structured_c.CDirtyExpression)
                for item in _iter_c_nodes_deep_8616(_boundary_attr_8616(node, "rhs", None))
            ),
        )
        for node in all_assignments
    ]
    print(f"[direct-global-register-update] facts={facts!r} assignments={candidates!r}", file=sys.stderr)


def _fact_match_assignments_8616(
    fact: DirectGlobalRegisterUpdate8616,
    all_assignments: Iterable[structured_c.CAssignment],
) -> tuple[structured_c.CAssignment, ...] | None:
    """Find the assignments covering every destination byte lane of a fact."""
    direct_lane_matches = [
        node
        for node in all_assignments
        if fact.update_insn_addr in instruction_addrs_from_node_8616(node)
        and isinstance(node.lhs, structured_c.CVariable)
        and isinstance(node.lhs.variable, SimMemoryVariable)
        and isinstance(node.lhs.variable.addr, int)
        and (node.lhs.variable.addr & 0xFFFF)
        in range(fact.destination_offset, fact.destination_offset + fact.width)
        and node.lhs.variable.size == 1
    ]
    segmented_store_matches = [
        node
        for node in all_assignments
        if fact.update_insn_addr in instruction_addrs_from_node_8616(node)
        and isinstance(node.lhs, structured_c.CFunctionCall)
        and any(
            isinstance(item, structured_c.CDirtyExpression)
            for item in _iter_c_nodes_deep_8616(node.rhs)
        )
    ]
    lanes = {int(node.lhs.variable.addr) & 0xFFFF: node for node in direct_lane_matches}
    expected_lanes = set(range(fact.destination_offset, fact.destination_offset + fact.width))
    if set(lanes) == expected_lanes and len(direct_lane_matches) == fact.width:
        return tuple(lanes.values())
    if len(segmented_store_matches) == fact.width:
        return tuple(segmented_store_matches)
    return None


def _apply_update_fact_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
    fact: DirectGlobalRegisterUpdate8616,
    all_assignments: Iterable[structured_c.CAssignment],
) -> tuple[bool, bool]:
    """Apply one update fact; return (materialized, ast_changed)."""
    matched_assignments = _fact_match_assignments_8616(fact, all_assignments)
    if matched_assignments is None:
        return False, False
    replacements = 0
    for assignment in matched_assignments:
        source = _source_variable_8616(project, codegen, synthetic_globals, fact, assignment.lhs.type)
        if source is None:
            break
        replacements += _replace_unsupported_carrier_8616(assignment.rhs, source)
    return replacements >= fact.width, replacements > 0


__all__ = [
    "DirectGlobalRegisterUpdate8616",
    "DirectGlobalRegisterUpdateOp8616",
    "DirectGlobalRegisterUpdateStats8616",
    "collect_direct_global_register_updates_8616",
    "materialize_direct_global_register_updates_8616",
]
