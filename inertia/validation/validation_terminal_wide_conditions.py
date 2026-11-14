# cython: language_level=3, infer_types=True
"""Check complete terminal decisions after their scalar carriers are consumed.

Layer: Validation.
Responsibility: consume immutable Structuring polarity and Lowering storage
proofs, checking the final predicate, unique call capture, and loop placement.
Never reconstruct missing semantics or accept branch-address tags alone.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunction,
    CFunctionCall,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimType, SimTypeLong
from angr.sim_variable import SimStackVariable, SimTemporaryVariable, SimVariable

from inertia.ir.condition_ir import ConditionIR, condition_sort_key_8616
from inertia.lowering.c_ast_utils import _iter_c_node_occurrences_8616, _iter_c_nodes_deep_8616
from inertia.lowering.semantic_cast import CSemanticCast8616
from inertia.lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from inertia.lowering.wide_call_condition_binding import (
    WIDE_CALL_BINDING_TAG_8616,
    WideCallBinding8616,
    wide_call_identity_8616,
)
from inertia.lowering.wide_call_condition_capture import _OPERATORS
from inertia.structuring.composite_pretest_conditions import _statements_8616
from inertia.structuring.condition_chain_provenance import condition_chain_provenance_8616
from inertia.structuring.terminal_loop_exit_conditions import (
    TERMINAL_WIDE_DECISION_TAG_8616,
    TerminalWideDecision8616,
    _terminal_guard_8616,
)
import operator
import builtins

_WIDE_BYTES: cython.longlong = 4
_WIDE_BITS: cython.longlong = 32
_CAPTURE_AND_GUARD: cython.longlong = 2


class TerminalWideValidation8616(StrEnum):
    """Explicit distinction between absent evidence and a corrupted proof."""

    NOT_APPLICABLE = "not-applicable"
    PROVEN = "proven"
    FACT_MISMATCH = "fact-mismatch"
    STORAGE_MISMATCH = "storage-mismatch"
    CAPTURE_MISMATCH = "capture-mismatch"
    PLACEMENT_MISMATCH = "placement-mismatch"


class _DeclarationFunction8616(Protocol):
    """Already materialized declaration surface consumed from angr."""

    unified_local_vars: object


class _DeclarationCodegen8616(Protocol):
    """Codegen boundary exposing the final declaration inventory."""

    cfunc: _DeclarationFunction8616


def _declared_wide_value(codegen: object, value: CVariable) -> cython.bint:
    """Check emitted declaration types as well as the expression's storage size."""
    try:
        declarations = cast(_DeclarationCodegen8616, codegen).cfunc.unified_local_vars
    except AttributeError:
        return False
    rendered = CFunction.sort_local_vars(declarations)
    display_identity = value.unified_variable if value.unified_variable is not None else value.variable
    types = tuple(
        type_ for variable, entries in builtins.iter(declarations.items()) if variable in rendered and variable == display_identity
        for cvar, type_ in iter(entries) if operator.eq(cvar.variable, value.variable)
    )
    types = tuple(tuple(types) + (value.variable_type,)) if types else tuple(())
    return bool(types) and all(isinstance(type_, SimTypeLong) and operator.eq(type_.size, _WIDE_BITS) for type_ in iter(types))


@cython.ccall
def _signed_wide_variable(expression: object) -> CVariable | None:
    """Require the semantic signed conversion and an actual four-byte value."""
    if not isinstance(expression, CSemanticCast8616):
        return None
    destination = expression.dst_type
    if not isinstance(destination, SimTypeLong) or not destination.signed or operator.ne(destination.size, _WIDE_BITS):
        return None
    value = expression.expr
    if not isinstance(value, CVariable) or operator.ne(value.variable.size, _WIDE_BYTES):
        return None
    return value


def _capture_for(root: object, value: CVariable, binding: WideCallBinding8616) -> CAssignment | None:
    """Require one writer and one dynamic call occurrence for the captured value."""
    writers = tuple(
        node for node in builtins.iter(_iter_c_node_occurrences_8616(root))
        if isinstance(node, CAssignment) and isinstance(node.lhs, CVariable)
        and operator.eq(node.lhs.variable, value.variable)
    )
    if len(writers) != 1:
        return None
    writer = writers[0]
    call = writer.rhs
    if not isinstance(call, CFunctionCall) or call.args:
        return None
    if operator.ne(writer.tags.get("ins_addr"), binding.callsite_addr) or operator.ne(wide_call_identity_8616(call), binding.callee_identity):
        return None
    return writer if sum(node is call for node in builtins.iter(_iter_c_node_occurrences_8616(root))) == 1 else None


@cython.ccall
def _capture_precedes_terminal_guard(
    root: object, condition: CBinaryOp, capture: CAssignment, header: cython.longlong,
) -> cython.bint:
    """Require the capture immediately before the final guard on each iteration."""
    guard: object
    node: object
    owners: list[CWhileLoop] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CWhileLoop):
            guard = _terminal_guard_8616(node)
            if guard is not None and guard[1] is condition:
                owners.append(node)
    if len(owners) != 1:
        return False
    loop = owners[0]
    unconditional = isinstance(loop.condition, CConstant) and loop.condition.value == 1
    if not unconditional or operator.ne(loop.tags.get("ins_addr"), header):
        return False
    statements = tuple(_statements_8616(loop.body))
    # This intentionally refuses intervening effects instead of proving them
    # harmless here. Broader placement proofs belong to the earlier owners.
    return len(statements) >= _CAPTURE_AND_GUARD and statements[-2] is capture


def _matching_decision_facts(
    condition: CBinaryOp,
    decision: TerminalWideDecision8616,
    binding: WideCallBinding8616,
    facts_by_jcc: Mapping[cython.longlong, Mapping[tuple[object, ...], ConditionIR]],
) -> cython.bint:
    """Require every current fact and both published projections to agree."""
    provenance: object
    facts = decision.comparison.conditions
    provenance = condition_chain_provenance_8616(condition)
    if provenance is None or operator.ne(provenance.jcc_addrs, tuple(fact.src_insn for fact in iter(facts))):
        return False
    keys = tuple(condition_sort_key_8616(fact) for fact in iter(facts))
    exact_facts = all(
        isinstance(fact.src_insn, int)
        and operator.eq(tuple(facts_by_jcc.get(fact.src_insn, {})), (key,))
        for fact, key in builtins.iter(zip(facts, keys, strict=True))
    )
    return exact_facts and operator.eq(keys, binding.condition_keys) and operator.eq(condition.tags.get("ins_addr"), facts[0].src_insn)


@cython.ccall
def validate_terminal_wide_condition_8616(
    codegen: object,
    root: object,
    condition: object,
    facts_by_jcc: Mapping[cython.longlong, Mapping[tuple[object, ...], ConditionIR]],
) -> TerminalWideValidation8616:
    """Compare final AST effects against both independently published proofs."""
    binding: object
    capture: object
    decision: object
    lhs: object
    rhs: object
    if not isinstance(condition, CBinaryOp):
        return TerminalWideValidation8616.NOT_APPLICABLE
    decision = condition.tags.get(TERMINAL_WIDE_DECISION_TAG_8616)
    if not isinstance(decision, TerminalWideDecision8616):
        return TerminalWideValidation8616.NOT_APPLICABLE
    binding = condition.tags.get(WIDE_CALL_BINDING_TAG_8616)
    if not isinstance(binding, WideCallBinding8616):
        return TerminalWideValidation8616.STORAGE_MISMATCH
    if not _matching_decision_facts(condition, decision, binding, facts_by_jcc):
        return TerminalWideValidation8616.FACT_MISMATCH
    lhs, rhs = _signed_wide_variable(condition.lhs), _signed_wide_variable(condition.rhs)
    if lhs is None or rhs is None or operator.ne(condition.op, _OPERATORS.get(decision.comparison.operator)):
        return TerminalWideValidation8616.STORAGE_MISMATCH
    temporary_matches = isinstance(lhs.variable, SimTemporaryVariable) and operator.eq(lhs.variable.tmp_id, binding.temporary_id)
    stack_matches = (
        isinstance(rhs.variable, SimStackVariable)
        and operator.eq(machine_bp_offset_for_stack_variable_8616(codegen, rhs.variable), binding.stack_bp_offset)
        and operator.eq(binding.stack_bp_offset, decision.comparison.low_stack.offset)
    )
    if not temporary_matches or not stack_matches:
        return TerminalWideValidation8616.STORAGE_MISMATCH
    if not _declared_wide_value(codegen, lhs) or not _declared_wide_value(codegen, rhs):
        return TerminalWideValidation8616.STORAGE_MISMATCH
    capture = _capture_for(root, lhs, binding)
    if capture is None:
        return TerminalWideValidation8616.CAPTURE_MISMATCH
    if not _capture_precedes_terminal_guard(root, condition, capture, decision.loop_header):
        return TerminalWideValidation8616.PLACEMENT_MISMATCH
    return TerminalWideValidation8616.PROVEN
