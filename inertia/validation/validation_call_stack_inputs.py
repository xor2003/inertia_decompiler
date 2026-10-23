"""Check actual architectural SP call inputs against fresh source positions.

Layer: Validation.
Responsibility: independently prove ordered call contexts and their word writes,
then expose only those proved protocol nodes as logical calls to existing tail
observation. Malformed or missing contexts remain explicit semantic failures.
No emitted tree is changed, and no tag alone authorizes normalization.
"""
from __future__ import annotations

from copy import copy
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

import z3
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimTemporaryVariable

from inertia.alias.call_stack_positions import (
    CallStackPosition8616,
    prove_call_stack_position_8616,
)
from inertia.alias.scoped_call_stack_context import ScopedCallStackContext8616
from inertia.ir.core import IRFunctionArtifact
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from inertia.lowering.call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
    CallStackInputBinding8616,
    call_stack_context_layout_8616,
    call_stack_temporary_8616,
    call_stack_value_size_8616,
    current_call_stack_source_8616,
    direct_call_target_8616,
)
from inertia.lowering.call_stack_value_uses import CallStackValueUse8616, call_stack_value_uses_8616
from inertia.lowering.entry_stack_pointer_capture import (
    EntryStackPointerCaptureObservation8616,
    ScopedCallPositionAuthority8616,
    StackPointerCaptureFunction8616,
    observe_entry_stack_pointer_capture_8616,
)
from inertia.lowering.gp_register_state import runtime_gp_expression_view_8616
from inertia.semantics.callsite_summary import structured_callsite_addr_8616


class _ActualCodegenRoot8616(Protocol):
    """Current declaration and source publication at the native boundary."""

    cfunc: StackPointerCaptureFunction8616 | None
    _inertia_vex_ir_artifact: IRFunctionArtifact | None


class CallStackInputIssueKind8616(StrEnum):
    """Failures of the actual source-required architectural call input."""

    SOURCE = "call_stack_input_source"
    MISSING = "call_stack_input_missing"
    INVALID = "call_stack_input_invalid"


@dataclass(frozen=True, slots=True)
class CallStackInputIssue8616:
    """One typed input failure retaining its exact source scope."""

    kind: CallStackInputIssueKind8616
    callsite_addr: int | None

    def token(self) -> str:
        """Adapt structured evidence to the existing tail issue-token boundary."""
        suffix = "unknown" if self.callsite_addr is None else f"0x{self.callsite_addr:x}"
        return f"{self.kind.value}@{suffix}"


@dataclass(frozen=True, slots=True)
class _CallStackInputObservation8616:
    """Neutral observation shared by the universal and scoped verdict types."""

    root: object
    raw_fact_count: int
    materialized_count: int
    issues: tuple[CallStackInputIssue8616, ...]

    def issue_tokens(self) -> tuple[str, ...]:
        """Export all failures without filtering a stable observable delta."""
        return tuple(issue.token() for issue in self.issues)


@dataclass(frozen=True, slots=True)
class CallStackInputValidation8616(_CallStackInputObservation8616):
    """Pure logical view and the census that authorizes each projected context."""


@dataclass(frozen=True, slots=True)
class _SpEquation8616:
    """Independent symbolic entry and current values for one word-state equation."""

    entry_id: int
    entry: z3.BitVecRef
    current: z3.BitVecRef


def _sp_leaf(expression: object, equation: _SpEquation8616) -> z3.BitVecRef | None:
    """Interpret constants and canonical storage, never local names as proof."""
    if call_stack_temporary_8616(expression, equation.entry_id):
        return equation.entry & 0xffff
    if isinstance(expression, c.CConstant) and type(expression.value) is int:
        return z3.BitVecVal(expression.value & 0xffffffff, 32)
    if isinstance(expression, c.CVariable):
        view = runtime_gp_expression_view_8616(expression)
        if view is not None and view.register_name == "esp":
            return equation.current
    return None


def _sp_value(expression: object, equation: _SpEquation8616, depth: int = 0) -> z3.BitVecRef | None:
    """Interpret supported unsigned operations and exact signed/unsigned casts."""
    if depth > 16:
        return None
    leaf = _sp_leaf(expression, equation)
    if leaf is not None:
        return leaf
    if isinstance(expression, c.CTypeCast):
        value = _sp_value(expression.expr, equation, depth + 1)
        size = call_stack_value_size_8616(expression.dst_type)
        if value is None or not isinstance(expression.dst_type, SimTypeInt) or size not in {2, 4}:
            return None
        if size == 4:
            return value
        word = z3.Extract(15, 0, value)
        return z3.SignExt(16, word) if expression.dst_type.signed else z3.ZeroExt(16, word)
    if not isinstance(expression, c.CBinaryOp):
        return None
    if not isinstance(expression.type, SimTypeInt) or expression.type.signed or call_stack_value_size_8616(expression.type) != 4:
        return None
    left = _sp_value(expression.lhs, equation, depth + 1)
    right = _sp_value(expression.rhs, equation, depth + 1)
    if left is None or right is None:
        return None
    operations = {"Add": lambda: left + right, "Sub": lambda: left - right,
                  "And": lambda: left & right, "Or": lambda: left | right}
    operation = operations.get(expression.op)
    return None if operation is None else operation()


def _authority_is_current_8616(
    marker: CallStackInputBinding8616,
    source: IRFunctionArtifact,
    capture: EntryStackPointerCaptureObservation8616,
    scoped_context: ScopedCallStackContext8616 | None,
    scoped_caller_scope: Real16InvocationDomain8616 | None,
) -> bool:
    """Reprove the retained authority variant against the current source."""
    authority = marker.authority
    if type(authority) is ScopedCallPositionAuthority8616:
        return (authority.is_current_for(
            source, scoped_context=scoped_context,
            scoped_caller_scope=scoped_caller_scope,
        ) and authority in capture.uses)
    position = marker.position
    if type(authority) is not CallStackPosition8616 or position is None:
        return False
    fresh = prove_call_stack_position_8616(source, position.block_addr, position.instruction_index).proof
    return bool(fresh == position and authority in capture.uses)


def _verify_context(codegen: object, wrapper: c.CMultiStatementExpression, source: IRFunctionArtifact,
                    capture: EntryStackPointerCaptureObservation8616 | None,
                    value_use: CallStackValueUse8616,
                    scoped_context: ScopedCallStackContext8616 | None = None,
                    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
                    ) -> _VerifiedContext8616 | None:
    """Close source, immutable input, ordered layout and independent SP equations."""
    layout = call_stack_context_layout_8616(wrapper, value_use=value_use)
    if layout is None or capture is None:
        return None
    marker, position = layout.marker, layout.marker.position
    if position is None or not _declared_temporaries_8616(codegen, wrapper, marker):
        return None
    if not _authority_is_current_8616(marker, source, capture, scoped_context, scoped_caller_scope):
        return None
    if not call_stack_temporary_8616(capture.value, marker.entry_tmp_id):
        return None
    if structured_callsite_addr_8616(layout.call) != position.callsite_addr or direct_call_target_8616(codegen, layout.call) != position.target_addr:
        return None
    if not _sp_write(layout.pre_write, marker.entry_tmp_id, position.callee_entry_offset):
        return None
    if not _sp_write(layout.post_write, marker.entry_tmp_id, position.caller_after_offset):
        return None
    logical = copy(layout.call)
    logical.args = list(layout.original_arguments)
    return _VerifiedContext8616(wrapper, marker, logical)


def _unowned_sp_use(root: object, capture: EntryStackPointerCaptureObservation8616 | None,
                    contexts: list[_VerifiedContext8616]) -> bool:
    """Refuse retained/current SP observations not proved compatible with the ABI."""
    allowed: set[int] = set()
    if capture is not None:
        allowed.update(id(node) for node in _iter_c_nodes_deep_8616(capture.assignment))
    for context in contexts:
        allowed.update(id(node) for node in _iter_c_nodes_deep_8616(context.wrapper))
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, c.CVariable) and id(node) not in allowed:
            view = runtime_gp_expression_view_8616(node)
            if view is not None and view.parent_name == "esp":
                return True
    return False

def _sp_write(statement: object, entry_id: int, offset: int) -> bool:
    """Prove the exact source entry value and preservation of arbitrary upper ESP."""
    if not isinstance(statement, c.CAssignment) or not isinstance(statement.lhs, c.CVariable):
        return False
    view = runtime_gp_expression_view_8616(statement.lhs)
    if view is None or view.register_name != "esp":
        return False
    entry, current = z3.BitVecs("call_entry_esp call_current_esp", 32)
    actual = _sp_value(statement.rhs, _SpEquation8616(entry_id, entry, current))
    if actual is None:
        return False
    expected = (current & 0xffff0000) | ((entry + offset) & 0xffff)
    solver = z3.Solver()
    solver.set(timeout=1000)
    solver.add(actual != expected)
    return bool(solver.check() == z3.unsat)


def _declared_temporaries_8616(codegen: object, wrapper: c.CMultiStatementExpression,
                              marker: CallStackInputBinding8616) -> bool:
    """Require protocol uses to match the actual owned C local declarations."""
    function = cast(_ActualCodegenRoot8616, codegen).cfunc
    if function is None:
        return False
    identities = {marker.entry_tmp_id, *marker.argument_tmp_ids}
    if marker.result_tmp_id is not None:
        identities.add(marker.result_tmp_id)
    declarations = {variable.tmp_id: value for variable, value in function.variables_in_use.items()
                    if isinstance(variable, SimTemporaryVariable) and variable.tmp_id in identities}
    if len(declarations) != len(identities):
        return False
    for value in declarations.values():
        if function.variable_manager.get_variable_type(value.variable) != value.type:
            return False
    for node in _iter_c_nodes_deep_8616(wrapper):
        if isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable) and node.variable.tmp_id in identities:
            declared = declarations[node.variable.tmp_id]
            if (node.variable.name, node.variable.size, node.variable.ident, node.type) != (
                    declared.variable.name, declared.variable.size, declared.variable.ident, declared.type):
                return False
    return True


@dataclass(frozen=True, slots=True)
class _VerifiedContext8616:
    """Ephemeral original-call projection after all protocol obligations close."""

    wrapper: c.CMultiStatementExpression
    marker: CallStackInputBinding8616
    logical_call: c.CFunctionCall


def _logical_view(root: object, contexts: list[_VerifiedContext8616]) -> object:
    """Copy only the declared C graph, retaining immutable external metadata."""
    replacements = {id(item.wrapper): item.logical_call for item in contexts}
    copies: dict[int, object] = {}

    def project(node: object) -> object:
        """Retain unchanged identities and copy only ancestors of replaced contexts."""
        if id(node) in replacements:
            return replacements[id(node)]
        if id(node) in copies:
            return copies[id(node)]
        candidate = copy(node)
        copies[id(node)] = candidate
        changed = _replace_c_children_8616(candidate, project,
            should_process_child=lambda current, _field: current is candidate)
        result = candidate if changed else node
        copies[id(node)] = result
        return result

    return project(root)



def _unknown_source_8616(codegen: object, root: object) -> _CallStackInputObservation8616:
    """Keep failed source authentication visible instead of treating it as no calls."""
    try:
        source = cast(_ActualCodegenRoot8616, codegen)._inertia_vex_ir_artifact
    except AttributeError:
        source = None
    raw = (sum(instruction.op == "CALL" for block in source.blocks for instruction in block.instrs)
           if isinstance(source, IRFunctionArtifact) else 0)
    issues = (CallStackInputIssue8616(CallStackInputIssueKind8616.SOURCE, None),) if raw else ()
    return _CallStackInputObservation8616(root, raw, 0, issues)


def _validate_call_inputs_8616(
    codegen: object, root: object,
    scoped_context: ScopedCallStackContext8616 | None,
    scoped_caller_scope: Real16InvocationDomain8616 | None,
) -> _CallStackInputObservation8616:
    """Shared validation walk parameterized by the offered context and domain."""
    source = current_call_stack_source_8616(codegen)
    if source is None:
        return _unknown_source_8616(codegen, root)
    calls = [instruction for block in source.blocks for instruction in block.instrs if instruction.op == "CALL"]
    function = cast(_ActualCodegenRoot8616, codegen).cfunc
    if calls and (function is None or function.statements is not root):
        return _CallStackInputObservation8616(root, len(calls), 0,
            (CallStackInputIssue8616(CallStackInputIssueKind8616.SOURCE, None),))
    wrappers = [node for node in _iter_c_nodes_deep_8616(root)
                if isinstance(node, c.CMultiStatementExpression) and CALL_STACK_INPUT_BINDING_TAG_8616 in node.tags]
    capture = (observe_entry_stack_pointer_capture_8616(
        codegen, source, scoped_context=scoped_context,
        scoped_caller_scope=scoped_caller_scope)
        if wrappers else None)
    contexts: list[_VerifiedContext8616] = []
    issues: list[CallStackInputIssue8616] = []
    value_uses = call_stack_value_uses_8616(root)
    for wrapper in wrappers:
        verified = _verify_context(codegen, wrapper, source, capture,
                                   value_uses.get(id(wrapper), CallStackValueUse8616.UNKNOWN),
                                   scoped_context=scoped_context,
                                   scoped_caller_scope=scoped_caller_scope)
        if verified is None:
            issues.append(CallStackInputIssue8616(CallStackInputIssueKind8616.INVALID, None))
        else:
            contexts.append(verified)
    for call in calls:
        count = sum(
            item.marker.position is not None
            and item.marker.position.callsite_addr == call.addr
            for item in contexts)
        if count != 1:
            issues.append(CallStackInputIssue8616(CallStackInputIssueKind8616.MISSING, call.addr))
    if contexts and _unowned_sp_use(root, capture, contexts):
        issues.append(CallStackInputIssue8616(CallStackInputIssueKind8616.INVALID, None))
    logical = _logical_view(root, contexts) if contexts else root
    return _CallStackInputObservation8616(logical, len(calls), len(contexts), tuple(issues))


def validate_call_stack_inputs_8616(codegen: object, root: object) -> CallStackInputValidation8616:
    """Require one independently verified architectural input per real source CALL."""
    observed = _validate_call_inputs_8616(codegen, root, None, None)
    return CallStackInputValidation8616(
        observed.root, observed.raw_fact_count,
        observed.materialized_count, observed.issues)


@dataclass(frozen=True, slots=True)
class ScopedCallStackInputValidation8616(_CallStackInputObservation8616):
    """Scope-restricted verdict; never substitutable for universal validation.

    ``complete`` names scoped-only success: every independently verified
    context revalidated under the offered caller domain and binding context,
    with no claim that the same calls would verify context-free. Universal
    consumers reading a plain ``CallStackInputValidation8616`` cannot accept
    this type.
    """

    caller_scope: Real16InvocationDomain8616
    context: ScopedCallStackContext8616

    @property
    def complete(self) -> bool:
        """Scoped success: every source CALL verified under the offered scope."""
        return (not self.issues
                and self.materialized_count == self.raw_fact_count
                and self.raw_fact_count > 0)


def validate_scoped_call_stack_inputs_8616(
    codegen: object,
    root: object,
    *,
    scoped_context: ScopedCallStackContext8616,
    scoped_caller_scope: Real16InvocationDomain8616,
) -> ScopedCallStackInputValidation8616:
    """Independently verify scoped call inputs under the offered authority.

    The context is required: a scoped tree cannot be accepted without the
    binding set its markers claim. The verdict is a distinct type whose
    ``complete`` is explicitly scope-restricted — never a universal pass.
    """
    observed = _validate_call_inputs_8616(
        codegen, root, scoped_context, scoped_caller_scope)
    return ScopedCallStackInputValidation8616(
        observed.root, observed.raw_fact_count, observed.materialized_count,
        observed.issues, scoped_caller_scope, scoped_context)
