"""Materialize source-proved architectural SP inputs at generated calls.

Layer: Types/Lowering.
Responsibility: preserve argument evaluation, invoke the original call once,
and publish its proved caller-after word through the canonical register owner.
Unknown positions, effects or remaining unowned ESP uses keep the input tree.
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimType, SimTypeBottom, SimTypeNum
from angr.sim_variable import SimTemporaryVariable

from inertia.alias.call_stack_positions import CallStackPosition8616, prove_call_stack_position_8616
from inertia.alias.scoped_call_stack_context import ScopedCallStackContext8616
from inertia.alias.scoped_call_stack_positions import prove_scoped_call_stack_position_8616
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.pipeline.call_stack_input_outcome import (
    CallStackInputFailure8616,
    CallStackInputResult8616,
    CallStackInputStats8616,
    CallStackInputStatus8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary import structured_callsite_addr_8616

from .c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616, _same_c_expression_8616
from .call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
    CallStackInputAuthority8616,
    CallStackInputBinding8616,
    call_stack_argument_is_stable_8616,
    call_stack_argument_value_type_8616,
    call_stack_authority_position_8616,
    call_stack_context_layout_8616,
    call_stack_has_runtime_sp_8616,
    call_stack_value_size_8616,
    current_call_stack_source_8616,
    direct_call_target_8616,
)
from .call_stack_value_uses import CallStackValueUse8616, call_stack_value_uses_8616
from .entry_stack_pointer_capture import (
    ScopedCallPositionAuthority8616,
    StackPointerCaptureFunction8616,
    entry_stack_pointer_projection_8616,
    observe_entry_stack_pointer_capture_8616,
    prepare_entry_stack_pointer_capture_8616,
)
from .gp_register_state import runtime_gp_state_assignment_8616
from .semantic_cast import CSemanticCast8616


class _CodegenBindings8616(Protocol):
    """Native declaration and owned result publication boundary."""

    cfunc: StackPointerCaptureFunction8616 | None
    _inertia_call_stack_input_lowering_8616: CallStackInputResult8616 | None


@dataclass(frozen=True, slots=True)
class _CallPlan8616:
    """One complete preflight plan before any argument or tree changes."""

    call: c.CFunctionCall
    authority: CallStackInputAuthority8616
    arguments: tuple[c.CExpression, ...]
    value_use: CallStackValueUse8616

    @property
    def position(self) -> CallStackPosition8616:
        """Project scalar coordinates for SP writes; never proof by itself."""
        position = call_stack_authority_position_8616(self.authority)
        assert position is not None
        return position


def _outcome(raw: int, normalized: int, failure: CallStackInputFailure8616 | None = None,
             *, changed: int = 0, classified: int | None = None) -> CallStackInputResult8616:
    """Close one atomic function attempt without claiming partial publication."""
    known = normalized if failure is None else (classified or 0)
    status = CallStackInputStatus8616.REFUSED if failure is not None else (
        CallStackInputStatus8616.MATERIALIZED if changed else CallStackInputStatus8616.STABLE)
    return CallStackInputResult8616(status, CallStackInputStats8616(
        raw, normalized, known, normalized if failure is None else 0,
        max(1, raw) if failure is not None and known else 0, changed,
        max(1, raw) if failure is not None and not known else 0,
    ), failure)


def _plan_failure(call: c.CFunctionCall) -> CallStackInputFailure8616 | None:
    """Require declared storage and transparent argument computations."""
    if call_stack_value_size_8616(call.type) is None:
        return CallStackInputFailure8616.TYPE_UNPROVEN
    for argument in call.args or []:
        value_type = call_stack_argument_value_type_8616(argument)
        if value_type is None or call_stack_value_size_8616(value_type) in {None, 0}:
            return CallStackInputFailure8616.TYPE_UNPROVEN
        if not call_stack_argument_is_stable_8616(argument) or call_stack_has_runtime_sp_8616(argument):
            return CallStackInputFailure8616.ARGUMENT_EFFECT
    return None


def _sp_write(codegen: object, function: StackPointerCaptureFunction8616, entry: c.CVariable,
              offset: int) -> c.CAssignment:
    """Delegate the word write, including upper-lane preservation, to its owner."""
    expression = entry_stack_pointer_projection_8616(entry, offset, codegen)
    assignment = runtime_gp_state_assignment_8616("sp", expression, codegen=codegen, function_addr=function.addr)
    if assignment is None:
        raise PipelineHardError(layer="types:call_stack_inputs", message="Canonical SP state write is unavailable",
                                function_addr=function.addr, details={"offset": offset})
    return assignment


def _existing_binding_is_current(codegen: object, function: StackPointerCaptureFunction8616,
                                 wrapper: object, entry: c.CVariable, authority: CallStackInputAuthority8616,
                                 *, value_use: CallStackValueUse8616) -> bool:
    """Check the canonical producer layout; validation separately proves equations."""
    layout = call_stack_context_layout_8616(wrapper, value_use=value_use)
    if layout is None or layout.marker.authority != authority:
        return False
    position = call_stack_authority_position_8616(authority)
    if position is None:
        return False
    if not isinstance(entry.variable, SimTemporaryVariable) or layout.marker.entry_tmp_id != entry.variable.tmp_id:
        return False
    pairs = ((layout.pre_write, position.callee_entry_offset), (layout.post_write, position.caller_after_offset))
    return all(_same_c_expression_8616(actual.lhs, expected.lhs) and _same_c_expression_8616(actual.rhs, expected.rhs)
               for actual, offset in pairs if (expected := _sp_write(codegen, function, entry, offset)) is not None)


def _has_unowned_sp(root: object, allowed: tuple[object, ...]) -> bool:
    """Require all remaining runtime-SP observations to have a proved owner."""
    allowed_ids = {id(node) for item in allowed for node in _iter_c_nodes_deep_8616(item)}
    return any(id(node) not in allowed_ids and isinstance(node, c.CVariable)
               and call_stack_has_runtime_sp_8616(node) for node in _iter_c_nodes_deep_8616(root))


@dataclass
class _Locals8616:
    """Function-scoped temporary publication with collision-free native IDs."""

    codegen: object
    function: StackPointerCaptureFunction8616
    next_identity: int

    def create(self, type_: SimType) -> c.CVariable:
        """Allocate exactly the declared C value storage and type."""
        size = call_stack_value_size_8616(type_)
        if size is None or size == 0:
            raise PipelineHardError(layer="types:call_stack_inputs", message="Preflight lost a declared temporary type",
                                    function_addr=self.function.addr)
        temporary = SimTemporaryVariable(self.next_identity, size)
        self.next_identity += 1
        value = c.CVariable(temporary, variable_type=type_, codegen=self.codegen)
        actual_type = value.type
        assert actual_type is not None
        self.function.variables_in_use[temporary] = value
        self.function.variable_manager.set_variable_type(temporary, actual_type)
        return value


def _temporary_identity_8616(value: c.CVariable) -> int:
    """Retain the declared storage identity guaranteed by the local factory."""
    variable = value.variable
    assert isinstance(variable, SimTemporaryVariable)
    return cast(int, variable.tmp_id)


def _materialize_context(codegen: object, function: StackPointerCaptureFunction8616, plan: _CallPlan8616,
                         entry: c.CVariable, locals_: _Locals8616) -> c.CMultiStatementExpression:
    """Evaluate arguments, enter the callee, invoke once, then restore continuation."""
    statements: list[object] = []
    arguments = []
    for argument in plan.arguments:
        argument_type = call_stack_argument_value_type_8616(argument)
        assert argument_type is not None
        temporary = locals_.create(argument_type)
        statements.append(c.CAssignment(temporary, argument, codegen=codegen))
        arguments.append(temporary)
    statements.append(_sp_write(codegen, function, entry, plan.position.callee_entry_offset))
    plan.call.args = arguments
    if call_stack_value_size_8616(plan.call.type) == 0 or plan.value_use is CallStackValueUse8616.DISCARDED:
        statements.append(plan.call)
        result = None
        word = SimTypeNum(32, False)
        expression: c.CExpression = CSemanticCast8616(word, SimTypeBottom(label="void"),
                                c.CConstant(0, word, codegen=codegen), codegen=codegen)
    else:
        result = locals_.create(plan.call.type)
        statements.append(c.CAssignment(result, plan.call, codegen=codegen))
        expression = result
    statements.append(_sp_write(codegen, function, entry, plan.position.caller_after_offset))
    assert isinstance(entry.variable, SimTemporaryVariable)
    marker = CallStackInputBinding8616(plan.authority, entry.variable.tmp_id,
        tuple(_temporary_identity_8616(item) for item in arguments), _temporary_identity_8616(result) if result is not None else None)
    return c.CMultiStatementExpression(c.CStatements(statements, codegen=codegen), expression,
        codegen=codegen, tags={CALL_STACK_INPUT_BINDING_TAG_8616: marker})


def _site_authority_8616(
    source: IRFunctionArtifact, block: IRBlock, index: int,
    scoped_context: ScopedCallStackContext8616 | None,
    scoped_caller_scope: Real16InvocationDomain8616 | None,
) -> CallStackInputAuthority8616 | None:
    """Authenticate one CALL's position under universal or scoped evidence."""
    if scoped_context is None:
        return prove_call_stack_position_8616(source, block.addr, index).proof
    call = block.instrs[index]
    binding = scoped_context.for_callsite(call.addr)
    if binding is None:
        return None
    result = prove_scoped_call_stack_position_8616(
        source, block.addr, index, scoped_caller_scope, binding.callee_scope,
        context=scoped_context,
    )
    if result.failure is not None or result.proof is None:
        return None
    return ScopedCallPositionAuthority8616(result)


def _collect_plans_8616(
    codegen: object, source: IRFunctionArtifact, nodes: tuple[object, ...],
    sites: list[tuple[IRBlock, int, IRInstr]],
    value_uses: dict[int, CallStackValueUse8616],
    scoped_context: ScopedCallStackContext8616 | None,
    scoped_caller_scope: Real16InvocationDomain8616 | None,
) -> tuple[tuple[_CallPlan8616, ...], CallStackInputFailure8616 | None]:
    """Require a complete function-wide set of source- and type-bound calls."""
    plans: list[_CallPlan8616] = []
    for block, index, instruction in sites:
        matches = [node for node in nodes if isinstance(node, c.CFunctionCall)
                   and structured_callsite_addr_8616(node) == instruction.addr]
        if len(matches) != 1:
            return tuple(plans), CallStackInputFailure8616.CALL_IDENTITY
        authority = _site_authority_8616(
            source, block, index, scoped_context, scoped_caller_scope)
        position = None if authority is None else call_stack_authority_position_8616(authority)
        if authority is None or position is None:
            return tuple(plans), CallStackInputFailure8616.POSITION_UNPROVEN
        call = matches[0]
        if direct_call_target_8616(codegen, call) != position.target_addr:
            return tuple(plans), CallStackInputFailure8616.CALL_IDENTITY
        failure = _plan_failure(call)
        if failure is not None:
            return tuple(plans), failure
        value_use = value_uses.get(id(call), CallStackValueUse8616.UNKNOWN)
        if value_use is CallStackValueUse8616.UNKNOWN:
            return tuple(plans), CallStackInputFailure8616.RESULT_USE_UNPROVEN
        if value_use is CallStackValueUse8616.VALUE and call_stack_value_size_8616(call.type) == 0:
            return tuple(plans), CallStackInputFailure8616.TYPE_UNPROVEN
        plans.append(_CallPlan8616(call, authority, tuple(call.args or []), value_use))
    return tuple(plans), None


def lower_call_stack_inputs_8616(
    codegen: object,
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> CallStackInputResult8616 | None:
    """Preflight the entire function, keeping unknown input trees unchanged.

    Without scoped inputs the universal position proof applies. With them,
    every source CALL must authenticate through the offered context and
    caller domain before any argument, temporary or AST change — scoped
    evidence is never projected through the universal path.
    """
    function = cast(_CodegenBindings8616, codegen).cfunc
    source = current_call_stack_source_8616(codegen)
    if function is None or source is None:
        return None
    sites = [(block, index, instruction) for block in source.blocks for index, instruction in enumerate(block.instrs)
             if instruction.op == "CALL"]
    if not sites:
        return None
    scoped = (type(scoped_context) is ScopedCallStackContext8616
              and type(scoped_caller_scope) is Real16InvocationDomain8616)
    if not scoped:
        scoped_context, scoped_caller_scope = None, None
    nodes = tuple(_iter_c_nodes_deep_8616(function.statements))
    wrappers = [node for node in nodes if isinstance(node, c.CMultiStatementExpression)
                and CALL_STACK_INPUT_BINDING_TAG_8616 in node.tags]
    capture = observe_entry_stack_pointer_capture_8616(
        codegen, source, scoped_context=scoped_context,
        scoped_caller_scope=scoped_caller_scope)
    allowed = ((capture.assignment,) if capture is not None else ()) + tuple(wrappers)
    if _has_unowned_sp(function.statements, allowed):
        return _outcome(len(sites), 0, CallStackInputFailure8616.UNOWNED_SP_USE)
    value_uses = call_stack_value_uses_8616(function.statements)
    plans, failure = _collect_plans_8616(
        codegen, source, nodes, sites, value_uses, scoped_context, scoped_caller_scope)
    if failure is not None:
        return _outcome(len(sites), len(plans), failure)
    if wrappers:
        valid = capture is not None and len(wrappers) == len(plans)
        if valid and capture is not None:
            valid = all(any(_existing_binding_is_current(codegen, function, wrapper, capture.value, plan.authority,
                                                         value_use=value_uses.get(id(wrapper), CallStackValueUse8616.UNKNOWN))
                            for wrapper in wrappers) for plan in plans)
        return _outcome(len(sites), len(plans), None if valid else CallStackInputFailure8616.INVALID_BINDING,
                        classified=len(plans))
    captured = prepare_entry_stack_pointer_capture_8616(
        codegen, source, tuple(plan.authority for plan in plans),
        scoped_context=scoped_context,
        scoped_caller_scope=scoped_caller_scope)
    if captured is None or captured.failure is not None or captured.value is None:
        return _outcome(len(sites), len(plans), CallStackInputFailure8616.ENTRY_CAPTURE, classified=len(plans))
    used = [node.variable.tmp_id for node in _iter_c_nodes_deep_8616(function.statements)
            if isinstance(node, c.CVariable) and isinstance(node.variable, SimTemporaryVariable)]
    used.extend(var.tmp_id for var in function.variables_in_use if isinstance(var, SimTemporaryVariable))
    locals_ = _Locals8616(codegen, function, max(used, default=-1) + 1)
    replacements = {id(plan.call): _materialize_context(codegen, function, plan, captured.value, locals_) for plan in plans}
    opaque_ids = {id(value) for value in replacements.values()}
    _replace_c_children_8616(function.statements, lambda node: replacements.get(id(node), node),
                           should_process_child=lambda node, _field: id(node) not in opaque_ids)
    function.refresh()
    return _outcome(len(sites), len(plans), changed=len(plans) + captured.changed_count)


def apply_call_stack_input_lowering_8616(
    codegen: object,
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> CallStackInputResult8616 | None:
    """Publish the real outcome and fail loudly for classified unmaterialized calls."""
    result = lower_call_stack_inputs_8616(
        codegen, scoped_context=scoped_context, scoped_caller_scope=scoped_caller_scope)
    cast(_CodegenBindings8616, codegen)._inertia_call_stack_input_lowering_8616 = result
    if result is not None and result.stats.classified_fact_count > 0 and result.stats.materialized_count == 0:
        raise PipelineHardError(layer="types:call_stack_inputs", message="Proved call inputs were not materialized", details=result.to_dict())
    return result
