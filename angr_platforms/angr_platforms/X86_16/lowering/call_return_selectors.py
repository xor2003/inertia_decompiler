"""Bind proven scalar call returns to structured switch selectors.

Layer: Types/Lowering.
Responsibility: materialize one storage identity for an ABI-proven scalar call
return and its structured switch use after Structuring rebuilds the C AST.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This pass consumes typed callsite summaries and structured AST nodes only. It
does not infer calls from names or rendered C, recover switch shape, or relax
validation. A missing or interrupted dataflow path is an explicit refusal.

Dynamic boundary: angr structured-codegen nodes and codegen containers are
third-party surfaces, so narrowly scoped dynamic attribute access is required.
Owned callsite summaries and result contracts use typed dot access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteReturnShape8616, CallsiteSummary8616
from ..pipeline.errors import PipelineHardError
from .register_local_declarations import register_typed_register_local_8616

_WORD_RETURN_BYTES: int = 2

__all__ = [
    "CallReturnSelectorBindingResult8616",
    "bind_call_return_switch_selectors_8616",
    "is_scalar_ax_call_return_8616",
    "replay_call_return_switch_selectors_8616",
]


@dataclass(frozen=True, slots=True)
class CallReturnSelectorBindingResult8616:
    """Closed evidence counters for scalar call-return selector binding."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether this invocation changed a structured identity."""
        return self.changed_count > 0


@dataclass(frozen=True, slots=True)
class _RegisterView8616:
    """One physical register byte range exposed by structured codegen."""

    expression: structured_c.CExpression
    offset: int
    size: int


def is_scalar_ax_call_return_8616(summary: CallsiteSummary8616 | None) -> bool:
    """Require a used, proven scalar AX result; never narrow DX:AX or unknown returns."""
    return bool(
        summary is not None and summary.return_register == "ax"
        and summary.return_used is True and summary.return_shape == CallsiteReturnShape8616.AX.value
    )


def _register_cvar_8616(node: object) -> structured_c.CVariable | None:
    """Return a register-backed C variable through harmless C casts."""
    current = node
    while isinstance(current, structured_c.CTypeCast):
        current = current.expr
    if not isinstance(current, structured_c.CVariable):
        return None
    if not isinstance(current.variable, SimRegisterVariable):
        return None
    return current


def _register_view_8616(node: object) -> _RegisterView8616 | None:
    """Return a register view across variable-backed and raw AIL surfaces."""
    current = node
    while isinstance(current, structured_c.CTypeCast):
        current = current.expr
    if isinstance(current, structured_c.CVariable):
        variable = current.variable
        if isinstance(variable, SimRegisterVariable):
            return _RegisterView8616(current, variable.reg, variable.size)
        return None
    if isinstance(current, structured_c.CRegister):
        # Dynamic boundary: CRegister retains angr's AIL Register expression.
        register = current.reg
        offset = getattr(register, "reg_offset", None)
        size = getattr(register, "size", None)
        if isinstance(offset, int) and isinstance(size, int) and size > 0:
            return _RegisterView8616(current, offset, size)
    return None


def _same_register_view_8616(left: _RegisterView8616, right: _RegisterView8616) -> bool:
    """Return whether two C variables are the same physical register view."""
    return left.offset == right.offset and left.size == right.size


def _flatten_sequential_statements_8616(root: structured_c.CStatements) -> tuple[object, ...]:
    """Flatten only transparent nested statement lists in execution order."""
    flattened: list[object] = []
    for statement in root.statements:
        if isinstance(statement, structured_c.CStatements):
            flattened.extend(_flatten_sequential_statements_8616(statement))
        else:
            flattened.append(statement)
    return tuple(flattened)


def _statement_writes_register_view_8616(
    statement: object,
    register: _RegisterView8616,
) -> bool:
    """Return whether a statement overwrites the candidate register view."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = _register_view_8616(statement.lhs)
    return lhs is not None and _same_register_view_8616(lhs, register)


def _statement_contains_call_8616(statement: object) -> bool:
    """Return whether a structured statement contains any call."""
    return any(
        isinstance(node, structured_c.CFunctionCall)
        for node in _iter_c_nodes_deep_8616(statement)
    )


def _selector_after_call_8616(
    statements: tuple[object, ...],
    call_index: int,
    register: _RegisterView8616,
) -> tuple[structured_c.CSwitchCase, _RegisterView8616] | None:
    """Find the first uninterrupted switch read of one call-return register."""
    for statement in statements[call_index + 1 :]:
        if isinstance(statement, structured_c.CSwitchCase):
            selector = _register_view_8616(statement.switch)
            if selector is not None and _same_register_view_8616(selector, register):
                return statement, selector
            return None
        if _statement_writes_register_view_8616(statement, register):
            return None
        if _statement_contains_call_8616(statement):
            return None
        if not isinstance(
            statement,
            (structured_c.CAssignment, structured_c.CExpressionStatement),
        ):
            return None
    return None


def _structured_return_variable_8616(
    summary: CallsiteSummary8616,
    register: structured_c.CVariable,
    selector: _RegisterView8616,
    function_addr: int,
) -> SimRegisterVariable:
    """Reuse or build deterministic register-SSA identity from one exact callsite fact."""
    variable = register.variable
    assert isinstance(variable, SimRegisterVariable)
    name = (
        summary.return_register
        if isinstance(summary.return_register, str) and summary.return_register
        else variable.name
    )
    selector_variable = (
        selector.expression.variable
        if isinstance(selector.expression, structured_c.CVariable)
        else None
    )
    for candidate in (variable, selector_variable):
        if not isinstance(candidate, SimRegisterVariable):
            continue
        same_storage = candidate.reg == variable.reg and candidate.size == variable.size
        if (
            same_storage
            and candidate.ident == f"call-return-{summary.callsite_addr:x}"
            and candidate.name == name
            and candidate.region == function_addr
        ):
            return candidate
    return SimRegisterVariable(
        variable.reg,
        variable.size,
        ident=f"call-return-{summary.callsite_addr:x}",
        name=name,
        region=function_addr,
    )


def _bind_cvar_identity_8616(
    cvar: structured_c.CVariable,
    variable: SimRegisterVariable,
) -> bool:
    """Bind both C-variable views and report only a fresh identity mutation."""
    changed = False
    if cvar.variable is not variable:
        cvar.variable = variable
        changed = True
    if cvar.unified_variable is not variable:
        cvar.unified_variable = variable
        changed = True
    return changed


def _bind_switch_selector_identity_8616(
    switch: structured_c.CSwitchCase,
    selector: _RegisterView8616,
    register: structured_c.CVariable,
    variable: SimRegisterVariable,
) -> bool:
    """Bind or replace the switch selector with one call-return identity."""
    if isinstance(selector.expression, structured_c.CVariable):
        return _bind_cvar_identity_8616(selector.expression, variable)
    raw_selector = selector.expression
    tags = raw_selector.tags if isinstance(raw_selector, structured_c.CExpression) else None
    switch.switch = structured_c.CVariable(
        variable,
        unified_variable=variable,
        variable_type=register.variable_type,
        codegen=register.codegen,
        tags=tags,
    )
    return True


def bind_call_return_switch_selectors_8616(
    codegen: object,
) -> CallReturnSelectorBindingResult8616:
    """Bind exact used AX call returns to uninterrupted AX switch selectors.

    The call object must have an exact ``CallsiteSummary8616`` entry, its return
    shape must be the 16-bit AX view, and assignment-to-switch flow must contain
    no AX clobber, nested call, or control-flow boundary.
    """
    # Dynamic boundary: regenerated angr codegen trees need to call back into
    # this Lowering owner without importing its semantics into CLI.
    cast(Any, codegen)._inertia_call_return_selector_replayer_8616 = (
        replay_call_return_switch_selectors_8616
    )
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    function_addr = getattr(cfunc, "addr", None)
    raw_summaries = getattr(codegen, "_inertia_callsite_summaries", None)
    if (
        not isinstance(root, structured_c.CStatements)
        or not isinstance(function_addr, int)
        or not isinstance(raw_summaries, dict)
    ):
        return CallReturnSelectorBindingResult8616()

    summaries = {
        call_id: summary
        for call_id, summary in raw_summaries.items()
        if isinstance(call_id, int) and isinstance(summary, CallsiteSummary8616)
    }
    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    failure_count = 0
    changed_count = 0
    visited_calls: set[int] = set()

    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        statements = _flatten_sequential_statements_8616(node)
        for index, statement in enumerate(statements):
            if not isinstance(statement, structured_c.CAssignment):
                continue
            call = statement.rhs
            if not isinstance(call, structured_c.CFunctionCall) or id(call) in visited_calls:
                continue
            visited_calls.add(id(call))
            summary = summaries.get(id(call))
            if not is_scalar_ax_call_return_8616(summary):
                continue
            assert summary is not None
            raw_fact_count += 1
            register = _register_cvar_8616(statement.lhs)
            if register is None or register.variable.size != _WORD_RETURN_BYTES:
                failure_count += 1
                continue
            normalized_fact_count += 1
            register_view = _register_view_8616(register)
            selector_match = (
                _selector_after_call_8616(statements, index, register_view)
                if register_view is not None
                else None
            )
            if selector_match is None:
                failure_count += 1
                continue
            switch, selector = selector_match
            classified_fact_count += 1
            identity = _structured_return_variable_8616(summary, register, selector, function_addr)
            identity_changed = _bind_cvar_identity_8616(register, identity)
            identity_changed = (
                _bind_switch_selector_identity_8616(
                    switch,
                    selector,
                    register,
                    identity,
                )
                or identity_changed
            )
            identity_changed = register_typed_register_local_8616(codegen, register) or identity_changed
            materialized_count += 1
            changed_count += int(identity_changed)

    return CallReturnSelectorBindingResult8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        changed_count=changed_count,
    )


def replay_call_return_switch_selectors_8616(codegen: object) -> bool:
    """Replay selector identity at its Lowering owner after AST regeneration."""
    result = bind_call_return_switch_selectors_8616(codegen)
    if result.classified_fact_count > 0 and result.materialized_count == 0:
        raise PipelineHardError(
            "classified call-return switch selector was not materialized: "
            f"classified={result.classified_fact_count} "
            f"failures={result.failure_count}",
            layer="types/lowering:call_return_selectors",
        )
    cast(Any, codegen)._inertia_call_return_selector_binding_8616 = result
    return result.changed
