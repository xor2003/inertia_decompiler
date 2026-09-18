from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.call_return_selectors import (
    bind_call_return_switch_selectors_8616,
    is_scalar_ax_call_return_8616,
    replay_call_return_switch_selectors_8616,
)
from angr_platforms.X86_16.validation_dataflow import validate_structured_def_use_8616

FUNCTION_ADDR = 0x4010


def _codegen() -> SimpleNamespace:
    project = SimpleNamespace(arch=SimpleNamespace(bits=16, byte_width=8))
    indices: dict[str, int] = {}

    def next_idx(kind: str) -> int:
        index = indices.get(kind, 0)
        indices[kind] = index + 1
        return index

    return SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=FUNCTION_ADDR,
            statements=None,
            variables_in_use={},
            unified_local_vars={},
        ),
        next_idx=next_idx,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda: 0)


def _ax(codegen: SimpleNamespace, *, name: str = "ax") -> structured_c.CVariable:
    return structured_c.CVariable(
        SimRegisterVariable(0, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _call(codegen: SimpleNamespace) -> structured_c.CFunctionCall:
    return structured_c.CFunctionCall(
        "toupper",
        SimpleNamespace(addr=0x2048, name="toupper", block_addrs_set={0x2048}),
        [],
        codegen=codegen,
    )


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1048,
        target_addr=0x2048,
        return_addr=0x104B,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        return_shape="ax",
    )


@pytest.mark.parametrize("shape", ["ax", "dx_ax", None])
@pytest.mark.parametrize("used", [False, True])
def test_scalar_selector_requires_exact_return_width(shape, used):
    summary = replace(_summary(), return_shape=shape, return_used=used)
    assert is_scalar_ax_call_return_8616(summary) is (shape == "ax" and used)
    assert not is_scalar_ax_call_return_8616(None)


def test_call_return_selector_binding_materializes_one_structured_identity() -> None:
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen, name="ax_2"), call, codegen=codegen)
    intermediate = structured_c.CAssignment(
        structured_c.CVariable(
            SimRegisterVariable(18, 2, name="flags"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    switch = structured_c.CSwitchCase(_ax(codegen), [], None, codegen=codegen)
    root = structured_c.CStatements(
        [
            structured_c.CStatements([assignment], codegen=codegen),
            intermediate,
            switch,
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = root
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assert result.changed_count == 1
    assert result.changed
    assignment_variable = assignment.lhs.variable
    selector_variable = switch.switch.variable
    assert assignment_variable is selector_variable
    assert assignment_variable.ident == "call-return-1048"
    assert assignment_variable.name == "ax"
    assert assignment_variable.region == FUNCTION_ADDR
    assert codegen.cfunc.variables_in_use[assignment_variable] is assignment.lhs
    assert codegen.cfunc.unified_local_vars[assignment_variable] == {
        (assignment.lhs, assignment.lhs.variable_type)
    }
    assert codegen._inertia_call_return_selector_replayer_8616 is replay_call_return_switch_selectors_8616
    assert validate_structured_def_use_8616(root).passed

    repeated = bind_call_return_switch_selectors_8616(codegen)

    assert repeated.materialized_count == 1
    assert repeated.failure_count == 0
    assert repeated.changed_count == 0
    assert not repeated.changed
    assert assignment.lhs.variable is assignment_variable
    assert switch.switch.variable is assignment_variable
    assert codegen.cfunc.variables_in_use == {assignment_variable: assignment.lhs}
    assert codegen.cfunc.unified_local_vars == {
        assignment_variable: {(assignment.lhs, assignment.lhs.variable_type)}
    }


def test_call_return_selector_binding_refuses_intervening_ax_clobber() -> None:
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen), call, codegen=codegen)
    clobber = structured_c.CAssignment(
        _ax(codegen),
        structured_c.CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    switch = structured_c.CSwitchCase(_ax(codegen), [], None, codegen=codegen)
    root = structured_c.CStatements([assignment, clobber, switch], codegen=codegen)
    codegen.cfunc.statements = root
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 0
    assert result.materialized_count == 0
    assert result.failure_count == 1
    assert result.changed_count == 0
    assert assignment.lhs.variable.ident is None
    assert switch.switch.variable.ident is None


def test_call_return_selector_binding_refuses_unproven_return_shape() -> None:
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen), call, codegen=codegen)
    switch = structured_c.CSwitchCase(_ax(codegen), [], None, codegen=codegen)
    root = structured_c.CStatements([assignment, switch], codegen=codegen)
    codegen.cfunc.statements = root
    summary = _summary()
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=summary.callsite_addr,
            target_addr=summary.target_addr,
            return_addr=summary.return_addr,
            kind=summary.kind,
            arg_count=summary.arg_count,
            arg_widths=summary.arg_widths,
            stack_cleanup=summary.stack_cleanup,
            return_register=summary.return_register,
            return_used=summary.return_used,
            return_shape=None,
        )
    }

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 0
    assert result.materialized_count == 0
    assert result.changed_count == 0
    assert assignment.lhs.variable.ident is None
    assert switch.switch.variable.ident is None


def test_call_return_selector_binding_materializes_raw_ail_register_selector() -> None:
    """Join Structuring's raw AIL switch register to the typed AX call return."""
    codegen = _codegen()
    call = _call(codegen)
    assignment = structured_c.CAssignment(_ax(codegen, name="ax_2"), call, codegen=codegen)
    raw_selector = structured_c.CRegister(
        Expr.Register(None, 0, 16, reg_name="ax"),
        codegen=codegen,
    )
    switch = structured_c.CSwitchCase(raw_selector, [], None, codegen=codegen)
    root = structured_c.CStatements([assignment, switch], codegen=codegen)
    codegen.cfunc.statements = root
    codegen._inertia_callsite_summaries = {id(call): _summary()}

    result = bind_call_return_switch_selectors_8616(codegen)

    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assert result.changed_count == 1
    assert isinstance(switch.switch, structured_c.CVariable)
    assert switch.switch.variable is assignment.lhs.variable
    assert switch.switch.name == "ax"
    assert codegen.cfunc.variables_in_use[assignment.lhs.variable] is assignment.lhs
    assert validate_structured_def_use_8616(root).passed
