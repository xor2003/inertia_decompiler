"""Exact Boolean call wrappers retain one call and publish branch ownership."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CITE, CBinaryOp, CConstant, CFunctionCall, CUnaryOp
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr_platforms.X86_16.callsite_summary import bind_structured_callsite_identity_8616
from angr_platforms.X86_16.structuring.bound_call_condition import materialize_bound_call_condition_8616
from angr_platforms.X86_16.structuring.call_return_conditions import (
    _target_calls_8616,
    materialize_call_return_conditions_8616,
)
from test_x86_16_call_return_conditions import _condition, _summary, _surface

_GUARD_ARGUMENT = 104


@pytest.mark.parametrize("target_kind", ["constant", "integer", "tag", "name_only", "conflict"])
@pytest.mark.parametrize("rebased", [False, True])
def test_numeric_call_target_survives_detached_callee(target_kind, rebased):
    project, codegen, _ = _surface()
    address = _summary().target_addr
    target = address
    if rebased:
        project = SimpleNamespace(
            _inertia_original_project=project,
            _inertia_original_linear_delta=0xf000,
        )
        target -= 0xf000
    callee_target = "unnamed"
    tags = {}
    if target_kind == "constant":
        callee_target = CConstant(target, SimTypeShort(False), codegen=codegen)
    elif target_kind == "integer":
        callee_target = target
    elif target_kind == "tag":
        tags["inertia_target_addr_8616"] = address
    elif target_kind == "conflict":
        callee_target = CConstant(target, SimTypeShort(False), codegen=codegen)
        tags["inertia_target_addr_8616"] = address + 2
    argument = CConstant(_GUARD_ARGUMENT, SimTypeShort(False), codegen=codegen)
    call = CFunctionCall(callee_target, None, [argument], codegen=codegen, tags=tags)
    matches = _target_calls_8616(project, call, address)
    assert matches == (() if target_kind in {"name_only", "conflict"} else (call,))
    assert call.args == [argument]


@pytest.mark.parametrize("target_kind", ["callee", "constant", "tag"])
@pytest.mark.parametrize("inverted", [False, True])
def test_bound_call_boolean_wrapper_gets_exact_owned_zero_test(inverted, target_kind):
    project, codegen, branch = _surface()
    project.kb.functions.function(addr=0x10010, create=False).prototype_libname = None
    project.kb.functions.function(addr=0x10010, create=False).prototype = SimTypeFunction(
        [], SimTypeShort(False),
    ).with_arch(project.arch)
    original, body = branch.condition_and_nodes[0]
    call = CFunctionCall("sub_10010", project.kb.functions.function(addr=0x10010, create=False),
                         [CConstant(_GUARD_ARGUMENT, SimTypeShort(False), codegen=codegen)], codegen=codegen)
    if target_kind != "callee":
        call.callee_func = None
        if target_kind == "constant":
            call.callee_target = CConstant(_summary().target_addr, SimTypeShort(False), codegen=codegen)
        else:
            call.tags["inertia_target_addr_8616"] = _summary().target_addr
    bind_structured_callsite_identity_8616(call, _summary())
    expression = CITE(call, CConstant(0, SimTypeShort(False), codegen=codegen),
                     CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen,
                     tags=original.tags)
    if not inverted:
        expression = CUnaryOp("Not", expression, codegen=codegen, tags=original.tags)
    branch.condition_and_nodes = [(expression, body)]
    materialize_call_return_conditions_8616(project, codegen)
    condition = branch.condition_and_nodes[0][0]
    assert isinstance(condition, CBinaryOp)
    assert condition.op == ("CmpEQ" if inverted else "CmpNE")
    assert condition.lhs is call
    assert call.args[0].value == _GUARD_ARGUMENT
    assert condition.tags["inertia_structuring_condition_cfg_materialized_8616"] is True
    assert not materialize_call_return_conditions_8616(project, codegen)


@pytest.mark.parametrize("outcomes", [(0, 0), (1, 1), (2, 0), (0, 2)])
def test_non_boolean_call_wrapper_is_not_published(outcomes):
    _, codegen, _ = _surface()
    call = CFunctionCall("unknown", None, [], codegen=codegen)
    expression = CITE(call, CConstant(outcomes[0], SimTypeShort(False), codegen=codegen),
                     CConstant(outcomes[1], SimTypeShort(False), codegen=codegen), codegen=codegen)
    assert materialize_bound_call_condition_8616(expression, call, _condition(), codegen) is expression
    assert not expression.tags.get("inertia_structuring_condition_cfg_materialized_8616")


@pytest.mark.parametrize("value", [1, 0xffff])
@pytest.mark.parametrize("inverted", [False, True])
def test_bound_call_constant_wrapper_preserves_comparison(value, inverted):
    _, codegen, _ = _surface()
    call = CFunctionCall("unknown", None, [], codegen=codegen)
    constant = CConstant(value, SimTypeShort(False), codegen=codegen)
    comparison = CBinaryOp("CmpNE", call, constant, codegen=codegen)
    wrapper = CITE(comparison, CConstant(0, SimTypeShort(False), codegen=codegen),
                   CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    if not inverted:
        wrapper = CUnaryOp("Not", wrapper, codegen=codegen)
    fact = _condition()
    fact = replace(fact, rhs=replace(fact.rhs, const=value))
    result = materialize_bound_call_condition_8616(wrapper, call, fact, codegen)
    assert isinstance(result, CBinaryOp)
    assert result.op == ("CmpEQ" if inverted else "CmpNE")
    assert result.lhs is call
    assert result.rhs is constant
    assert result.tags["inertia_structuring_condition_cfg_materialized_8616"] is True
