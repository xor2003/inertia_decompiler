"""Exact Boolean call wrappers retain one call and publish branch ownership."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CITE, CBinaryOp, CConstant, CFunctionCall, CUnaryOp
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr_platforms.X86_16.callsite_summary import bind_structured_callsite_identity_8616
from angr_platforms.X86_16.structuring.bound_call_condition import materialize_bound_call_condition_8616
from angr_platforms.X86_16.structuring.call_return_conditions import materialize_call_return_conditions_8616
from test_x86_16_call_return_conditions import _condition, _summary, _surface

_GUARD_ARGUMENT = 104


@pytest.mark.parametrize("inverted", [False, True])
def test_bound_call_boolean_wrapper_gets_exact_owned_zero_test(inverted):
    project, codegen, branch = _surface()
    project.kb.functions.function(addr=0x10010, create=False).prototype_libname = None
    project.kb.functions.function(addr=0x10010, create=False).prototype = SimTypeFunction(
        [], SimTypeShort(False),
    ).with_arch(project.arch)
    original, body = branch.condition_and_nodes[0]
    call = CFunctionCall("sub_10010", project.kb.functions.function(addr=0x10010, create=False),
                         [CConstant(_GUARD_ARGUMENT, SimTypeShort(False), codegen=codegen)], codegen=codegen)
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
