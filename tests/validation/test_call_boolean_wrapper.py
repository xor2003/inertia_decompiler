"""Validation preserves exact identity and orientation across Boolean wrappers."""
from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CITE, CBinaryOp, CConstant, CFunctionCall, CUnaryOp
from angr.sim_type import SimTypeShort

from inertia.semantics.callsite_summary import bind_structured_callsite_identity_8616
from inertia.structuring.bound_call_condition import materialize_bound_call_condition_8616
from inertia.validation.tail_validation_fingerprint import _expr_fingerprint
from inertia.validation.validation_call_return_storage import direct_call_return_condition_projection_8616
from tests.validation.test_x86_16_validation_call_return_storage import (
    JCC_ADDR,
    RETURN_ADDR,
    _callee,
    _condition,
    _direct_summary,
    _surface,
)

pytestmark = pytest.mark.decompiler


def _case(arms=(0, 1), inverted=False):
    summary = _direct_summary()
    project, codegen = _surface(summaries=(summary,))
    callee = _callee()
    call = CFunctionCall(callee.name, callee, [CConstant(7, SimTypeShort(False), codegen=codegen)], codegen=codegen)
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries[id(call)] = summary
    expression = CITE(call, CConstant(arms[0], SimTypeShort(False), codegen=codegen),
                     CConstant(arms[1], SimTypeShort(False), codegen=codegen), codegen=codegen,
                     tags={'ins_addr': JCC_ADDR, 'vex_block_addr': RETURN_ADDR})
    if inverted:
        expression = CUnaryOp('Not', expression, codegen=codegen, tags=expression.tags)
    return project, codegen, call, expression


def _projection(project, codegen, expression):
    return direct_call_return_condition_projection_8616(
        project, codegen, jcc_addr=JCC_ADDR, block_addr=RETURN_ADDR,
        structured_condition=expression,
    )


@pytest.mark.parametrize('arms', [(0, 1), (1, 0)])
@pytest.mark.parametrize('inverted', [False, True])
def test_wrapper_projection_matches_production_materializer(arms, inverted):
    project, codegen, call, expression = _case(arms, inverted)
    before = _projection(project, codegen, expression)
    after_expression = materialize_bound_call_condition_8616(expression, call, _condition(), codegen)
    assert isinstance(after_expression, CBinaryOp)
    after = _projection(project, codegen, after_expression)
    assert before is not None and after is not None
    assert before == after
    assert before.comparison.value == ('CmpEQ' if (arms == (0, 1)) != inverted else 'CmpNE')
    assert after_expression.lhs is call and call.args[0].value == 7


@pytest.mark.parametrize('arms', [(0, 0), (1, 1), (2, 0), (0, 2)])
def test_nonboolean_wrapper_refuses_projection(arms):
    project, codegen, _call, expression = _case(arms)
    assert _projection(project, codegen, expression) is None


@pytest.mark.parametrize('mutation', ['unknown', 'different_callee', 'different_callsite'])
def test_wrapper_does_not_create_call_identity(mutation):
    project, codegen, call, expression = _case()
    summary = _direct_summary()
    if mutation == 'unknown':
        codegen._inertia_callsite_summaries.clear()
    elif mutation == 'different_callee':
        codegen._inertia_callsite_summaries[id(call)] = replace(summary, target_addr=0x3000)
    else:
        call.tags['ins_addr'] = summary.callsite_addr + 2
    assert _projection(project, codegen, expression) is None


def test_argument_difference_remains_visible_to_separate_effect_fingerprint():
    project, codegen, call, expression = _case()
    before = _projection(project, codegen, expression)
    before_call = _expr_fingerprint(call, project)
    project, codegen, call, expression = _case()
    call.args[0] = CConstant(9, SimTypeShort(False), codegen=codegen)
    after = _projection(project, codegen, expression)
    after_call = _expr_fingerprint(call, project)
    assert before is not None and before == after
    assert before_call != after_call


def test_effectful_arm_and_recursive_wrapper_refuse():
    project, codegen, call, expression = _case()
    expression.iftrue = call
    assert _projection(project, codegen, expression) is None
    recursive = CUnaryOp('Not', call, codegen=codegen)
    recursive.operand = recursive
    assert _projection(project, codegen, recursive) is None
