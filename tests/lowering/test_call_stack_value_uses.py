"""Distinguish required C values from discarded call results using actual syntax."""
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeNum

from inertia.lowering.c_ast_utils import CTraversalContractError8616, CTraversalFailure8616, iter_c_direct_children_8616
from inertia.lowering.call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
    call_stack_context_layout_8616,
)
from inertia.lowering.call_stack_inputs import lower_call_stack_inputs_8616
from inertia.lowering.call_stack_value_uses import CallStackValueUse8616, call_stack_value_uses_8616
from inertia.lowering.segmented_memory_lowering import materialize_runtime_helper_segment_carriers_8616
from inertia.pipeline.call_stack_input_outcome import CallStackInputFailure8616, CallStackInputStatus8616
from inertia.validation.validation_call_stack_inputs import validate_call_stack_inputs_8616
from tests.lowering.test_call_stack_inputs import _fixture, _wrapper


def test_segment_carrier_keeps_discarded_call_context() -> None:
    """An unrelated segment pass must retain the context's explicit no-value cast."""
    codegen, call = _fixture(returns_call_value=False)
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    call.callee_func.prototype = SimTypeFunction([], SimTypeBottom(label='void')).with_arch(codegen.project.arch)
    before = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert before.materialized_count == 1 and not before.issues
    changed = materialize_runtime_helper_segment_carriers_8616(codegen)
    after = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert after.materialized_count == 1 and not after.issues, after.issue_tokens()
    assert not changed


def test_missing_native_child_is_not_an_empty_expression() -> None:
    """Malformed native fields retain their precise cause instead of losing a use."""
    malformed = c.CUnaryOp.__new__(c.CUnaryOp)
    with pytest.raises(CTraversalContractError8616) as caught:
        tuple(iter_c_direct_children_8616(malformed))
    assert caught.value.reason is CTraversalFailure8616.CHILD_READ
    assert isinstance(caught.value.__cause__, AttributeError)


@pytest.mark.parametrize(('role', 'expected'), [
    ('statement', CallStackValueUse8616.DISCARDED),
    ('expression_statement', CallStackValueUse8616.DISCARDED),
    ('return', CallStackValueUse8616.VALUE),
    ('condition', CallStackValueUse8616.VALUE),
    ('switch_selector', CallStackValueUse8616.VALUE),
    ('switch_case', CallStackValueUse8616.DISCARDED),
    ('switch_default', CallStackValueUse8616.DISCARDED),
    ('loop_init', CallStackValueUse8616.DISCARDED),
    ('loop_condition', CallStackValueUse8616.VALUE),
    ('loop_step', CallStackValueUse8616.DISCARDED),
    ('loop_body', CallStackValueUse8616.DISCARDED),
    ('void_cast', CallStackValueUse8616.DISCARDED),
    ('multi_return', CallStackValueUse8616.VALUE),
    ('shared', CallStackValueUse8616.VALUE),
])
def test_structured_value_roles_preserve_required_occurrences(role, expected) -> None:
    """Conditions and shared value uses cannot be confused with statement positions."""
    codegen, call = _fixture()
    empty = c.CStatements([], codegen=codegen)
    constant = c.CConstant(1, SimTypeNum(16, False), codegen=codegen)
    if role == 'statement':
        root = c.CStatements([call], codegen=codegen)
    elif role == 'expression_statement':
        root = c.CExpressionStatement(call, codegen=codegen)
    elif role == 'return':
        root = c.CReturn(call, codegen=codegen)
    elif role == 'condition':
        root = c.CIfElse([(call, empty)], else_node=empty, codegen=codegen)
    elif role.startswith('switch_'):
        statement = c.CStatements([c.CExpressionStatement(call, codegen=codegen)], codegen=codegen)
        root = c.CSwitchCase(call if role == 'switch_selector' else constant,
            [(1, statement if role == 'switch_case' else empty)],
            statement if role == 'switch_default' else empty, codegen=codegen)
    elif role.startswith('loop_'):
        root = c.CForLoop(initializer=call if role == 'loop_init' else None,
            condition=call if role == 'loop_condition' else constant,
            iterator=call if role == 'loop_step' else None,
            body=call if role == 'loop_body' else empty, codegen=codegen)
    elif role == 'void_cast':
        root = c.CTypeCast(call.type, SimTypeBottom(label='void'), call, codegen=codegen)
    elif role == 'multi_return':
        root = c.CReturn(c.CMultiStatementExpression(c.CStatements([call], codegen=codegen),
                                                   call, codegen=codegen), codegen=codegen)
    else:
        root = c.CStatements([call, c.CReturn(call, codegen=codegen)], codegen=codegen)
    assert call_stack_value_uses_8616(root)[id(call)] is expected


@pytest.mark.parametrize('show_casts', [False, True])
def test_discarded_call_survives_void_prototype_refinement(tmp_path: Path, show_casts: bool) -> None:
    """A statement call keeps one invocation and never acquires a result use."""
    codegen, call = _fixture(returns_call_value=False)
    codegen.show_casts = show_casts
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    statement = codegen.cfunc.statements.statements[-2]
    assert isinstance(statement, c.CExpressionStatement)
    wrapper = statement.expr
    layout = call_stack_context_layout_8616(wrapper, value_use=CallStackValueUse8616.DISCARDED)
    assert layout is not None and layout.marker.result_tmp_id is None
    call.callee_func.prototype = SimTypeFunction([], SimTypeBottom(label='void')).with_arch(codegen.project.arch)
    stable = lower_call_stack_inputs_8616(codegen)
    assert stable is not None and stable.status is CallStackInputStatus8616.STABLE
    report = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert report.materialized_count == 1 and not report.issues
    declarations = '\n'.join(value.type.c_repr(name=value.c_repr())+';'
                             for value in codegen.cfunc.variables_in_use.values())
    text = '#include <stdint.h>\n#include <stdio.h>\nuint32_t inertia_esp=0x12348000;\n'
    text += 'unsigned calls=0, seen=0; void callee(void) { ++calls; seen=inertia_esp & 0xffff; }\n'
    category = f'_Static_assert(_Generic(({wrapper.c_repr()}), int:0, unsigned int:0, default:1), "discard category");'
    text += f'unsigned short caller(void) {{ {declarations}\n{category}\n{codegen.cfunc.statements.c_repr()}\n}}\n'
    text += 'int main(void) { unsigned value=caller(); printf("%u %u %u\\n",value,calls,seen); }\n'
    path = tmp_path/'discarded.c'
    path.write_text(text)
    compiled = subprocess.run(['gcc','-std=c11','-Werror','-O2',str(path),'-o',str(path.with_suffix(''))],
                              capture_output=True,text=True)
    assert compiled.returncode == 0, compiled.stderr+'\n'+text
    executed = subprocess.run([str(path.with_suffix(''))],capture_output=True,text=True)
    assert executed.returncode == 0, executed.stderr
    assert tuple(map(int,executed.stdout.split())) == (7,1,0x7ffe)


@pytest.mark.parametrize('void_callee', [False, True])
def test_marker_cannot_discard_a_live_result(void_callee: bool) -> None:
    """Even coherent void-shaped wrapper metadata must retain an outer value use."""
    codegen, call = _fixture()
    lower_call_stack_inputs_8616(codegen)
    if void_callee:
        call.callee_func.prototype = SimTypeFunction([], SimTypeBottom(label='void')).with_arch(codegen.project.arch)
    wrapper = _wrapper(codegen)
    marker = wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616]
    wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616] = replace(marker, result_tmp_id=None)
    wrapper.stmts.statements[1] = call
    word = SimTypeNum(32,False)
    wrapper.expr = c.CTypeCast(word,SimTypeBottom(label='void'),c.CConstant(0,word,codegen=codegen),codegen=codegen)
    report = validate_call_stack_inputs_8616(codegen,codegen.cfunc.statements)
    assert report.issues and report.materialized_count == 0


def test_void_call_cannot_supply_a_required_value() -> None:
    """A void declaration cannot authorize a synthetic scalar result or partial edits."""
    codegen, call = _fixture()
    call.callee_func.prototype = SimTypeFunction([], SimTypeBottom(label='void')).with_arch(codegen.project.arch)
    root = codegen.cfunc.statements
    variables = tuple(codegen.cfunc.variables_in_use)
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.REFUSED
    assert result.failure is CallStackInputFailure8616.TYPE_UNPROVEN
    assert codegen.cfunc.statements is root and tuple(codegen.cfunc.variables_in_use) == variables
