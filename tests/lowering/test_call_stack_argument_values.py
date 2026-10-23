"""Preserve C argument values while binding source-proved architectural SP.

These controls verify a local C transformation, not argument recovery from the
fixture binary. Native source positions remain independently authenticated.
"""
import subprocess
from enum import Enum
from pathlib import Path

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeArray, SimTypeFunction, SimTypeNum, SimTypePointer, SimTypeShort
from angr.sim_variable import SimTemporaryVariable

from inertia.lowering.call_stack_input_contracts import call_stack_context_layout_8616
from inertia.lowering.call_stack_inputs import lower_call_stack_inputs_8616
from inertia.pipeline.call_stack_input_outcome import CallStackInputFailure8616, CallStackInputStatus8616
from inertia.pipeline.structured_ast_output import observe_structured_ast_output_8616
from inertia.validation.validation_call_stack_inputs import validate_call_stack_inputs_8616
from tests.lowering.test_call_stack_inputs import _fixture, _wrapper


class ArgumentKind(Enum):
    """Original C argument value categories, including implicit conversions."""

    SCALAR = 'scalar'
    POINTER = 'pointer'
    ARRAY = 'array'
    UNBOUND_ARRAY = 'unbound_array'
    FUNCTION = 'function'


def _argument_fixture(kind: ArgumentKind):
    codegen, call = _fixture()
    arch = codegen.project.arch
    word = SimTypeShort(False).with_arch(arch)
    callback = SimTypeFunction([], word).with_arch(arch)
    type_ = word
    if kind is ArgumentKind.ARRAY:
        type_ = SimTypeArray(word, 3).with_arch(arch)
    elif kind is ArgumentKind.UNBOUND_ARRAY:
        type_ = SimTypeArray(SimTypeNum(16, False), 3)
    elif kind is ArgumentKind.FUNCTION:
        type_ = callback
    variable = SimTemporaryVariable(1000, 6 if kind in {ArgumentKind.ARRAY, ArgumentKind.UNBOUND_ARRAY} else 2)
    variable.name = 'argument'
    argument = c.CVariable(variable, variable_type=type_, codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = argument
    codegen.cfunc.variable_manager.set_variable_type(variable, type_)
    call.args = [c.CUnaryOp('Reference', argument, codegen=codegen)] if kind is ArgumentKind.POINTER else [argument]
    formal = word
    if kind in {ArgumentKind.POINTER, ArgumentKind.ARRAY, ArgumentKind.UNBOUND_ARRAY}:
        formal = SimTypePointer(word).with_arch(arch)
    elif kind is ArgumentKind.FUNCTION:
        formal = SimTypePointer(callback).with_arch(arch)
    call.callee_func.prototype = SimTypeFunction([formal], word).with_arch(arch)
    return codegen, call


def _compile_and_run(codegen, kind: ArgumentKind, path: Path) -> tuple[int, ...]:
    declarations = '\n'.join(value.type.c_repr(name=value.c_repr())+';'
                             for value in codegen.cfunc.variables_in_use.values())
    callback = ''
    if kind in {ArgumentKind.ARRAY, ArgumentKind.UNBOUND_ARRAY}:
        initialize, parameter, returned = 'argument[0]=11; argument[1]=17;', 'unsigned short *p', 'p[1]'
    elif kind is ArgumentKind.POINTER:
        initialize, parameter, returned = 'argument=17;', 'unsigned short *p', '*p'
    elif kind is ArgumentKind.FUNCTION:
        initialize, parameter, returned = '', 'unsigned short (*p)(void)', 'p()'
        callback = 'unsigned short argument(void) { return 17; }\n'
    else:
        initialize, parameter, returned = 'argument=17;', 'unsigned short p', 'p'
    text = '#include <stdint.h>\n#include <stdio.h>\nuint32_t inertia_esp=0x12348000;\n'
    text += 'unsigned calls=0, seen_sp=0;\n'+callback
    text += f'unsigned short callee({parameter}) {{ ++calls; seen_sp=inertia_esp & 0xffff; return {returned}; }}\n'
    text += f'unsigned short caller(void) {{ {declarations}\n{initialize}\n'
    text += codegen.cfunc.statements.c_repr()+'\n}\n'
    text += 'int main(void) { unsigned value=caller(); printf("%u %u %u %u\\n",value,calls,seen_sp,inertia_esp>>16); }\n'
    path.write_text(text)
    compiled = subprocess.run(['gcc', '-std=c99', '-Werror', '-O2', str(path), '-o', str(path.with_suffix(''))],
                              capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr+'\n'+text
    executed = subprocess.run([str(path.with_suffix(''))], capture_output=True, text=True)
    assert executed.returncode == 0, executed.stderr
    return tuple(map(int, executed.stdout.split()))


@pytest.mark.parametrize('kind', list(ArgumentKind))
def test_argument_value_conversion_survives_sp_binding(tmp_path: Path, kind: ArgumentKind) -> None:
    """Value, pointer, array and callback inputs keep their value and one call."""
    codegen, call = _argument_fixture(kind)
    assert _compile_and_run(codegen, kind, tmp_path/'before.c') == (18, 1, 0x8000, 0x1234)
    original = call.args[0]
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    layout = call_stack_context_layout_8616(_wrapper(codegen))
    assert layout is not None
    report = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert report.materialized_count == 1 and not report.issues
    assert _compile_and_run(codegen, kind, tmp_path/'after.c') == (18, 1, 0x7ffe, 0x1234)
    assert call.args[0] is not original
    if kind in {ArgumentKind.ARRAY, ArgumentKind.UNBOUND_ARRAY, ArgumentKind.FUNCTION}:
        assert isinstance(call.args[0].type, SimTypePointer)
    # Publish the same nodes through the real native function boundary as well.
    function = codegen.cfunc
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    codegen.cfunc = c.CFunction(0x1000, 'caller', SimTypeFunction([], word).with_arch(codegen.project.arch), [],
        function.statements, function.variables_in_use, function.variable_manager, codegen=codegen)
    observed = observe_structured_ast_output_8616(codegen)
    assert observed.complete and observed.snapshot is not None, observed


@pytest.mark.parametrize('kind', [ArgumentKind.ARRAY, ArgumentKind.FUNCTION])
def test_validator_rederives_argument_pointer_type(kind: ArgumentKind) -> None:
    """Matching producer declarations cannot authorize the wrong pointee type."""
    codegen, call = _argument_fixture(kind)
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    assert not validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements).issues
    assignment = _wrapper(codegen).stmts.statements[0]
    wrong_type = SimTypePointer(SimTypeShort(True)).with_arch(codegen.project.arch)
    wrong = c.CVariable(assignment.lhs.variable, variable_type=wrong_type, codegen=codegen)
    assignment.lhs = wrong
    call.args[0] = wrong
    codegen.cfunc.variables_in_use[wrong.variable] = wrong
    codegen.cfunc.variable_manager.set_variable_type(wrong.variable, wrong_type)
    report = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert report.issues and report.materialized_count == 0


@pytest.mark.parametrize('function_result', [False, True])
def test_non_value_call_result_refuses_before_allocating(function_result: bool) -> None:
    """A function or array is not a C return-value storage object."""
    codegen, call = _fixture()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    result_type = SimTypeFunction([], word) if function_result else SimTypeArray(word, 3)
    call.callee_func.prototype = SimTypeFunction([], result_type).with_arch(codegen.project.arch)
    root = codegen.cfunc.statements
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.REFUSED
    assert result.failure is CallStackInputFailure8616.TYPE_UNPROVEN
    assert result.stats.materialized_count == 0 and result.stats.classified_fact_count == 0
    assert result.stats.refusal_count == 1 and result.stats.failure_count == 0
    assert codegen.cfunc.statements is root and not codegen.cfunc.variables_in_use
