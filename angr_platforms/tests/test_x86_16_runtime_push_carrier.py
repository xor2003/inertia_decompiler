"""Preserve numeric SP observations while consuming materialized PUSH state."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_expr_8616
from angr_platforms.X86_16.lowering.real_mode_linear import prune_consumed_call_push_stack_assignments_8616
from angr_platforms.X86_16.lowering.runtime_push_carrier import (
    RuntimePushCarrierVerdict8616,
    classify_runtime_push_carrier_8616,
)
from test_x86_16_call_argument_carrier_liveness import _Codegen, _push_function


@pytest.mark.parametrize("wrapped", [False, True])
def test_consumed_push_accepts_unobserved_runtime_sp_projection(wrapped):
    codegen = _Codegen()
    push_addr = 0x4016
    state = runtime_gp_state_expr_8616("esp", codegen=codegen, function_addr=0x4010)
    argument = CConstant(21, SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(state, argument, tags={"ins_addr": push_addr}, codegen=codegen)
    result = CReturn(argument, codegen=codegen)
    codegen.cfunc.statements.statements[:] = [assignment, result]
    if wrapped:
        codegen.cfunc.statements.statements[:] = [CStatements([assignment, result], codegen=codegen)]

    assert prune_consumed_call_push_stack_assignments_8616(
        codegen.project, codegen, frozenset({push_addr}),
        materialized_args_by_push_instruction_addr={push_addr: (argument,)},
        function=_push_function(push_addr),
    )
    statements = codegen.cfunc.statements.statements
    assert (statements[0].statements if wrapped else statements) == [result]


@pytest.mark.parametrize("observer", ["return", "argument", "branch", "loop", "nested", "missing_args"])
def test_runtime_push_refuses_observed_or_uncertain_state(observer):
    codegen = _Codegen()
    state = runtime_gp_state_expr_8616("esp", codegen=codegen, function_addr=0x4010)
    value = CConstant(21, SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(state, value, tags={"ins_addr": 0x4016}, codegen=codegen)
    observed = CReturn(state, codegen=codegen)
    root = codegen.cfunc.statements
    root.statements[:] = [assignment]
    arguments = (value,)
    if observer == "return":
        root.statements.append(observed)
    elif observer == "argument":
        arguments = (state,)
    elif observer == "branch":
        root.statements.append(CIfElse([(value, observed)], codegen=codegen))
    elif observer == "loop":
        root.statements.append(CWhileLoop(value, CStatements([], codegen=codegen), codegen=codegen))
    elif observer == "nested":
        root.statements[:] = [CIfElse([(value, CStatements([assignment], codegen=codegen))], codegen=codegen)]
    else:
        arguments = ()
    verdict = classify_runtime_push_carrier_8616(root, assignment, arguments, sp_offset=codegen.project.arch.registers["sp"][0])
    assert verdict in {RuntimePushCarrierVerdict8616.OBSERVED, RuntimePushCarrierVerdict8616.UNKNOWN_REFUSE}


def test_runtime_push_allows_prior_read_but_refuses_later_call_argument():
    codegen = _Codegen()
    state = runtime_gp_state_expr_8616("esp", codegen=codegen, function_addr=0x4010)
    value = CConstant(21, SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(state, value, codegen=codegen)
    call = CExpressionStatement(CFunctionCall("observer", None, [state], codegen=codegen), codegen=codegen)
    root = codegen.cfunc.statements
    root.statements[:] = [call, assignment]
    kwargs = {"sp_offset": codegen.project.arch.registers["sp"][0]}
    assert classify_runtime_push_carrier_8616(root, assignment, (value,), **kwargs) is RuntimePushCarrierVerdict8616.UNOBSERVED
    root.statements[:] = [assignment, call]
    assert classify_runtime_push_carrier_8616(root, assignment, (value,), **kwargs) is RuntimePushCarrierVerdict8616.OBSERVED
