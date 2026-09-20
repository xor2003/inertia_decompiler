"""Result-zero validation must consume the exact arithmetic producer."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CFunctionCall
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.callsite_summary import bind_structured_callsite_identity_8616
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.condition_zero_input import project_register_zero_input_8616
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.validation_branch_conditions import _proven_call_return_condition_8616
from test_x86_16_call_return_conditions import _summary, _surface


@pytest.mark.parametrize("operation,constant", [("dec_reg16", 1), ("inc_reg16", 0xffff)])
@pytest.mark.parametrize("corruption", [None, "constant", "register", "width", "amount", "binding", "producer"])
def test_call_result_zero_requires_exact_producer(operation, constant, corruption):
    _, codegen, _ = _surface()
    summary = _summary()
    call = CFunctionCall("unlabelled", None, [], codegen=codegen)
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries = {id(call): summary}
    codegen.project = SimpleNamespace(arch=codegen.project.arch)
    fact = ConditionIR(
        "nonzero", IRValue(MemSpace.REG, name="ax", offset=8, size=2),
        width_bits=16, src_insn=0x100AC, block_addr=summary.return_addr,
        producer_insn=0x100AB, operand_bind_insn=0x100AC,
        producer_semantics=(operation, "ax", 1),
    )
    if corruption == "constant":
        constant = 0
    elif corruption == "register":
        fact = replace(fact, producer_semantics=(operation, "bx", 1))
    elif corruption == "width":
        fact = replace(fact, width_bits=32)
    elif corruption == "amount":
        fact = replace(fact, producer_semantics=(operation, "ax", 2))
    elif corruption == "binding":
        fact = replace(fact, operand_bind_insn=None)
    elif corruption == "producer":
        fact = replace(fact, producer_semantics=("opaque", "ax", 1))
    candidate = CBinaryOp("CmpNE", call, CConstant(constant, SimTypeShort(False), codegen=codegen), codegen=codegen)
    assert _proven_call_return_condition_8616(codegen, fact, candidate) is (corruption is None)


@pytest.mark.parametrize("operation,delta", [("inc_reg16", 1), ("dec_reg16", -1)])
@pytest.mark.parametrize("predicate", ["zero", "nonzero"])
def test_input_projection_matches_every_word_result(operation, delta, predicate):
    register = IRValue(MemSpace.REG, name="ax", offset=8, size=2)
    fact = ConditionIR(
        predicate, register, width_bits=16, src_insn=0x1235,
        producer_insn=0x1234, operand_bind_insn=0x1235,
        producer_semantics=(operation, "ax", 1),
    )
    projection = project_register_zero_input_8616(fact)
    assert projection is not None
    assert projection.register is register
    assert fact.producer_semantics == (operation, "ax", 1)
    for value in range(0x10000):
        result_is_zero = ((value + delta) & 0xffff) == 0
        input_matches = value == projection.constant
        assert result_is_zero == input_matches
