"""CITE operands remain observable when structuring exposes a comparison.

Layer: Tests.
Responsibility: preserve the observed storage domain across conditional expressions.
"""
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CFunctionCall,
    CIfElse,
    CStatements,
    CUnaryOp,
)

from inertia.validation import tail_validation as owner
from tests.validation.test_x86_16_tail_validation_micro_slices import (
    _codegen,
    _const,
    _DummyCodegen,
    _project,
    _reg,
    _stack,
)

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("jcc,producer,value,operation", [
    (0x1F11, 0x1F0E, 35, "CmpNE"), (0x1F23, 0x1F20, 35, "CmpEQ"),
    (0x1F3A, 0x1F37, 44, "CmpNE"), (0x1F4C, 0x1F49, 44, "CmpEQ"),
])
def test_cite_comparison_keeps_captured_eax_observed(jcc, producer, value, operation):
    """Actual MAIN carrier width/tags expose the missing CITE observation arm."""
    project, codegen = _project(), _DummyCodegen()
    carrier = _reg(project, "eax", codegen)
    assert carrier.variable.reg == 0 and carrier.variable.size == 4
    tags = {"ins_addr": jcc, "condition_producer_insn": producer}
    inner = CBinaryOp(operation, carrier, _const(value, codegen), codegen=codegen)
    condition = CITE(inner, _const(0, codegen), _const(1, codegen), codegen=codegen, tags=tags)
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], None, codegen=codegen, tags={"ins_addr": jcc})
    assignment = CAssignment(carrier, _const(value, codegen), codegen=codegen)
    _codegen([assignment, branch], codegen)
    before = owner.collect_x86_16_tail_validation_summary(project, codegen)
    inverse = "CmpEQ" if operation == "CmpNE" else "CmpNE"
    branch.condition_and_nodes[0] = (CBinaryOp(inverse, carrier, inner.rhs, codegen=codegen, tags=tags), branch.condition_and_nodes[0][1])
    after = owner.collect_x86_16_tail_validation_summary(project, codegen)
    assert before.register_writes == after.register_writes == ("reg:eax",)
    assert owner.compare_x86_16_tail_validation_summaries(before, after)["changed"] is False


def test_cite_observes_both_arms_call_arguments_and_address_exposure():
    project, codegen = _project(), _DummyCodegen()
    stack = _stack(-2, codegen)
    call = CFunctionCall("helper", None, [_reg(project, "ebx", codegen)], codegen=codegen)
    nested = CITE(_reg(project, "edx", codegen), call,
                  CUnaryOp("Reference", stack, codegen=codegen), codegen=codegen)
    condition = CITE(_reg(project, "eax", codegen), _reg(project, "ecx", codegen), nested, codegen=codegen)
    root = CIfElse([(condition, CStatements([], codegen=codegen))], None, codegen=codegen)
    observed = owner._collect_observed_locations(root, project, "live_out")
    stack_location = owner._location_fingerprint(stack, project)
    assert {"reg:eax", "reg:ebx", "reg:ecx", "reg:edx", stack_location} <= observed
    assert stack_location in observed.address_exposed_locations


def test_genuine_extra_write_inside_cite_domain_still_changes_summary():
    project, codegen = _project(), _DummyCodegen()
    register = _reg(project, "eax", codegen)
    condition = CITE(register, _const(1, codegen), _const(0, codegen), codegen=codegen)
    branch = CIfElse([(condition, CStatements([], codegen=codegen))], None, codegen=codegen)
    _codegen([branch], codegen)
    before = owner.collect_x86_16_tail_validation_summary(project, codegen)
    codegen.cfunc.body.statements.insert(0, CAssignment(register, _const(7, codegen), codegen=codegen))
    after = owner.collect_x86_16_tail_validation_summary(project, codegen)
    delta = owner.compare_x86_16_tail_validation_summaries(before, after)
    assert delta["changed"] is True
    assert delta["delta"]["register_writes"]["added"] == ("reg:eax",)
