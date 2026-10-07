"""Typed binary operands at the loop-update lowering boundary."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR, ConditionRegisterBindingIR, ConditionRegisterUpdateIR
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace

from inertia.structuring.condition_lowering import lower_ir_value_to_c_expr_8616
from inertia.structuring.loop_condition_materialization import (
    _materialize_bound_loop_register_update_8616,
)


def _lower(value):
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(project=project, cstyle_null_cmp=False,
                              next_node_idx=count().__next__, next_ident=lambda name: name)
    return lower_ir_value_to_c_expr_8616(value, project, codegen, resolve_register_name=True)


@pytest.mark.parametrize("operator,expected", (
    ("add", "Add"), ("and", "And"), ("or", "Or"),
    ("shr", "Shr"), ("sub", "Sub"), ("xor", "Xor"),
))
def test_binary_loop_update_rhs_uses_proven_operator(operator, expected):
    """Do not send binary IR values through the scalar .space interface."""
    left = IRValue(MemSpace.CONST, const=12, size=2)
    right = IRValue(MemSpace.CONST, const=3, size=2)
    result = _lower(IRBinaryValue(operator, left, right, size=2))
    assert isinstance(result, CBinaryOp)
    assert result.op == expected
    assert isinstance(result.lhs, CConstant) and result.lhs.value == 12
    assert isinstance(result.rhs, CConstant) and result.rhs.value == 3


def test_nested_binary_rhs_preserves_structure_and_refuses_unknown_operator():
    value = IRValue(MemSpace.CONST, const=3, size=2)
    nested = IRBinaryValue("sub", value, value, size=2)
    result = _lower(IRBinaryValue("add", value, nested, size=2))
    assert isinstance(result, CBinaryOp) and result.op == "Add"
    assert isinstance(result.rhs, CBinaryOp) and result.rhs.op == "Sub"
    assert _lower(IRBinaryValue("unknown", value, nested, size=2)) is None


def test_unsupported_update_does_not_rebind_initializer():
    """Refused binary RHS must not mutate existing register identities."""
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), cstyle_null_cmp=False,
                              next_node_idx=count().__next__, next_ident=lambda name: name)
    word = SimTypeShort(False).with_arch(arch)
    offset, size = arch.registers["bx"]
    original = SimRegisterVariable(offset, size, ident="original", name="bx", region=0x1000)
    target = CVariable(original, variable_type=word, codegen=codegen)
    zero = CConstant(0, word, codegen=codegen)
    initializer = CAssignment(target, zero, codegen=codegen, tags={"ins_addr": 0x1000})
    body = CStatements([], codegen=codegen)
    loop = CForLoop(None, zero, None, body, codegen=codegen)
    root = CStatements([initializer, loop], codegen=codegen)
    value = IRValue(MemSpace.REG, name="bx", size=2)
    update = ConditionRegisterUpdateIR(0x1010, "bx", "add", IRBinaryValue("unknown", value, value, size=2))
    condition = ConditionIR("eq", value, value, register_bindings=(ConditionRegisterBindingIR("bx", value, update),))
    result = _materialize_bound_loop_register_update_8616(root, loop, condition, codegen)
    assert not result.changed
    assert target.variable is original
    assert initializer.rhs is zero
    assert body.statements == []
