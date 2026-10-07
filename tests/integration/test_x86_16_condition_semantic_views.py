"""Refusal boundaries for validation-only semantic cast views."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace
from inertia.lowering.semantic_cast import CSemanticCast8616
from archinfo import ArchX86

from inertia.validation.validation_condition_identity import (
    condition_semantic_view_projection_fingerprint_8616,
)


def _candidate():
    arch = ArchX86()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), cstyle_null_cmp=False,
                              next_ident=lambda name: name, next_node_idx=count().__next__)
    source = SimTypeShort(False).with_arch(arch)
    destination = SimTypeShort(True).with_arch(arch)
    value = c.CConstant(1, source, codegen=codegen)
    view = CSemanticCast8616(source, destination, value, codegen=codegen)
    return c.CBinaryOp("CmpLT", view, view, codegen=codegen)


@pytest.mark.parametrize("side", ("lhs", "rhs"))
@pytest.mark.parametrize("operand", (
    None, object(), IRValue(MemSpace.REG, name="ax", size=0),
    IRValue(MemSpace.REG, name="ax", size=-1), IRValue(MemSpace.REG, name="al", size=1),
))
def test_missing_or_incompatible_operand_width_refuses(side, operand):
    """Missing width evidence must not crash or become cast equivalence."""
    good = IRValue(MemSpace.REG, name="ax", size=2)
    condition = ConditionIR("slt", operand if side == "lhs" else good,
                            operand if side == "rhs" else good)
    result = condition_semantic_view_projection_fingerprint_8616(
        condition, _candidate(), condition_fingerprint=lambda _value: "bits",
    )
    assert result is None


@pytest.mark.parametrize("binary", (False, True))
def test_exact_typed_value_width_accepts_view(binary):
    """Scalar and binary IR values retain their proven same-width bit view."""
    value = IRValue(MemSpace.REG, name="ax", size=2)
    operand = IRBinaryValue("Add", value, value, size=2) if binary else value
    result = condition_semantic_view_projection_fingerprint_8616(
        ConditionIR("slt", operand, operand), _candidate(),
        condition_fingerprint=lambda _value: "bits",
    )
    assert result == "CmpLT(bits,bits)"
