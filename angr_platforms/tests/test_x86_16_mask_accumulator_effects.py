"""Require whole-body mask reconstruction to preserve unrelated storage."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CFunctionCall, CReturn, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.structuring.return_chains import (
    MaskAccumulatorMaterializationCallbacks8616,
    materialize_cfg_mask_accumulator_8616,
)
from test_x86_16_structuring_return_chains import _const, _DummyCodegen


@pytest.mark.parametrize("extra", ["stack", "runtime", "unknown", "call", "same-offset", None])
def test_mask_reconstruction_does_not_discard_unconsumed_storage(extra):
    codegen = _DummyCodegen()
    mask = CVariable(SimStackVariable(-2, 2, base="bp", name="mask"),
                     variable_type=SimTypeShort(False), codegen=codegen)
    statements = [CAssignment(mask, _const(0, codegen), codegen=codegen)]
    if extra is not None:
        value = _const(7, codegen)
        if extra == "call":
            target = mask
            value = CFunctionCall(_const(0x2000, codegen), None, [], codegen=codegen)
        elif extra == "unknown":
            target = _const(1, codegen)
        else:
            offset = -2 if extra == "same-offset" else -4
            variable = (SimStackVariable(offset, 2, base="bp") if extra in {"stack", "same-offset"}
                        else SimMemoryVariable(0x10010, 4, name="inertia_esi"))
            target = CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
        statements.append(CAssignment(target, value, codegen=codegen))
    statements.append(CReturn(mask, codegen=codegen))
    original = CStatements(statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=original)
    callbacks = MaskAccumulatorMaterializationCallbacks8616(
        first_stack_zero_init=lambda *_: -2,
        ordered_mask_update_pairs=lambda *_: [(_const(1, codegen), 1), (_const(2, codegen), 2)],
        stack_slot_expr=lambda *_: mask,
        expr_fingerprint=lambda *_: "condition",
    )

    changed = materialize_cfg_mask_accumulator_8616(object(), codegen, callbacks)

    assert changed is (extra is None)
    if extra is not None:
        assert codegen.cfunc.statements is original
