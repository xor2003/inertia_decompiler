from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.widening.widening_copyprop_8616 import (
    _widening_copy_propagation_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def test_widening_copyprop_rewrites_register_copy_in_return_expression() -> None:
    codegen = _Codegen()
    source = CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(0, 2, name="v5"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(carrier, source, codegen=codegen)
    returned = CReturn(
        CBinaryOp(
            "Add",
            carrier,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    assignments = CStatements([copy], codegen=codegen)
    terminal = CStatements([returned], codegen=codegen)
    root = CStatements([assignments, terminal], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed
    assert isinstance(returned.retval, CBinaryOp)
    assert isinstance(returned.retval.lhs, CVariable)
    assert returned.retval.lhs is not source
    assert returned.retval.lhs.variable is source.variable
    assert returned.retval.lhs.variable.offset == source.variable.offset


def test_widening_copyprop_refuses_initializer_after_conditional_update() -> None:
    codegen = _Codegen()
    mask_variable = SimStackVariable(-4, 2, base="bp", name="mask", region=0x1000)
    mask = CVariable(mask_variable, variable_type=SimTypeShort(False), codegen=codegen)
    initializer = CAssignment(
        mask,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    update = CAssignment(
        mask,
        CBinaryOp(
            "Or",
            mask,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    branch = CIfElse(
        [(CConstant(1, SimTypeShort(False), codegen=codegen), CStatements([update], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    returned = CReturn(mask, codegen=codegen)
    root = CStatements([initializer, branch, returned], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)

    _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert returned.retval is mask
