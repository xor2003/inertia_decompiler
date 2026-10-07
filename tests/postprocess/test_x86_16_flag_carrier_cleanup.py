"""Focused regressions for X86-16 structured flag-carrier cleanup."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.postprocess.flags_cleanup import (
    _c_expr_uses_var_8616,
    _rewrite_flag_bit_value_uses_8616,
)


class _FakeCodegen(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _constant(codegen: _FakeCodegen, value: int) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _register(
    codegen: _FakeCodegen,
    register_name: str,
    variable_name: str,
) -> structured_c.CVariable:
    register_offset = codegen.project.arch.registers[register_name][0]
    return structured_c.CVariable(
        SimRegisterVariable(register_offset, 2, name=variable_name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_flag_bit_rewrite_accepts_nested_redundant_one_bit_masks() -> None:
    codegen = _FakeCodegen()
    flags = _register(codegen, "flags", "flags_tmp")
    target = _register(codegen, "dx", "target_tmp")
    left = _register(codegen, "ax", "left")
    right = _register(codegen, "bx", "right")
    carry = structured_c.CBinaryOp("CmpLT", left, right, codegen=codegen)
    merged_flags = structured_c.CBinaryOp(
        "Or",
        structured_c.CBinaryOp("And", flags, _constant(codegen, 0xFFFE), codegen=codegen),
        structured_c.CBinaryOp(
            "Shl",
            structured_c.CBinaryOp("And", carry, _constant(codegen, 1), codegen=codegen),
            _constant(codegen, 0),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    shifted_flags = structured_c.CBinaryOp(
        "Shr",
        flags,
        _constant(codegen, 0),
        codegen=codegen,
    )
    nested_mask = structured_c.CBinaryOp(
        "And",
        structured_c.CBinaryOp(
            "And",
            _constant(codegen, 1),
            shifted_flags,
            codegen=codegen,
        ),
        _constant(codegen, 1),
        codegen=codegen,
    )
    use = structured_c.CAssignment(
        target,
        structured_c.CBinaryOp("Add", target, nested_mask, codegen=codegen),
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [structured_c.CAssignment(flags, merged_flags, codegen=codegen), use],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=statements)

    changed = _rewrite_flag_bit_value_uses_8616(codegen)

    assert changed is True
    assert _c_expr_uses_var_8616(use.rhs, flags) is False
    assert _c_expr_uses_var_8616(use.rhs, left) is True
    assert _c_expr_uses_var_8616(use.rhs, right) is True
