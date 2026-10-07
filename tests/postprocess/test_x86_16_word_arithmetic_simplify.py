from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_simplify import _simplify_structured_expressions_8616


class _FakeCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _cvar(variable, codegen, ty=None):
    return structured_c.CVariable(variable, variable_type=ty or SimTypeShort(False), codegen=codegen)


def _const(value: int, codegen):
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def test_stack_word_arithmetic_update_consumes_byte_carrier_pair() -> None:
    codegen = _FakeCodegen()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_alias_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_hi_var = SimStackVariable(-1, 1, base="bp", name="total_hi", region=0x1000)
    total_hi_alias_var = SimStackVariable(-1, 1, base="bp", name="total_hi", region=0x1000)
    x_var = SimStackVariable(4, 2, base="bp", name="x", region=0x1000)
    tmp_low_var = SimRegisterVariable(0x20, 2, name="tmp_23")
    tmp_high_var = SimRegisterVariable(0x22, 2, name="tmp_25")
    tmp_delta_var = SimRegisterVariable(0x24, 2, name="vvar_3")

    total = _cvar(total_var, codegen)
    total_alias = _cvar(total_alias_var, codegen)
    total_hi = _cvar(total_hi_var, codegen, SimTypeChar())
    total_hi_alias = _cvar(total_hi_alias_var, codegen, SimTypeChar())
    x = _cvar(x_var, codegen)
    tmp_low = _cvar(tmp_low_var, codegen)
    tmp_high = _cvar(tmp_high_var, codegen)
    tmp_delta = _cvar(tmp_delta_var, codegen)

    joined = structured_c.CBinaryOp(
        "Or",
        tmp_low,
        structured_c.CBinaryOp("Shl", tmp_high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    update = structured_c.CBinaryOp("Add", joined, tmp_delta, codegen=codegen)
    high_update = structured_c.CBinaryOp("Shr", update, _const(8, codegen), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(tmp_delta, x, codegen=codegen),
                structured_c.CAssignment(tmp_low, total_alias, codegen=codegen),
                structured_c.CAssignment(tmp_high, total_hi_alias, codegen=codegen),
                structured_c.CAssignment(total, update, codegen=codegen),
                structured_c.CAssignment(total_hi, high_update, codegen=codegen),
            ],
            codegen=codegen,
        )
    )

    assert _simplify_structured_expressions_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 1
    rewritten = statements[0]
    assert rewritten.lhs is total
    assert isinstance(rewritten.rhs, structured_c.CBinaryOp)
    assert rewritten.rhs.op == "Add"
    assert rewritten.rhs.lhs is total
    assert rewritten.rhs.rhs is x
    assert codegen._inertia_word_arithmetic_update_materialized_count == 1


def test_duplicate_word_arithmetic_shift_consumes_copy_aliases() -> None:
    codegen = _FakeCodegen()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_alias_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    x_var = SimStackVariable(4, 2, base="bp", name="x", region=0x1000)
    tmp_low_var = SimRegisterVariable(0x20, 2, name="tmp_23")
    tmp_high_var = SimRegisterVariable(0x22, 2, name="tmp_25")

    total = _cvar(total_var, codegen)
    total_alias = _cvar(total_alias_var, codegen)
    x = _cvar(x_var, codegen)
    tmp_low = _cvar(tmp_low_var, codegen)
    tmp_high = _cvar(tmp_high_var, codegen)

    joined = structured_c.CBinaryOp(
        "Or",
        tmp_low,
        structured_c.CBinaryOp("Shl", tmp_high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    update = structured_c.CBinaryOp("Add", joined, x, codegen=codegen)
    shifted_update = structured_c.CBinaryOp("Shr", update, _const(8, codegen), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(tmp_low, total_alias, codegen=codegen),
                structured_c.CAssignment(tmp_high, total_alias, codegen=codegen),
                structured_c.CAssignment(total, shifted_update, codegen=codegen),
            ],
            codegen=codegen,
        )
    )

    assert _simplify_structured_expressions_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 1
    rewritten = statements[0]
    assert rewritten.lhs is total
    assert isinstance(rewritten.rhs, structured_c.CBinaryOp)
    assert rewritten.rhs.op == "Add"
    assert rewritten.rhs.lhs is total
    assert rewritten.rhs.rhs is x
    assert codegen._inertia_word_arithmetic_shift_materialized_count == 1


def test_stack_word_arithmetic_update_resolves_structural_dirty_delta_alias() -> None:
    codegen = _FakeCodegen()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_alias_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_hi_var = SimStackVariable(-1, 1, base="bp", name="total_hi", region=0x1000)
    total_hi_alias_var = SimStackVariable(-1, 1, base="bp", name="total_hi", region=0x1000)
    x_var = SimStackVariable(4, 2, base="bp", name="x", region=0x1000)
    tmp_low_var = SimRegisterVariable(0x20, 2, name="tmp_23")
    tmp_high_var = SimRegisterVariable(0x22, 2, name="tmp_25")

    total = _cvar(total_var, codegen)
    total_alias = _cvar(total_alias_var, codegen)
    total_hi = _cvar(total_hi_var, codegen, SimTypeChar())
    total_hi_alias = _cvar(total_hi_alias_var, codegen, SimTypeChar())
    x = _cvar(x_var, codegen)
    tmp_low = _cvar(tmp_low_var, codegen)
    tmp_high = _cvar(tmp_high_var, codegen)
    dirty_def = structured_c.CDirtyExpression(
        SimpleNamespace(varid=13, name="vvar_13", reg=0, bits=16),
        codegen=codegen,
    )
    dirty_low = structured_c.CDirtyExpression(
        SimpleNamespace(varid=3, name="vvar_3", reg=0, bits=16),
        codegen=codegen,
    )
    dirty_high = structured_c.CDirtyExpression(
        SimpleNamespace(varid=3, name="vvar_3", reg=0, bits=16),
        codegen=codegen,
    )

    joined_a = structured_c.CBinaryOp(
        "Or",
        tmp_low,
        structured_c.CBinaryOp("Shl", tmp_high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    joined_b = structured_c.CBinaryOp(
        "Or",
        tmp_low,
        structured_c.CBinaryOp("Shl", tmp_high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    update_low = structured_c.CBinaryOp("Add", joined_a, dirty_low, codegen=codegen)
    update_high = structured_c.CBinaryOp("Add", dirty_high, joined_b, codegen=codegen)
    high_update = structured_c.CBinaryOp("Shr", update_high, _const(8, codegen), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(dirty_def, x, codegen=codegen),
                structured_c.CAssignment(tmp_low, total_alias, codegen=codegen),
                structured_c.CAssignment(tmp_high, total_hi_alias, codegen=codegen),
                structured_c.CAssignment(total, update_low, codegen=codegen),
                structured_c.CAssignment(total_hi, high_update, codegen=codegen),
            ],
            codegen=codegen,
        )
    )

    assert _simplify_structured_expressions_8616(codegen) is True

    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 1
    rewritten = statements[0]
    assert rewritten.lhs is total
    assert isinstance(rewritten.rhs, structured_c.CBinaryOp)
    assert rewritten.rhs.op == "Add"
    assert rewritten.rhs.lhs is total
    assert rewritten.rhs.rhs is x
    assert codegen._inertia_word_arithmetic_update_materialized_count == 1


def test_stack_word_arithmetic_update_refuses_unresolved_dirty_delta() -> None:
    codegen = _FakeCodegen()
    total_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_alias_var = SimStackVariable(-2, 2, base="bp", name="total", region=0x1000)
    total_hi_var = SimStackVariable(-1, 1, base="bp", name="total_hi", region=0x1000)
    total_hi_alias_var = SimStackVariable(-1, 1, base="bp", name="total_hi", region=0x1000)
    tmp_low_var = SimRegisterVariable(0x20, 2, name="tmp_23")
    tmp_high_var = SimRegisterVariable(0x22, 2, name="tmp_25")

    total = _cvar(total_var, codegen)
    total_alias = _cvar(total_alias_var, codegen)
    total_hi = _cvar(total_hi_var, codegen, SimTypeChar())
    total_hi_alias = _cvar(total_hi_alias_var, codegen, SimTypeChar())
    tmp_low = _cvar(tmp_low_var, codegen)
    tmp_high = _cvar(tmp_high_var, codegen)
    dirty_low = structured_c.CDirtyExpression(SimpleNamespace(varid=13, name="vvar_3"), codegen=codegen)
    dirty_high = structured_c.CDirtyExpression(SimpleNamespace(varid=13, name="vvar_3"), codegen=codegen)

    joined_a = structured_c.CBinaryOp(
        "Or",
        tmp_low,
        structured_c.CBinaryOp("Shl", tmp_high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    joined_b = structured_c.CBinaryOp(
        "Or",
        tmp_low,
        structured_c.CBinaryOp("Shl", tmp_high, _const(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    update_low = structured_c.CBinaryOp("Add", joined_a, dirty_low, codegen=codegen)
    update_high = structured_c.CBinaryOp("Add", dirty_high, joined_b, codegen=codegen)
    high_update = structured_c.CBinaryOp("Shr", update_high, _const(8, codegen), codegen=codegen)

    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [
                structured_c.CAssignment(tmp_low, total_alias, codegen=codegen),
                structured_c.CAssignment(tmp_high, total_hi_alias, codegen=codegen),
                structured_c.CAssignment(total, update_low, codegen=codegen),
                structured_c.CAssignment(total_hi, high_update, codegen=codegen),
            ],
            codegen=codegen,
        )
    )

    _simplify_structured_expressions_8616(codegen)

    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 2
    assert int(getattr(codegen, "_inertia_word_arithmetic_update_materialized_count", 0) or 0) == 0
    assert statements[0].lhs is total
    assert statements[1].lhs is total_hi
