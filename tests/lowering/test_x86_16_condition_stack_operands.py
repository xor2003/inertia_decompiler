"""Tests for typed condition views over x86-16 stack storage."""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.condition_stack_operands import (
    materialize_typed_condition_stack_operand_8616,
)
from inertia.lowering.condition_stack_projection_contracts import (
    ConditionStackProjectionFact8616,
    condition_stack_projection_fact_8616,
)
from inertia.lowering.semantic_cast import CSemanticCast8616
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


class _FakeCodegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cfunc = SimpleNamespace(addr=0x108D0, variables_in_use={}, unified_local_vars={})
        self.display_vvar_ids = False
        self.cstyle_null_cmp = False
        self._next_idx = 0

    def next_idx(self, _kind: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _declare_unsigned_local(codegen: _FakeCodegen) -> tuple[SimStackVariable, structured_c.CVariable]:
    variable = SimStackVariable(-4, 2, base="bp", ident="limit", name="local_4", region=0x108D0)
    cvar = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.unified_local_vars[variable] = {(cvar, cvar.variable_type)}
    return variable, cvar


def test_signed_condition_reuses_stack_storage_with_cast_view() -> None:
    codegen = _FakeCodegen()
    variable, declaration = _declare_unsigned_local(codegen)

    expr = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=2,
        name="local_4",
        signed=True,
        prefer_signed_local_storage=True,
    )

    assert isinstance(expr, CSemanticCast8616)
    assert isinstance(expr.expr, structured_c.CVariable)
    assert expr.expr.variable is variable
    assert "".join(text for text, _node in expr.c_repr_chunks()) == "(short)local_4"
    assert tuple(codegen.cfunc.variables_in_use.values()) == (declaration,)
    assert tuple(codegen.cfunc.unified_local_vars) == (variable,)


def test_matching_condition_type_reuses_stack_storage_without_cast() -> None:
    codegen = _FakeCodegen()
    variable, declaration = _declare_unsigned_local(codegen)

    expr = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=2,
        name="local_4",
        signed=False,
    )

    assert isinstance(expr, structured_c.CVariable)
    assert expr.variable is variable
    assert tuple(codegen.cfunc.variables_in_use.values()) == (declaration,)


def test_missing_stack_storage_is_materialized_in_function_region() -> None:
    codegen = _FakeCodegen()

    expr = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-6,
        size=2,
        name="local_6",
        signed=True,
    )

    assert isinstance(expr, structured_c.CVariable)
    assert expr.variable.region == 0x108D0
    assert tuple(codegen.cfunc.variables_in_use) == (expr.variable,)
    assert tuple(codegen.cfunc.unified_local_vars) == (expr.variable,)


def test_machine_bp_condition_reuses_projected_entry_sp_declaration() -> None:
    codegen = _FakeCodegen()
    projected_variable = SimStackVariable(-8, 2, base="bp", name="local_6", region=0x108D0)
    projected = structured_c.CVariable(
        projected_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    competing_variable = SimStackVariable(-6, 2, base="bp", name="local_4", region=0x108D0)
    competing = structured_c.CVariable(
        competing_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use.update(
        {competing_variable: competing, projected_variable: projected}
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_variable,
        cvar=projected,
        bp_offset=-6,
        entry_sp_offset=-8,
        size=2,
    )

    expression = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-6,
        size=2,
        name="local_6",
        signed=False,
    )

    assert isinstance(expression, structured_c.CVariable)
    assert expression.variable is projected_variable


def test_stale_map_keys_do_not_collapse_machine_bp_arguments() -> None:
    codegen = _FakeCodegen()
    first_key = SimStackVariable(2, 2, base="bp", name="arg_0", region=0x108D0)
    first_variable = SimStackVariable(4, 2, base="bp", name="a", region=0x108D0)
    first = structured_c.CVariable(
        first_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    second_key = SimStackVariable(4, 2, base="bp", name="arg_2", region=0x108D0)
    second_variable = SimStackVariable(6, 2, base="bp", name="b", region=0x108D0)
    second = structured_c.CVariable(
        second_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use.update({first_key: first, second_key: second})

    first_expression = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=4,
        size=2,
        name="a",
        signed=False,
    )
    second_expression = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=6,
        size=2,
        name="b",
        signed=False,
    )

    assert isinstance(first_expression, structured_c.CVariable)
    assert isinstance(second_expression, structured_c.CVariable)
    assert first_expression.variable is first_variable
    assert second_expression.variable is second_variable


def test_machine_bp_byte_view_uses_unique_projected_word_owner() -> None:
    codegen = _FakeCodegen()
    total_variable = SimStackVariable(-4, 2, base="bp", name="local_2", region=0x108D0)
    total = structured_c.CVariable(
        total_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index_variable = SimStackVariable(-6, 2, base="bp", name="local_4", region=0x108D0)
    index = structured_c.CVariable(
        index_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use.update(
        {total_variable: total, index_variable: index}
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=total_variable,
        cvar=total,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=index_variable,
        cvar=index,
        bp_offset=-4,
        entry_sp_offset=-6,
        size=2,
    )

    expression = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=1,
        name="local_4",
        signed=False,
    )

    assert isinstance(expression, structured_c.CBinaryOp)
    assert expression.op == "And"
    assert isinstance(expression.lhs, structured_c.CVariable)
    assert expression.lhs.variable is index_variable
    assert isinstance(expression.rhs, structured_c.CConstant)
    assert expression.rhs.value == 0xFF


def test_wide_word_projection_uses_machine_bp_owner_coordinate() -> None:
    """Project the low word from canonical BP, not the raw angr stack offset."""
    codegen = _FakeCodegen()
    variable = SimStackVariable(-6, 4, base="bp", name="goal", region=0x108D0)
    declaration = structured_c.CVariable(
        variable,
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[variable] = declaration
    codegen.cfunc.unified_local_vars[variable] = {(declaration, declaration.variable_type)}
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=declaration,
        bp_offset=-4,
        entry_sp_offset=-6,
        size=4,
    )

    expression = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=2,
        storage_size=4,
        name="goal",
        signed=False,
    )

    assert isinstance(expression, structured_c.CBinaryOp)
    assert expression.op == "And"
    assert isinstance(expression.lhs, structured_c.CVariable)
    assert expression.lhs.variable is variable
    assert condition_stack_projection_fact_8616(expression) == (
        ConditionStackProjectionFact8616(
            base="bp",
            owner_offset=-4,
            owner_size=4,
            view_offset=-4,
            view_size=2,
        )
    )
