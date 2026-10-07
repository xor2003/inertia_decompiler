from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable, SimTemporaryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.terminal_return_expressions as terminal_return_expressions
from inertia.lowering.terminal_return_render_projection import (
    TerminalReturnRenderProjectionStatus8616,
    project_terminal_return_renderability_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.display_vvar_ids = False

    def next_idx(self, _name: str) -> int:
        self.index += 1
        return self.index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_deep_terminal_expression_uses_one_structural_clone(monkeypatch) -> None:
    """Keep terminal expression resolution linear in AST depth."""
    codegen = _Codegen()
    short_type = SimTypeShort(signed=False)
    expression: object = structured_c.CConstant(1, short_type, codegen=codegen)
    for value in range(2, 34):
        expression = structured_c.CBinaryOp(
            "Add",
            expression,
            structured_c.CConstant(value, short_type, codegen=codegen),
            codegen=codegen,
        )

    clone_count = 0
    original_clone = terminal_return_expressions._clone_c_ast_tree_8616

    def counted_clone(node: object) -> object:
        nonlocal clone_count
        clone_count += 1
        return original_clone(node)

    monkeypatch.setattr(terminal_return_expressions, "_clone_c_ast_tree_8616", counted_clone)

    resolved = terminal_return_expressions.resolve_linear_virtual_return_expression_8616((), expression)

    assert isinstance(resolved, structured_c.CBinaryOp)
    assert clone_count == 1


def test_safe_terminal_expression_clears_codegen_depth_collapse() -> None:
    """Render a proven scalar return even when angr hid it by depth."""
    codegen = _Codegen()
    short_type = SimTypeShort(signed=True)
    lhs = structured_c.CBinaryOp(
        "Add",
        structured_c.CConstant(1, short_type, codegen=codegen),
        structured_c.CConstant(2, short_type, codegen=codegen),
        codegen=codegen,
        collapsed=True,
    )
    expression = structured_c.CBinaryOp(
        "Add",
        lhs,
        structured_c.CConstant(3, short_type, codegen=codegen),
        codegen=codegen,
        collapsed=True,
    )

    changed = terminal_return_expressions.uncollapse_safe_scalar_expression_8616(expression)

    assert changed is True
    assert expression.collapsed is False
    assert lhs.collapsed is False


def test_unresolved_terminal_expression_keeps_codegen_depth_collapse() -> None:
    """Do not expose a hidden return while its value remains unresolved."""
    codegen = _Codegen()
    expression = structured_c.CDirtyExpression(SimpleNamespace(varid=7), codegen=codegen)
    expression.collapsed = True

    changed = terminal_return_expressions.uncollapse_safe_scalar_expression_8616(expression)

    assert changed is False
    assert expression.collapsed is True


def test_terminal_return_projection_exposes_lowered_wide_arithmetic() -> None:
    """Clear stale collapse only after both wide operands are stack variables."""
    codegen = _Codegen()
    long_type = SimTypeShort(signed=True)
    lhs = structured_c.CVariable(
        SimStackVariable(2, 4, base="bp", name="a"),
        variable_type=long_type,
        codegen=codegen,
    )
    rhs = structured_c.CVariable(
        SimStackVariable(6, 4, base="bp", name="b"),
        variable_type=long_type,
        codegen=codegen,
    )
    retval = structured_c.CBinaryOp("Add", lhs, rhs, codegen=codegen, collapsed=True)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CReturn(retval, codegen=codegen)],
            codegen=codegen,
        )
    )

    result = project_terminal_return_renderability_8616(codegen)

    assert result.status is TerminalReturnRenderProjectionStatus8616.MATERIALIZED
    assert result.candidate_count == 1
    assert result.materialized_expression_count == 1
    assert result.uncollapsed_node_count == 1
    assert result.refused_expression_count == 0
    assert retval.collapsed is False
    assert "".join(text for text, _node in retval.c_repr_chunks()) == "a + b"


def test_terminal_return_projection_refuses_unresolved_carrier() -> None:
    """Keep unresolved generated carriers hidden instead of exposing guessed C."""
    codegen = _Codegen()
    retval = structured_c.CVariable(
        SimTemporaryVariable(7, 2),
        variable_type=SimTypeShort(signed=False),
        codegen=codegen,
        collapsed=True,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(
            [structured_c.CReturn(retval, codegen=codegen)],
            codegen=codegen,
        )
    )

    result = project_terminal_return_renderability_8616(codegen)

    assert result.status is TerminalReturnRenderProjectionStatus8616.REFUSED
    assert result.candidate_count == 1
    assert result.materialized_expression_count == 0
    assert result.uncollapsed_node_count == 0
    assert result.refused_expression_count == 1
    assert retval.collapsed is True
