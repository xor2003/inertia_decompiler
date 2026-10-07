"""Tests for architecture binding before structured stack-expression rebuilds."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.stack_lowering_impl as stack_lowering_impl


class _CurrentAngrCodegen:
    """Minimum codegen surface used by current structured C expressions."""

    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_ident(self, name: str) -> str:
        """Return a stable display identity."""
        return name

    def next_node_idx(self) -> int:
        """Return one unique C AST node identity."""
        self._idx += 1
        return self._idx


def test_stack_expression_type_binding_uses_cvariable_owned_type_field() -> None:
    """An unbound variable type must be rebound before binary-op construction."""
    codegen = _CurrentAngrCodegen()
    variable = SimStackVariable(4, 2, base="bp", name="value", region=0x1000)
    cvar = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    cvar.variable_type = SimTypeShort(False)

    stack_lowering_impl._bind_expr_types_to_project_arch_8616(cvar, codegen)
    constant = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    binary = structured_c.CBinaryOp("Add", cvar, constant, codegen=codegen)

    assert cvar.variable_type is not None
    assert cvar.variable_type.size == 16
    assert binary.type.size == 16
