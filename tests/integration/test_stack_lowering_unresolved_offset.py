from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.cli.cli_c_ast_rewrites import _canonicalize_stack_cvar_expr


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.cfunc = SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            statements=structured_c.CStatements([], codegen=self),
            unified_local_vars={},
            variables_in_use={},
        )

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_canonicalize_stack_deref_refuses_alias_without_integer_offset() -> None:
    codegen = _Codegen()
    variable = SimStackVariable(None, 2, base="bp", name="unknown_slot", region=0x1000)
    pointer = structured_c.CVariable(
        variable,
        variable_type=SimTypePointer(SimTypeShort(False)),
        codegen=codegen,
    )
    expression = structured_c.CUnaryOp("Dereference", pointer, codegen=codegen)

    canonical = _canonicalize_stack_cvar_expr(expression, codegen)

    assert canonical is expression
