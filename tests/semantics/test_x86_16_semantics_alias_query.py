from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.semantics.alias_query import (
    _storage_domain_for_expr,
    can_join_alias_storage,
    describe_alias_storage,
    needs_alias_synthesis,
    same_alias_storage_domain,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _const(value: int) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=_Codegen())


def _variable(variable: SimVariable) -> structured_c.CVariable:
    return structured_c.CVariable(variable, codegen=_Codegen())


def test_describe_alias_storage_preserves_stack_identity() -> None:
    expr = _variable(SimStackVariable(-2, 2, base="bp"))
    facts = describe_alias_storage(expr)

    assert facts.domain.space == "stack"
    assert facts.identity is not None
    assert facts.identity[0] == "stack"
    assert same_alias_storage_domain(expr, _variable(SimStackVariable(-2, 2, base="bp")))


def test_can_join_alias_storage_for_adjacent_register_byte_views() -> None:
    low = _variable(SimRegisterVariable(0, 1, name="al"))
    high = _variable(SimRegisterVariable(1, 1, name="ah"))

    assert can_join_alias_storage(low, high)


def test_mixed_alias_expression_requires_synthesis() -> None:
    lhs = _variable(SimRegisterVariable(0, 2, name="ax"))
    rhs = _variable(SimStackVariable(-2, 2, base="bp"))
    expr = structured_c.CBinaryOp("+", lhs, rhs, codegen=_Codegen())

    assert _storage_domain_for_expr(expr).space == "mixed"
    assert needs_alias_synthesis(expr)


def test_mk_fp_expression_has_far_pointer_identity() -> None:
    expr = structured_c.CFunctionCall("MK_FP", None, [_const(0xB800), _const(0x40)], codegen=_Codegen())
    facts = describe_alias_storage(expr)

    assert facts.domain.space == "far_pointer"
    assert facts.identity == ("far_pointer", (0xB800, 0x40))
