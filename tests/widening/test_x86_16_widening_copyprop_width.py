from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.widening.widening_copyprop_8616 import (
    _widening_copy_propagation_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _copy_then_divide(source_size: int) -> tuple[_Codegen, CVariable, CBinaryOp]:
    codegen = _Codegen()
    stack_byte = CVariable(
        SimStackVariable(-2, 1, base="bp", name="local_2"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    source = CVariable(
        SimRegisterVariable(0, source_size, name="source"),
        variable_type=SimTypeChar(False) if source_size == 1 else SimTypeShort(False),
        codegen=codegen,
    )
    dividend = CVariable(
        SimRegisterVariable(2, 2, name="dividend"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    quotient = CVariable(
        SimRegisterVariable(4, 2, name="quotient"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    division = CBinaryOp("Div", dividend, stack_byte, codegen=codegen)
    root = CStatements(
        [
            CAssignment(stack_byte, source, codegen=codegen),
            CAssignment(quotient, division, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    return codegen, stack_byte, division


def test_widening_copyprop_refuses_narrowing_stack_definition() -> None:
    codegen, stack_byte, division = _copy_then_divide(source_size=2)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert division.rhs is stack_byte
    assert codegen.widening_copyprop_width_mismatch_refused_8616 == 1
    guard = codegen._inertia_widening_copy_width_guard_8616
    assert (
        guard.raw_fact_count,
        guard.normalized_fact_count,
        guard.classified_fact_count,
        guard.materialized_count,
        guard.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_widening_copyprop_keeps_equal_width_register_copy() -> None:
    codegen, stack_byte, division = _copy_then_divide(source_size=1)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert isinstance(division.rhs, CVariable)
    assert division.rhs is not stack_byte
    assert division.rhs.variable.size == 1
    assert codegen.widening_copyprop_width_mismatch_refused_8616 == 0
