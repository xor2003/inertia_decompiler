from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.widening.widening_memory_fold_8616 import _widening_store_to_load_forwarding_8616


class _DummyCodegen:
    def __init__(self):
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


def test_widening_memory_fold_walks_list_backed_switch_case_bodies():
    codegen = _DummyCodegen()
    addr = CVariable(
        SimStackVariable(-4, 2, base="bp", name="addr", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    value = CConstant(7, SimTypeShort(False), codegen=codegen)
    out = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    store = CAssignment(CUnaryOp("Dereference", addr, codegen=codegen), value, codegen=codegen)
    load = CAssignment(out, CUnaryOp("Dereference", addr, codegen=codegen), codegen=codegen)
    case_body = CStatements([store, load], addr=0x4020, codegen=codegen)
    switch = CSwitchCase(out, [(69, case_body)], None, codegen=codegen)
    root = CStatements([switch], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_store_to_load_forwarding_8616(codegen)

    assert changed is True
    assert load.rhs is value
