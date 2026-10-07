from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.postprocess.optimization.dce import _dead_code_elimination_8616


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


def test_dce_keeps_register_used_by_segment_helper_store_lvalue() -> None:
    codegen = _Codegen()
    carrier = SimRegisterVariable(6, 2, ident="ir_6", name="v9", region=0x10678)
    carrier_def = structured_c.CVariable(carrier, variable_type=SimTypeShort(False), codegen=codegen)
    carrier_read = structured_c.CVariable(carrier, variable_type=SimTypeShort(False), codegen=codegen)
    definition = structured_c.CAssignment(
        carrier_def,
        structured_c.CConstant(4, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    store = structured_c.CAssignment(
        structured_c.CFunctionCall(
            "SEG_U8",
            SimTypeChar(False),
            args=(
                structured_c.CConstant(0x1000, SimTypeShort(False), codegen=codegen),
                structured_c.CBinaryOp(
                    "Add",
                    structured_c.CConstant(2892, SimTypeShort(False), codegen=codegen),
                    carrier_read,
                    codegen=codegen,
                ),
            ),
            codegen=codegen,
        ),
        structured_c.CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([definition, store], codegen=codegen),
        variables_in_use={carrier: carrier_def},
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements == [definition, store]
