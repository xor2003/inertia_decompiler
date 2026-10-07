from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    _replace_tagged_statement_assignment_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


class _Codegen:
    def __init__(self, project: object) -> None:
        self._index = 0
        self.project = project

    def next_idx(self, _name: str) -> int:
        self._index += 1
        return self._index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        return name


def test_tagged_stack_move_replaces_equivalent_provisional_storage_view() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    value_type = SimTypeShort(False).with_arch(project.arch)
    provisional = CVariable(
        SimStackVariable(-2, 2, base="bp", name="stack_sp_m2_2"),
        variable_type=value_type,
        codegen=codegen,
    )
    canonical = CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2"),
        variable_type=value_type,
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=canonical.variable,
        cvar=canonical,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    actual = CAssignment(
        provisional,
        CConstant(0, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10A93},
    )
    root = CStatements([actual], codegen=codegen)

    changed = _replace_tagged_statement_assignment_8616(
        root,
        project,
        0x10A93,
        lambda tags: CAssignment(
            canonical,
            CConstant(0, value_type, codegen=codegen),
            codegen=codegen,
            tags=tags,
        ),
    )

    assert changed is True
    assert root.statements[0].lhs is canonical


def test_tagged_stack_move_keeps_exact_canonical_storage_view() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    value_type = SimTypeShort(False).with_arch(project.arch)
    canonical = CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2"),
        variable_type=value_type,
        codegen=codegen,
    )
    actual = CAssignment(
        canonical,
        CConstant(0, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10A93},
    )
    root = CStatements([actual], codegen=codegen)

    changed = _replace_tagged_statement_assignment_8616(
        root,
        project,
        0x10A93,
        lambda tags: CAssignment(
            canonical,
            CConstant(0, value_type, codegen=codegen),
            codegen=codegen,
            tags=tags,
        ),
    )

    assert changed is False
    assert root.statements[0] is actual
