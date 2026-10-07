"""Regression tests for direct stack-move insertion before indexed reads."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeFixedSizeArray, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.real_mode_linear import (
    _insert_before_first_stack_cvar_use_8616,
    _node_has_instruction_address_8616,
)
from archinfo import ArchX86


class _Codegen:
    """Minimal angr structured-codegen boundary used by this regression."""

    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        """Return a stable node index."""
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_inserts_before_first_stack_index_read() -> None:
    """An index expression is a semantic read of its stack-backed variable."""
    codegen = _Codegen()
    index = CVariable(
        SimStackVariable(-14, 2, base="bp", name="index"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    array = CVariable(
        SimStackVariable(-12, 8, base="bp", name="array"),
        variable_type=SimTypeFixedSizeArray(SimTypeShort(False), 4),
        codegen=codegen,
    )
    read = CExpressionStatement(
        CIndexedVariable(
            array,
            index,
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    assignment = CAssignment(
        index,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([read], codegen=codegen)

    assert _insert_before_first_stack_cvar_use_8616(
        root,
        assignment,
        ignore_existing_assignment=True,
    )
    assert root.statements == [assignment, read]


def test_instruction_address_accepts_current_ail_tags_mapping() -> None:
    """Current angr AIL tags retain exact instruction-origin evidence."""
    codegen = _Codegen()
    local = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        local,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    assignment.tags = Tags({"ins_addr": 0x100C})

    assert _node_has_instruction_address_8616(assignment, codegen.project, 0x100C)
