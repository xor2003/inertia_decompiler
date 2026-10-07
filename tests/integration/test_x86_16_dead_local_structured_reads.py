"""Regression shields for reads hidden behind structured C containers."""
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from tests.integration.test_x86_16_dead_local_prune import _FakeCodegen

import decompile


@pytest.mark.parametrize("read_position", ["indexed_base", "indexed_subscript", "loop_iterator"])
def test_dead_local_prune_preserves_structured_reads(read_position):
    codegen = _FakeCodegen()
    short = SimTypeShort(False).with_arch(codegen.project.arch)
    pointer = SimTypePointer(short).with_arch(codegen.project.arch)
    variable = SimStackVariable(-2, 2, base="bp", name="value", region=0x1000)
    local = c.CVariable(variable, variable_type=pointer if read_position == "indexed_base" else short,
                        codegen=codegen)
    initializer = c.CAssignment(local, c.CConstant(0, short, codegen=codegen), codegen=codegen)
    if read_position == "loop_iterator":
        read = c.CFunctionCall("observe", short, args=(local,), codegen=codegen)
        consumer = c.CForLoop(None, c.CConstant(1, short, codegen=codegen), read,
                              c.CStatements([], codegen=codegen), codegen=codegen)
    else:
        base = local if read_position == "indexed_base" else c.CConstant(0x1200, pointer, codegen=codegen)
        index = local if read_position == "indexed_subscript" else c.CConstant(0, short, codegen=codegen)
        read = c.CIndexedVariable(base, index, variable_type=short, codegen=codegen)
        consumer = c.CReturn(read, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=c.CStatements([initializer, consumer], codegen=codegen),
        variables_in_use={variable: local},
    )

    decompile._prune_dead_local_assignments(codegen)

    assert initializer in codegen.cfunc.statements.statements
