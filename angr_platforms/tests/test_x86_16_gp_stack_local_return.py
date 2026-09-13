"""Verify initialized local returns without weakening GP restore accounting."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.lowering.gp_stack_local_return import has_materialized_gp_local_return_8616
from angr_platforms.X86_16.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from test_x86_16_gp_stack_restore import _artifact, _Codegen


def _fixture():
    arch = Arch86_16()
    codegen = _Codegen(project=SimpleNamespace(arch=arch))
    word = SimTypeShort(True).with_arch(arch)
    local = structured_c.CVariable(SimStackVariable(-2, 2, base="bp", name="local"),
                                  variable_type=word, codegen=codegen)
    save = structured_c.CAssignment(local, structured_c.CConstant(7, word, codegen=codegen),
                                   codegen=codegen, tags={"ins_addr": 0x1000})
    returned = structured_c.CReturn(local, codegen=codegen, tags={"ins_addr": 0x100a})
    container = structured_c.CStatements([save, returned], codegen=codegen)
    definition = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (), addr=0x1008)
    ret = IRInstr("RET", None, (), addr=0x100a)
    codegen._inertia_vex_ir_artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, (definition, ret)),))
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=container,
                                   functy=SimTypeFunction([], word).with_arch(arch))
    return codegen, container, _artifact().facts[0]


def test_existing_local_closes_fact_without_creating_a_runtime_snapshot():
    codegen, container, fact = _fixture()
    statements = tuple(container.statements)

    assert has_materialized_gp_local_return_8616(codegen, (container,), fact)
    assert materialize_gp_stack_restores_8616(codegen) is False
    assert tuple(container.statements) == statements
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.closed
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.materialized_count == 1


@pytest.mark.parametrize("corruption", ["missing", "late", "duplicate", "offset", "return-site", "return-value"])
def test_invalid_c_binding_refuses(corruption):
    codegen, container, fact = _fixture()
    save, returned = container.statements
    if corruption == "missing":
        container.statements = [returned]
    elif corruption == "late":
        container.statements = [returned, save]
    elif corruption == "duplicate":
        container.statements.insert(1, structured_c.CAssignment(save.lhs, save.rhs, codegen=codegen))
    elif corruption == "offset":
        fact = replace(fact, stack_offsets=(-4, -3))
    elif corruption == "return-site":
        returned.tags = {"ins_addr": 0x100b}
    else:
        returned.retval = save.rhs

    assert not has_materialized_gp_local_return_8616(codegen, (container,), fact)


def test_one_valid_return_copy_does_not_hide_a_corrupted_copy():
    codegen, container, fact = _fixture()
    returned = structured_c.CReturn(container.statements[0].rhs, codegen=codegen, tags={"ins_addr": 0x100a})
    other = structured_c.CStatements([returned], codegen=codegen)

    assert not has_materialized_gp_local_return_8616(codegen, (container, other), fact)


def test_machine_clobber_invalidates_an_otherwise_valid_c_binding():
    codegen, container, fact = _fixture()
    artifact = codegen._inertia_vex_ir_artifact
    block = artifact.blocks[0]
    clobber = IRInstr("MOV", IRValue(MemSpace.REG, name="al", size=1), (), addr=0x1009)
    codegen._inertia_vex_ir_artifact = replace(artifact, blocks=(replace(
        block, instrs=(block.instrs[0], clobber, block.instrs[1]),
    ),))

    assert not has_materialized_gp_local_return_8616(codegen, (container,), fact)
