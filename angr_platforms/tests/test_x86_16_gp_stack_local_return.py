"""Verify initialized local returns without weakening GP restore accounting."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.segment_stack_restore import SegmentStackRestoreVerdict8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.lowering.codegen_return_origin import ReturnValueOrigin8616
from angr_platforms.X86_16.lowering.gp_stack_local_return import has_materialized_gp_local_return_8616
from angr_platforms.X86_16.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from angr_platforms.X86_16.semantics.register_definition_return import unchanged_register_return_path_8616
from test_x86_16_gp_stack_local_reload import _fixture as _reload_fixture
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


def test_unknown_alias_storage_cannot_be_authorized_by_a_valid_return_path():
    """Matching storage fields are not a substitute for Alias's proof verdict."""
    codegen, container, fact = _fixture()
    fact = replace(fact, verdict=SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE)

    assert not has_materialized_gp_local_return_8616(codegen, (container,), fact)


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


def test_shared_epilogue_path_does_not_authorize_another_return_value():
    """A correct machine path is not sufficient to bless all C return copies."""
    codegen, container, fact = _fixture()
    artifact = codegen._inertia_vex_ir_artifact
    definition, returned = artifact.blocks[0].instrs
    codegen._inertia_vex_ir_artifact = replace(artifact, blocks=(
        IRBlock(0x1000, (definition,), successor_addrs=(0x100a,)),
        IRBlock(0x100a, (returned,)),
    ))
    assert unchanged_register_return_path_8616(codegen._inertia_vex_ir_artifact, 0x1008, "ax") is not None
    other_return = structured_c.CReturn(container.statements[0].rhs, codegen=codegen, tags={"ins_addr": 0x100a})
    other = structured_c.CStatements([other_return], codegen=codegen)

    assert not has_materialized_gp_local_return_8616(codegen, (container, other), fact)


def _distinct_return_fixture():
    codegen, container, fact = _fixture()
    artifact = codegen._inertia_vex_ir_artifact
    definition, returned = artifact.blocks[0].instrs
    other_definition = replace(definition, addr=0x2000)
    codegen._inertia_vex_ir_artifact = replace(artifact, blocks=(
        IRBlock(0x1000, (definition,), successor_addrs=(0x100a,)),
        IRBlock(0x100a, (returned,)),
        IRBlock(0x2000, (other_definition,), successor_addrs=(0x100a,)),
    ))
    container.statements[-1].tags = {
        "ins_addr": 0x100a,
        "inertia_x86_16_return_value_origin": ReturnValueOrigin8616(0x1008, 0x1000, 16),
    }
    other = structured_c.CStatements([
        structured_c.CReturn(container.statements[0].rhs, codegen=codegen, tags={
            "ins_addr": 0x100a,
            "inertia_x86_16_return_value_origin": ReturnValueOrigin8616(0x2000, 0x2000, 16),
        }),
    ], codegen=codegen)
    return codegen, container, other, fact


def test_distinct_proven_return_origins_keep_other_values_independent():
    codegen, container, other, fact = _distinct_return_fixture()

    assert has_materialized_gp_local_return_8616(codegen, (container, other), fact)


@pytest.mark.parametrize("corruption", ["missing", "block", "width", "definition", "other-path", "own-value"])
def test_return_origin_is_not_a_substitute_for_machine_or_storage_proof(corruption):
    codegen, container, other, fact = _distinct_return_fixture()
    own_return = container.statements[-1]
    key = "inertia_x86_16_return_value_origin"
    if corruption == "missing":
        own_return.tags.pop(key)
    elif corruption == "block":
        own_return.tags[key] = replace(own_return.tags[key], block_addr=0x9999)
    elif corruption == "width":
        own_return.tags[key] = replace(own_return.tags[key], width_bits=32)
    elif corruption == "definition":
        own_return.tags[key] = replace(own_return.tags[key], instruction_addr=0x9999)
    elif corruption == "other-path":
        artifact = codegen._inertia_vex_ir_artifact
        codegen._inertia_vex_ir_artifact = replace(artifact, blocks=artifact.blocks[:-1])
    else:
        own_return.retval = container.statements[0].rhs

    assert not has_materialized_gp_local_return_8616(codegen, (container, other), fact)


def _conditional_return_fixture():
    machine, _container, _fact = _fixture()
    codegen, container, local, fact = _reload_fixture()
    codegen._inertia_vex_ir_artifact = machine._inertia_vex_ir_artifact
    codegen.cfunc.functy = SimTypeFunction([], local.variable_type).with_arch(codegen.project.arch)
    low, high, _restore = container.statements
    returned = structured_c.CReturn(local, codegen=codegen, tags={"ins_addr": 0x100a})
    call = structured_c.CFunctionCall("arbitrary_callee", None, [], codegen=codegen)
    branch = structured_c.CStatements([call, returned], codegen=codegen)
    condition = structured_c.CConstant(1, local.variable_type, codegen=codegen)
    conditional = structured_c.CIfElse([(condition, branch)], codegen=codegen)
    container.statements = [low, high, conditional]
    return codegen, container, branch, local, fact


@pytest.mark.parametrize("corruption", [None, "transparent", "partial", "conditional-store", "late", "escape", "duplicate", "wrong-value"])
def test_complete_unescaped_local_bytes_dominate_conditional_return(corruption):
    codegen, container, branch, local, fact = _conditional_return_fixture()
    low, high, conditional = container.statements
    call, returned = branch.statements
    condition = conditional.condition_and_nodes[0][0]
    if corruption == "partial":
        container.statements.remove(high)
    elif corruption == "conditional-store":
        container.statements = [structured_c.CIfElse([(condition, structured_c.CStatements(
            [low, high], codegen=codegen))], codegen=codegen), conditional]
    elif corruption == "late":
        container.statements = [conditional, low, high]
    elif corruption == "escape":
        call.args = [structured_c.CUnaryOp("Reference", local, codegen=codegen)]
    elif corruption == "duplicate":
        branch.statements.insert(0, structured_c.CAssignment(low.lhs, low.rhs, codegen=codegen, tags=low.tags))
    elif corruption == "wrong-value":
        returned.retval = condition
    elif corruption == "transparent":
        container.statements = [structured_c.CStatements([low, high], codegen=codegen), conditional]

    assert has_materialized_gp_local_return_8616(codegen, (container, branch), fact) is (corruption in (None, "transparent"))


@pytest.mark.parametrize("corruption", ["shared-return", "goto", "opaque", "loop-return", "earlier-return"])
def test_conditional_return_dominance_refuses_unproven_control_flow(corruption):
    codegen, container, branch, _local, fact = _conditional_return_fixture()
    low, high, conditional = container.statements
    condition = conditional.condition_and_nodes[0][0]
    returned = branch.statements[-1]
    if corruption == "shared-return":
        conditional.else_node = structured_c.CStatements([returned], codegen=codegen)
    elif corruption == "goto":
        container.statements.insert(0, structured_c.CGoto(0x100a, None, codegen=codegen))
    elif corruption == "opaque":
        container.statements.insert(2, structured_c.CDirtyExpression(None, codegen=codegen))
    elif corruption == "loop-return":
        container.statements = [low, high, structured_c.CWhileLoop(condition, branch, codegen=codegen)]
    else:
        container.statements.insert(0, structured_c.CReturn(condition, codegen=codegen))

    assert not has_materialized_gp_local_return_8616(codegen, (container, branch), fact)
