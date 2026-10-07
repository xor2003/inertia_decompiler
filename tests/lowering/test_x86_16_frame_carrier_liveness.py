"""Canonical frame tags cannot justify deleting a still-observed scalar."""

from types import SimpleNamespace

import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.frame_carrier_liveness import (
    FrameCarrierUseVerdict8616,
    prove_frame_carrier_uses_8616,
)
from inertia.lowering.gp_register_state import runtime_gp_state_expr_8616
from inertia.lowering.real_mode_linear import prune_frame_prologue_stack_assignments_8616
from capstone.x86_const import X86_INS_MOV, X86_INS_PUSH, X86_REG_BP, X86_REG_SP
from tests.lowering.test_x86_16_canonical_frame_carriers import _Codegen, _instruction


@pytest.mark.parametrize("representation", ["dirty", "variable", "mixed", "missing_id"])
@pytest.mark.parametrize("nested", [False, True])
def test_frame_pruning_retains_group_with_external_numeric_use(representation, nested):
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    word = SimTypeShort(False)

    def register(name, varid, *, read=False):
        offset = project.arch.registers[name][0]
        if representation == "dirty" or (representation in {"mixed", "missing_id"} and not read):
            return CDirtyExpression(
                VirtualVariable(varid, varid, 16, VirtualVariableCategory.REGISTER, oident=offset),
                codegen=codegen,
            )
        return CVariable(
            SimRegisterVariable(offset, 2, ident=f"r{varid}", region=0x1000),
            variable_type=word, vvar_id=None if representation == "missing_id" else varid, codegen=codegen,
        )

    push = CAssignment(
        register("sp", 11),
        CBinaryOp("Sub", register("sp", 6), CConstant(2, word, codegen=codegen), codegen=codegen),
        tags={"ins_addr": 0x1000}, codegen=codegen,
    )
    setup = CAssignment(register("bp", 12), register("sp", 11), tags={"ins_addr": 0x1001}, codegen=codegen)
    result = CReturn(
        CBinaryOp("Sub", register("sp", 11, read=True), CConstant(2, word, codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    carriers = CStatements([push, setup], codegen=codegen)
    root = CStatements([carriers, result] if nested else [push, setup, result], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, unified_local_vars={})
    function = SimpleNamespace(addr=0x1000, blocks=(SimpleNamespace(
        addr=0x1000, capstone=SimpleNamespace(insns=(
            _instruction(0x1000, 1, X86_INS_PUSH, X86_REG_BP),
            _instruction(0x1001, 2, X86_INS_MOV, X86_REG_BP, X86_REG_SP),
        )),
    ),))

    assert not prune_frame_prologue_stack_assignments_8616(project, codegen, function=function)
    assert carriers.statements == [push, setup]
    assert root.statements == ([carriers, result] if nested else [push, setup, result])


@pytest.mark.parametrize("read_id,expected", [
    (11, FrameCarrierUseVerdict8616.EXTERNAL_USE),
    (12, FrameCarrierUseVerdict8616.CLOSED),
])
def test_frame_use_proof_distinguishes_scalar_versions(read_id, expected):
    codegen = _Codegen(SimpleNamespace(arch=Arch86_16()))
    def scalar(varid):
        return CDirtyExpression(
            VirtualVariable(varid, varid, 16, VirtualVariableCategory.TMP, oident=0), codegen=codegen,
        )
    candidate = CAssignment(
        scalar(11), CConstant(3, SimTypeShort(False), codegen=codegen),
        tags={"ins_addr": 0x1000}, codegen=codegen,
    )
    root = CStatements([candidate, CReturn(scalar(read_id), codegen=codegen)], codegen=codegen)
    proof = prove_frame_carrier_uses_8616(root, frozenset({0x1000}))
    assert proof.verdict is expected
    assert proof.candidate_count == 1


def test_frame_use_proof_refuses_unknown_scalar_identity():
    codegen = _Codegen(SimpleNamespace(arch=Arch86_16()))
    candidate = CAssignment(
        CDirtyExpression("opaque", codegen=codegen), CConstant(3, SimTypeShort(False), codegen=codegen),
        tags={"ins_addr": 0x1000}, codegen=codegen,
    )
    proof = prove_frame_carrier_uses_8616(CStatements([candidate], codegen=codegen), frozenset({0x1000}))
    assert proof.verdict is FrameCarrierUseVerdict8616.UNKNOWN_IDENTITY
    assert not proof.complete


def test_stack_object_reuse_is_not_a_scalar_register_escape():
    codegen = _Codegen(SimpleNamespace(arch=Arch86_16()))
    word = SimTypeShort(False)
    slot = CVariable(SimStackVariable(-2, 2, base="bp"), variable_type=word, codegen=codegen)
    candidate = CAssignment(slot, CConstant(3, word, codegen=codegen), tags={"ins_addr": 0x1000}, codegen=codegen)
    overwrite = CAssignment(slot, CConstant(42, word, codegen=codegen), codegen=codegen)
    root = CStatements([candidate, overwrite, CReturn(slot, codegen=codegen)], codegen=codegen)
    proof = prove_frame_carrier_uses_8616(root, frozenset({0x1000}))
    assert proof.complete


def test_owned_runtime_register_is_still_an_observable_scalar():
    codegen = _Codegen(SimpleNamespace(arch=Arch86_16()))
    state = runtime_gp_state_expr_8616("esp", codegen=codegen, function_addr=0x1000)
    candidate = CAssignment(
        state, CConstant(3, SimTypeShort(False), codegen=codegen), tags={"ins_addr": 0x1000}, codegen=codegen,
    )
    root = CStatements([candidate, CReturn(state, codegen=codegen)], codegen=codegen)
    assert prove_frame_carrier_uses_8616(root, frozenset({0x1000})).verdict is FrameCarrierUseVerdict8616.EXTERNAL_USE
