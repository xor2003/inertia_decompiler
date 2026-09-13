"""Equivalent branch exits require empty SSA blocks and matching edges."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CGoto, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRInstr, IRRefusal, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring import condition_exit_normalization as normalization
from angr_platforms.X86_16.structuring.condition_exit_normalization import transparent_condition_exit_8616
from test_x86_16_typed_condition_side_effect_preservation import _codegen

ENTRY_EXIT = 0x110
EFFECTFUL_DESTINATION = 0x130
UNRELATED_BLOCK = 0x900


def _artifact():
    return SSAFunctionArtifact(
        0x100,
        (
            SSABlock(0x110, (), ()),
            SSABlock(0x120, (), ()),
            SSABlock(0x130, (IRInstr(op="CALL", dst=None, args=(), size=0, addr=0x130),), ()),
        ),
        predecessor_map={0x120: (0x110,), 0x130: (0x120,)},
    )


def test_empty_exit_path_stops_before_continuation_effects():
    artifact = _artifact()
    assert transparent_condition_exit_8616(
        artifact, 0x110, {0x110: (0x120,), 0x120: (0x130,)}, stop_at=0x200,
    ) == EFFECTFUL_DESTINATION
    assert artifact.blocks[-1].instrs[0].op == "CALL"


@pytest.mark.parametrize("refusal_kind", ["memory", "block"])
def test_effectful_destination_is_retained_even_when_its_effects_are_unresolved(refusal_kind):
    artifact = _artifact()
    if refusal_kind == "memory":
        artifact = replace(
            artifact, memory_refusals=(IRRefusal("unknown", "unresolved destination", 0x130),),
        )
    else:
        artifact = replace(
            artifact, blocks=(*artifact.blocks[:-1], replace(artifact.blocks[-1], refusals=("unknown",))),
        )
    original = artifact
    assert transparent_condition_exit_8616(
        artifact, 0x110, {0x110: (0x120,), 0x120: (0x130,), 0x130: (0x140,)}, stop_at=0x200,
    ) == EFFECTFUL_DESTINATION
    assert artifact == original
    assert artifact.blocks[-1].instrs[0].op == "CALL"


@pytest.mark.parametrize("refused_block", [None, 0x110, 0x120, 0x900])
def test_memory_refusals_are_scoped_but_unknown_locations_refuse(refused_block):
    artifact = replace(
        _artifact(), memory_refusals=(IRRefusal("unknown", "missing evidence", refused_block),),
    )
    result = transparent_condition_exit_8616(
        artifact, 0x110, {0x110: (0x120,), 0x120: (0x130,)}, stop_at=0x200,
    )
    assert result == (EFFECTFUL_DESTINATION if refused_block == UNRELATED_BLOCK else ENTRY_EXIT)


@pytest.mark.parametrize("case", ["missing", "refusal", "mismatch", "cycle", "opposite", "effect"])
def test_uncertain_or_effectful_exit_is_not_bypassed(case):
    artifact = _artifact()
    edges = {0x110: (0x120,), 0x120: (0x130,)}
    stop = 0x200
    if case == "missing":
        artifact = None
    elif case == "refusal":
        artifact = replace(artifact, blocks=(replace(artifact.blocks[0], refusals=("unknown",)), *artifact.blocks[1:]))
    elif case == "mismatch":
        edges[0x110] = (0x130,)
    elif case == "cycle":
        edges[0x120] = (0x110,)
        artifact = replace(artifact, predecessor_map={0x120: (0x110,), 0x110: (0x120,)})
    elif case == "opposite":
        stop = 0x130
    else:
        artifact = replace(artifact, blocks=(replace(artifact.blocks[0], instrs=artifact.blocks[-1].instrs), *artifact.blocks[1:]))
    assert transparent_condition_exit_8616(artifact, ENTRY_EXIT, edges, stop_at=stop) == ENTRY_EXIT


@pytest.mark.parametrize("inverted", [False, True])
@pytest.mark.parametrize("fault", [None, "effect", "same-body", "missing-edge", "missing-ssa"])
def test_binary_arm_polarity_requires_exact_effect_free_paths(inverted, fault):
    artifact = _artifact()
    fact = ConditionIR("eq", IRValue(MemSpace.REG, name="ax", size=2),
                       IRValue(MemSpace.CONST, const=0, size=2),
                       block_addr=0x100, src_insn=0x102,
                       taken_target=0x110, fallthrough_target=0x200)
    edges = {0x100: (0x110, 0x200), 0x110: (0x120,), 0x120: (0x130,)}
    bodies = (0x200, 0x130) if inverted else (0x130, 0x200)
    if fault == "effect":
        artifact = replace(artifact, blocks=(replace(artifact.blocks[0], instrs=artifact.blocks[-1].instrs), *artifact.blocks[1:]))
    elif fault == "same-body":
        bodies = (0x130, 0x130)
    elif fault == "missing-edge":
        edges[0x100] = (0x110,)
    elif fault == "missing-ssa":
        artifact = None
    result = normalization.exact_condition_exit_polarity_8616(
        artifact, fact, *bodies, edges,
    )
    assert result is (not inverted if fault is None else None)


@pytest.mark.parametrize("fault", [None, "prefix", "wrong-target", "no-continuation"])
def test_conditional_goto_requires_sole_jump_and_complementary_cfg_endpoints(fault):
    codegen = _codegen()
    target = 0x131 if fault == "wrong-target" else 0x130
    jump = CGoto(target, None, codegen=codegen)
    body = CStatements([jump], codegen=codegen)
    if fault == "prefix":
        body.statements.insert(0, CConstant(1, SimTypeShort(False), codegen=codegen))
    fact = ConditionIR("eq", IRValue(MemSpace.REG, name="ax", size=2),
                       IRValue(MemSpace.CONST, const=0, size=2),
                       block_addr=0x100, src_insn=0x102,
                       taken_target=0x110, fallthrough_target=0x200)
    result = normalization.conditional_goto_polarity_8616(
        body, _artifact(), fact, None if fault == "no-continuation" else 0x200,
        {0x100: (0x110, 0x200), 0x110: (0x120,), 0x120: (0x130,)},
    )
    assert result is (True if fault is None else None)
    assert body.statements[-1] is jump
