"""Local continuations must bound pure guards before shared eventual returns."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CIfElse, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring.local_condition_regions import (
    local_condition_continuations_8616,
    prove_local_condition_region_8616,
)
from test_x86_16_structuring_multi_arm_condition_ownership import _Codegen

ROOT, LOW, BODY, CONTINUATION = 0x100, 0x110, 0x200, 0x300


def _region():
    value = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    root = ConditionIR("slt", value, value, block_addr=ROOT, src_insn=ROOT,
                       taken_target=CONTINUATION, fallthrough_target=LOW)
    low = replace(root, op="ugt", block_addr=LOW, src_insn=LOW,
                  taken_target=BODY, fallthrough_target=CONTINUATION)
    facts = {ROOT: root, LOW: low}
    successors = {ROOT: (CONTINUATION, LOW), LOW: (BODY, CONTINUATION), CONTINUATION: (BODY,)}
    artifact = SSAFunctionArtifact(
        ROOT,
        (SSABlock(ROOT, (), ()), SSABlock(LOW, (), ()),
         SSABlock(CONTINUATION, (IRInstr("CALL", None, ()),), ())),
        predecessor_map={LOW: (ROOT,), BODY: (LOW, CONTINUATION), CONTINUATION: (ROOT, LOW)},
    )
    return root, facts, successors, artifact


def test_local_region_stops_before_effectful_continuation_with_shared_return():
    root, facts, successors, artifact = _region()
    result = prove_local_condition_region_8616(root, BODY, CONTINUATION, facts, successors, artifact)
    assert result is not None
    assert result.conditions == (root, facts[LOW])
    assert result.body_target == BODY
    assert result.continuation == CONTINUATION


@pytest.mark.parametrize("operation", ["CALL", "STORE", "UNKNOWN", "Iop_Unknown16", "Iop_DivS16"])
def test_local_region_refuses_effectful_or_unclassified_operations(operation):
    root, facts, successors, artifact = _region()
    temporary = IRValue(MemSpace.TMP, name="t0", size=2)
    block = replace(artifact.blocks[1], instrs=(IRInstr(operation, temporary, ()),))
    artifact = replace(artifact, blocks=(artifact.blocks[0], block, artifact.blocks[2]))
    assert prove_local_condition_region_8616(root, BODY, CONTINUATION, facts, successors, artifact) is None


@pytest.mark.parametrize("fault", ["cycle", "missing-fact", "missing-ssa", "edge-mismatch", "register-write"])
def test_local_region_refuses_incomplete_or_conflicting_proof(fault):
    root, facts, successors, artifact = _region()
    if fault == "cycle":
        facts[LOW] = replace(facts[LOW], fallthrough_target=ROOT)
        successors[LOW] = (BODY, ROOT)
        artifact = replace(artifact, predecessor_map={LOW: (ROOT,), BODY: (LOW,), ROOT: (LOW,), CONTINUATION: (ROOT,)})
    elif fault == "missing-fact":
        facts.pop(LOW)
    elif fault == "missing-ssa":
        artifact = None
    elif fault == "edge-mismatch":
        successors[LOW] = (BODY,)
    else:
        instruction = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), ())
        artifact = replace(artifact, blocks=(artifact.blocks[0], replace(artifact.blocks[1], instrs=(instruction,))))
    assert prove_local_condition_region_8616(root, BODY, CONTINUATION, facts, successors, artifact) is None


@pytest.mark.parametrize("fault", [None, "unknown-address", "unknown-segment", "ds", "non-frame"])
def test_local_region_requires_stable_segmented_frame_reads(fault):
    root, facts, successors, artifact = _region()
    address = IRAddress(MemSpace.SS, base=("bp",), offset=4, size=2,
                        status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN)
    if fault == "unknown-address":
        address = replace(address, status=AddressStatus.UNKNOWN)
    elif fault == "unknown-segment":
        address = replace(address, segment_origin=SegmentOrigin.UNKNOWN)
    elif fault == "ds":
        address = replace(address, space=MemSpace.DS)
    elif fault == "non-frame":
        address = replace(address, base=("bx",))
    instruction = IRInstr("LOAD", IRValue(MemSpace.TMP, name="t0", size=2), (address,))
    artifact = replace(artifact, blocks=(artifact.blocks[0], replace(artifact.blocks[1], instrs=(instruction,))))
    result = prove_local_condition_region_8616(root, BODY, CONTINUATION, facts, successors, artifact)
    assert (result is not None) == (fault is None)


@pytest.mark.parametrize("fault", [None, "operand-tag-only", "reused-last-guard", "missing-fact"])
def test_continuation_uses_direct_unique_statement_ownership(fault):
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    guard = CIfElse([(condition, None)], codegen=codegen, tags={"ins_addr": ROOT})
    following = CIfElse([(condition, None)], codegen=codegen, tags={"ins_addr": CONTINUATION})
    root, _, _, _ = _region()
    facts = {CONTINUATION: replace(root, src_insn=CONTINUATION, block_addr=CONTINUATION)}
    if fault == "operand-tag-only":
        following = SimpleNamespace(tags={}, operand=SimpleNamespace(tags={"vex_block_addr": CONTINUATION}))
    elif fault == "missing-fact":
        facts = {}
    statements = [guard, following]
    if fault == "reused-last-guard":
        statements.append(guard)
    container = CStatements(statements, codegen=codegen)
    result = local_condition_continuations_8616((container,), facts)
    assert result.get(id(guard)) == (CONTINUATION if fault is None else None)
