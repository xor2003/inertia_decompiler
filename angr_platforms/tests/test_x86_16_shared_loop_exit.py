"""Shared loop exits require current predicates, scope and epilogue evidence."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CReturn, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring.loop_body_repair import SwitchLoopExitReturnEvidence8616
from angr_platforms.X86_16.structuring.shared_loop_exit import (
    matching_shared_loop_exits_8616,
    prove_shared_loop_exits_8616,
    shared_exit_fingerprint_8616,
)
from angr_platforms.X86_16.validation_control_flow_obligations import validate_switch_exit_obligations_8616
from test_x86_16_existing_loop_exit_conditions import _fixture, _run


def _shared_exit():
    codegen, loop, guard, _, fact, topology = _fixture()
    header = topology.loops[0].header
    loop.condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    loop.tags = {"ins_addr": header}
    loop.body.statements.insert(0, CConstant(0, SimTypeShort(False), codegen=codegen,
                                            tags={"vex_block_addr": header}))
    fact = replace(fact, op="eq", lhs=IRValue(MemSpace.CONST, const=1, size=2),
                   rhs=IRValue(MemSpace.CONST, const=27, size=2))
    def lower(_fact):
        return CBinaryOp("CmpEQ", CConstant(1, SimTypeShort(False), codegen=codegen),
                         CConstant(27, SimTypeShort(False), codegen=codegen), codegen=codegen)
    _run(codegen, loop, (fact,), topology, lower=lower)
    epilogue = CReturn(None, codegen=codegen, tags={"vex_block_addr": 0x1060})
    root = CStatements([loop, epilogue], codegen=codegen)
    evidence = SwitchLoopExitReturnEvidence8616(27, 0x1050, 0x1060)
    artifact = SSAFunctionArtifact(0x1000, (SSABlock(0x1040, (), ()),),
                                   predecessor_map={0x1050: (0x1040,)})
    edges = {source: tuple(target for src, target in topology.edges if src == source)
             for source, _ in topology.edges}
    edges[0x1040] = (0x1050,)
    return codegen, root, loop, guard, epilogue, fact, topology, artifact, edges, evidence


@pytest.mark.parametrize("mutation", [None, "predicate", "key", "break", "loop", "return", "exit-tag"])
def test_shared_exit_binding_rejects_mutated_current_surface(mutation):
    codegen, root, loop, guard, epilogue, fact, topology, artifact, edges, evidence = _shared_exit()
    def fingerprint(expression):
        return shared_exit_fingerprint_8616(expression, codegen.project)
    result = prove_shared_loop_exits_8616(root, (evidence,), (fact,), topology, artifact, edges, fingerprint)
    assert result.materialized_count == 1
    condition, body = guard.condition_and_nodes[0]
    if mutation == "predicate":
        condition.op = "CmpNE"
    elif mutation == "key":
        condition.tags["ins_addr"] += 1
    elif mutation == "break":
        body.statements.clear()
    elif mutation == "loop":
        loop.condition.value = 0
    elif mutation == "return":
        epilogue.retval = CConstant(1, SimTypeShort(False), codegen=codegen)
    elif mutation == "exit-tag":
        epilogue.tags["vex_block_addr"] += 1
    matches = matching_shared_loop_exits_8616(root, evidence, result.bindings, fingerprint)
    assert len(matches) == int(mutation is None)
    assert not validate_switch_exit_obligations_8616(root, (evidence,)).passed
    validated = validate_switch_exit_obligations_8616(
        root, (evidence,), shared_bindings=result.bindings, fingerprint=fingerprint,
    )
    assert validated.passed is (mutation is None)


@pytest.mark.parametrize("fault", ["wrong-case", "missing-ssa", "connector-refusal", "wrong-edge", "duplicate-loop"])
def test_shared_exit_refuses_missing_or_conflicting_binary_proof(fault):
    codegen, root, _, _, _, fact, topology, artifact, edges, evidence = _shared_exit()
    if fault == "wrong-case":
        evidence = replace(evidence, case_value=28)
    elif fault == "missing-ssa":
        artifact = None
    elif fault == "connector-refusal":
        artifact = replace(artifact, blocks=(replace(artifact.blocks[0], refusals=("unknown",)),))
    elif fault == "wrong-edge":
        edges[0x1040] = (0x1060,)
    elif fault == "duplicate-loop":
        topology = replace(topology, loops=topology.loops * 2)
    result = prove_shared_loop_exits_8616(
        root, (evidence,), (fact,), topology, artifact, edges,
        lambda expression: shared_exit_fingerprint_8616(expression, codegen.project),
    )
    assert result.materialized_count == 0
    assert result.failure_count == 1
