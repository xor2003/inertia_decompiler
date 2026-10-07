"""Regressions for carry proof over exact Semantics-owned call outputs."""

from __future__ import annotations

from dataclasses import replace

from inertia.ir import (
    IRInstr,
    IRValue,
)
from inertia.ir.ssa_function import SSAFunctionArtifact
from tests.fixtures.x86_16_carry_borrow_call_output_support import lift_after_dx_ax_call

from inertia.alias.carry_borrow_projection import (
    CarryBorrowAliasFailure8616,
    project_carry_borrow_aliases_8616,
)
from inertia.semantics.carry_borrow_contracts import CarryBorrowFailure8616
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from inertia.widening.carry_borrow_values import widen_carry_borrow_values_8616


def _low_adds(artifact: SSAFunctionArtifact) -> tuple[tuple[int, IRInstr], ...]:
    return tuple(
        (index, instruction)
        for block in artifact.blocks
        for index, instruction in enumerate(block.instrs)
        if instruction.addr == 0x1000 and instruction.op == "Iop_Add16"
    )


def test_call_output_preserves_prewrite_operand_for_carry_proof() -> None:
    artifact = lift_after_dx_ax_call()
    adds = _low_adds(artifact)

    assert len(adds) == 2
    for _index, addition in adds:
        lhs = addition.args[0]
        assert isinstance(lhs, IRValue)
        assert (lhs.name, lhs.version, lhs.source_tmp) == ("ax", 0, 0)

    evidence = analyze_carry_borrow_links_8616(artifact)

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 1
    link = evidence.links[0]
    assert link.low_result_write.instruction.dst is not None
    assert link.low_result_write.instruction.dst.version == 1

    aliases = project_carry_borrow_aliases_8616(evidence, artifact)
    assert aliases.complete
    assert aliases.stats.materialized_count == 1
    call_output = aliases.facts[0].lhs_call_output
    assert call_output is not None
    assert call_output.provenance.callsite_addr == 0xFF0
    assert (call_output.low_output.name, call_output.high_output.name) == ("ax", "dx")

    widening = widen_carry_borrow_values_8616(aliases)
    assert widening.complete
    assert widening.values[0].lhs_call_output == call_output


def test_alias_refuses_conflicting_call_output_provenance() -> None:
    artifact = lift_after_dx_ax_call(high_callsite_addr=0xFF1)
    evidence = analyze_carry_borrow_links_8616(artifact)

    aliases = project_carry_borrow_aliases_8616(evidence, artifact)

    assert aliases.complete
    assert aliases.stats.failure_count == 1
    assert aliases.resolutions[0].failure is CarryBorrowAliasFailure8616.CALL_OUTPUT_CONFLICT


def test_alias_refuses_partial_call_output_provenance() -> None:
    artifact = lift_after_dx_ax_call(retain_high_provenance=False)
    evidence = analyze_carry_borrow_links_8616(artifact)

    aliases = project_carry_borrow_aliases_8616(evidence, artifact)

    assert aliases.complete
    assert aliases.stats.failure_count == 1
    assert aliases.resolutions[0].failure is CarryBorrowAliasFailure8616.CALL_OUTPUT_PARTIAL


def test_alias_requires_function_ssa_for_claimed_call_output() -> None:
    artifact = lift_after_dx_ax_call()
    evidence = analyze_carry_borrow_links_8616(artifact)

    aliases = project_carry_borrow_aliases_8616(evidence)

    assert aliases.complete
    assert aliases.stats.failure_count == 1
    assert aliases.resolutions[0].failure is CarryBorrowAliasFailure8616.CALL_OUTPUT_SSA_MISSING


def test_carry_proof_refuses_corrupted_temporary_snapshot_version() -> None:
    artifact = lift_after_dx_ax_call()
    adds = _low_adds(artifact)
    flags_add_index, flags_add = adds[1]
    lhs = flags_add.args[0]
    assert isinstance(lhs, IRValue)
    changed_add = replace(flags_add, args=(replace(lhs, version=1), *flags_add.args[1:]))
    block = artifact.blocks[0]
    instructions = list(block.instrs)
    instructions[flags_add_index] = changed_add
    corrupted = replace(artifact, blocks=(replace(block, instrs=tuple(instructions)),))

    evidence = analyze_carry_borrow_links_8616(corrupted)

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.failure_count == 1
    assert evidence.stats.materialized_count == 0
    assert evidence.resolutions[0].failure is CarryBorrowFailure8616.LOW_RESULT_AMBIGUOUS
