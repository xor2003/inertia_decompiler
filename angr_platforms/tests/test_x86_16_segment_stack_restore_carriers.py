"""Tests for lowering alias-proven segment stack restore carriers."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CStatements, CSwitchCase
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.segment_stack_restore_carriers import (
    prune_proven_segment_stack_restore_carriers_8616,
)


def _assignment(codegen: object, instruction_addr: int) -> CAssignment:
    """Build one tagged assignment carrier."""
    value_type = SimTypeShort(False)
    return CAssignment(
        CConstant(0, value_type, codegen=codegen),
        CConstant(1, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": instruction_addr},
    )


@pytest.mark.parametrize("nested", [False, True])
def test_proven_nonconstant_segment_restore_keeps_saved_state(nested) -> None:
    """Binary pair proof alone cannot remove caller-visible runtime restoration."""
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    save = _assignment(codegen, 0x1000)
    restore = _assignment(codegen, 0x1006)
    unrelated = _assignment(codegen, 0x1004)
    codegen.cfunc = SimpleNamespace(statements=CStatements([save, unrelated, restore], codegen=codegen))
    body = codegen.cfunc.statements
    if nested:
        switch = CSwitchCase(
            CConstant(1, SimTypeShort(False), codegen=codegen), [(1, body)], None, codegen=codegen,
        )
        codegen.cfunc.statements = CStatements([switch], codegen=codegen)
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=(
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1006,
                restore_register="es",
                saved_instruction_addr=0x1000,
                saved_register="es",
                stack_offsets=(-2, -1),
                verdict=SegmentStackRestoreVerdict8616.PROVEN,
            ),
        ),
    )

    assert prune_proven_segment_stack_restore_carriers_8616(object(), codegen) is False
    assert body.statements == [save, unrelated, restore]
    assert codegen._inertia_segment_stack_restore_carrier_stats_8616.refused_pair_count == 1
    assert codegen._inertia_segment_stack_restore_carrier_stats_8616.closed


def test_unknown_segment_restore_keeps_every_assignment() -> None:
    """Unknown restore provenance is an explicit refusal, never deletion."""
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    restore = _assignment(codegen, 0x1006)
    codegen.cfunc = SimpleNamespace(statements=CStatements([restore], codegen=codegen))
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=(
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1006,
                restore_register="es",
                saved_instruction_addr=None,
                saved_register=None,
                stack_offsets=(),
                verdict=SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
            ),
        ),
    )

    assert prune_proven_segment_stack_restore_carriers_8616(object(), codegen) is False
    assert codegen.cfunc.statements.statements == [restore]


@pytest.mark.parametrize("present_addr", [0x1000, 0x1006])
@pytest.mark.parametrize("constant_value", [None, 0x284E])
@pytest.mark.parametrize("shared_pair", [False, True])
def test_incomplete_pair_is_not_partially_consumed(present_addr, constant_value, shared_pair):
    """Missing structured evidence must be discovered before any AST mutation."""
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    present = _assignment(codegen, present_addr)
    codegen.cfunc = SimpleNamespace(statements=CStatements([present], codegen=codegen))
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=(SegmentStackRestoreFact8616(
            block_addr=0x1000, restore_instruction_addr=0x1006,
            restore_register="es", saved_instruction_addr=0x1000,
            saved_register="es", stack_offsets=(-2, -1),
            verdict=SegmentStackRestoreVerdict8616.PROVEN,
            constant_value=constant_value,
        ),),
    )
    original = [present]
    if shared_pair:
        shared_restore = _assignment(codegen, 0x1008)
        original.append(shared_restore)
        codegen.cfunc.statements.statements.append(shared_restore)
        fact = codegen._inertia_segment_stack_restore_artifact.facts[0]
        codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
            facts=(fact, replace(fact, saved_instruction_addr=present_addr, restore_instruction_addr=0x1008)),
        )
    assert prune_proven_segment_stack_restore_carriers_8616(object(), codegen) is False
    assert codegen.cfunc.statements.statements == original
    stats = codegen._inertia_segment_stack_restore_carrier_stats_8616
    assert stats.materialized_count == 0
    assert stats.refused_pair_count == len(codegen._inertia_segment_stack_restore_artifact.facts)
    assert stats.closed


def test_proven_constant_segment_transfer_replaces_restore_and_removes_push() -> None:
    """A proven stack constant becomes one direct segment-register assignment."""
    segment_value = 0x284E
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    save_low = _assignment(codegen, 0x1000)
    save_high = _assignment(codegen, 0x1000)
    restore = _assignment(codegen, 0x1003)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([save_low, save_high, restore], codegen=codegen)
    )
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=(
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1003,
                restore_register="ds",
                saved_instruction_addr=0x1000,
                saved_register=None,
                stack_offsets=(-2, -1),
                verdict=SegmentStackRestoreVerdict8616.PROVEN,
                constant_value=segment_value,
            ),
        ),
    )

    assert prune_proven_segment_stack_restore_carriers_8616(object(), codegen) is True
    statements = codegen.cfunc.statements.statements
    assert len(statements) == 1
    assert statements[0].lhs is restore.lhs
    assert statements[0].rhs.value == segment_value
    stats = codegen._inertia_segment_stack_restore_carrier_stats_8616
    assert stats.removed_assignment_count == len((save_low, save_high))
    assert stats.replaced_assignment_count == 1
    assert stats.closed
