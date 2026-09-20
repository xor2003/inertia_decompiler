"""Tests for lowering terminal far-return CS boundary carriers."""

from __future__ import annotations

import io
from types import SimpleNamespace
from typing import Any

import angr
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CStatements,
    CSwitchCase,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.vex_control_flow import terminal_ret_instruction_addrs_8616
from angr_platforms.X86_16.lowering.far_return_boundary_carriers import (
    FarReturnBoundaryRefusal8616,
    consume_terminal_far_return_boundary_carriers_8616,
)
from angr_platforms.X86_16.semantics.terminal_return_contract import (
    TerminalReturnFrameKind8616,
    TerminalStackCleanupEvidence8616,
)

RETF_ADDR = 0x1006
VALUE_TYPE = SimTypeShort(False)


def _codegen() -> SimpleNamespace:
    """Return the minimal third-party codegen surface needed by C nodes."""
    return SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )


def _far_cleanup_evidence(
    *,
    frame_kind: TerminalReturnFrameKind8616 = TerminalReturnFrameKind8616.FAR,
    cleanup: int = 0,
    operand_bits: int = 16,
) -> TerminalStackCleanupEvidence8616:
    """Build one complete terminal decode proof for a seeded project cache."""
    return TerminalStackCleanupEvidence8616(
        frozenset({cleanup}),
        1,
        1,
        1,
        1,
        0,
        frozenset({frame_kind}),
        frozenset({operand_bits}),
    )


def _project(
    evidence_by_addr: dict[int, TerminalStackCleanupEvidence8616] | None = None,
) -> SimpleNamespace:
    """Return one fake project whose cleanup decode cache is pre-seeded."""
    return SimpleNamespace(
        arch=Arch86_16(),
        _inertia_terminal_stack_cleanup_cache_8616=dict(evidence_by_addr or {}),
    )


def _terminal_ret_artifact(*addresses: int) -> SimpleNamespace:
    """Build one typed IR artifact surface with block-terminal RET instructions."""
    return SimpleNamespace(
        blocks=[
            SimpleNamespace(instrs=[SimpleNamespace(op="RET", addr=address)])
            for address in addresses
        ]
    )


def _cs_fact(address: int) -> SegmentStackRestoreFact8616:
    """Build one Alias-refused terminal far-frame CS restore candidate."""
    return SegmentStackRestoreFact8616(
        block_addr=0x1000,
        restore_instruction_addr=address,
        restore_register="cs",
        saved_instruction_addr=None,
        saved_register=None,
        stack_offsets=(),
        verdict=SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
    )


def _cs_state_assignment(codegen: object, address: int = RETF_ADDR) -> CAssignment:
    """Build one runtime segment-state CS carrier assignment."""
    lhs = CVariable(
        SimMemoryVariable(
            0x10000,
            2,
            name="inertia_cs",
            ident="inertia_cs",
            region=0x1000,
            category="inertia_segment_state",
        ),
        variable_type=VALUE_TYPE,
        codegen=codegen,
    )
    return CAssignment(
        lhs,
        CConstant(1, VALUE_TYPE, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": address},
    )


def _plain_assignment(codegen: object, address: int) -> CAssignment:
    """Build one non-CS structured assignment carrier."""
    return CAssignment(
        CConstant(0, VALUE_TYPE, codegen=codegen),
        CConstant(1, VALUE_TYPE, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": address},
    )


def _attach(
    codegen: SimpleNamespace,
    *,
    facts: tuple[SegmentStackRestoreFact8616, ...],
    statements: Any,
    terminal_rets: tuple[int, ...] = (RETF_ADDR,),
) -> None:
    """Attach the artifact surfaces consumed by the far-return boundary pass."""
    codegen.cfunc = SimpleNamespace(statements=statements)
    codegen._inertia_segment_stack_restore_artifact = SegmentStackRestoreArtifact8616(
        facts=facts
    )
    codegen._inertia_vex_ir_artifact = _terminal_ret_artifact(*terminal_rets)


@pytest.mark.parametrize("nested", [False, True])
def test_terminal_far_cs_carrier_is_consumed(nested: bool) -> None:
    """Complete terminal far evidence removes exactly the CS frame carrier."""
    codegen = _codegen()
    carrier = _cs_state_assignment(codegen)
    unrelated = _plain_assignment(codegen, 0x1004)
    body = CStatements([unrelated, carrier], codegen=codegen)
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=body,
    )
    if nested:
        codegen.cfunc.statements = CStatements(
            [
                CSwitchCase(
                    CConstant(1, VALUE_TYPE, codegen=codegen),
                    [(1, body)],
                    None,
                    codegen=codegen,
                )
            ],
            codegen=codegen,
        )
    project = _project({RETF_ADDR: _far_cleanup_evidence()})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is True
    assert body.statements == [unrelated]
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.already_materialized_count == 0
    assert stats.removed_assignment_count == 1
    assert stats.refusals == ()
    assert stats.closed
    assert codegen._inertia_far_return_boundary_consumed_restores_8616 == frozenset({RETF_ADDR})


def test_consumed_far_boundary_is_idempotent_and_reprunes_rebuilds() -> None:
    """Absent carriers are stable; rebuilt carriers are consumed again."""
    codegen = _codegen()
    carrier = _cs_state_assignment(codegen)
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=CStatements([carrier], codegen=codegen),
    )
    project = _project({RETF_ADDR: _far_cleanup_evidence()})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is True
    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.materialized_count == 0
    assert stats.already_materialized_count == 1
    assert stats.closed

    rebuilt = _cs_state_assignment(codegen)
    codegen.cfunc.statements.statements.append(rebuilt)
    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.materialized_count == 1
    assert stats.already_materialized_count == 0
    assert stats.removed_assignment_count == 1
    assert stats.closed


def test_non_terminal_cs_restore_refuses() -> None:
    """A CS restore that is not a block-terminal RET stays structured."""
    codegen = _codegen()
    carrier = _cs_state_assignment(codegen)
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=CStatements([carrier], codegen=codegen),
        terminal_rets=(0x1002,),
    )
    project = _project({RETF_ADDR: _far_cleanup_evidence()})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    assert codegen.cfunc.statements.statements == [carrier]
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.refusals == ((RETF_ADDR, FarReturnBoundaryRefusal8616.NOT_TERMINAL_RET),)
    assert stats.closed
    assert codegen._inertia_far_return_boundary_consumed_restores_8616 == frozenset()


@pytest.mark.parametrize(
    ("evidence", "refusal"),
    [
        (
            _far_cleanup_evidence(frame_kind=TerminalReturnFrameKind8616.NEAR),
            FarReturnBoundaryRefusal8616.NOT_FAR_RETURN_FRAME,
        ),
        (
            _far_cleanup_evidence(frame_kind=TerminalReturnFrameKind8616.INTERRUPT),
            FarReturnBoundaryRefusal8616.NOT_FAR_RETURN_FRAME,
        ),
        (
            _far_cleanup_evidence(operand_bits=32),
            FarReturnBoundaryRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP,
        ),
        (
            _far_cleanup_evidence(cleanup=2),
            FarReturnBoundaryRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP,
        ),
        (
            TerminalStackCleanupEvidence8616(frozenset({0}), 1, 0, 0, 0, 1),
            FarReturnBoundaryRefusal8616.NOT_FAR_RETURN_FRAME,
        ),
    ],
)
def test_incomplete_terminal_evidence_refuses(
    evidence: TerminalStackCleanupEvidence8616,
    refusal: FarReturnBoundaryRefusal8616,
) -> None:
    """Only one complete 16-bit zero-cleanup far frame may be consumed."""
    codegen = _codegen()
    carrier = _cs_state_assignment(codegen)
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=CStatements([carrier], codegen=codegen),
    )
    project = _project({RETF_ADDR: evidence})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    assert codegen.cfunc.statements.statements == [carrier]
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.refusals == ((RETF_ADDR, refusal),)
    assert stats.materialized_count == 0
    assert stats.closed


def test_absent_carrier_refuses_until_consumed() -> None:
    """A proven boundary with no structured carrier is an explicit refusal."""
    codegen = _codegen()
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=CStatements([_plain_assignment(codegen, 0x1004)], codegen=codegen),
    )
    project = _project({RETF_ADDR: _far_cleanup_evidence()})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.refusals == ((RETF_ADDR, FarReturnBoundaryRefusal8616.CARRIER_ABSENT),)
    assert stats.closed

    codegen._inertia_far_return_boundary_consumed_restores_8616 = frozenset({RETF_ADDR})
    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.refusals == ()
    assert stats.already_materialized_count == 1
    assert stats.closed


@pytest.mark.parametrize("mixed", [False, True])
def test_non_cs_assignment_lhs_refuses(mixed: bool) -> None:
    """Assignments at the boundary that do not carry CS state stay intact."""
    codegen = _codegen()
    other = _plain_assignment(codegen, RETF_ADDR)
    statements = [_cs_state_assignment(codegen), other] if mixed else [other]
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=CStatements(statements, codegen=codegen),
    )
    project = _project({RETF_ADDR: _far_cleanup_evidence()})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    assert codegen.cfunc.statements.statements == statements
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.refusals == ((RETF_ADDR, FarReturnBoundaryRefusal8616.NOT_CS_STATE_CARRIER),)
    assert stats.removed_assignment_count == 0
    assert stats.closed


def test_physical_cs_register_lhs_is_consumed() -> None:
    """A physical architectural CS assignment LHS carries the same state."""
    codegen = _codegen()
    project = _project({RETF_ADDR: _far_cleanup_evidence()})
    cs_offset = next(
        offset
        for offset, name in project.arch.register_names.items()
        if name == "cs"
    )
    carrier = CAssignment(
        CVariable(
            SimRegisterVariable(cs_offset, 2, ident="cs"),
            variable_type=VALUE_TYPE,
            codegen=codegen,
        ),
        CConstant(1, VALUE_TYPE, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": RETF_ADDR},
    )
    _attach(
        codegen,
        facts=(_cs_fact(RETF_ADDR),),
        statements=CStatements([carrier], codegen=codegen),
    )

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is True
    assert codegen.cfunc.statements.statements == []
    assert codegen._inertia_far_return_boundary_carrier_stats_8616.closed


def test_proven_pair_and_missing_artifact_are_not_candidates() -> None:
    """Pair-proven saves and missing surfaces contribute no candidates."""
    codegen = _codegen()
    _attach(
        codegen,
        facts=(
            _cs_fact(RETF_ADDR),
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1008,
                restore_register="cs",
                saved_instruction_addr=0x1002,
                saved_register="cs",
                stack_offsets=(-2, -1),
                verdict=SegmentStackRestoreVerdict8616.PROVEN,
            ),
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x100A,
                restore_register="es",
                saved_instruction_addr=None,
                saved_register=None,
                stack_offsets=(),
                verdict=SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
            ),
        ),
        statements=CStatements([_cs_state_assignment(codegen)], codegen=codegen),
    )
    project = _project({RETF_ADDR: _far_cleanup_evidence()})

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is True
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.closed

    bare = _codegen()
    assert consume_terminal_far_return_boundary_carriers_8616(_project(), bare) is False
    assert not hasattr(bare, "_inertia_far_return_boundary_carrier_stats_8616")


def test_shared_terminal_ret_helper_reads_fake_blocks() -> None:
    """The IR terminal-RET contract stays duck-typed for structured fakes."""
    artifact = _terminal_ret_artifact(0x1000, 0x1006)
    assert terminal_ret_instruction_addrs_8616(artifact) == frozenset({0x1000, 0x1006})
    assert terminal_ret_instruction_addrs_8616(SimpleNamespace()) == frozenset()


def _blob_project(code: bytes) -> Any:
    """Build one real blob project for decode-dependent terminal evidence."""
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )


@pytest.mark.parametrize(
    ("code", "refusal"),
    [
        (b"\xc3", FarReturnBoundaryRefusal8616.NOT_FAR_RETURN_FRAME),
        (b"\xca\x02\x00", FarReturnBoundaryRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
        (b"\x66\xcb", FarReturnBoundaryRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
    ],
)
def test_decoded_terminal_shapes_refuse_or_consume(code: bytes, refusal: Any) -> None:
    """Real decoded RETF shapes gate the boundary carrier by exact evidence."""
    project = _blob_project(code)
    codegen = _codegen()
    carrier = _cs_state_assignment(codegen, address=0x1000)
    _attach(
        codegen,
        facts=(_cs_fact(0x1000),),
        statements=CStatements([carrier], codegen=codegen),
        terminal_rets=(0x1000,),
    )

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is False
    assert codegen.cfunc.statements.statements == [carrier]
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.refusals == ((0x1000, refusal),)
    assert stats.closed


def test_decoded_plain_retf_far_frame_is_consumed() -> None:
    """A real decoded plain RETF proves the far frame and frees the carrier."""
    project = _blob_project(b"\xcb")
    codegen = _codegen()
    carrier = _cs_state_assignment(codegen, address=0x1000)
    _attach(
        codegen,
        facts=(_cs_fact(0x1000),),
        statements=CStatements([carrier], codegen=codegen),
        terminal_rets=(0x1000,),
    )

    assert consume_terminal_far_return_boundary_carriers_8616(project, codegen) is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_far_return_boundary_carrier_stats_8616
    assert stats.materialized_count == 1
    assert stats.closed