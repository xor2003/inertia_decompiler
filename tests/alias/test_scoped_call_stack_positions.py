"""Scoped caller CALL positions — declared-context native controls.

The callsite-keyed overlay proves caller-before, callee-entry and
caller-after SP positions for the fixture's exact near CALL: AX=0 yields a
net-zero caller delta, AX=4 yields -4. The raw artifact is never touched;
every refusal path revokes rather than defaults.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import angr
import pytest

from inertia.alias.call_stack_positions import (
    CallStackPositionRefusal8616,
    prove_call_stack_position_8616,
)
from inertia.alias.scoped_call_stack_context import (
    ScopedCallEntryBinding8616,
    ScopedCallStackContext8616,
    prove_scoped_call_stack_context_8616,
)
from inertia.alias.scoped_call_stack_positions import (
    ScopedCallStackPositionFailure8616,
    ScopedCallStackPositionResult8616,
    prove_scoped_call_stack_position_8616,
    solve_scoped_stack_states_8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.ir.scoped_call_stack_coordinates import IRScopedCallStackCoordinates8616
from inertia.semantics.call_return_segment import ReturnSegmentFrame8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.scoped_call_stack_coordinates import (
    prove_scoped_call_stack_coordinates_8616,
)
from tests.support.scoped_stack_fixture import (
    CALL2_RET_1,
    CALL2_RET_2,
    CALL2_SITE_1,
    CALL2_SITE_2,
    CALLEE,
    CALLEE_LOOP,
    CALLSITE,
    RETURN_ADDR,
    build_scoped_stack_parts_8616,
    scoped_callee_domain_for_callsite_8616,
)

pytestmark = pytest.mark.decompiler


def _call_site(artifact: IRFunctionArtifact) -> tuple[int, int, IRInstr, IRBlock]:
    """Locate (block_addr, instruction_index, call_instr, block) for the CALL."""
    for block in artifact.blocks:
        for index, instruction in enumerate(block.instrs):
            if instruction.op == "CALL":
                return block.addr, index, instruction, block
    raise AssertionError("fixture caller must contain one CALL row")


def _world(
    ax_seed: int,
) -> tuple[
    dict[str, object], IRFunctionArtifact, int, int, IRInstr,
    IRScopedCallStackCoordinates8616, ScopedCallStackContext8616,
]:
    """Build one declared world with carrier, context, and call site."""
    parts = build_scoped_stack_parts_8616(ax_seed, CALLEE_LOOP)
    artifact = parts["caller_artifact"]
    assert isinstance(artifact, IRFunctionArtifact)
    block_addr, index, call_instr, call_block = _call_site(artifact)
    summary = CallsiteSummary8616(
        callsite_addr=CALLSITE, target_addr=CALLEE, return_addr=RETURN_ADDR,
        kind="near", arg_count=0, arg_widths=(), stack_cleanup=None,
        return_register=None, return_used=None,
    )
    carrier = prove_scoped_call_stack_coordinates_8616(
        parts["project"], summary,
        instruction=call_instr, block=call_block,
        return_frame=ReturnSegmentFrame8616(callsite_addr=CALLSITE),
        caller_scope=cast(Real16InvocationDomain8616, parts["caller_domain"]),
        callee_scope=cast(Real16InvocationDomain8616, parts["callee_domain"]),
        coverage=cast(IRBoundaryCoverageResult8616, parts["coverage"]),
    )
    assert carrier.failure is None
    context = prove_scoped_call_stack_context_8616((
        ScopedCallEntryBinding8616(
            carrier,
            cast(Real16InvocationDomain8616, parts["caller_domain"]),
            cast(Real16InvocationDomain8616, parts["callee_domain"]),
        ),
    ))
    assert context is not None
    return parts, artifact, block_addr, index, call_instr, carrier, context


def _prove(
    parts: dict[str, object], artifact: IRFunctionArtifact,
    block_addr: int, index: int, context: ScopedCallStackContext8616,
) -> ScopedCallStackPositionResult8616:
    """Run the scoped position proof under the fixture's retained scopes."""
    return prove_scoped_call_stack_position_8616(
        artifact, block_addr, index,
        cast(Real16InvocationDomain8616, parts["caller_domain"]),
        cast(Real16InvocationDomain8616, parts["callee_domain"]),
        context=context,
    )


def test_scoped_positions_net_zero_ax0(tmp_path: Path) -> None:
    """AX=0: before 0, callee-entry -2, caller-after 0 — net zero caller delta."""
    parts, artifact, block_addr, index, _instr, _carrier, context = _world(0)
    result = _prove(parts, artifact, block_addr, index, context)
    assert result.failure is None
    proof = result.position_for(parts["caller_domain"], parts["callee_domain"])
    assert proof is not None
    assert (proof.caller_before_offset, proof.callee_entry_offset,
            proof.caller_after_offset) == (0, -2, 0)
    assert proof.callsite_addr == CALLSITE and proof.target_addr == CALLEE
    assert proof.return_frame_bytes == 2


def test_scoped_positions_net_minus_four_ax4(tmp_path: Path) -> None:
    """AX=4: caller-after -4; the scoped delta propagates through the solve."""
    parts, artifact, block_addr, index, _instr, _carrier, context = _world(4)
    result = _prove(parts, artifact, block_addr, index, context)
    assert result.failure is None
    proof = result.position_for(parts["caller_domain"], parts["callee_domain"])
    assert proof is not None
    assert (proof.caller_before_offset, proof.callee_entry_offset,
            proof.caller_after_offset) == (0, -2, -4)


def test_downstream_solver_carries_scoped_delta(tmp_path: Path) -> None:
    """The post-call SP persists past the call into the caller's RET block."""
    parts, artifact, _b, _i, _instr, _carrier, context = _world(4)
    states = solve_scoped_stack_states_8616(
        artifact, parts["caller_domain"], context=context)
    assert states is not None
    exits = [addr for addr, state in states.items() if state.sp_delta is not None]
    assert exits
    # The caller's own RET adds its +2 machine pop on top of the -4 delta.
    ret_states = [s.sp_delta for s in states.values() if s.sp_delta is not None]
    assert -2 in ret_states


def test_absent_and_foreign_scopes_refuse(tmp_path: Path) -> None:
    """Missing, mistyped or foreign scopes refuse without a position."""
    parts, artifact, block_addr, index, _instr, _carrier, context = _world(0)
    absent = prove_scoped_call_stack_position_8616(
        artifact, block_addr, index, None, None, context=context)
    assert absent.failure is ScopedCallStackPositionFailure8616.SCOPE_ABSENT
    parts_b, _a2, _b2, _i2, _x, _c, _ctx_b = _world(0)
    result = _prove(parts, artifact, block_addr, index, context)
    assert result.failure is None
    assert result.complete_for(parts_b["caller_domain"], parts["callee_domain"]) is False
    assert result.position_for(parts_b["caller_domain"], parts_b["callee_domain"]) is None


def test_unbound_callsite_refuses(tmp_path: Path) -> None:
    """A context without this callsite's binding refuses, never guesses."""
    parts, artifact, block_addr, index, _instr, _carrier, _ctx = _world(0)
    empty = prove_scoped_call_stack_context_8616(())
    assert empty is not None
    refused = prove_scoped_call_stack_position_8616(
        artifact, block_addr, index,
        cast(Real16InvocationDomain8616, parts["caller_domain"]),
        cast(Real16InvocationDomain8616, parts["callee_domain"]),
        context=empty,
    )
    assert refused.failure is ScopedCallStackPositionFailure8616.CONTEXT_UNBOUND


def test_wrong_call_identity_refuses(tmp_path: Path) -> None:
    """A carrier bound to different coordinates refuses the physical match."""
    parts, artifact, block_addr, index, _instr, carrier, _ctx = _world(0)
    assert carrier.coordinates is not None
    forged = replace(
        carrier.coordinates,
        callsite_addr=CALLSITE + 1, source=None,
    )
    bad_carrier = replace(carrier, coordinates=forged)
    context = prove_scoped_call_stack_context_8616((
        ScopedCallEntryBinding8616(
            bad_carrier,
            cast(Real16InvocationDomain8616, parts["caller_domain"]),
            cast(Real16InvocationDomain8616, parts["callee_domain"]),
        ),
    ))
    # Forged carrier's own callsite no longer matches the CALL either way.
    result = prove_scoped_call_stack_position_8616(
        artifact, block_addr, index,
        cast(Real16InvocationDomain8616, parts["caller_domain"]),
        cast(Real16InvocationDomain8616, parts["callee_domain"]),
        context=cast(ScopedCallStackContext8616, context),
    )
    assert result.failure is not None


def test_source_byte_drift_revokes_position(tmp_path: Path) -> None:
    """In-place mutation on the original surface revokes the projection."""
    parts, artifact, block_addr, index, _instr, _carrier, context = _world(0)
    result = _prove(parts, artifact, block_addr, index, context)
    assert result.position_for(parts["caller_domain"], parts["callee_domain"]) is not None
    project = cast(angr.Project, parts["project"])
    project.loader.memory.store(0x1076, b"\x2b\xd9")
    assert bytes(project.loader.memory.load(0x1076, 2)) == b"\x2b\xd9"
    assert result.position_for(parts["caller_domain"], parts["callee_domain"]) is None
    assert result.complete_for(parts["caller_domain"], parts["callee_domain"]) is False


def test_raw_artifact_and_universal_path_unchanged(tmp_path: Path) -> None:
    """The scoped overlay leaves the raw artifact and universal proof alone."""
    parts, artifact, block_addr, index, _instr, _carrier, context = _world(0)
    refusals_before = tuple(
        (block.addr, tuple(r.kind for r in block.refusals))
        for block in artifact.blocks
    )
    universal = prove_call_stack_position_8616(artifact, block_addr, index)
    scoped = _prove(parts, artifact, block_addr, index, context)
    assert scoped.failure is None
    assert scoped.complete is False
    assert scoped.position_for(None, None) is None
    assert universal.refusal is CallStackPositionRefusal8616.UNPROVEN_EFFECT
    refusals_after = tuple(
        (block.addr, tuple(r.kind for r in block.refusals))
        for block in artifact.blocks
    )
    assert refusals_after == refusals_before
    for block in artifact.blocks:
        for instr in block.instrs:
            effect = instr.call_stack_effect
            if effect is not None:
                assert effect.scoped_coordinates is None


def test_forged_result_fields_revoked(tmp_path: Path) -> None:
    """Fabricated retained proof/counters fail the re-run check on access."""
    parts, artifact, block_addr, index, _instr, _carrier, context = _world(0)
    result = _prove(parts, artifact, block_addr, index, context)
    assert result.failure is None and result.proof is not None
    forged = replace(
        result.proof,
        caller_after_offset=result.proof.caller_after_offset + 2,
    )
    forged_result = replace(result, proof=forged)
    assert forged_result.position_for(
        parts["caller_domain"], parts["callee_domain"]) is None
    forged_counts = replace(result, materialized_count=9)
    assert forged_counts.complete_for(
        parts["caller_domain"], parts["callee_domain"]) is False


def test_foreign_artifact_refuses_overlay(tmp_path: Path) -> None:
    """World-A authority must never apply to world-B's raw artifact."""
    parts_a, _art_a, _b_a, _i_a, _x_a, _c_a, context_a = _world(4)
    _parts_b, artifact_b, block_b, index_b, _x_b, _c_b, _ctx_b = _world(0)
    states = solve_scoped_stack_states_8616(
        artifact_b,
        cast(Real16InvocationDomain8616, parts_a["caller_domain"]),
        context=context_a,
    )
    assert states is None, "foreign raw artifact accepted another world's overlay"
    scoped = prove_scoped_call_stack_position_8616(
        artifact_b, block_b, index_b,
        cast(Real16InvocationDomain8616, parts_a["caller_domain"]),
        cast(Real16InvocationDomain8616, parts_a["callee_domain"]),
        context=context_a,
    )
    assert scoped.failure is not None, "foreign artifact produced a position"


def _carrier_for_call(
    parts: dict[str, object], artifact: IRFunctionArtifact,
    callsite: int, return_addr: int,
    caller_scope: object, callee_scope: object,
    coverage: object | None = None,
) -> IRScopedCallStackCoordinates8616:
    """Build the scoped carrier bound to one exact callsite row."""
    call_instr = call_block = None
    for block in artifact.blocks:
        for instr in block.instrs:
            if instr.op == "CALL" and instr.addr == callsite:
                call_instr, call_block = instr, block
    assert call_instr is not None
    summary = CallsiteSummary8616(
        callsite_addr=callsite, target_addr=CALLEE, return_addr=return_addr,
        kind="near", arg_count=0, arg_widths=(), stack_cleanup=None,
        return_register=None, return_used=None,
    )
    carrier = prove_scoped_call_stack_coordinates_8616(
        cast(angr.Project, parts["project"]), summary,
        instruction=call_instr, block=call_block,
        return_frame=ReturnSegmentFrame8616(callsite_addr=callsite),
        caller_scope=cast(Real16InvocationDomain8616, caller_scope),
        callee_scope=cast(Real16InvocationDomain8616, callee_scope),
        coverage=cast(
            IRBoundaryCoverageResult8616,
            parts["coverage"] if coverage is None else coverage,
        ),
    )
    assert carrier.failure is None
    return carrier


def test_two_calls_each_bind_own_scope(tmp_path: Path) -> None:
    """Two physical calls each consume their own authenticated domains."""
    parts = build_scoped_stack_parts_8616(4, CALLEE_LOOP, two_calls=True)
    artifact = parts["caller_artifact"]
    parent2, callee2, coverage2 = scoped_callee_domain_for_callsite_8616(
        parts, CALL2_SITE_2)
    carrier1 = _carrier_for_call(
        parts, artifact, CALL2_SITE_1, CALL2_RET_1,
        parts["caller_domain"], parts["callee_domain"])
    carrier2 = _carrier_for_call(
        parts, artifact, CALL2_SITE_2, CALL2_RET_2, parent2, callee2,
        coverage=coverage2)
    context = prove_scoped_call_stack_context_8616((
        ScopedCallEntryBinding8616(
            carrier1, cast(Real16InvocationDomain8616, parts["caller_domain"]),
            cast(Real16InvocationDomain8616, parts["callee_domain"])),
        ScopedCallEntryBinding8616(
            carrier2, cast(Real16InvocationDomain8616, parent2),
            cast(Real16InvocationDomain8616, callee2)),
    ))
    assert context is not None
    states = solve_scoped_stack_states_8616(
        artifact, parts["caller_domain"], context=context)
    assert states is not None
    # Each disjoint call block applies its own -4 delta; the shared RET
    # block joins to the common post-call coordinate, not a guessed sum.
    deltas = {addr: state.sp_delta for addr, state in states.items()
              if state.sp_delta is not None}
    assert -4 in deltas.values()
    site2_block = next(
        block.addr for block in artifact.blocks
        if any(ins.addr == CALL2_SITE_2 for ins in block.instrs))
    assert deltas[site2_block] == -4
    ret_addr = next(
        block.addr for block in artifact.blocks
        if any(ins.op == "RET" for ins in block.instrs))
    assert deltas[ret_addr] == -2
    site2_index = next(
        i for block in artifact.blocks if block.addr == site2_block
        for i, ins in enumerate(block.instrs)
        if ins.op == "CALL" and ins.addr == CALL2_SITE_2)
    result = prove_scoped_call_stack_position_8616(
        artifact, site2_block, site2_index,
        cast(Real16InvocationDomain8616, parent2),
        cast(Real16InvocationDomain8616, callee2), context=context)
    assert result.failure is None
    proof = result.position_for(parent2, callee2)
    assert proof is not None
    assert (proof.caller_before_offset, proof.callee_entry_offset,
            proof.caller_after_offset) == (0, -2, -4)


def test_foreign_secondary_call_refuses(tmp_path: Path) -> None:
    """A valid foreign binding refuses beside a same-world one — no mixing."""
    parts = build_scoped_stack_parts_8616(0, CALLEE_LOOP, two_calls=True)
    artifact = parts["caller_artifact"]
    parent2, callee2, coverage2 = scoped_callee_domain_for_callsite_8616(
        parts, CALL2_SITE_2)
    carrier1 = _carrier_for_call(
        parts, artifact, CALL2_SITE_1, CALL2_RET_1,
        parts["caller_domain"], parts["callee_domain"])
    parts_b, _a2, _b2, _i2, _x2, carrier_b, _ctx_b = _world(0)
    context = prove_scoped_call_stack_context_8616((
        ScopedCallEntryBinding8616(
            carrier1, cast(Real16InvocationDomain8616, parts["caller_domain"]),
            cast(Real16InvocationDomain8616, parts["callee_domain"])),
        ScopedCallEntryBinding8616(
            carrier_b, cast(Real16InvocationDomain8616, parts_b["caller_domain"]),
            cast(Real16InvocationDomain8616, parts_b["callee_domain"])),
    ))
    # Foreign binding may be context-admissible in shape but must never
    # project inside this caller execution.
    assert context is None or solve_scoped_stack_states_8616(
        artifact, parts["caller_domain"], context=context) is None
    # The same-world second call still proves alone once bound correctly.
    carrier2 = _carrier_for_call(
        parts, artifact, CALL2_SITE_2, CALL2_RET_2, parent2, callee2,
        coverage=coverage2)
    context2 = prove_scoped_call_stack_context_8616((
        ScopedCallEntryBinding8616(
            carrier1, cast(Real16InvocationDomain8616, parts["caller_domain"]),
            cast(Real16InvocationDomain8616, parts["callee_domain"])),
        ScopedCallEntryBinding8616(
            carrier2, cast(Real16InvocationDomain8616, parent2),
            cast(Real16InvocationDomain8616, callee2)),
    ))
    assert context2 is not None
    assert solve_scoped_stack_states_8616(
        artifact, parts["caller_domain"], context=context2) is not None
