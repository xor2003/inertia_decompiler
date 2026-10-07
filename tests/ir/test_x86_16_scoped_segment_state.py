"""Synthetic boundary controls for scoped segment-state CFG transport.

Layer: tests.
Responsibility: pin the steps 3-4 contract of the scoped-view design —
``solve_segment_state_8616`` consuming the authenticated effective CFG and
``SegmentStateArtifact`` retaining the explicit scoped condition — with real
typed objects. Domain ``complete`` re-derivation and both preservation
verdicts are patched at the documented class-level unit boundary so the
typed scope/dependency plumbing runs without the native census. Nothing
here claims native proof; the parent owns that slot.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
import inertia.ir.entry_domain_call_preservation as edcp
import inertia.ir.entry_jump_domain as ejd
import inertia.ir.real16_invocation_domain as domain
import inertia.ir.scoped_function_ir_view as view_mod
import inertia.ir.segment_call_preservation as scp
import inertia.ir.segment_effect_closure as sce
import inertia.ir.segment_state as state_mod
import inertia.ir.segment_state_solver as solver_mod
from inertia.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from inertia.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
)
from inertia.ir.ssa_function import (
    SSAFunctionArtifact,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.relative_control_edge import (
    DecodedRelativeEdge,
    decode_relative_edge,
)

FUNC = 0x10000
MOV_HEAD = 0x10004
CALL_HEAD = 0x10008
JMP_HEAD = 0x10010
ISLAND = 0x10018
SECOND = 0x10020
CALLEE = 0x11000
CALLER_ADDR = 0x9000
PENDING_KIND = "terminal_jump_selector_window_unproved"
SEGMENT_WRITE_SOURCE = hex(0x2345)


def _jmp_pending(head: int, encoding: bytes, block_addr: int = FUNC) -> object:
    """Decode one pending terminal jump candidate from exact bytes."""
    decoded = decode_relative_edge(head, encoding)
    assert type(decoded) is DecodedRelativeEdge
    return ejd.PendingTerminalJump8616(block_addr=block_addr, decoded=decoded)


def _caller_surface(
    project: object,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616, object]:
    """Build one registered refusal-free caller surface for the parent."""
    caller = IRFunctionArtifact(
        CALLER_ADDR,
        (
            IRBlock(
                CALLER_ADDR,
                instrs=(
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=FUNC, size=2),),
                        addr=CALLER_ADDR,
                    ),
                    IRInstr("RET", None, (), addr=CALLER_ADDR + 3),
                ),
            ),
        ),
    )
    publish_function_ir_artifact_8616(project, caller)
    boundary = ExactFunctionRangeBoundary8616(
        project,
        CALLER_ADDR,
        4,
        frozenset({CALLER_ADDR}),
        frozenset({CALLER_ADDR, CALLER_ADDR + 3}),
        (),
    )
    coverage = prove_ir_boundary_coverage_8616(project, boundary, caller)
    assert coverage.complete
    return caller, boundary, coverage


def _domain(
    boot: object,
    *,
    coverage: object | None,
    chain: object | None,
    callsite_addr: int,
    kind: object,
    path: tuple[int, ...],
    project: object,
) -> object:
    """Build one typed invocation-domain record at the unit boundary."""
    return domain.Real16InvocationDomain8616(
        coverage=coverage,
        boot=boot,
        boot_recompute=None,
        callsite_addr=callsite_addr,
        entry_segment=0x1000,
        entry_offset=0,
        stack_segment=0x2000,
        stack_offset=0xFFFE,
        load_segment=0x1000,
        source_sha256="synthetic-entry",
        minimum_selector=0x15,
        maximum_selector=0x1014,
        kind=kind,
        path_block_addrs=path,
        fetched_range_count=len(path),
        checked_store_count=0,
        assumptions=(),
        call_preservations=(),
        failure=None,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        project=project,
        chain=chain,
    )


def _scope_for(
    project: object,
    boot: object,
    caller_pack: tuple,
    source: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    callsite_addr: int = JMP_HEAD,
) -> object:
    """Build the in-flight chained entry owning ``source``/``boundary``."""
    caller, caller_boundary, caller_cov = caller_pack
    entry = DecodedDirectCallsite8616(
        CALLER_ADDR, (SimpleNamespace(address=CALLER_ADDR),), 0,
        CALLER_ADDR, FUNC,
    )
    index = DecodedDirectCallsiteIndex8616(
        {FUNC: (entry,)}, DecodedDirectCallsiteIndexStats8616(1, 1, 1, 1, 0)
    )
    parent = _domain(
        boot,
        coverage=caller_cov,
        chain=None,
        callsite_addr=CALLER_ADDR,
        kind=domain.Real16InvocationKind8616.BOOT_ENTRY_PATH,
        path=(CALLER_ADDR,),
        project=project,
    )
    link = domain.Real16CallChainLink8616(
        parent=parent,
        callsite_index=index,
        callsite=entry,
        callsite_artifact=caller,
        callsite_boundary=caller_boundary,
        call_state=(("cs", 0x1000), ("ss", 0x2000), ("sp", 0xFFFE)),
        callee_artifact=source,
        callee_boundary=boundary,
    )
    scope = _domain(
        boot,
        coverage=None,
        chain=link,
        callsite_addr=callsite_addr,
        kind=domain.Real16InvocationKind8616.CALL_CHAINED,
        path=tuple(sorted(boundary.block_addrs_set)),
        project=project,
    )
    return scope, link, index


def _call_record(
    source: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    block: IRBlock,
    instruction: IRInstr,
    index: object,
    scope: object,
) -> object:
    """Build the typed conditional callsite record for the source CALL."""
    return edcp.EntryDomainCallPreservation8616(
        source, boundary, block, instruction, index, None, None, None,
        CALL_HEAD, CALLEE, None, 1, 1, 1, 1, 0, invocation_scope=scope,
    )


def _proof(
    source: IRFunctionArtifact,
    pending: tuple,
    admitted: tuple,
    refusals: tuple,
    records: tuple,
    scope: object | None,
) -> object:
    """Build the typed entry-domain proof bound to ``source``."""
    binding = ejd.EntryJumpDomainSourceBinding8616(
        function_addr=source.function_addr,
        block_count=len(source.blocks),
        digest=ejd._source_digest_8616(source.function_addr, source.blocks),
        pending=tuple(pending),
    )
    return ejd.EntryJumpDomainProof8616(
        function_addr=source.function_addr,
        source_binding=binding,
        admitted=tuple(admitted),
        refusals=tuple(refusals),
        ledger=(),
        stats=ejd.EntryJumpDomainStats8616(
            len(pending), len(pending), len(admitted) + len(refusals),
            len(admitted), len(refusals),
        ),
        terms_consumed=4,
        iterations=1,
        call_preservations=tuple(records),
        invocation_scope=scope,
    )


def _source(
    *,
    call: bool = False,
    pending_second: bool = False,
    second_edge: bool = False,
) -> tuple:
    """Build the raw in-flight source surface for one variant.

    ``MOV`` writes a constant into ``ds`` so the effective edge's dataflow
    is observable downstream; a ``CALL`` sits between the write and the
    pending ``JMP`` so preservation evidence is load-bearing.
    """
    instrs: list[IRInstr] = []
    named: dict[str, IRInstr] = {}
    named["mov"] = IRInstr(
        "MOV",
        IRValue(MemSpace.REG, name="ds", size=2),
        (IRValue(MemSpace.CONST, const=0x2345, size=2),),
        addr=MOV_HEAD,
    )
    instrs.append(named["mov"])
    if call:
        named["call"] = IRInstr(
            "CALL", None,
            (IRValue(MemSpace.CONST, const=CALLEE, size=2),),
            addr=CALL_HEAD,
        )
        instrs.append(named["call"])
    named["jmp"] = IRInstr(
        "JMP", None, (IRValue(MemSpace.TMP, source_tmp=7, size=4),),
        addr=JMP_HEAD,
    )
    instrs.append(named["jmp"])
    block_a = IRBlock(
        FUNC,
        instrs=tuple(instrs),
        refusals=(
            IRRefusal(PENDING_KIND, "selector window unproved", FUNC),
        ),
        successor_addrs=(),
    )
    island = IRBlock(
        ISLAND,
        instrs=(IRInstr("RET", None, (), addr=ISLAND),),
        successor_addrs=(),
    )
    blocks: list[IRBlock] = [block_a, island]
    if pending_second:
        blocks.append(
            IRBlock(
                SECOND,
                instrs=(
                    IRInstr(
                        "JMP", None,
                        (IRValue(MemSpace.TMP, source_tmp=9, size=4),),
                        addr=SECOND,
                    ),
                ),
                refusals=(
                    IRRefusal(PENDING_KIND, "selector window unproved", SECOND),
                ),
                successor_addrs=(ISLAND,) if second_edge else (),
            )
        )
    return IRFunctionArtifact(FUNC, tuple(blocks)), named


def _boundary(
    project: object, source: IRFunctionArtifact, edges: tuple,
) -> ExactFunctionRangeBoundary8616:
    """Build the exact frontend boundary for one source surface."""
    return ExactFunctionRangeBoundary8616(
        project,
        source.function_addr,
        0x200,
        frozenset(block.addr for block in source.blocks),
        frozenset(
            instr.addr
            for block in source.blocks
            for instr in block.instrs
        ),
        edges,
    )


def _patch_domain_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the documented unit boundary: verdict replay, not plumbing."""
    monkeypatch.setattr(
        domain.Real16InvocationDomain8616, "complete",
        property(lambda self: self.failure is None),
    )
    monkeypatch.setattr(
        edcp.EntryDomainCallPreservation8616, "complete_for",
        lambda self, offered: domain.same_real16_entry_scope_8616(
            offered, self.required_scope
        ),
    )
    monkeypatch.setattr(
        edcp.EntryDomainCallPreservation8616, "preserved_registers_for",
        lambda self, offered: ("cs",) if self.complete_for(offered) else (),
    )


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """One conditional scoped world: pending JMP plus a source-bound CALL."""
    project = SimpleNamespace()
    boot = object()
    caller_pack = _caller_surface(project)
    source, named = _source(call=True)
    boundary = _boundary(project, source, ((FUNC, ISLAND),))
    scope, link, index = _scope_for(
        project, boot, caller_pack, source, boundary
    )
    _patch_domain_boundaries(monkeypatch)
    record = _call_record(
        source, boundary, source.blocks[0], named["call"], index, scope
    )
    dep = ejd._ScopedCallDependency8616(CALL_HEAD, record, scope)
    pending = _jmp_pending(JMP_HEAD, b"\xe9\x05\x00")
    jump = ejd.AdmittedTerminalJump8616(
        FUNC, JMP_HEAD, ISLAND,
        invocation_scope=scope, call_dependencies=(dep,),
    )
    proof = _proof(source, (pending,), (jump,), (), (record,), scope)
    view = view_mod.prove_scoped_function_ir_view_8616(
        source, boundary, proof, invocation_scope=scope,
    )
    assert view.failure is None
    return SimpleNamespace(
        project=project, boot=boot, caller_pack=caller_pack, source=source,
        boundary=boundary, scope=scope, link=link, index=index,
        record=record, dep=dep, pending=pending, jump=jump, proof=proof,
        named=named, view=view,
    )


def _leaf_state(source: IRFunctionArtifact) -> object:
    """Build one universal segment state for callee-side proof plumbing."""
    return state_mod.build_x86_16_segment_state_artifact(source)


def _scoped_call_proof(
    source: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    index: object,
    scope: object,
) -> object:
    """Build the typed scoped leaf-call preservation for the source CALL.

    ``caller`` retains an exact coverage record over the identical raw
    source so ``call_preservation_at_instruction_8616`` binds by object
    identity; the verdict is supplied by the patched class boundary.
    """
    caller_coverage = IRBoundaryCoverageResult8616(
        source, boundary, None, 1, 1, 1, 1, 0,
    )
    closure = sce.SegmentEffectClosureResult8616(
        caller_coverage, _leaf_state(source), None, (), (ISLAND,),
        1, 1, 1, 1, 0,
    )
    return scp.SegmentCallPreservationResult8616(
        caller_coverage, closure, index, CALL_HEAD, None,
        1, 1, 1, 1, 0, invocation_scope=scope,
    )


def test_scoped_state_flows_over_authenticated_edge(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive: the admitted edge feeds predecessors; view+scope retained."""
    proof = _scoped_call_proof(
        world.source, world.boundary, world.index, world.scope
    )
    monkeypatch.setattr(
        scp.SegmentCallPreservationResult8616, "complete_for",
        lambda self, offered: domain.same_real16_entry_scope_8616(
            offered, self.invocation_scope
        ),
    )
    monkeypatch.setattr(
        scp.SegmentCallPreservationResult8616, "preserved_registers_for",
        lambda self, offered: ("cs", "ds") if self.complete_for(offered) else (),
    )
    state = state_mod.build_x86_16_segment_state_artifact(
        world.source,
        call_preservations=(proof,),
        invocation_scope=world.scope,
        scoped_view=world.view,
    )
    # Effective CFG edge: ISLAND's entry joins the admitted predecessor's
    # exit state, so the pre-CALL ``ds`` constant survives through the
    # scoped call proof.
    island_entry = state.state_at_block_entry(ISLAND, "ds")
    assert island_entry is not None
    assert island_entry.origin is SegmentOrigin.PROVEN
    assert island_entry.source == SEGMENT_WRITE_SOURCE
    # The retained condition is the exact supplied view and entry.
    assert state.scoped_view is world.view
    assert state.invocation_scope is world.scope
    assert state.source_artifact is world.source
    assert state.call_preservations == (proof,)
    summary = state.summary
    assert summary["scoped_view_bound"] is True
    assert summary["scoped_discharged_edge_count"] == 1
    assert summary["scoped_pending_block_count"] == 0
    assert summary["call_boundary_count"] == 1
    assert summary["classified_call_count"] == 1
    assert summary["raw_fact_count"] == 2
    assert summary["failure_count"] == 0
    receipt = state.to_dict()
    assert receipt["scoped_view"]["authenticated"] is True
    assert len(receipt["scoped_view"]["applied"]) == 1
    assert receipt["invocation_scope"] is not None
    # The scoped route never implies a universal verdict.
    assert not world.view.complete


def test_universal_route_unchanged_without_view(
    world: SimpleNamespace,
) -> None:
    """The default route still solves the raw CFG and rejects in-flight scope."""
    state = state_mod.build_x86_16_segment_state_artifact(world.source)
    island_entry = state.state_at_block_entry(ISLAND, "ds")
    assert island_entry is not None
    assert island_entry.origin is SegmentOrigin.UNKNOWN
    assert state.scoped_view is None
    assert state.invocation_scope is None
    assert state.summary["scoped_view_bound"] is False
    assert state.summary["scoped_discharged_edge_count"] == 0
    assert state.to_dict()["scoped_view"] is None
    # Supplied SSA over the raw CFG still feeds the universal solve.
    raw_ssa = SSAFunctionArtifact(
        FUNC, (), predecessor_map={FUNC: (), ISLAND: ()},
    )
    again = state_mod.build_x86_16_segment_state_artifact(
        world.source, function_ssa=raw_ssa
    )
    assert again.entry_states[ISLAND]["ds"].origin is SegmentOrigin.UNKNOWN
    # An in-flight scope without registered coverage still refuses the
    # universal route — the scoped route never weakens that check.
    with pytest.raises(ValueError, match="registered IR"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source, invocation_scope=world.scope
        )


def test_scoped_route_requires_independently_supplied_scope(
    world: SimpleNamespace,
) -> None:
    """The retained view scope is never copied to authorize a solve."""
    with pytest.raises(ValueError, match="independently supplied"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source, scoped_view=world.view
        )
    with pytest.raises(ValueError, match="independently supplied"):
        solver_mod.solve_segment_state_8616(
            world.source, None, (), (),
            invocation_scope=None, scoped_view=world.view,
        )
    with pytest.raises(ValueError, match="typed consuming entry"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            invocation_scope=SimpleNamespace(),
            scoped_view=world.view,
        )


def test_scoped_route_rejects_foreign_scope(world: SimpleNamespace) -> None:
    """An authentic-but-different entry cannot consume this view."""
    foreign = replace(world.scope, boot=object())
    with pytest.raises(ValueError):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            invocation_scope=foreign,
            scoped_view=world.view,
        )


def test_scoped_route_rejects_wrong_source(world: SimpleNamespace) -> None:
    """The view must be bound to the identical raw artifact."""
    other_source, _ = _source()
    with pytest.raises(ValueError, match="identical raw IR"):
        state_mod.build_x86_16_segment_state_artifact(
            other_source,
            invocation_scope=world.scope,
            scoped_view=world.view,
        )


def test_scoped_route_rejects_wrong_view(world: SimpleNamespace) -> None:
    """A non-view object and a refused view are both caller errors."""
    with pytest.raises(TypeError, match="typed scoped view owner"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            invocation_scope=world.scope,
            scoped_view=SimpleNamespace(),
        )
    refused = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof, invocation_scope=None,
    )
    assert (
        refused.failure is view_mod.ScopedFunctionIRViewFailure8616.SCOPE_ABSENT
    )
    with pytest.raises(ValueError):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            invocation_scope=world.scope,
            scoped_view=refused,
        )


def test_pending_edge_never_becomes_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A withheld pending successor keeps its hole; raw in-edges still join."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, _named = _source(pending_second=True, second_edge=True)
    boundary = _boundary(
        project, source, ((FUNC, ISLAND), (SECOND, ISLAND))
    )
    scope, _link, _index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
    _patch_domain_boundaries(monkeypatch)
    pending_a = _jmp_pending(JMP_HEAD, b"\xe9\x05\x00")
    pending_b = _jmp_pending(SECOND, b"\xe9\xf5\xff", SECOND)
    jump = ejd.AdmittedTerminalJump8616(FUNC, JMP_HEAD, ISLAND)
    proof = _proof(
        source,
        (pending_a, pending_b),
        (jump,),
        (
            IRRefusal(
                "entry_jump_domain_joint_window_unproved",
                "synthetic residual", SECOND,
            ),
        ),
        (),
        None,
    )
    view = view_mod.prove_scoped_function_ir_view_8616(
        source, boundary, proof, invocation_scope=scope,
    )
    assert view.failure is None
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    assert projection.successors_for(SECOND) is None
    assert projection.predecessors_for(ISLAND) == (FUNC, SECOND)
    state = state_mod.build_x86_16_segment_state_artifact(
        source, invocation_scope=scope, scoped_view=view,
    )
    # SECOND is unreachable in the effective CFG: honest unknowns, and its
    # recorded census in-edge still weakens ISLAND's join — the pending
    # hole is neither deleted nor converted into a proved exit.
    second_entry = state.entry_states[SECOND]
    assert second_entry["ds"].origin is SegmentOrigin.UNKNOWN
    island_entry = state.state_at_block_entry(ISLAND, "ds")
    assert island_entry is not None
    assert island_entry.origin is SegmentOrigin.UNKNOWN
    assert state.summary["scoped_pending_block_count"] == 1
    receipt = state.to_dict()
    assert receipt["scoped_view"]["residual_pending_count"] == 1
    # Without the recorded in-edge the join would have stayed proven.
    narrow, _ = _source(pending_second=True, second_edge=False)
    narrow_boundary = _boundary(project, narrow, ((FUNC, ISLAND),))
    narrow_scope, _l, _i = _scope_for(
        project, object(), caller_pack, narrow, narrow_boundary
    )
    narrow_proof = _proof(
        narrow,
        (pending_a, pending_b),
        (jump,),
        proof.refusals,
        (),
        None,
    )
    narrow_view = view_mod.prove_scoped_function_ir_view_8616(
        narrow, narrow_boundary, narrow_proof, invocation_scope=narrow_scope,
    )
    assert narrow_view.failure is None
    narrow_state = state_mod.build_x86_16_segment_state_artifact(
        narrow, invocation_scope=narrow_scope, scoped_view=narrow_view,
    )
    recovered = narrow_state.state_at_block_entry(ISLAND, "ds")
    assert recovered is not None
    assert recovered.origin is SegmentOrigin.PROVEN
    assert recovered.source == SEGMENT_WRITE_SOURCE


def test_supplied_ssa_must_match_effective_cfg(
    world: SimpleNamespace,
) -> None:
    """A supplied SSA graph is cross-checked, never silently preferred."""
    effective = SSAFunctionArtifact(
        FUNC, (), predecessor_map={FUNC: (), ISLAND: (FUNC,)},
    )
    state = state_mod.build_x86_16_segment_state_artifact(
        world.source,
        function_ssa=effective,
        invocation_scope=world.scope,
        scoped_view=world.view,
    )
    island_entry = state.state_at_block_entry(ISLAND, "ds")
    assert island_entry is not None
    assert island_entry.origin is SegmentOrigin.UNKNOWN
    # Omitted empty entries are tolerated only when they agree.
    sparse = SSAFunctionArtifact(
        FUNC, (), predecessor_map={ISLAND: (FUNC,)},
    )
    also = state_mod.build_x86_16_segment_state_artifact(
        world.source,
        function_ssa=sparse,
        invocation_scope=world.scope,
        scoped_view=world.view,
    )
    assert also.entry_states.keys() == state.entry_states.keys()
    # The raw CFG map conflicts with the effective edge and refuses.
    raw_map = SSAFunctionArtifact(
        FUNC, (), predecessor_map={FUNC: (), ISLAND: ()},
    )
    with pytest.raises(ValueError, match="conflicts"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            function_ssa=raw_map,
            invocation_scope=world.scope,
            scoped_view=world.view,
        )
    # A vacuous supplied map is still a conflicting claim, not a fallback.
    empty = SSAFunctionArtifact(FUNC, (), predecessor_map={})
    with pytest.raises(ValueError, match="conflicts"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            function_ssa=empty,
            invocation_scope=world.scope,
            scoped_view=world.view,
        )
    # A foreign block address in the supplied map refuses outright.
    foreign = SSAFunctionArtifact(
        FUNC, (), predecessor_map={FUNC: (), ISLAND: (FUNC,), 0xDEAD: ()},
    )
    with pytest.raises(ValueError, match="foreign"):
        state_mod.build_x86_16_segment_state_artifact(
            world.source,
            function_ssa=foreign,
            invocation_scope=world.scope,
            scoped_view=world.view,
        )


def test_call_identity_and_condition_retained(world: SimpleNamespace) -> None:
    """CALL accounting binds the original instruction object and the scope."""
    assert world.source.blocks[0].instrs[1] is world.named["call"]
    effective = world.view.effective_blocks_for(world.scope)
    assert effective[0].instrs[1] is not world.named["call"]
    state = state_mod.build_x86_16_segment_state_artifact(
        world.source,
        invocation_scope=world.scope,
        scoped_view=world.view,
    )
    # The unproved CALL is a counted boundary refusal, not a guessed effect.
    assert state.summary["call_boundary_count"] == 1
    assert state.summary["classified_call_count"] == 0
    assert state.summary["failure_count"] == 1
    # Instruction states key on the original instruction coordinates.
    assert CALL_HEAD in state.instruction_entry_states
    assert state.instruction_entry_states[CALL_HEAD]["ds"].source == (
        SEGMENT_WRITE_SOURCE
    )
    assert (
        state.instruction_exit_states[CALL_HEAD]["ds"].origin
        is SegmentOrigin.UNKNOWN
    )
    # The retained objects remain the raw source's, never rebuilt ones.
    assert state.source_artifact.blocks[0].instrs[1] is world.named["call"]
    receipt = state.to_dict()
    assert receipt["source_function_addr"] == FUNC
    assert receipt["call_preservation_sites"] == []
    assert receipt["invocation_scope"]["callsite_addr"] == JMP_HEAD


def test_scoped_projection_retained_on_solution(
    world: SimpleNamespace,
) -> None:
    """The solution carries the one bounded projection the solve consumed."""
    solution = solver_mod.solve_segment_state_8616(
        world.source, None, (), (),
        invocation_scope=world.scope, scoped_view=world.view,
    )
    projection = solution.scoped_projection
    assert projection is not None
    assert projection.source_artifact is world.source
    assert projection.scope is world.scope
    assert projection.applied == world.proof.admitted
    assert projection.predecessors_for(ISLAND) == (FUNC,)
    universal = solver_mod.solve_segment_state_8616(world.source, None, ())
    assert universal.scoped_projection is None
