"""Synthetic contract tests for ``ScopedFunctionIRView8616``.

Layer: tests.
Responsibility: pin the scoped-CFG-view contract with real typed objects.
The only unit boundary is shared with the sibling suite:
``Real16InvocationDomain8616.complete`` re-derivation and the
``EntryDomainCallPreservation8616`` callsite revalidation are patched at
the class level so the typed scope/dependency plumbing runs without the
native census. Native source authentication is a separate parent-owned
slot; nothing here claims native proof.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import entry_jump_domain as ejd
from angr_platforms.X86_16.ir import real16_invocation_domain as domain
from angr_platforms.X86_16.ir import scoped_function_ir_view as view_mod
from angr_platforms.X86_16.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.relative_control_edge import (
    DecodedRelativeEdge,
    decode_relative_edge,
)

FUNC = 0x10000
CALL_HEAD = 0x10000
JMP_HEAD = 0x10010
ISLAND = 0x10018
FAR_ISLAND = 0x10140
SECOND = 0x10020
CALLEE = 0x11000
CALLER_ADDR = 0x9000
PENDING_KIND = "terminal_jump_selector_window_unproved"


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
    call: bool = True,
    far: bool = False,
    second_pending: bool = False,
    alien_refusal: bool = False,
) -> tuple:
    """Build the raw in-flight source surface for one variant."""
    instrs: list[IRInstr] = []
    if call:
        instrs.append(
            IRInstr(
                "CALL", None,
                (IRValue(MemSpace.CONST, const=CALLEE, size=2),),
                addr=CALL_HEAD,
            )
        )
    instrs.append(
        IRInstr(
            "JMP", None, (IRValue(MemSpace.TMP, source_tmp=7, size=4),),
            addr=JMP_HEAD,
        )
    )
    block_a = IRBlock(
        FUNC,
        instrs=tuple(instrs),
        refusals=(
            IRRefusal(PENDING_KIND, "selector window unproved", FUNC),
        ),
        successor_addrs=(),
    )
    target = FAR_ISLAND if far else ISLAND
    island = IRBlock(
        target,
        instrs=(IRInstr("RET", None, (), addr=target),),
        refusals=(
            (IRRefusal("alias_recovery_unknown", "synthetic", target),)
            if alien_refusal
            else ()
        ),
        successor_addrs=(),
    )
    blocks: list[IRBlock] = [block_a, island]
    if second_pending:
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
                successor_addrs=(),
            )
        )
    return IRFunctionArtifact(FUNC, tuple(blocks)), tuple(instrs)


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


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """One conditional scoped world: pending JMP plus a source-bound CALL."""
    project = SimpleNamespace()
    boot = object()
    caller_pack = _caller_surface(project)
    source, instrs = _source(call=True)
    boundary = _boundary(project, source, ((FUNC, ISLAND),))
    scope, link, index = _scope_for(
        project, boot, caller_pack, source, boundary
    )
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
    record = _call_record(
        source, boundary, source.blocks[0], instrs[0], index, scope
    )
    dep = ejd._ScopedCallDependency8616(CALL_HEAD, record, scope)
    pending = _jmp_pending(JMP_HEAD, b"\xe9\x05\x00")
    jump = ejd.AdmittedTerminalJump8616(
        FUNC, JMP_HEAD, ISLAND,
        invocation_scope=scope, call_dependencies=(dep,),
    )
    proof = _proof(source, (pending,), (jump,), (), (record,), scope)
    return SimpleNamespace(
        project=project, boot=boot, caller_pack=caller_pack, source=source,
        boundary=boundary, scope=scope, link=link, index=index,
        record=record, dep=dep, pending=pending, jump=jump, proof=proof,
        call_instr=instrs[0],
    )


def test_conditional_view_completes_under_authenticated_entry(
    world: SimpleNamespace,
) -> None:
    """Positive: scope + CALL census + admitted edge all revalidate."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert view.failure is None
    assert view.complete_for(world.scope)
    assert not view.complete
    assert not view.complete_for(None)
    assert view.effective_successors_for(world.scope, FUNC) == (ISLAND,)
    assert view.effective_predecessors_for(world.scope, ISLAND) == (FUNC,)
    assert view.effective_predecessors_for(world.scope, FUNC) == ()
    assert view.effective_successors_for(world.scope, ISLAND) == ()
    assert view.applied_jumps_for(world.scope) == world.proof.admitted
    # The original instruction objects stay the binding surface; the
    # admitted block is rebuilt by the application owner, so its CALL is
    # a reconstructed equal, never the retained identity.
    assert view.source_block(FUNC) is world.source.blocks[0]
    assert view.source_block(FUNC).instrs[0] is world.call_instr
    effective = view.effective_blocks_for(world.scope)
    assert effective[0].instrs[0] == world.call_instr
    assert effective[0].instrs[0] is not world.call_instr
    assert effective[0].successor_addrs == (ISLAND,)
    assert effective[0].refusals == ()
    assert effective[1] is world.source.blocks[1]
    receipt = view.to_dict()
    assert receipt["authenticated"] is True
    assert receipt["application_status"] == "applied"
    assert len(receipt["applied"]) == 1
    assert receipt["residual_pending_count"] == 0


def test_bulk_cfg_projection_validates_once(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One consumer operation replays admission once, not per block."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert view.failure is None
    replays = 0
    real_apply = view_mod.apply_entry_jump_domain_8616

    def counting_apply(*args: object, **kwargs: object) -> object:
        nonlocal replays
        replays += 1
        return real_apply(*args, **kwargs)

    monkeypatch.setattr(
        view_mod, "apply_entry_jump_domain_8616", counting_apply
    )
    projection = view.cfg_projection_for(world.scope)
    assert projection is not None
    assert replays == 1
    # Every block lookup is served from the single bounded result — the
    # projection is evidence only under the authenticated entry.
    assert projection.scope is world.scope
    assert projection.source_artifact is world.source
    assert projection.function_addr == FUNC
    assert projection.applied == world.proof.admitted
    assert projection.successors_for(FUNC) == (ISLAND,)
    assert projection.predecessors_for(ISLAND) == (FUNC,)
    assert projection.predecessors_for(FUNC) == ()
    assert projection.successors_for(ISLAND) == ()
    assert projection.pending_for(FUNC) == ()
    assert projection.pending_for(ISLAND) == ()
    assert projection.block_for(ISLAND) is world.source.blocks[1]
    assert replays == 1
    assert view.cfg_projection_for(None) is None
    foreign = replace(world.scope, boot=object())
    assert view.cfg_projection_for(foreign) is None


def test_bulk_projection_absent_block_is_typed_unknown(
    world: SimpleNamespace,
) -> None:
    """An address outside the census is typed unknown, never an exit."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    projection = view.cfg_projection_for(world.scope)
    assert projection is not None
    assert projection.successors_for(0xDEAD) is None
    assert projection.predecessors_for(0xDEAD) is None
    assert projection.pending_for(0xDEAD) is None
    assert projection.block_for(0xDEAD) is None
    assert view.effective_successors_for(world.scope, 0xDEAD) is None
    assert view.effective_predecessors_for(world.scope, 0xDEAD) is None


def test_window_unconditional_view_still_requires_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A window-discharged admission still needs an authenticated entry."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, _instrs = _source(call=False)
    boundary = _boundary(project, source, ((FUNC, ISLAND),))
    scope, _link, _index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
    monkeypatch.setattr(
        domain.Real16InvocationDomain8616, "complete",
        property(lambda self: self.failure is None),
    )
    pending = _jmp_pending(JMP_HEAD, b"\xe9\x05\x00")
    jump = ejd.AdmittedTerminalJump8616(FUNC, JMP_HEAD, ISLAND)
    proof = _proof(source, (pending,), (jump,), (), (), None)
    view = view_mod.prove_scoped_function_ir_view_8616(
        source, boundary, proof, invocation_scope=scope,
    )
    assert view.failure is None
    assert view.complete_for(scope)
    assert not view.complete
    assert view.effective_successors_for(scope, FUNC) == (ISLAND,)
    assert view.effective_successors_for(None, FUNC) is None


def test_absent_consuming_scope_refuses(world: SimpleNamespace) -> None:
    """No independently supplied entry: the view records a typed refusal."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof, invocation_scope=None,
    )
    assert view.failure is view_mod.ScopedFunctionIRViewFailure8616.SCOPE_ABSENT
    assert not view.complete_for(world.scope)
    assert view.effective_blocks_for(world.scope) is None
    assert view.applied_jumps_for(world.scope) is None


def test_foreign_consuming_entry_refuses(world: SimpleNamespace) -> None:
    """A different authentic entry never authorizes this view."""
    foreign = replace(world.scope, boot=object())
    refused = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=foreign,
    )
    assert (
        refused.failure
        is view_mod.ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED
    )
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert not view.complete_for(foreign)
    assert view.effective_successors_for(foreign, FUNC) is None


def test_scope_not_owning_source_refuses(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authentic entry for another surface cannot consume this source."""
    other_source, _ = _source(call=False)
    other_boundary = _boundary(world.project, other_source, ())
    foreign_link = replace(
        world.link,
        callee_artifact=other_source,
        callee_boundary=other_boundary,
    )
    foreign_scope = replace(world.scope, chain=foreign_link)
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=foreign_scope,
    )
    assert (
        view.failure is view_mod.ScopedFunctionIRViewFailure8616.SCOPE_UNBOUND
    )
    assert not view.complete_for(foreign_scope)


def test_changed_admitted_target_refuses(world: SimpleNamespace) -> None:
    """A retargeted admission fails the proof's own replay."""
    forged = replace(
        world.proof,
        admitted=(replace(world.jump, target=ISLAND + 0x10),),
    )
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, forged,
        invocation_scope=world.scope,
    )
    assert (
        view.failure
        is view_mod.ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED
    )
    assert not view.complete_for(world.scope)


def test_premise_discharged_view_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A premise-discharged far target applies under the real gate."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, instrs = _source(call=True, far=True)
    boundary = _boundary(project, source, ((FUNC, FAR_ISLAND),))
    scope, _link, index = _scope_for(
        project, object(), caller_pack, source, boundary,
        callsite_addr=JMP_HEAD,
    )
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
    record = _call_record(
        source, boundary, source.blocks[0], instrs[0], index, scope
    )
    dep = ejd._ScopedCallDependency8616(CALL_HEAD, record, scope)
    pending = _jmp_pending(JMP_HEAD, b"\xe9\x2d\x01")
    jump = ejd.AdmittedTerminalJump8616(
        FUNC, JMP_HEAD, FAR_ISLAND,
        invocation=scope, invocation_scope=scope, call_dependencies=(dep,),
    )
    proof = _proof(source, (pending,), (jump,), (), (record,), scope)
    view = view_mod.prove_scoped_function_ir_view_8616(
        source, boundary, proof, invocation_scope=scope,
    )
    assert view.failure is None
    assert view.complete_for(scope)
    assert view.effective_successors_for(scope, FUNC) == (FAR_ISLAND,)


def test_premise_from_foreign_entry_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A premise that is not the common entry cannot redischarge."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, instrs = _source(call=True, far=True)
    boundary = _boundary(project, source, ((FUNC, FAR_ISLAND),))
    scope, _link, index = _scope_for(
        project, object(), caller_pack, source, boundary,
        callsite_addr=JMP_HEAD,
    )
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
    record = _call_record(
        source, boundary, source.blocks[0], instrs[0], index, scope
    )
    dep = ejd._ScopedCallDependency8616(CALL_HEAD, record, scope)
    pending = _jmp_pending(JMP_HEAD, b"\xe9\x2d\x01")
    jump = ejd.AdmittedTerminalJump8616(
        FUNC, JMP_HEAD, FAR_ISLAND,
        invocation=replace(scope, boot=object()),
        invocation_scope=scope, call_dependencies=(dep,),
    )
    proof = _proof(source, (pending,), (jump,), (), (record,), scope)
    view = view_mod.prove_scoped_function_ir_view_8616(
        source, boundary, proof, invocation_scope=scope,
    )
    assert (
        view.failure
        is view_mod.ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED
    )


def test_dropped_call_dependency_refuses(world: SimpleNamespace) -> None:
    """Losing a retained dependency fails the source CALL census."""
    forged = replace(
        world.proof,
        admitted=(replace(world.jump, call_dependencies=()),),
    )
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, forged,
        invocation_scope=world.scope,
    )
    assert (
        view.failure
        is view_mod.ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED
    )


def test_stale_source_refuses(
    world: SimpleNamespace,
) -> None:
    """A body the proof never consumed fails the source binding digest."""
    stale_block = replace(
        world.source.blocks[0],
        instrs=(
            world.call_instr,
            replace(
                world.source.blocks[0].instrs[1],
                args=(IRValue(MemSpace.TMP, source_tmp=11, size=4),),
            ),
        ),
    )
    stale_source = replace(world.source, blocks=(stale_block, *world.source.blocks[1:]))
    stale_link = replace(
        world.link,
        callee_artifact=stale_source,
        callee_boundary=world.boundary,
    )
    stale_scope = replace(world.scope, chain=stale_link)
    view = view_mod.prove_scoped_function_ir_view_8616(
        stale_source, world.boundary, world.proof,
        invocation_scope=stale_scope,
    )
    assert (
        view.failure
        is view_mod.ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED
    )


def test_foreign_extra_block_refuses(world: SimpleNamespace) -> None:
    """A source census the proof never covered is stale input."""
    extra = IRBlock(
        SECOND,
        instrs=(IRInstr("RET", None, (), addr=SECOND),),
    )
    bloated = replace(
        world.source, blocks=(*world.source.blocks, extra)
    )
    bloated_boundary = _boundary(world.project, bloated, ())
    bloated_link = replace(
        world.link,
        callee_artifact=bloated,
        callee_boundary=bloated_boundary,
    )
    bloated_scope = replace(world.scope, chain=bloated_link)
    view = view_mod.prove_scoped_function_ir_view_8616(
        bloated, bloated_boundary, world.proof,
        invocation_scope=bloated_scope,
    )
    assert (
        view.failure
        is view_mod.ScopedFunctionIRViewFailure8616.APPLICATION_REFUSED
    )


def test_unrelated_refusal_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-window refusal surviving the delta refuses the whole view."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, instrs = _source(call=True, alien_refusal=True)
    boundary = _boundary(project, source, ((FUNC, ISLAND),))
    scope, _link, index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
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
    record = _call_record(
        source, boundary, source.blocks[0], instrs[0], index, scope
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
    assert (
        view.failure
        is view_mod.ScopedFunctionIRViewFailure8616.RESIDUAL_REFUSAL
    )
    assert not view.complete_for(scope)
    assert view.effective_blocks_for(scope) is None


def _partial_view(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[object, object, IRFunctionArtifact]:
    """Build one partially discharged scoped view with a pending hole."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, _instrs = _source(call=False, second_pending=True)
    boundary = _boundary(
        project, source, ((FUNC, ISLAND), (SECOND, ISLAND))
    )
    scope, _link, _index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
    monkeypatch.setattr(
        domain.Real16InvocationDomain8616, "complete",
        property(lambda self: self.failure is None),
    )
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
    return view, scope, source


def test_partial_discharge_keeps_pending_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused candidate stays pending: the edge is never fabricated."""
    view, scope, source = _partial_view(monkeypatch)
    assert view.failure is None
    assert view.complete_for(scope)
    assert view.effective_successors_for(scope, FUNC) == (ISLAND,)
    # The undischarged candidate exposes no outgoing claim and keeps its
    # refusal: an open hole is typed unknown, never a proved exit.
    assert view.effective_successors_for(scope, SECOND) is None
    second = view.source_block(SECOND)
    assert second is source.blocks[2]
    effective = view.effective_blocks_for(scope)
    assert effective[2] is source.blocks[2]
    assert effective[2].refusals == source.blocks[2].refusals


def test_pending_block_exposes_no_exit_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bulk projection marks the pending hole instead of an exit."""
    view, scope, source = _partial_view(monkeypatch)
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    assert projection.successors_for(FUNC) == (ISLAND,)
    assert projection.pending_for(FUNC) == ()
    # SECOND is in the census but carries the residual pending-window
    # refusal: no successor entry, the refusal stays visibly pending.
    assert projection.successors_for(SECOND) is None
    assert projection.pending_for(SECOND) == source.blocks[2].refusals
    assert projection.block_for(SECOND) is source.blocks[2]
    assert projection.predecessors_for(SECOND) == ()
    assert projection.predecessors_for(ISLAND) == (FUNC,)
    receipt = view.to_dict()
    assert receipt["authenticated"] is True
    assert receipt["residual_pending_count"] == 1


def test_forged_retained_application_refuses(world: SimpleNamespace) -> None:
    """A hand-built application record cannot impersonate the replay."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert view.failure is None
    extra = IRBlock(
        SECOND, instrs=(IRInstr("RET", None, (), addr=SECOND),)
    )
    forged = replace(
        view,
        application=replace(
            view.application,
            blocks=(*view.application.blocks, extra),
        ),
    )
    assert not forged.complete_for(world.scope)
    assert forged.effective_blocks_for(world.scope) is None
    empty = replace(view, application=None, failure=None)
    assert not empty.complete_for(world.scope)


def test_second_entry_does_not_share(world: SimpleNamespace) -> None:
    """Two entries over one surface never share consuming authority."""
    boot_b = object()
    parent_b = replace(world.link.parent, boot=boot_b)
    link_b = replace(world.link, parent=parent_b)
    scope_b = replace(world.scope, boot=boot_b, chain=link_b)
    record_b = replace(world.record, invocation_scope=scope_b)
    dep_b = ejd._ScopedCallDependency8616(CALL_HEAD, record_b, scope_b)
    jump_b = replace(
        world.jump, invocation_scope=scope_b, call_dependencies=(dep_b,)
    )
    proof_b = _proof(
        world.source, (world.pending,), (jump_b,), (), (record_b,), scope_b
    )
    view_b = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, proof_b, invocation_scope=scope_b,
    )
    assert view_b.failure is None
    assert view_b.complete_for(scope_b)
    assert not view_b.complete_for(world.scope)
    view_a = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert not view_a.complete_for(scope_b)


def test_context_free_complete_never_true(world: SimpleNamespace) -> None:
    """The context-free property is always false, even after success."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert not view.complete
    assert not replace(view, application=None).complete


def _authentic_view(world: SimpleNamespace) -> object:
    """Build the authenticated conditional view for mutation controls."""
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof,
        invocation_scope=world.scope,
    )
    assert view.failure is None
    assert view.complete_for(world.scope)
    return view


def test_stripped_application_scope_refuses(world: SimpleNamespace) -> None:
    """A retained application losing its recorded entry is stale."""
    view = _authentic_view(world)
    stripped = replace(
        view,
        application=replace(view.application, invocation_scope=None),
    )
    assert not stripped.complete_for(world.scope)
    assert stripped.effective_blocks_for(world.scope) is None
    assert stripped.cfg_projection_for(world.scope) is None
    receipt = stripped.to_dict()
    assert receipt["authenticated"] is False
    assert receipt["applied"] == []


def test_stripped_application_dependency_refuses(
    world: SimpleNamespace,
) -> None:
    """A retained admission losing compare-excluded fields is stale."""
    view = _authentic_view(world)
    admission = view.application.applied[0]
    assert admission.call_dependencies
    for mutation in (
        replace(admission, call_dependencies=()),
        replace(admission, invocation_scope=None),
        replace(admission),
    ):
        corrupt = replace(
            view,
            application=replace(
                view.application, applied=(mutation,)
            ),
        )
        assert not corrupt.complete_for(world.scope)
        assert corrupt.applied_jumps_for(world.scope) is None
        assert corrupt.to_dict()["authenticated"] is False


def test_rebuilt_unadmitted_block_refuses(world: SimpleNamespace) -> None:
    """An equal-but-rebuilt unadmitted block breaks retained identity."""
    view = _authentic_view(world)
    clone = replace(view.application.blocks[1])
    assert clone == view.application.blocks[1]
    corrupt = replace(
        view,
        application=replace(
            view.application,
            blocks=(view.application.blocks[0], clone),
        ),
    )
    assert not corrupt.complete_for(world.scope)


def test_excluded_ir_metadata_mutation_refuses(
    world: SimpleNamespace,
) -> None:
    """compare=False IR provenance cannot hide inside retained blocks."""
    view = _authentic_view(world)
    admitted_block = view.application.blocks[0]
    rewritten = admitted_block.instrs[1]
    arg = rewritten.args[0]
    poisoned = replace(arg, source_tmp=99, memory_access_insn=0x40)
    bad_block = replace(
        admitted_block,
        instrs=(
            admitted_block.instrs[0],
            replace(rewritten, args=(poisoned,)),
        ),
    )
    corrupt = replace(
        view,
        application=replace(
            view.application,
            blocks=(bad_block, *view.application.blocks[1:]),
        ),
    )
    assert not corrupt.complete_for(world.scope)
    assert corrupt.effective_successors_for(world.scope, FUNC) is None
    assert corrupt.to_dict()["authenticated"] is False


@pytest.mark.parametrize(
    "counts",
    [
        {"raw_fact_count": 0},
        {"normalized_fact_count": 0},
        {"classified_fact_count": 0},
        {"materialized_count": 0},
        {"failure_count": 1},
    ],
)
def test_corrupt_view_counter_refuses(
    world: SimpleNamespace, counts: dict,
) -> None:
    """Retained counters are recomputed from the proof at consumption."""
    view = _authentic_view(world)
    corrupt = replace(view, **counts)
    assert not corrupt.complete_for(world.scope)
    assert corrupt.cfg_projection_for(world.scope) is None
    assert corrupt.effective_blocks_for(world.scope) is None
    receipt = corrupt.to_dict()
    assert receipt["authenticated"] is False
    assert receipt["applied"] == []
