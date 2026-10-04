"""Synthetic contract tests for the scoped IR boundary coverage route.

Layer: tests.
Responsibility: pin the ``IRBoundaryCoverageResult8616.complete_for``
contract with real typed objects: an authentic ``ScopedFunctionIRView8616``
over a pending-JMP-plus-CALL body, real staged invocation domains with
completeness patched only at the documented unit boundary (the same seam
the sibling view suite uses), and a ``vex_import`` ``sys.modules`` seam
standing in for the guarded native census import. No MZ loader, solver,
or lifter paths are exercised; native source authentication is a separate
parent-owned slot and nothing here claims native proof.

``COVERAGE_VARIANT=before`` runs the identical suite against the
pre-change coverage owner for red evidence: every scoped-route control
fails there while the universal controls stay green.
"""

from __future__ import annotations

from dataclasses import replace
from types import ModuleType, SimpleNamespace

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
from angr_platforms.X86_16.ir import ir_boundary_cfg as cov_mod
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
from angr_platforms.X86_16.relative_control_edge import (
    DecodedRelativeEdge,
    decode_relative_edge,
)

FUNC = 0x10000
CALL_HEAD = 0x10000
JMP_HEAD = 0x10010
ISLAND = 0x10018
SECOND = 0x10020
CALLEE = 0x11000
CALLER_ADDR = 0x9000
PENDING_KIND = "terminal_jump_selector_window_unproved"
F = cov_mod.IRBoundaryCoverageFailure8616


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
    coverage = cov_mod.prove_ir_boundary_coverage_8616(
        project, boundary, caller
    )
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
    second_pending: bool = False,
    nop: bool = False,
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
    if nop:
        instrs.append(IRInstr("NOP", None, (), addr=CALL_HEAD + 3))
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
    island = IRBlock(
        ISLAND,
        instrs=(IRInstr("RET", None, (), addr=ISLAND),),
        refusals=(
            (IRRefusal("alias_recovery_unknown", "synthetic", ISLAND),)
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


def _native_seam(
    monkeypatch: pytest.MonkeyPatch, make_artifact: object,
) -> ModuleType:
    """Stand in for the guarded native census import (synthetic seam).

    ``real16_native_census_import_8616`` defers
    ``from .vex_import import build_x86_16_ir_function_artifact``; this
    seam injects the sibling module carrying a test-controlled
    rederivation product. The census importer itself stays the real
    staged code — only its innermost import boundary is a seam, and
    every returned surface is still compared by full canonical source
    and instruction census before coverage can close.
    """
    from angr_platforms.X86_16.ir import vex_import as fake

    def build_x86_16_ir_function_artifact(
        project: object, boundary: object,
    ) -> object:
        return make_artifact()

    monkeypatch.setattr(fake, "build_x86_16_ir_function_artifact", build_x86_16_ir_function_artifact)
    return fake


def _rebuilt(source: IRFunctionArtifact) -> IRFunctionArtifact:
    """Return a canonical-identical but distinct artifact object."""
    return IRFunctionArtifact(
        source.function_addr,
        tuple(replace(block) for block in source.blocks),
        source.refusals,
    )


def _patch_domain_unit_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch domain/record completeness at the documented unit boundary.

    Same seam the sibling view suite uses: ``complete`` becomes
    ``failure is None`` and the callsite record authenticates through
    ``same_real16_entry_scope_8616`` only — no native census replay.
    """
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


def _coverage(project: object, boundary: object, source: object, view: object) -> object:
    """Run the scoped coverage constructor under test."""
    return cov_mod.prove_scoped_ir_boundary_coverage_8616(
        project, boundary, source, view
    )


def _shifted_view(
    world: SimpleNamespace, boundary: ExactFunctionRangeBoundary8616,
) -> tuple:
    """Rebind the world's whole conditional chain to a shifted boundary.

    A coverage consumer compares the effective CFG against the identical
    boundary object the view retains, so exercising a wrong edge/block
    census requires rebuilding every scope-bound record coherently —
    piecemeal replacement leaves a foreign entry and fails earlier at
    admission, never reaching the census under test.
    """
    link = replace(world.link, callee_boundary=boundary)
    scope = replace(world.scope, chain=link)
    record = replace(
        world.record, boundary=boundary, invocation_scope=scope
    )
    dep = ejd._ScopedCallDependency8616(CALL_HEAD, record, scope)
    jump = replace(
        world.jump, invocation_scope=scope, call_dependencies=(dep,)
    )
    proof = _proof(
        world.source, (world.pending,), (jump,), (), (record,), scope
    )
    view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, boundary, proof, invocation_scope=scope,
    )
    return scope, view


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
    _patch_domain_unit_boundary(monkeypatch)
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
    _native_seam(monkeypatch, lambda: _rebuilt(source))
    view = view_mod.prove_scoped_function_ir_view_8616(
        source, boundary, proof, invocation_scope=scope,
    )
    assert view.failure is None, view.to_dict()
    return SimpleNamespace(
        project=project, boot=boot, caller_pack=caller_pack, source=source,
        boundary=boundary, scope=scope, link=link, index=index,
        record=record, dep=dep, pending=pending, jump=jump, proof=proof,
        call_instr=instrs[0], view=view,
    )


def test_scoped_coverage_completes_only_under_its_entry(
    world: SimpleNamespace,
) -> None:
    """Positive: authentic view + raw surface + entry closes coverage."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.failure is None
    assert result.artifact is world.source
    assert result.boundary is world.boundary
    assert result.scoped_view is world.view
    assert result.complete_for(world.scope)
    # The raw pending body stays raw and unpublished: the admitted edge
    # and the discharged refusal never land on the retained artifact.
    assert all(
        ISLAND not in block.successor_addrs
        for block in result.artifact.blocks
    )
    assert any(block.refusals for block in result.artifact.blocks)
    assert result.artifact.blocks[0].instrs[0] is world.call_instr


def test_context_free_complete_never_true(world: SimpleNamespace) -> None:
    """Scoped evidence never certifies without an explicit entry."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.failure is None
    assert not result.complete
    assert not result.complete_for(None)
    forged = replace(result, failure=None)
    assert not forged.complete
    assert not forged.complete_for(None)


def test_universal_route_unchanged(world: SimpleNamespace) -> None:
    """The universal branch is untouched and still refuses pending bodies."""
    caller, caller_boundary, caller_cov = world.caller_pack
    assert caller_cov.scoped_view is None
    assert caller_cov.complete
    assert caller_cov.complete_for(None)
    # A universal verdict does not depend on any offered entry.
    assert caller_cov.complete_for(world.scope)
    manual = cov_mod.IRBoundaryCoverageResult8616(
        caller, caller_boundary, None, 1, 1, 1, 1, 0
    )
    assert manual.scoped_view is None
    assert manual.complete
    # The pending raw body still cannot certify universal coverage, and
    # a scope cannot rescue it — only the explicit scoped route applies.
    raw = cov_mod.prove_ir_boundary_coverage_8616(
        world.project, world.boundary, world.source
    )
    assert raw.scoped_view is None
    assert not raw.complete
    assert not raw.complete_for(world.scope)


def test_foreign_and_other_surface_scopes_refuse(
    world: SimpleNamespace,
) -> None:
    """Wrong-scope consumption stays refused even when construction passed."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.complete_for(world.scope)
    foreign = replace(world.scope, boot=object())
    assert not result.complete_for(foreign)
    # A scope anchored to a different surface never authorizes this one.
    other_source, _ = _source(call=False)
    other_boundary = _boundary(world.project, other_source, ())
    foreign_link = replace(
        world.link,
        callee_artifact=other_source,
        callee_boundary=other_boundary,
    )
    other_scope = replace(world.scope, chain=foreign_link)
    assert not result.complete_for(other_scope)


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
    result_b = _coverage(
        world.project, world.boundary, world.source, view_b
    )
    assert result_b.complete_for(scope_b)
    assert not result_b.complete_for(world.scope)
    result_a = _coverage(
        world.project, world.boundary, world.source, world.view
    )
    assert not result_a.complete_for(scope_b)


def test_missing_or_untyped_view_refuses(world: SimpleNamespace) -> None:
    """No view, a failed view, or a non-view is typed non-evidence."""
    absent = _coverage(world.project, world.boundary, world.source, None)
    assert absent.failure is F.SCOPED_VIEW_REFUSED
    assert not absent.complete_for(world.scope)
    refused_view = view_mod.prove_scoped_function_ir_view_8616(
        world.source, world.boundary, world.proof, invocation_scope=None,
    )
    assert refused_view.failure is not None
    refused = _coverage(
        world.project, world.boundary, world.source, refused_view
    )
    assert refused.failure is F.SCOPED_VIEW_REFUSED
    assert not refused.complete_for(world.scope)
    impostor = _coverage(
        world.project, world.boundary, world.source, SimpleNamespace()
    )
    assert impostor.failure is F.SCOPED_VIEW_REFUSED


def test_view_bound_to_other_surface_refuses(world: SimpleNamespace) -> None:
    """Coverage and view must name the identical raw surface objects."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.complete_for(world.scope)
    equal_source = replace(world.source)
    assert equal_source == world.source
    corrupt = replace(result, artifact=equal_source)
    assert not corrupt.complete_for(world.scope)
    equal_boundary = replace(world.boundary)
    corrupt = replace(result, boundary=equal_boundary)
    assert not corrupt.complete_for(world.scope)


@pytest.mark.parametrize(
    "edges", [(), ((FUNC, ISLAND), (FUNC, ISLAND)),
              ((FUNC, ISLAND), (ISLAND, FUNC)),
              ((FUNC, ISLAND), (FUNC, 0xDEAD))],
)
def test_edge_census_mismatch_refuses(
    world: SimpleNamespace, edges: tuple,
) -> None:
    """Dropped, duplicated, extra, or foreign boundary edges all refuse."""
    shifted = _boundary(world.project, world.source, edges)
    scope, view = _shifted_view(world, shifted)
    assert view.failure is None, view.to_dict()
    result = _coverage(world.project, shifted, world.source, view)
    assert result.failure is F.SCOPED_CFG_MISMATCH, result.failure
    assert not result.complete_for(scope)


def test_block_census_mismatch_refuses(world: SimpleNamespace) -> None:
    """A boundary claiming a foreign or missing block cannot close."""
    shifted = _boundary(world.project, world.source, ((FUNC, ISLAND),))
    shifted = replace(
        shifted, block_addrs_set=frozenset({FUNC, ISLAND, SECOND})
    )
    scope, view = _shifted_view(world, shifted)
    assert view.failure is None, view.to_dict()
    result = _coverage(world.project, shifted, world.source, view)
    assert result.failure is F.SCOPED_CFG_MISMATCH, result.failure
    assert not result.complete_for(scope)


def test_bootstrap_scope_refuses(world: SimpleNamespace) -> None:
    """An entry citing this coverage as its own authority is a cycle."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.complete_for(world.scope)
    cyclic = replace(world.scope, coverage=result)
    assert not result.complete_for(cyclic)


def test_residual_pending_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pending hole on the effective surface is not closed coverage."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, _instrs = _source(call=False, second_pending=True)
    boundary = _boundary(
        project, source, ((FUNC, ISLAND), (SECOND, ISLAND))
    )
    scope, _link, _index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
    _patch_domain_unit_boundary(monkeypatch)
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
    assert view.complete_for(scope)
    _native_seam(monkeypatch, lambda: _rebuilt(source))
    result = _coverage(project, boundary, source, view)
    assert result.failure is F.SCOPED_REFUSAL, result.failure
    assert not result.complete_for(scope)


def test_unrelated_residual_refusal_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused view is typed non-evidence, never carried as coverage."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, instrs = _source(call=True, alien_refusal=True)
    boundary = _boundary(project, source, ((FUNC, ISLAND),))
    scope, _link, index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
    _patch_domain_unit_boundary(monkeypatch)
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
    assert view.failure is view_mod.ScopedFunctionIRViewFailure8616.RESIDUAL_REFUSAL
    _native_seam(monkeypatch, lambda: _rebuilt(source))
    result = _coverage(project, boundary, source, view)
    assert result.failure is F.SCOPED_VIEW_REFUSED
    assert not result.complete_for(scope)


@pytest.mark.parametrize(
    "mutation", ["provenance", "opcode", "dropped_instr", "none"],
)
def test_native_surface_mutation_refuses(
    world: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Changed native bytes or IR metadata make the rederived surface stale."""
    if mutation == "none":
        _native_seam(monkeypatch, lambda: None)
    else:
        if mutation == "provenance":
            # compare=False IR provenance cannot hide inside rederived
            # blocks: canonical source equality catches what ``==`` misses.
            poisoned_arg = replace(
                world.source.blocks[0].instrs[1].args[0], source_tmp=99
            )
            bad_block = replace(
                world.source.blocks[0],
                instrs=(
                    world.source.blocks[0].instrs[0],
                    replace(
                        world.source.blocks[0].instrs[1],
                        args=(poisoned_arg,),
                    ),
                ),
            )
            assert bad_block.instrs[1] == world.source.blocks[0].instrs[1]
            mutated = replace(
                world.source,
                blocks=(bad_block, *world.source.blocks[1:]),
            )
        elif mutation == "opcode":
            bad_block = replace(
                world.source.blocks[1],
                instrs=(
                    replace(world.source.blocks[1].instrs[0], op="HLT"),
                ),
            )
            mutated = replace(
                world.source,
                blocks=(*world.source.blocks[:1], bad_block),
            )
        else:
            bad_block = replace(
                world.source.blocks[1], instrs=(),
            )
            mutated = replace(
                world.source,
                blocks=(*world.source.blocks[:1], bad_block),
            )
        _native_seam(monkeypatch, lambda: mutated)
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.failure is F.SCOPED_NATIVE_MISMATCH, result.failure
    assert not result.complete_for(world.scope)


def test_fabricated_no_effect_instruction_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare ``NOP`` claim cannot satisfy the bound native census."""
    project = SimpleNamespace()
    caller_pack = _caller_surface(project)
    source, instrs = _source(call=True, nop=True)
    boundary = _boundary(project, source, ((FUNC, ISLAND),))
    scope, _link, index = _scope_for(
        project, object(), caller_pack, source, boundary
    )
    _patch_domain_unit_boundary(monkeypatch)
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
    assert view.failure is None, view.to_dict()
    _native_seam(monkeypatch, lambda: _rebuilt(source))
    result = _coverage(project, boundary, source, view)
    assert result.failure is F.SCOPED_CENSUS_MISMATCH, result.failure
    assert not result.complete_for(scope)


@pytest.mark.parametrize(
    "counts",
    [
        {"raw_fact_count": 0},
        {"normalized_fact_count": 0},
        {"classified_fact_count": 0},
        {"materialized_count": 0},
        {"failure_count": 1},
        {"raw_fact_count": "1"},
    ],
)
def test_corrupt_counter_refuses(
    world: SimpleNamespace, counts: dict,
) -> None:
    """Retained counters are recomputed, never trusted, at consumption."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.complete_for(world.scope)
    corrupt = replace(result, **counts)
    assert not corrupt.complete_for(world.scope)


def test_recorded_failure_is_terminal(world: SimpleNamespace) -> None:
    """A result constructed with a typed failure never revives."""
    result = _coverage(world.project, world.boundary, world.source, world.view)
    assert result.complete_for(world.scope)
    failed = replace(result, failure=F.SCOPED_CFG_MISMATCH)
    assert not failed.complete_for(world.scope)
    assert not failed.complete
