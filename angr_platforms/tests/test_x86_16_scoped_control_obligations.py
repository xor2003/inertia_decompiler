"""Scoped control-obligation composition: native-derived red/green cohort.

One premise-derived callee surface carrying BOTH conditional marker
classes — the ``near_return_continuation_pending`` marker on the proven
continuation block and ``terminal_jump_selector_window_unproved`` on a
selector-dependent terminal — must discharge only through the composed
scoped view under one independently supplied invocation entry. Real
decoded instruction facts, real MZ native bytes, and the real
resolver/producer chain establish every proof; nothing here fabricates
marker truth. Every missing, foreign, stale, or mutated leg keeps a
typed refusal, and the raw artifact keeps its raw ``JMP`` terminals plus
pending markers on every universal route.
"""

from __future__ import annotations

from dataclasses import replace
from functools import partial
from pathlib import Path

import angr
from angr_platforms.X86_16 import frontend_function_boundary as boundary_mod
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    build_boundary_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_near_return_continuation import (
    NearCallFramePremise8616,
)
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import ir_boundary_cfg as ibc
from angr_platforms.X86_16.ir import near_return_continuation_view as nrcv
from angr_platforms.X86_16.ir import scoped_control_obligations as sco
from angr_platforms.X86_16.ir import vex_import
from angr_platforms.X86_16.ir.entry_jump_domain import (
    EntryJumpDomainApplicationStatus8616,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from test_x86_16_near_return_continuation import (
    _mz_boot_recompute,
    _mz_exe,
)

from inertia_decompiler.project_loading import _build_project
from tools.dosunit.real16_program_boot import (
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_replay_model import LinearRange

_CONTINUATION_KIND = "near_return_continuation_pending"
_SELECTOR_KIND = "terminal_jump_selector_window_unproved"
_FAIL = nrcv.ScopedNearReturnContinuationViewFailure8616

# The MZ world: CALLER is the MZ entry whose one decoded near-CALL row
# targets CALLEE. CALLEE is an unregistered premise-derived body with
# three blocks: a conditional head, a selector-dependent self-loop
# terminal (selector pending marker), and the proven near-return
# continuation block (continuation pending marker). Every object the
# scope authenticates — the registered caller artifact, the retained
# index row, the pending callee pair — is produced by the real pipeline,
# never fabricated by the test.
_MZ_SEGMENT = 0x1000
_MZ_BASE = _MZ_SEGMENT << 4
_MZ_CALLER = _MZ_BASE + 0x20
_MZ_CALLEE = _MZ_BASE + 0x60
_MZ_SELECTOR_BLOCK = _MZ_BASE + 0x64
_MZ_JMP_HEAD = _MZ_BASE + 0x70
_MZ_CONTINUATION_BLOCK = _MZ_BASE + 0x73
_MZ_CALLER_CODE = (
    b"\xe8"
    + ((_MZ_CALLEE - (_MZ_CALLER + 3)) & 0xFFFF).to_bytes(2, "little")
    + b"\xc3"
)
#   A 0x10060: test ax,ax; jz C
#   B 0x10064: nops; jmp 0x10064 (selector-dependent self-loop)
#   C 0x10073: pop cx; mov bx,sp; sub bx,ax; mov sp,bx; jmp cx
_MZ_CALLEE_CODE = bytes.fromhex(
    "85 C0"                             # 0x10060 test ax,ax
    "74 0F"                             # 0x10062 jz 0x10073
    "909090909090909090909090"          # 0x10064..0x1006F nops
    "E9 F1 FF"                          # 0x10070 jmp 0x10064
    "59 8B DC 2B D8 8B E3 FF E1"        # 0x10073 continuation block
)
# Same A/B blocks and the same selector transfer; the continuation block
# carries the mov-chain carrier instead, so a proof minted over this
# surface binds a different canonical source digest.
_MZ_FOREIGN_CALLEE_CODE = bytes.fromhex(
    "85 C0"                             # 0x10060 test ax,ax
    "74 0F"                             # 0x10062 jz 0x10073
    "909090909090909090909090"          # 0x10064..0x1006F nops
    "E9 F1 FF"                          # 0x10070 jmp 0x10064
    "58 8B C8 FF E1"                    # 0x10073 mov-chain continuation
)
# A third shape whose selector marker lives on a different block
# (0x10066): its terminal evidence can never describe this surface.
_MZ_SPLIT_CALLEE_CODE = bytes.fromhex(
    "85 C0"                             # 0x10060 test ax,ax
    "74 0F"                             # 0x10062 jz 0x10073
    "909090909090909090909090"          # 0x10064..0x1006F nops
    "E9 F3 FF"                          # 0x10070 jmp 0x10066
    "59 8B DC 2B D8 8B E3 FF E1"        # 0x10073 continuation block
)


def _image(callee_code: bytes) -> bytes:
    """Lay out the caller and callee islands inside one module image."""
    image = b""
    cursor = _MZ_BASE
    for address, code in (
        (_MZ_CALLER, _MZ_CALLER_CODE),
        (_MZ_CALLEE, callee_code),
    ):
        assert address >= cursor
        image += bytes(address - cursor) + code
        cursor = address + len(code)
    return image


def _ranges(callee_code: bytes) -> tuple[LinearRange, LinearRange]:
    """Return the replay ranges covering both module islands."""
    return (
        LinearRange(_MZ_CALLER, len(_MZ_CALLER_CODE)),
        LinearRange(_MZ_CALLEE, len(callee_code)),
    )


def _world(
    tmp_path: Path, callee_code: bytes = _MZ_CALLEE_CODE
) -> tuple[object, angr.Project]:
    """Build the authentic ProgramBoot and project for one MZ fixture."""
    image = _image(callee_code)
    mz = _mz_exe(image, _MZ_CALLER - _MZ_BASE)
    env = ProgramEnvironment(
        psp_segment=_MZ_SEGMENT - 0x10,
        allocation=bytes(0x400),
        registers=tuple(
            (name, 0)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                "eflags",
            )
        ),
        fs=0,
        gs=0,
    )
    boot = program_from_mz_bytes(
        mz, env, code_ranges=_ranges(callee_code)
    )
    fixture = tmp_path / "mixed_obligations.exe"
    fixture.write_bytes(mz)
    project = _build_project(
        fixture, force_blob=False, base_addr=_MZ_BASE,
        entry_point=_MZ_CALLER,
    )
    return boot, project


def _resolver(project: angr.Project) -> object:
    """Return the shared decoded direct-target resolver for one project."""
    return partial(resolve_direct_call_target_from_instruction_8616, project)


def _caller_surface(project: angr.Project) -> tuple[object, object, object]:
    """Register the caller and retain its decoded callsite index."""
    caller_boundary = boundary_mod.mapped_entry_function_boundary_8616(
        project, _MZ_CALLER
    )
    assert caller_boundary is not None
    caller_artifact = vex_import.build_x86_16_ir_function_artifact(
        project, caller_boundary
    )
    verdict = publish_function_ir_artifact_8616(project, caller_artifact)
    assert verdict.verdict is FunctionIRArtifactVerdict8616.PROVEN
    index = build_boundary_direct_callsite_index_8616(
        caller_boundary, direct_target_resolver=_resolver(project)
    )
    return caller_boundary, caller_artifact, index


def _install_source(project: angr.Project, boot: object, index: object) -> None:
    """Install the typed invocation source carrying the decoded index."""
    edcp.install_real16_invocation_source_8616(
        project,
        edcp.Real16InvocationSource8616(
            boot=boot,
            boot_recompute=_mz_boot_recompute,
            callsite_index=index,
        ),
    )


def _fixture(tmp_path: Path) -> tuple[object, object, object, object, object]:
    """Build the full pending surface, bound entry, and native bundle.

    Returns ``(project, artifact, boundary, scope, bundle)`` with the
    invocation source still installed; callers must uninstall it in a
    ``finally`` block.
    """
    boot, project = _world(tmp_path)
    _caller_boundary, _caller_artifact, index = _caller_surface(project)
    _install_source(project, boot, index)
    resolved = edcp._callee_artifact_and_boundary_8616(project, _MZ_CALLEE)
    assert resolved is not None
    artifact, boundary = resolved
    scope = edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, _MZ_JMP_HEAD
    )
    assert scope is not None and scope.complete
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
        project, boundary, artifact
    )
    assert bundle is not None and bundle.artifact is artifact
    return project, artifact, boundary, scope, bundle


def _foreign_view(
    tmp_path: Path, callee_code: bytes
) -> tuple[object, object]:
    """Mint a green joint view over a differently bytewise surface.

    The returned ``(project, view)`` pair retains a selector proof and
    application authenticated to the foreign surface's own canonical
    source — never to this test's primary artifact.
    """
    boot, project = _world(tmp_path, callee_code)
    _caller_boundary, _caller_artifact, index = _caller_surface(project)
    _install_source(project, boot, index)
    resolved = edcp._callee_artifact_and_boundary_8616(project, _MZ_CALLEE)
    assert resolved is not None
    artifact, boundary = resolved
    bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
        project, boundary, artifact
    )
    assert bundle is not None
    scope = edcp.entry_domain_invocation_premise_8616(
        project, artifact, boundary, _MZ_JMP_HEAD
    )
    view = vex_import.prove_scoped_control_obligations_view_8616(
        project, bundle, boundary, invocation_scope=scope
    )
    return project, view


def _block(artifact: object, addr: int) -> object:
    """Return the single raw block at one address."""
    return next(b for b in artifact.blocks if b.addr == addr)


def test_mixed_surface_carries_both_marker_classes(tmp_path: Path) -> None:
    """The raw pending artifact retains both conditional markers."""
    project, artifact, boundary, scope, _bundle = _fixture(tmp_path)
    try:
        assert sco.mixed_pending_obligations_8616(artifact)
        selector = _block(artifact, _MZ_SELECTOR_BLOCK)
        assert selector.instrs[-1].op == "JMP"
        assert [r.kind for r in selector.refusals] == [_SELECTOR_KIND]
        continuation = _block(artifact, _MZ_CONTINUATION_BLOCK)
        assert continuation.instrs[-1].op == "JMP"
        assert [r.kind for r in continuation.refusals] == [
            _CONTINUATION_KIND
        ]
        continuations = boundary.near_return_continuations
        assert continuations is not None
        assert continuations.proven_block_addrs == frozenset(
            {_MZ_CONTINUATION_BLOCK}
        )
        # The continuation-only owner refuses this surface by contract.
        single = nrcv.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=scope
        )
        assert single.failure is _FAIL.RESIDUAL_REFUSAL
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_composed_view_discharges_both_classes(tmp_path: Path) -> None:
    """One bound entry discharges both obligations on one coherent view."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        assert view.source_artifact is artifact
        assert view.boundary is boundary
        assert view.proven_block_addrs == frozenset({_MZ_CONTINUATION_BLOCK})
        # The joint ledger counts each marker: one continuation plus one
        # selector obligation, both materialized, none refused.
        assert (
            view.raw_fact_count,
            view.normalized_fact_count,
            view.classified_fact_count,
            view.materialized_count,
            view.failure_count,
        ) == (2, 2, 2, 2, 0)
        assert view.selector_proof is not None
        assert [j.block_addr for j in view.selector_proof.admitted] == [
            _MZ_SELECTOR_BLOCK
        ]
        assert view.selector_application is not None
        assert (
            view.selector_application.status
            is EntryJumpDomainApplicationStatus8616.APPLIED
        )
        # Context-free consumption stays refused; the bound entry exposes
        # the composed effective surface through a fresh replay.
        assert not view.complete
        assert view.cfg_projection_for(None) is None
        projection = view.cfg_projection_for(scope)
        assert projection is not None
        assert projection.scope is scope
        assert projection.source_artifact is artifact
        assert [j.block_addr for j in projection.applied] == [
            _MZ_SELECTOR_BLOCK
        ]
        assert projection.successors_for(_MZ_CALLEE) == (
            _MZ_SELECTOR_BLOCK,
            _MZ_CONTINUATION_BLOCK,
        )
        assert projection.successors_for(_MZ_SELECTOR_BLOCK) == (
            _MZ_SELECTOR_BLOCK,
        )
        assert projection.successors_for(_MZ_CONTINUATION_BLOCK) == ()
        assert not any(projection.pending.values())
        pblock = next(
            b for b in projection.blocks if b.addr == _MZ_CONTINUATION_BLOCK
        )
        assert pblock.instrs[-1].op == "RET"
        # The retained raw artifact is untouched: both markers and the
        # raw JMP terminals survive every projection.
        assert _block(artifact, _MZ_SELECTOR_BLOCK).instrs[-1].op == "JMP"
        assert _block(
            artifact, _MZ_CONTINUATION_BLOCK
        ).instrs[-1].op == "JMP"
        assert any(
            r.kind == _SELECTOR_KIND
            for r in _block(artifact, _MZ_SELECTOR_BLOCK).refusals
        )
        assert any(
            r.kind == _CONTINUATION_KIND
            for r in _block(artifact, _MZ_CONTINUATION_BLOCK).refusals
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_scoped_coverage_and_closure_consume_joint_view(
    tmp_path: Path,
) -> None:
    """The existing scoped pipeline consumes the composed view end to end."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        coverage = ibc.prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, view
        )
        assert coverage.scoped_view is view
        assert coverage.complete_for(scope)
        assert not coverage.complete
        assert not coverage.complete_for(None)
        # The callee-coverage seam routes the mixed surface through the
        # composed owner and closes under the same entry.
        seam = edcp._scoped_callee_coverage_8616(
            project, artifact, boundary, scope
        )
        assert seam is not None and seam.complete_for(scope)
        assert not seam.complete
        resolution = edcp._CalleeResolution8616(
            resolver=_resolver(project)
        )
        closure, refusal = edcp._callee_closure_8616(
            project, _MZ_CALLEE, resolution, invocation_scope=scope
        )
        assert refusal is None and closure is not None
        assert closure.complete_for(scope)
        assert not closure.complete
        state = closure.state
        assert state.source_artifact is artifact
        assert state.scoped_view is coverage.scoped_view or (
            type(state.scoped_view) is type(view)
            and state.scoped_view.source_artifact is artifact
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_missing_scope_refuses(tmp_path: Path) -> None:
    """No consuming entry: the joint view keeps a typed refusal."""
    project, artifact, boundary, _scope, bundle = _fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=None
        )
        assert view.failure is _FAIL.SCOPE_ABSENT
        assert view.materialized_count == 0
        assert view.failure_count == 1
        assert not view.complete
        assert view.cfg_projection_for(None) is None
        assert (
            edcp._scoped_callee_coverage_8616(
                project, artifact, boundary, None
            )
            is None
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_foreign_scope_refuses(tmp_path: Path) -> None:
    """A scope minted over a distinct artifact object owns nothing here."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        from angr_platforms.X86_16.ir.real16_invocation_domain import (
            real16_native_census_import_8616,
        )

        foreign_artifact = real16_native_census_import_8616(
            project, boundary
        )
        assert foreign_artifact is not None
        assert foreign_artifact is not artifact
        foreign_scope = edcp.entry_domain_invocation_premise_8616(
            project, foreign_artifact, boundary, _MZ_JMP_HEAD
        )
        assert foreign_scope is not None and foreign_scope.complete
        refused = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=foreign_scope
        )
        assert refused.failure is _FAIL.SCOPE_UNBOUND
        assert refused.cfg_projection_for(foreign_scope) is None
        # A real joint view stays refused for the foreign entry at
        # consumption, and the scoped coverage seam never inherits it.
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        assert view.cfg_projection_for(foreign_scope) is None
        coverage = ibc.prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, view
        )
        assert coverage.complete_for(scope)
        assert not coverage.complete_for(foreign_scope)
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_missing_continuation_premise_refuses(tmp_path: Path) -> None:
    """A boundary without the source-bound frame premise is refused."""
    project, _artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        tampered = replace(boundary, near_return_continuations=None)
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, tampered, invocation_scope=scope
        )
        assert view.failure is _FAIL.PREMISE_ABSENT
        assert view.materialized_count == 0
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_stale_continuation_premise_refuses(tmp_path: Path) -> None:
    """A premise whose retained index no longer authenticates it revokes."""
    project, _artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        continuations = boundary.near_return_continuations
        assert continuations is not None
        premise = continuations.premise
        assert type(premise) is NearCallFramePremise8616
        # A rebuilt index carries equal-but-distinct row objects: the
        # premise's retained row is no longer identity-authenticated.
        caller_boundary = boundary_mod.mapped_entry_function_boundary_8616(
            project, _MZ_CALLER
        )
        assert caller_boundary is not None
        rebuilt = build_boundary_direct_callsite_index_8616(
            caller_boundary, direct_target_resolver=_resolver(project)
        )
        stale = NearCallFramePremise8616(
            kind=premise.kind,
            callsite=premise.callsite,
            callsite_index=rebuilt,
            callee_addr=premise.callee_addr,
            callsite_addr=premise.callsite_addr,
            caller_start=premise.caller_start,
            return_addr=premise.return_addr,
        )
        tampered = replace(
            boundary,
            near_return_continuations=replace(
                continuations, premise=stale
            ),
        )
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, tampered, invocation_scope=scope
        )
        assert view.failure is _FAIL.PREMISE_STALE
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_foreign_continuation_premise_refuses(tmp_path: Path) -> None:
    """A premise bound to another callee head is foreign authority."""
    project, _artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        continuations = boundary.near_return_continuations
        assert continuations is not None
        premise = continuations.premise
        foreign = replace(premise, callee_addr=premise.callee_addr + 0x40)
        tampered = replace(
            boundary,
            near_return_continuations=replace(
                continuations, premise=foreign
            ),
        )
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, tampered, invocation_scope=scope
        )
        assert view.failure is _FAIL.SURFACE_MISMATCH
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_missing_selector_evidence_refuses(tmp_path: Path) -> None:
    """Without selector evidence no marker may be silently discharged."""
    project, artifact, boundary, scope, _bundle = _fixture(tmp_path)
    try:
        view = sco.prove_scoped_control_obligations_8616(
            artifact,
            boundary,
            {},
            project=project,
            invocation_scope=scope,
        )
        assert view.failure is _FAIL.RESIDUAL_REFUSAL
        assert view.materialized_count == 0
        assert view.failure_count == 2
        assert view.cfg_projection_for(scope) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_foreign_selector_evidence_refuses(tmp_path: Path) -> None:
    """Selector evidence minted over another surface binds nothing."""
    project, artifact, boundary, scope, _bundle = _fixture(tmp_path)
    foreign_project: angr.Project | None = None
    try:
        # A second world whose callee places its selector obligation on
        # a different block: its terminal evidence can never account for
        # this surface's marker census.
        boot2, project2 = _world(tmp_path, _MZ_SPLIT_CALLEE_CODE)
        foreign_project = project2
        _cb, _ca, index2 = _caller_surface(project2)
        _install_source(project2, boot2, index2)
        resolved2 = edcp._callee_artifact_and_boundary_8616(
            project2, _MZ_CALLEE
        )
        assert resolved2 is not None
        artifact2, boundary2 = resolved2
        bundle2 = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project2, boundary2, artifact2
        )
        assert bundle2 is not None
        view = sco.prove_scoped_control_obligations_8616(
            artifact,
            boundary,
            bundle2.terminal_evidence,
            project=project,
            invocation_scope=scope,
        )
        assert view.failure is _FAIL.RESIDUAL_REFUSAL
        assert view.cfg_projection_for(scope) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        if foreign_project is not None:
            edcp.install_real16_invocation_source_8616(
                foreign_project, None
            )


def test_mutated_native_bytes_revoke_everything(tmp_path: Path) -> None:
    """Changed native bytes void the bundle, the proof, and the seam."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        assert view.cfg_projection_for(scope) is not None
        # Overwrite the selector transfer's displacement: every
        # downstream re-authentication must now refuse.
        project.loader.memory.store(_MZ_JMP_HEAD + 1, b"\x00\x00")
        assert (
            vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                project, boundary, artifact
            )
            is None
        )
        refused = sco.prove_scoped_control_obligations_8616(
            artifact,
            boundary,
            {},
            project=project,
            invocation_scope=scope,
        )
        assert refused.failure is not None
        assert refused.cfg_projection_for(scope) is None
        assert (
            edcp._scoped_callee_coverage_8616(
                project, artifact, boundary, scope
            )
            is None
        )
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_changed_selector_proof_at_consumption_refuses(
    tmp_path: Path,
) -> None:
    """A retained view never exposes stale evidence under mutated bytes."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        assert view.cfg_projection_for(scope) is not None
        # Once the native bytes change, the consuming entry's own
        # re-derivation refuses and the per-consumption replay can no
        # longer authenticate the retained chain.
        project.loader.memory.store(_MZ_JMP_HEAD + 1, b"\x00\x00")
        assert view.cfg_projection_for(scope) is None
        assert not view.complete_for(scope)
        coverage = ibc.prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, view
        )
        assert not coverage.complete_for(scope)
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_retained_evidence_substitution_refuses(tmp_path: Path) -> None:
    """A substituted proof, application, or ledger can never launder."""
    project, _artifact, boundary, scope, bundle = _fixture(tmp_path)
    foreign_project: angr.Project | None = None
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        # A forged ledger never authorizes a projection.
        for field_name, value in (
            ("raw_fact_count", 1),
            ("normalized_fact_count", 1),
            ("classified_fact_count", 1),
            ("materialized_count", 0),
            ("failure_count", 1),
        ):
            forged = replace(view, **{field_name: value})
            assert forged.cfg_projection_for(scope) is None
        # A proof minted over a surface whose continuation carrier
        # differs binds a different canonical source digest; an
        # application minted over it fails object-identity binding.
        foreign_project, foreign_view = _foreign_view(
            tmp_path, _MZ_FOREIGN_CALLEE_CODE
        )
        assert foreign_view.failure is None
        assert foreign_view.selector_proof is not None
        assert foreign_view.selector_application is not None
        substituted = replace(
            view, selector_proof=foreign_view.selector_proof
        )
        assert substituted.cfg_projection_for(scope) is None
        substituted = replace(
            view,
            selector_application=foreign_view.selector_application,
        )
        assert substituted.cfg_projection_for(scope) is None
        # Dropping the retained joint evidence reverts to the
        # continuation-only ledger, which the joint counts cannot match.
        stripped = replace(
            view, selector_proof=None, selector_application=None
        )
        assert stripped.cfg_projection_for(scope) is None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
        if foreign_project is not None:
            edcp.install_real16_invocation_source_8616(
                foreign_project, None
            )


def test_universal_routes_stay_refused(tmp_path: Path) -> None:
    """Publication and context-free coverage never accept the joint body."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        verdict = publish_function_ir_artifact_8616(project, artifact)
        assert verdict.verdict is not FunctionIRArtifactVerdict8616.PROVEN
        assert verdict.artifact is None
        resolution = registered_function_ir_artifact_8616(
            project, _MZ_CALLEE
        )
        assert resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN
        universal = ibc.prove_ir_boundary_coverage_8616(
            project, boundary, artifact
        )
        assert universal.failure is not None
        assert not universal.complete
        assert not universal.complete_for(None)
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        assert not view.complete
        assert not view.complete_for(None)
        coverage = ibc.prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, view
        )
        assert coverage.complete_for(scope)
        assert not coverage.complete
    finally:
        edcp.install_real16_invocation_source_8616(project, None)


def test_per_marker_accounting_recomputes(tmp_path: Path) -> None:
    """The joint ledger is recomputable evidence, not a stored claim."""
    project, artifact, boundary, scope, bundle = _fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope
        )
        assert view.failure is None
        expected = sco.scoped_obligations_expected_counts_8616(
            view, authenticated=True
        )
        assert expected == (2, 2, 2, 2, 0)
        assert (
            view.raw_fact_count,
            view.normalized_fact_count,
            view.classified_fact_count,
            view.materialized_count,
            view.failure_count,
        ) == expected
        # A refused view materializes nothing and adds its own typed
        # failure on top of every un-discharged marker.
        refused = sco.prove_scoped_control_obligations_8616(
            artifact,
            boundary,
            {},
            project=project,
            invocation_scope=scope,
        )
        assert (
            refused.raw_fact_count,
            refused.normalized_fact_count,
            refused.classified_fact_count,
            refused.materialized_count,
            refused.failure_count,
        ) == (2, 2, 2, 0, 2)
        serialized = view.to_dict()
        assert serialized["verdict"] == "proven"
        assert serialized["selector_application_status"] == "applied"
        assert serialized["selector_proof"] is not None
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
