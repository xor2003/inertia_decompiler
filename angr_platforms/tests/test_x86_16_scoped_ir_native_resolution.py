"""Native scoped resolver/cache integration controls.

Layer: tests.
Responsibility: exercise actual MZ-derived entries and native dependency
revocation; no patched proof verdicts, lift results or source authenticity.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
import test_x86_16_scoped_native_inputs as native
from angr_platforms.X86_16.ir import entry_domain_call_preservation as resolver
from angr_platforms.X86_16.ir import ir_boundary_cfg, real16_invocation_domain, vex_import
from angr_platforms.X86_16.ir.core import IRRefusal
from angr_platforms.X86_16.ir.entry_jump_domain import (
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainRefusal8616,
)
from test_x86_16_scoped_native_inputs import LEAF, _view, world  # noqa: F401


def test_failed_optional_application_keeps_raw_refusals_and_diagnostics(world: tuple) -> None:  # noqa: F811
    """Failed discharge keeps raw native facts plus its separate typed diagnostic."""
    _boot, project, _sb, _sa, _index, boundary, held = world
    raw = vex_import._import_raw_x86_16_function_bundle_8616(project, boundary).artifact
    assert held.refusals == raw.refusals
    assert held.refusals, "pending native edges must remain refused"
    assert not ir_boundary_cfg.prove_ir_boundary_coverage_8616(project, boundary, held).complete
    application = held.summary["entry_jump_domain_application"]
    assert application["status"] == EntryJumpDomainApplicationStatus8616.STALE_INPUT.value
    assert application["refusals"], "failed application diagnostic must remain visible"


def test_native_census_stale_refusal_is_never_waived(
    world: tuple, monkeypatch: pytest.MonkeyPatch,  # noqa: F811
) -> None:
    """Even a familiar application reason cannot hide a native-census failure."""
    _boot, project, _sb, _sa, _index, boundary, _held = world
    raw = vex_import._import_raw_x86_16_function_bundle_8616(project, boundary).artifact
    marker = IRRefusal(EntryJumpDomainRefusal8616.APPLICATION_INPUT_STALE.value,
                       "injected independent native-census failure")
    corrupt_census = replace(raw, refusals=(*raw.refusals, marker))
    monkeypatch.setattr(real16_invocation_domain, "real16_native_census_import_8616",
                        lambda *_: corrupt_census)
    assert ir_boundary_cfg._scoped_native_failure_8616(
        project, boundary, raw,
    ) is ir_boundary_cfg.IRBoundaryCoverageFailure8616.SCOPED_REFUSAL


def test_native_resolver_closes_scoped_body_and_revalidates_cache(world: tuple) -> None:  # noqa: F811
    """Use the real resolver for a pending body with a nested CALL and RET."""
    view, scope, artifact = _view(world)
    project = view.boundary.project
    session = resolver._CalleeResolution8616(native._resolver(project))
    previous = getattr(project, '_inertia_entry_domain_call_resolution_8616', None)
    project._inertia_entry_domain_call_resolution_8616 = session
    try:
        closure, failure = resolver._callee_closure_8616(project, native.CALLER, session, scope)
        assert failure is None, failure
        assert closure is not None
        assert closure.complete_for(scope)
        assert not closure.complete
        assert closure.coverage.artifact is artifact
        assert closure.state.scoped_view is closure.coverage.scoped_view
        assert closure.callsite_addrs == (native.CALL_SITE,)
        assert closure.state.summary['classified_call_count'] == 1
        remaining = session.remaining
        cached, failure = resolver._callee_closure_8616(project, native.CALLER, session, scope)
        assert failure is None
        assert cached is closure
        assert session.remaining == remaining
        assert native.CALLER not in session.retained_closures
        assert native.CALLER not in session.retained
        universal, _ = resolver._callee_closure_8616(project, native.CALLER, session)
        assert universal is None or not universal.complete
        assert native.CALLER not in session.retained_closures
        foreign, _ = resolver._callee_closure_8616(
            project, native.CALLER, session, replace(scope, boot=object()),
        )
        assert foreign is None
        project.loader.memory.store(native.LEAF, b'\x90')
        stale, _ = resolver._callee_closure_8616(project, native.CALLER, session, scope)
        assert stale is None or not stale.complete_for(scope)
    finally:
        project._inertia_entry_domain_call_resolution_8616 = previous


def test_native_distinct_boot_scopes_do_not_share_conditional_closure(world: tuple) -> None:  # noqa: F811
    """Equal boot bytes with distinct retained authority remain separate scopes."""
    view, scope_a, artifact = _view(world)
    boot_b = replace(world[0])
    assert boot_b == world[0] and boot_b is not world[0]
    _other_view, scope_b, other_artifact = _view((boot_b, *world[1:]))
    assert other_artifact is artifact
    assert scope_a.complete and scope_b.complete
    assert not real16_invocation_domain.same_real16_entry_scope_8616(scope_a, scope_b)
    project = view.boundary.project
    session = resolver._CalleeResolution8616(native._resolver(project))
    previous = getattr(project, '_inertia_entry_domain_call_resolution_8616', None)
    project._inertia_entry_domain_call_resolution_8616 = session
    try:
        # _view installed B's source authority last. A cannot mint a new
        # closure from B's independently derived premises, despite equal bytes.
        refused, failure = resolver._callee_closure_8616(project, native.CALLER, session, scope_a)
        assert refused is None
        assert failure is resolver.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
        native._install(project, world[0], world[4])
        first, failure = resolver._callee_closure_8616(project, native.CALLER, session, scope_a)
        assert failure is None and first is not None
        native._install(project, boot_b, world[4])
        second, failure = resolver._callee_closure_8616(project, native.CALLER, session, scope_b)
        assert failure is None and second is not None
        assert first is not second
        assert first.complete_for(scope_a) and not first.complete_for(scope_b)
        assert second.complete_for(scope_b) and not second.complete_for(scope_a)
        native._install(project, world[0], world[4])
        remaining = session.remaining
        reused, failure = resolver._callee_closure_8616(project, native.CALLER, session, scope_a)
        assert failure is None and reused is first
        assert session.remaining == remaining
    finally:
        project._inertia_entry_domain_call_resolution_8616 = previous
