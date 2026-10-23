"""Regression controls for final-sealed internal near-call applications.

Layer: tests.
Responsibility: retain public admission behavior and reject late mutations
while internal CALL_TARGETS replay performs one final authentication.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

import inertia.ir.entry_jump_domain as ejd
from inertia.ir.entry_projection_mode import EntryProjectionMode8616


@dataclass
class _AuthenticationCounter:
    auth_calls: int = 0



def _count_authentications(monkeypatch: pytest.MonkeyPatch) -> _AuthenticationCounter:
    """Count owner authentications without changing any behavior."""
    box = _AuthenticationCounter()
    original = ejd.authenticate_near_call_jump_scope_8616

    def counted(scope, *, project, artifact):
        box.auth_calls += 1
        return original(scope, project=project, artifact=artifact)

    monkeypatch.setattr(ejd, "authenticate_near_call_jump_scope_8616", counted)
    return box


def test_internal_call_targets_replay_authenticates_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """FINAL replay: the single post-callback seal authenticates."""
    _, scope, view = _native_view()
    box = _count_authentications(monkeypatch)
    projection = view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS)
    assert projection is not None and len(projection.call_targets) == 1
    assert projection.call_target_status is ejd.ScopedCallTargetStatus8616.ADMITTED
    assert box.auth_calls == 1


def test_internal_control_only_replay_authenticates_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """CONTROL_ONLY keeps exactly one authentication, deferred to the seal."""
    _, scope, view = _native_view()
    box = _count_authentications(monkeypatch)
    projection = view.cfg_projection_for(scope)
    assert projection is not None and projection.applied
    assert box.auth_calls == 1


def test_public_standalone_apply_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """EAGER public apply keeps both authentications after integration."""
    _, scope, view = _native_view()
    box = _count_authentications(monkeypatch)
    application = ejd.apply_entry_jump_domain_8616(
        view.source_artifact, view.proof,
        near_call_scope=scope, projection_mode=EntryProjectionMode8616.CALL_TARGETS,
    )
    assert application.status is ejd.EntryJumpDomainApplicationStatus8616.APPLIED
    assert application.call_targets
    assert box.auth_calls == 2


def test_post_construction_mutation_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A native byte changed after construction still refuses via the seal."""
    surface, scope, view = _native_view()
    box = _count_authentications(monkeypatch)
    surface.project.loader.memory.store(0x1011, b"\x00")
    assert view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS) is None
    assert not view.complete_for(scope)
    assert box.auth_calls >= 1


def test_mid_admission_mutation_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Source drift inside the admission solver is caught by the final seal.

    The skipped in-admission recheck cannot hide drift: the seal's full
    authentication runs after the solver and before anything publishes.
    """
    surface, scope, view = _native_view()
    box = _count_authentications(monkeypatch)
    original_solve = ejd.solve_segment_state_8616
    poisoned = []

    def poisoning_solve(*args, **kwargs):
        if not poisoned:
            poisoned.append(1)
            surface.project.loader.memory.store(0x1011, b"\x00")
        return original_solve(*args, **kwargs)

    monkeypatch.setattr(ejd, "solve_segment_state_8616", poisoning_solve)
    assert view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS) is None
    assert poisoned, "admission solver never ran"
    assert box.auth_calls >= 1


def test_foreign_scope_still_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A copied (non-identical) scope never authenticates under the seal."""
    _, scope, view = _native_view()
    _count_authentications(monkeypatch)
    assert view.cfg_projection_for(replace(scope)) is None
    assert not view.complete_for(replace(scope))
    assert view.cfg_projection_for(None) is None


def _native_view():
    """Build the real native near-call scoped world for the tests."""
    from inertia.ir.vex_import import (
        prove_scoped_x86_16_ir_function_view_8616,
        raw_x86_16_import_bundle_for_artifact_8616,
    )
    from tests.ir.test_near_call_scoped_view import _native_pending_view_surface

    surface, scope = _native_pending_view_surface()
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact)
    assert bundle is not None
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope)
    assert view.failure is None, view.detail
    return surface, scope, view



def test_final_digest_observes_post_derive_source_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    """The final digest must cover source changes inside the entire authentication."""
    from inertia.ir import near_call_jump_scope as owner

    _, scope, view = _native_view()
    binding = view.proof.source_binding
    pins = ejd._ApplicationInputPins8616(
        binding, binding.digest, view.source_artifact.function_addr,
        view.proof.admitted, scope,
    )
    instruction = next(i for b in view.source_artifact.blocks for i in b.instrs if i.op != "CALL")
    derive = owner._derive_final_scoped_theorem_8616
    def mutate_after_derive(*args, **kwargs):
        result = derive(*args, **kwargs)
        object.__setattr__(instruction, "op", "CHANGED")
        return result
    monkeypatch.setattr(owner, "_derive_final_scoped_theorem_8616", mutate_after_derive)
    assert ejd._final_application_seal_refused_8616(view.source_artifact, view.proof, pins)
