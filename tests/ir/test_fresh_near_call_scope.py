"""Fresh near-call scoped view: one post-callback application seal.

The synchronous construction chain authenticated the conditional near-call
scope three times: the prove-time initial census gate, the proof run's
final re-verification, and the immediate application's own entry
authentication. The prove/apply owner's private staged operation defers
the producer's final seal into the application core's final seal, which
re-runs the full scope authentication and the original-binding digest
only after every application callback and solver. The count drops to two
without weakening either surviving authentication, and a mutation landing
inside the application admission callback still refuses.
"""
from dataclasses import replace

import pytest

from inertia.ir import entry_jump_domain as jumps
from inertia.ir import near_call_jump_scope as scope_owner
from inertia.ir.vex_import import (
    RawIRFunctionImportBundle8616,
    prove_scoped_x86_16_ir_function_view_8616,
    raw_x86_16_import_bundle_for_artifact_8616,
)
from tests.ir.test_near_call_preservation import _Surface
from tests.ir.test_near_call_scoped_view import _native_pending_view_surface

pytestmark = pytest.mark.decompiler


def _recorded_authentications(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record each full scope authentication with its calling stage."""
    frames: list[str] = []
    real = scope_owner.authenticate_near_call_jump_scope_8616

    def counted(*args: object, **kwargs: object) -> object:
        frames.append("authenticate")
        return real(*args, **kwargs)

    monkeypatch.setattr(
        scope_owner, "authenticate_near_call_jump_scope_8616", counted
    )
    monkeypatch.setattr(
        jumps, "authenticate_near_call_jump_scope_8616", counted
    )
    return frames


def _bundle(surface: _Surface) -> RawIRFunctionImportBundle8616:
    """Return the typed raw import bundle for the fixture surface."""
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    )
    assert bundle is not None
    return bundle


def test_initial_construction_authenticates_at_prove_and_final_seal_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The staged seal removes exactly one duplicate authentication."""
    surface, scope = _native_pending_view_surface()
    bundle = _bundle(surface)
    frames = _recorded_authentications(monkeypatch)
    admission = jumps._application_admission_failure_8616

    def observed_admission(*args: object, **kwargs: object) -> object:
        result = admission(*args, **kwargs)
        frames.append("admission")
        return result

    monkeypatch.setattr(jumps, "_application_admission_failure_8616", observed_admission)
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope,
    )
    assert view.failure is None, view.detail
    assert frames == ["authenticate", "admission", "authenticate"]


@pytest.mark.parametrize("damage", ["caller_bytes", "callee_bytes", "context", "binding_copy", "ir_and_digest"])
def test_mutation_at_application_callback_still_refuses(
    monkeypatch: pytest.MonkeyPatch, damage: str,
) -> None:
    """A source moved inside the admission callback is caught by the seal."""
    surface, scope = _native_pending_view_surface()
    bundle = _bundle(surface)
    admission = jumps._application_admission_failure_8616
    ran: list[object] = []

    def mutating_admission(*args: object, **kwargs: object) -> object:
        result = admission(*args, **kwargs)
        ran.append(result)
        proof = args[0]
        assert isinstance(proof, jumps.EntryJumpDomainProof8616)
        if damage == "caller_bytes":
            surface.project.loader.memory.store(surface.call.addr, b"\x90")
        elif damage == "callee_bytes":
            surface.project.loader.memory.store(0x1008, b"\xcc")
        elif damage == "context":
            object.__setattr__(scope.context, "selector_high", -1)
        elif damage == "binding_copy":
            object.__setattr__(proof, "source_binding", replace(proof.source_binding))
        else:
            object.__setattr__(surface.call, "op", "NOP")
            object.__setattr__(proof.source_binding, "digest", jumps._source_digest_8616(
                surface.artifact.function_addr, surface.artifact.blocks,
            ))
        return result

    monkeypatch.setattr(
        jumps, "_application_admission_failure_8616", mutating_admission
    )
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope,
    )
    assert ran and ran[0] is None
    assert view.failure is not None
    assert view.cfg_projection_for(scope) is None


def test_standalone_public_prove_keeps_final_reverification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public prove keeps its own final scope authentication."""
    surface, scope = _native_pending_view_surface()
    bundle = _bundle(surface)
    frames = _recorded_authentications(monkeypatch)
    proof = jumps.prove_entry_jump_domains_8616(
        surface.artifact,
        bundle.terminal_evidence,
        project=surface.project,
        near_call_scope=scope,
    )
    assert proof is not None
    assert len(frames) == 2


@pytest.mark.parametrize("damage", ["none", "caller_bytes", "callee_bytes", "context", "ir"])
def test_product_boundary_retains_fresh_admission(monkeypatch, damage):
    surface, scope = _native_pending_view_surface()
    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    )
    assert bundle is not None
    product = jumps._ProofRun8616.product
    observed = []

    def altered_product(run):
        proof = product(run)
        observed.append(len(proof.admitted))
        if damage == "caller_bytes":
            surface.project.loader.memory.store(surface.call.addr, b"\x90")
        elif damage == "callee_bytes":
            surface.project.loader.memory.store(0x1008, b"\xcc")
        elif damage == "context":
            object.__setattr__(scope.context, "selector_high", -1)
        elif damage == "ir":
            object.__setattr__(surface.call, "op", "NOP")
        return proof

    monkeypatch.setattr(jumps._ProofRun8616, "product", altered_product)
    view = prove_scoped_x86_16_ir_function_view_8616(
        surface.project, bundle, surface.boundary, near_call_scope=scope,
    )
    assert observed and observed[0] > 0
    if damage == "none":
        assert view.failure is None, view.detail
    else:
        assert view.failure is not None
        assert view.cfg_projection_for(scope) is None




@pytest.mark.parametrize("damage", [False, True])
def test_empty_application_is_sealed_even_without_a_view(monkeypatch, damage):
    from inertia.ir.near_call_jump_scope import NearCallJumpScope8616
    from tests.ir.test_near_call_preservation import _prove_step, _resolver, _surface

    surface = _surface()
    scope = NearCallJumpScope8616(
        surface.project, surface.artifact, surface.context,
        _resolver(surface.project), (_prove_step(surface),),
    )
    admission = jumps._application_admission_failure_8616
    observed = []

    def altered_admission(*args, **kwargs):
        result = admission(*args, **kwargs)
        observed.append(result)
        if damage:
            surface.project.loader.memory.store(surface.call.addr, b"\x90")
        return result

    monkeypatch.setattr(jumps, "_application_admission_failure_8616", altered_admission)
    result = jumps._staged_near_call_entry_domain_8616(
        surface.artifact, {}, project=surface.project, near_call_scope=scope,
    )
    assert observed and observed[0] is None
    expected = (jumps.EntryJumpDomainApplicationStatus8616.STALE_INPUT if damage
                else jumps.EntryJumpDomainApplicationStatus8616.EMPTY)
    assert result.application.status is expected
