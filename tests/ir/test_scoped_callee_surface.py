"""Authenticate coverage-free selection exactly once through its canonical route."""

import time

import pytest

from inertia.ir import entry_domain_call_preservation as intake
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from tests.ir.test_raw_callee_scoped_call_chain import _collect
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper

pytestmark = pytest.mark.decompiler


def test_current_route_authenticates_once(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scoped view owns current authentication after static surface selection."""
    callee = _collect(calls_with_pending_helper)[0].callee
    scope = callee.state.invocation_scope
    calls = []
    original = domain._derive_invocation_domain_8616

    def counted(*args: object, **kwargs: object) -> domain._Derivation8616:
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(domain, "_derive_invocation_domain_8616", counted)
    with direct_evidence_deadline_scope_8616(scope.project, time.monotonic() + 20), native_import_request_8616():
        surface = intake._closure_scope_bound_8616(scope.project, callee.coverage.artifact.function_addr, scope)
        assert surface is not None
        coverage = intake._scoped_callee_coverage_8616(scope.project, *surface, scope)
        assert coverage is not None
    # The factory and consumer each authenticate the two-entry chain once.
    assert len(calls) == 4


@pytest.mark.parametrize(
    "mutation",
    [
        "native",
        "environment",
        "ir",
        "boundary",
        "producer",
        "cycle",
        "deadline",
        "false_parent",
        "callback_environment",
    ],
)
def test_deferred_route_rejects_stale_scope(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    """Selection never converts stale or forged prerequisite fields into coverage."""
    from dataclasses import replace

    from inertia.ir import vex_import

    project, boot, caller, _boundary, _resolver, _admission = calls_with_pending_helper
    callee = _collect(calls_with_pending_helper)[0].callee
    scope = callee.state.invocation_scope
    artifact = callee.coverage.artifact
    if mutation == "native":
        project.loader.memory.store(0x1040, b"\x90")
    elif mutation == "environment":
        object.__setattr__(boot.environment, "psp_segment", boot.environment.psp_segment ^ 1)
    elif mutation == "ir":
        object.__setattr__(caller.blocks[0].instrs[0], "op", "NOP")
    elif mutation == "boundary":
        object.__setattr__(scope.chain.callee_boundary, "addr", artifact.function_addr + 1)
    elif mutation == "producer":
        monkeypatch.setattr(
            vex_import,
            "build_x86_16_ir_function_artifact",
            lambda *_a, **_k: replace(artifact, function_addr=artifact.function_addr + 1),
        )
    elif mutation == "cycle":
        object.__setattr__(scope.chain, "parent", scope)
    elif mutation == "false_parent":
        object.__setattr__(scope.chain, "parent", object())
    deadline = time.monotonic() + (-1 if mutation == "deadline" else 20)
    with direct_evidence_deadline_scope_8616(project, deadline), native_import_request_8616():
        surface = intake._closure_scope_bound_8616(project, artifact.function_addr, scope)
        if surface is None:
            return
        if mutation == "callback_environment":
            object.__setattr__(boot.environment, "psp_segment", boot.environment.psp_segment ^ 1)
        assert intake._scoped_callee_coverage_8616(project, *surface, scope) is None


def test_view_producer_mutation_refuses_coverage(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A producer callback cannot revoke scope then publish its coverage."""
    project, boot, _caller, _boundary, _resolver, _admission = calls_with_pending_helper
    callee = _collect(calls_with_pending_helper)[0].callee
    scope = callee.state.invocation_scope
    original = intake.prove_scoped_near_return_continuation_view_8616
    callbacks: list[bool] = []

    def revoked(*args: object, **kwargs: object) -> object:
        view = original(*args, **kwargs)
        callbacks.append(True)
        object.__setattr__(boot.environment, "psp_segment", boot.environment.psp_segment ^ 1)
        return view

    monkeypatch.setattr(intake, "prove_scoped_near_return_continuation_view_8616", revoked)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616():
        surface = intake._closure_scope_bound_8616(project, callee.coverage.artifact.function_addr, scope)
        assert surface is not None
        assert intake._scoped_callee_coverage_8616(project, *surface, scope) is None
    assert callbacks
