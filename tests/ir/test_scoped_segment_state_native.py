"""Authentic retained scopes remain fresh after removing one redundant replay."""
import time
from dataclasses import replace

import pytest

from inertia.ir import real16_invocation_domain as domain
from inertia.ir import scoped_function_ir_view as view_owner
from inertia.ir import vex_import
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from tests.ir.test_raw_callee_scoped_call_chain import (
    _collect,
)
from tests.ir.test_raw_callee_scoped_call_chain import (
    calls_with_pending_helper as calls_with_pending_helper,
)

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", ["native", "environment", "ir", "boundary", "producer", "cycle", "deadline"])
def test_current_scope_mutations_refuse(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Native scope authentication still rejects each mutable prerequisite."""
    project, boot, caller, _boundary, _resolver, _admission = calls_with_pending_helper
    record = _collect(calls_with_pending_helper)[0]
    callee = record.callee
    scope = callee.state.invocation_scope
    artifact = callee.coverage.artifact
    view = callee.coverage.scoped_view
    if mutation == "native":
        project.loader.memory.store(0x1040, b"\x90")
    elif mutation == "environment":
        object.__setattr__(boot.environment, "psp_segment", boot.environment.psp_segment ^ 1)
    elif mutation == "ir":
        object.__setattr__(caller.blocks[0].instrs[0], "op", "NOP")
    elif mutation == "boundary":
        object.__setattr__(scope.chain.callee_boundary, "addr", artifact.function_addr + 1)
    elif mutation == "producer":
        monkeypatch.setattr(vex_import, "build_x86_16_ir_function_artifact", lambda *_args, **_kwargs: replace(artifact, function_addr=artifact.function_addr + 1))
    elif mutation == "cycle":
        object.__setattr__(scope.chain, "parent", scope)
    deadline = time.monotonic() + (-1 if mutation == "deadline" else 20)
    with (
        direct_evidence_deadline_scope_8616(project, deadline),
        native_import_request_8616(), pytest.raises(ValueError),
    ):
        build_x86_16_segment_state_artifact(
            artifact, invocation_scope=scope, scoped_view=view,
        )


def test_refused_cfg_producer_remains_a_non_result(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typed producer that cannot supply current projection cannot authorize state."""
    record = _collect(calls_with_pending_helper)[0]
    callee = record.callee
    view = callee.coverage.scoped_view
    assert view is not None
    monkeypatch.setattr(type(view), "cfg_projection_for", lambda *_args: None)
    with pytest.raises(ValueError):
        build_x86_16_segment_state_artifact(
            callee.coverage.artifact, invocation_scope=callee.state.invocation_scope,
            scoped_view=callee.coverage.scoped_view,
        )


@pytest.mark.parametrize("field", ["source_artifact", "scope", "predecessors"])
def test_malformed_current_projection_cannot_authorize_state(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """The authentic producer must still return a projection of this exact census."""
    record = _collect(calls_with_pending_helper)[0]
    callee = record.callee
    scope = callee.state.invocation_scope
    view = callee.coverage.scoped_view
    original = type(view).cfg_projection_for

    def forged(self: view_owner.ScopedFunctionIRView8616, offered: object) -> object:
        projection = original(self, offered)
        assert projection is not None
        if field == "source_artifact":
            return replace(projection, source_artifact=replace(projection.source_artifact))
        if field == "scope":
            return replace(projection, scope=replace(scope, boot=object()))
        return replace(projection, predecessors={-1: ()})

    monkeypatch.setattr(type(view), "cfg_projection_for", forged)
    with pytest.raises(ValueError):
        build_x86_16_segment_state_artifact(
            callee.coverage.artifact, invocation_scope=scope, scoped_view=view,
        )


def test_native_scoped_solve_authenticates_once(
    calls_with_pending_helper: tuple[object, ...], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The current pending helper's scope is derived once per canonical projection."""
    callee = _collect(calls_with_pending_helper)[0].callee
    original = domain._derive_invocation_domain_8616
    calls = []

    def tracked(*args: object, **kwargs: object) -> domain._Derivation8616:
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(domain, "_derive_invocation_domain_8616", tracked)
    state = build_x86_16_segment_state_artifact(
        callee.coverage.artifact, invocation_scope=callee.state.invocation_scope,
        scoped_view=callee.coverage.scoped_view,
    )
    assert state.source_artifact is callee.coverage.artifact
    assert state.invocation_scope is callee.state.invocation_scope
    # The callee and its declared parent each replay exactly once.
    assert len(calls) == 2
