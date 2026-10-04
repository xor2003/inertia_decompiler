"""Exercise resolution guard lifetime independently of native proof semantics.

Layer: tests.
Responsibility: replace only proof-building seams to observe whether a scoped
callee stays in flight during effect construction and cleanup after failure,
and that parent-record work is performed only when its retry consumes it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.ir import entry_domain_call_preservation as resolver
from angr_platforms.X86_16.ir import real16_invocation_domain as domain


@pytest.mark.parametrize("raise_during_effects", [False, True])
def test_scoped_resolution_guard_spans_effect_construction(
    monkeypatch: pytest.MonkeyPatch, raise_during_effects: bool,
) -> None:
    """Guard both reentry during construction and restoration after exceptions."""
    project = SimpleNamespace()
    scope = SimpleNamespace(coverage=None)
    head = 0x10200
    artifact, boundary, coverage, closure = object(), object(), object(), object()
    session = resolver._CalleeResolution8616(lambda *args: None)
    session.in_flight = frozenset({0x10000})
    original_in_flight = session.in_flight
    monkeypatch.setattr(resolver, "_closure_scope_bound_8616", lambda *args: (artifact, boundary))
    monkeypatch.setattr(
        resolver, "_callee_route_8616",
        lambda *args: ((artifact, boundary, coverage), None),
    )
    monkeypatch.setattr(resolver, "_retain_callee_closure_8616", lambda *args: None)

    def effects(*args: object) -> tuple[object, tuple[object, ...]]:
        assert head in session.in_flight
        assert resolver._callee_resolution_guard_failure_8616(project, session, head) is (
            resolver.EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
        )
        if raise_during_effects:
            raise ValueError("sentinel effect-construction failure")
        return closure, ()

    monkeypatch.setattr(resolver, "_callee_effect_closure_8616", effects)
    try:
        if raise_during_effects:
            with pytest.raises(ValueError, match="sentinel effect-construction failure"):
                resolver._callee_closure_8616(project, head, session, scope)
        else:
            result, failure = resolver._callee_closure_8616(project, head, session, scope)
            assert result is closure and failure is None
    finally:
        assert session.in_flight is original_in_flight


@pytest.mark.parametrize("boot_complete,has_parent", [(True, False), (True, True), (False, False), (False, True)])
def test_records_only_for_parent_retry(
    monkeypatch: pytest.MonkeyPatch, boot_complete: bool, has_parent: bool,
) -> None:
    """Skip irrelevant record work; keep fallback records and guard semantics."""
    events: list[str] = []
    head = 0x10000
    artifact = object()
    boundary = SimpleNamespace(addr=head)
    coverage = SimpleNamespace(complete=True)
    boot = SimpleNamespace(failure=None if boot_complete else object(), complete=boot_complete)
    row, record, chained = object(), object(), object()
    project = object()
    session = resolver._PremiseResolution8616()
    source = SimpleNamespace(boot=object(), boot_recompute=object(), callsite_index=SimpleNamespace(for_target=lambda addr: (row,) if has_parent else ()))
    monkeypatch.setattr(resolver, "registered_function_ir_artifact_8616", lambda *a: SimpleNamespace(verdict=resolver.FunctionIRArtifactVerdict8616.PROVEN, artifact=artifact))
    monkeypatch.setattr(resolver, "_exact_boundary_for_8616", lambda *a: boundary)
    monkeypatch.setattr(resolver, "prove_ir_boundary_coverage_8616", lambda *a: coverage)

    def prove(*args: object, **kwargs: object) -> SimpleNamespace:
        assert head in session.in_flight
        events.append("boot")
        return boot

    def records(*args: object) -> tuple[object, ...]:
        assert head in session.in_flight
        events.append("records")
        return (record,)

    def edge(*args: object) -> object:
        assert head in session.in_flight
        assert args[-2] == (record,)
        events.append("edge")
        return chained

    monkeypatch.setattr(domain, "prove_real16_invocation_domain_8616", prove)
    monkeypatch.setattr(resolver, "_surface_call_preservations_8616", records)
    monkeypatch.setattr(resolver, "_edge_invocation_premise_8616", edge)
    result = resolver._registered_invocation_premise_8616(project, head, head + 2, source, session)
    assert result is (boot if boot_complete else chained if has_parent else None)
    assert events == (["boot", "records", "edge"] if not boot_complete and has_parent else ["boot"])
    assert session.in_flight == frozenset()
