"""Bound premise demand across sibling calls without memoizing proof verdicts.

Layer: tests.
Responsibility: observe aggregate collection budgets and reliable scope cleanup.
"""
from dataclasses import dataclass
from types import SimpleNamespace
from typing import cast

import pytest

import inertia.ir.direct_evidence_deadline as deadline_owner
import inertia.ir.entry_domain_call_preservation as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616


@dataclass(frozen=True)
class _RawBudgetProof:
    """Non-retry proof result used only to observe deadline transitions."""

    failure: Real16InvocationFailure8616 | None = None


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("raises", [False, True])
def test_collection_shares_premise_budget(
    monkeypatch: pytest.MonkeyPatch, ambient: bool, nested: bool, raises: bool,
) -> None:
    """Both passes and recursive collectors share accounting, then restore scope."""
    project = SimpleNamespace()
    source = owner.Real16InvocationSource8616(
        object(), None, SimpleNamespace(for_target=lambda head: ()),
    )
    sentinel = owner._PremiseResolution8616(remaining=12) if ambient else None
    project._inertia_entry_domain_premise_resolution_8616 = sentinel
    artifact = IRFunctionArtifact(0x10000, (IRBlock(0x10000, (
        IRInstr("CALL", None, (), addr=0x10000),
        IRInstr("CALL", None, (), addr=0x10003),
    )),))
    boundary = cast(
        owner.ExactFunctionRangeBoundary8616,
        SimpleNamespace(addr=artifact.function_addr, project=project),
    )
    monkeypatch.setattr(owner, "decoded_callsite_index_for_boundary_8616", lambda *a, **k: SimpleNamespace(index=None))
    monkeypatch.setattr(owner, "_decoded_instruction_map_8616", lambda *a: {})
    monkeypatch.setattr(owner, "_invocation_premise_source_8616", lambda *a: source)
    # This test observes budget/session ownership, not boot authentication.
    # Keep its sentinel source away from the native raw-boot proof boundary.
    monkeypatch.setattr(owner, "_request_raw_boot_premise_8616", lambda *a: None)
    monkeypatch.setattr(owner, "_current_entry_route_status_8616", lambda p, s, h, d, status: status)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", lambda *a: None)
    sessions = []
    before = []
    entered = False

    def collect() -> tuple[object, ...]:
        return owner.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda *a: None,
        )

    def prove(*args: object, **kwargs: object) -> SimpleNamespace:
        nonlocal entered
        session = owner._active_premise_resolution_8616(project)
        assert session is not None
        sessions.append(session)
        before.append(session.remaining)
        assert owner._registered_invocation_premise_8616(
            project,
            0x20000,
            0x20000,
            cast(owner.Real16InvocationSource8616, source),
            session,
        ) is None
        assert session.in_flight == frozenset()
        if raises:
            raise ValueError("construction failed")
        if nested and not entered:
            entered = True
            collect()
        return SimpleNamespace(
            binding=SimpleNamespace(failure=owner._selector_window_binding_failure_8616()),
            block=args[3], instruction=args[4],
        )

    monkeypatch.setattr(owner, "prove_entry_domain_call_preservation_8616", prove)
    if raises:
        with pytest.raises(ValueError, match="construction failed"):
            collect()
    else:
        assert len(collect()) == 2
    assert sessions and all(session is sessions[0] for session in sessions)
    initial = 12 if ambient else owner._ENTRY_PREMISE_MAX_RESOLUTIONS_8616
    expected = 1 if raises else 8 if nested else 4
    assert before == list(range(initial, initial - expected, -1))
    assert owner._active_premise_resolution_8616(project) is sentinel
    assert owner._active_resolution_8616(project) is None
    if not ambient and not raises:
        first = sessions[0]
        sessions.clear()
        before.clear()
        assert len(collect()) == 2
        assert sessions[0] is not first
        assert before == list(range(initial, initial - 4, -1))


def test_expired_premise_deadline_refuses_before_surface_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An expired premise request refuses without importing a caller surface."""
    deadline = 24.0
    project = SimpleNamespace(_inertia_direct_evidence_deadline_8616=deadline)
    session = owner._PremiseResolution8616(deadline=deadline + 10.0)
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: deadline)
    imports: list[int] = []
    monkeypatch.setattr(
        owner,
        "_caller_premise_surface_8616",
        lambda *args: imports.append(1),
    )

    premise = owner._registered_invocation_premise_8616(
        project,
        0x10200,
        0x10100,
        owner.Real16InvocationSource8616(
            object(), None, SimpleNamespace(for_target=lambda head: ()),
        ),
        session,
    )

    assert premise is None
    assert session.remaining == owner._ENTRY_PREMISE_MAX_RESOLUTIONS_8616
    assert session.in_flight == frozenset()
    assert imports == []


def test_nested_collections_inherit_one_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested callee and premise sessions join the same direct deadline."""
    project = SimpleNamespace()
    instruction = IRInstr("CALL", None, (), addr=0x10000)
    artifact = IRFunctionArtifact(0x10000, (IRBlock(0x10000, (instruction,)),))
    boundary = SimpleNamespace(project=project, addr=artifact.function_addr)
    deadline = deadline_owner.time.monotonic() + 60.0
    sessions: list[tuple[object, object]] = []

    monkeypatch.setattr(
        owner,
        "decoded_callsite_index_for_boundary_8616",
        lambda *args, **kwargs: SimpleNamespace(index=object()),
    )
    monkeypatch.setattr(owner, "_decoded_instruction_map_8616", lambda *args: {})
    nested_started = False

    def prove(*args: object, **kwargs: object) -> SimpleNamespace:
        nonlocal nested_started
        callee = owner._active_resolution_8616(project)
        premise = owner._active_premise_resolution_8616(project)
        assert callee is not None and premise is not None
        sessions.append((callee, premise))
        assert callee.deadline == premise.deadline == deadline
        if not nested_started:
            nested_started = True
            collect()
        return SimpleNamespace(binding=None)

    def collect() -> tuple[object, ...]:
        return owner.collect_entry_domain_call_preservations_8616(
            project,
            artifact,
            boundary,
            direct_target_resolver=lambda *args: None,
        )

    monkeypatch.setattr(owner, "prove_entry_domain_call_preservation_8616", prove)
    with deadline_owner.direct_evidence_deadline_scope_8616(project, deadline):
        assert len(collect()) == 1
        assert owner._active_direct_evidence_deadline_8616(project) == deadline

    assert len(sessions) == 2
    assert sessions[0][0] is sessions[1][0]
    assert sessions[0][1] is sessions[1][1]
    assert owner._active_resolution_8616(project) is None
    assert owner._active_premise_resolution_8616(project) is None
    assert owner._active_direct_evidence_deadline_8616(project) is None


def _raw_budget_world(monkeypatch, phase, *, ambient):
    """Advance a deterministic deadline at one raw-intake boundary."""
    import inertia.ir.real16_invocation_domain as invocation_owner
    from inertia.ir import raw_boot_route_admission as admission

    elapsed = [10.0 if phase == "entry" else 0.0]
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: elapsed[0])
    project = SimpleNamespace(_inertia_direct_evidence_deadline_8616=10.0 if ambient else None)
    resolution = None if ambient else owner._PremiseResolution8616(deadline=10.0)
    source = owner.Real16InvocationSource8616(object(), lambda *_: None, SimpleNamespace())
    boundary = SimpleNamespace(project=project, addr=0x10000)
    calls = []
    result = _RawBudgetProof()

    def advance(stage):
        if phase == stage:
            elapsed[0] = 10.0

    # Isolate deadline transitions; native eligibility has real-byte tests.
    monkeypatch.setattr(admission, "raw_boot_route_admission_8616",
                        lambda *_: advance("admission") or admission.RawBootRouteAdmission8616.RETAIN_ATTEMPT)

    def evidence(_boot):
        calls.append("evidence")
        advance("evidence")
        return SimpleNamespace(entry_linear=0x10000)

    def exact(_project, _head):
        calls.append("boundary")
        advance("boundary")
        return boundary

    def imported(_project, _boundary):
        calls.append("import")
        advance("import")
        return IRFunctionArtifact(0x10000)

    def cached(_cache, current, _source, surface, importer, *, should_abort):
        calls.append("cache")
        advance("cache")
        if should_abort():
            return None
        return importer(current, surface)

    def proven(*_args, **_kwargs):
        calls.append("proof")
        advance("proof")
        return result

    monkeypatch.setattr(invocation_owner, "_invocation_boot_evidence_8616", evidence)
    monkeypatch.setattr(invocation_owner, "real16_native_census_import_8616", imported)
    monkeypatch.setattr(invocation_owner, "prove_real16_raw_boot_invocation_domain_8616", proven)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", exact)
    def lookup(*_args):
        advance("lookup")
        return SimpleNamespace(verdict=owner.FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE)

    monkeypatch.setattr(owner, "registered_function_ir_artifact_8616", lookup)
    monkeypatch.setattr(owner, "request_raw_boot_native_import_8616", cached)
    return project, source, resolution, calls, result


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("phase", ["entry", "evidence", "lookup", "boundary", "admission", "import"])
def test_raw_boot_deadline_prevents_late_native_work(monkeypatch, ambient, phase):
    """Expired raw intake cannot start imports, cache snapshots or proof replay."""
    project, source, resolution, calls, _ = _raw_budget_world(monkeypatch, phase, ambient=ambient)
    # Only the admission phase needs record-free intake: managed call-record
    # retry deliberately bypasses that barrier. Other phase routes stay intact.
    result = owner._raw_boot_invocation_premise_8616(
        project, 0x10000, 0x10003, source, resolution, allow_call_records=phase != "admission",
    )
    assert result is None
    assert "proof" not in calls
    if phase != "import":
        assert "import" not in calls
        assert "cache" not in calls
    if phase == "entry":
        assert calls == []


@pytest.mark.parametrize("ambient", [False, True])
def test_raw_boot_with_live_deadline_keeps_normal_result(monkeypatch, ambient):
    """The guard changes no result while the original request remains live."""
    project, source, resolution, calls, expected = _raw_budget_world(monkeypatch, "live", ambient=ambient)
    assert owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10003, source, resolution) is expected
    assert calls.count("import") == calls.count("proof") == 1


def test_expired_raw_request_skips_blocked_prefix_snapshot(monkeypatch):
    """A retained refusal does not authorize expensive replay after expiry."""
    project = SimpleNamespace()
    resolution = owner._PremiseResolution8616(deadline=0.0)
    resolution.blocked_prefixes[(0x10000, 0x10003)] = object()
    monkeypatch.setattr(owner, "raw_boot_blocked_prefix_matches_8616",
                        lambda *_: pytest.fail("expired request replayed a blocked-prefix snapshot"))
    assert owner._request_raw_boot_premise_8616(project, 0x10000, 0x10003, object(), resolution) is None


def test_expired_retry_skips_parent_index_and_census(monkeypatch):
    """Fallback admission must check expiry before scanning parent edges."""
    project = SimpleNamespace()
    resolution = owner._PremiseResolution8616(deadline=0.0)
    source = SimpleNamespace(callsite_index=SimpleNamespace(
        for_target=lambda *_: pytest.fail("expired retry scanned parent edges")))
    assert owner._retry_registered_invocation_premise_8616(
        project, 0x10000, 0x10003, object(), object(), object(), source, resolution,
        retry_boot=True,
    ) is None


def test_boundary_exhaustion_never_enters_universal_fallback(monkeypatch):
    """Actual raw-boundary exhaustion remains a non-result for the resolver."""
    project, source, resolution, calls, _ = _raw_budget_world(monkeypatch, "boundary", ambient=False)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616",
                        lambda *_: pytest.fail("late raw work retried universal intake"))
    assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10003, source, resolution) is None
    assert "import" not in calls
    assert "proof" not in calls
    assert resolution.in_flight == frozenset()


def test_cache_snapshot_expiry_skips_raw_native_import(monkeypatch):
    project, source, resolution, calls, _ = _raw_budget_world(monkeypatch, "cache", ambient=False)
    assert owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10003, source, resolution) is None
    assert "cache" in calls
    assert "import" not in calls
    assert "proof" not in calls


def test_blocked_prefix_match_expiry_evicts_without_reuse(monkeypatch):
    elapsed = [0.0]
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: elapsed[0])
    project = SimpleNamespace()
    resolution = owner._PremiseResolution8616(deadline=10.0)
    key = (0x10000, 0x10003)
    resolution.blocked_prefixes[key] = SimpleNamespace(premise=object())

    def matches(*_args):
        elapsed[0] = 10.0
        return True

    monkeypatch.setattr(owner, "raw_boot_blocked_prefix_matches_8616", matches)
    assert owner._request_raw_boot_premise_8616(project, *key, object(), resolution) is None
    assert key not in resolution.blocked_prefixes
    assert resolution.blocked_prefix_reuse_count == 0


@pytest.mark.parametrize("ambient", [False, True])
def test_raw_boot_proof_expiry_returns_no_late_premise(monkeypatch, ambient):
    """Proof completion cannot expose a premise after either request deadline."""
    project, source, resolution, calls, _ = _raw_budget_world(monkeypatch, "proof", ambient=ambient)
    assert owner._raw_boot_invocation_premise_8616(project, 0x10000, 0x10003, source, resolution) is None
    assert calls.count("proof") == 1
