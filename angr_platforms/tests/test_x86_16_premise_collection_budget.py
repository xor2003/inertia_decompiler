"""Bound premise demand across sibling calls without memoizing proof verdicts.

Layer: tests.
Responsibility: observe aggregate collection budgets and reliable scope cleanup.
"""
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.ir import entry_domain_call_preservation as owner
from angr_platforms.X86_16.ir.core import IRBlock, IRFunctionArtifact, IRInstr


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("raises", [False, True])
def test_collection_shares_premise_budget(
    monkeypatch: pytest.MonkeyPatch, ambient: bool, nested: bool, raises: bool,
) -> None:
    """Both passes and recursive collectors share accounting, then restore scope."""
    project = SimpleNamespace()
    source = object()
    sentinel = owner._PremiseResolution8616(remaining=12) if ambient else None
    project._inertia_entry_domain_premise_resolution_8616 = sentinel
    artifact = IRFunctionArtifact(0x10000, (IRBlock(0x10000, (
        IRInstr("CALL", None, (), addr=0x10000),
        IRInstr("CALL", None, (), addr=0x10003),
    )),))
    boundary = SimpleNamespace(addr=artifact.function_addr, project=project)
    monkeypatch.setattr(owner, "decoded_callsite_index_for_boundary_8616", lambda *a, **k: SimpleNamespace(index=None))
    monkeypatch.setattr(owner, "_decoded_instruction_map_8616", lambda *a: {})
    monkeypatch.setattr(owner, "_invocation_premise_source_8616", lambda *a: source)
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
        assert owner._registered_invocation_premise_8616(project, 0x20000, 0x20000, source, session) is None
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
