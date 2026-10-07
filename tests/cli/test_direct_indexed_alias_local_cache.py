from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import angr
import inertia.ir.function_ssa_registry as function_ssa_registry
import networkx as nx
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.ir.direct_evidence_deadline as deadline_owner
import inertia.ir.entry_domain_call_preservation as resolution_owner

import inertia.cli.cache as cache_module
import inertia.cli.direct_indexed_alias_local_cache as local_cache
import inertia.cli.indexed_alias_program_context as program_context
from inertia.cli.direct_indexed_alias_local_cache import (
    build_cached_direct_indexed_alias_local_evidence_8616,
)

_INDEXED_FUNCTION = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 88 87 00 02 "
    "8b 5e fe d1 e3 88 a7 01 02 "
    "8b 5e fe d1 e3 88 87 00 03 "
    "8b 5e fe d1 e3 88 a7 01 03 c9 c3"
)


@dataclass(frozen=True, slots=True)
class _BlockNode:
    addr: int
    size: int


def _project() -> angr.Project:
    return angr.Project(
        io.BytesIO(_INDEXED_FUNCTION),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )


def _function() -> object:
    graph = nx.DiGraph()
    graph.add_node(_BlockNode(0x1000, len(_INDEXED_FUNCTION)))
    return SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        graph=graph,
        info={},
    )


def test_fresh_direct_project_hydrates_ir_ssa_before_local_alias_build(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    original_builder = function_ssa_registry.build_x86_16_ir_function_artifact
    raw_build_projects: list[object] = []

    def counted_builder(project: object, function: object) -> object:
        raw_build_projects.append(project)
        return original_builder(project, function)

    monkeypatch.setattr(
        function_ssa_registry,
        "build_x86_16_ir_function_artifact",
        counted_builder,
    )
    first_project = _project()
    first = build_cached_direct_indexed_alias_local_evidence_8616(
        first_project,
        _function(),
    )
    second_project = _project()
    second = build_cached_direct_indexed_alias_local_evidence_8616(
        second_project,
        _function(),
    )

    assert first.closed
    assert second.closed
    assert raw_build_projects == [first_project]
    assert second_project not in raw_build_projects


def test_local_alias_deadline_scope_restores_prior_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The direct evidence scope inherits the tighter deadline and restores it."""
    project = SimpleNamespace()
    previous_deadline = deadline_owner.time.monotonic() + 10.0
    requested_deadline = previous_deadline + 10.0
    project._inertia_direct_evidence_deadline_8616 = previous_deadline
    observed_deadlines: list[float | None] = []

    def fail_during_hydration(*args: object) -> object:
        observed_deadlines.append(
            deadline_owner.active_direct_evidence_deadline_8616(project)
        )
        raise ValueError("sentinel hydration failure")

    monkeypatch.setattr(
        local_cache,
        "hydrate_function_ir_ssa_catalog_8616",
        fail_during_hydration,
    )

    with pytest.raises(ValueError, match="sentinel hydration failure"):
        build_cached_direct_indexed_alias_local_evidence_8616(
            project,
            _function(),
            deadline=requested_deadline,
        )

    assert observed_deadlines == [previous_deadline]
    assert deadline_owner.active_direct_evidence_deadline_8616(project) == previous_deadline


def test_nested_deadline_scope_tightens_and_restores_on_exception() -> None:
    """Nested scopes take the minimum and restore the prior project slot."""
    project = SimpleNamespace()
    now = deadline_owner.time.monotonic()
    outer_deadline = now + 30.0
    inner_deadline = now + 15.0

    with (
        deadline_owner.direct_evidence_deadline_scope_8616(project, outer_deadline),
        deadline_owner.direct_evidence_deadline_scope_8616(project, inner_deadline),
    ):
        assert deadline_owner.active_direct_evidence_deadline_8616(project) == inner_deadline
    assert deadline_owner.active_direct_evidence_deadline_8616(project) is None

    with (
        pytest.raises(ValueError, match="sentinel scoped failure"),
        deadline_owner.direct_evidence_deadline_scope_8616(project, inner_deadline),
    ):
        raise ValueError("sentinel scoped failure")
    assert deadline_owner.active_direct_evidence_deadline_8616(project) is None


@pytest.mark.parametrize("session_kind", ["callee", "premise"])
def test_ambient_session_deadline_prevents_local_cache_work(
    monkeypatch: pytest.MonkeyPatch,
    session_kind: str,
) -> None:
    """A tighter active session deadline stops local work without a project slot."""
    project = SimpleNamespace()
    deadline = 30.0
    if session_kind == "callee":
        session = resolution_owner._CalleeResolution8616(
            resolver=lambda *args: None,
            deadline=deadline,
        )
        project._inertia_entry_domain_call_resolution_8616 = session
    else:
        session = resolution_owner._PremiseResolution8616(deadline=deadline)
        project._inertia_entry_domain_premise_resolution_8616 = session
    assert not hasattr(project, "_inertia_direct_evidence_deadline_8616")
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: deadline)
    calls: list[str] = []

    def unexpected_work(*args: object, **kwargs: object) -> object:
        calls.append("work")
        raise AssertionError("expired session must prevent local evidence work")

    monkeypatch.setattr(local_cache, "hydrate_function_ir_ssa_catalog_8616", unexpected_work)
    monkeypatch.setattr(local_cache, "build_indexed_alias_program_evidence_8616", unexpected_work)
    monkeypatch.setattr(local_cache, "store_function_ir_ssa_catalog_8616", unexpected_work)
    evidence = build_cached_direct_indexed_alias_local_evidence_8616(
        project,
        _function(),
        deadline=deadline + 10.0,
    )

    assert evidence.closed and evidence.stats.failure_count == 1
    assert calls == []
    if session_kind == "callee":
        assert project._inertia_entry_domain_call_resolution_8616 is session
    else:
        assert project._inertia_entry_domain_premise_resolution_8616 is session
    assert session.in_flight == frozenset()
    assert session.remaining == (
        resolution_owner._ENTRY_DOMAIN_CALLEE_MAX_RESOLUTIONS_8616
        if session_kind == "callee"
        else resolution_owner._ENTRY_PREMISE_MAX_RESOLUTIONS_8616
    )
    assert project._inertia_direct_evidence_deadline_8616 is None


def test_expiry_during_hydration_refuses_without_alias_or_cache_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expiry after hydration prevents Alias projection and cache publication."""
    project = _project()
    deadline = 20.0
    now = [19.0]
    calls: list[str] = []
    monkeypatch.setattr(deadline_owner.time, "monotonic", lambda: now[0])

    def hydrate(*args: object) -> object:
        calls.append("hydrate")
        now[0] = deadline
        return SimpleNamespace(stats=SimpleNamespace(closed=True))

    def alias(*args: object) -> object:
        calls.append("alias")
        raise AssertionError("Alias projection must stop after expiry")

    def store(*args: object, **kwargs: object) -> object:
        calls.append("store")
        raise AssertionError("expired IR/SSA must not be persisted")

    monkeypatch.setattr(local_cache, "hydrate_function_ir_ssa_catalog_8616", hydrate)
    monkeypatch.setattr(local_cache, "build_indexed_alias_program_evidence_8616", alias)
    monkeypatch.setattr(local_cache, "store_function_ir_ssa_catalog_8616", store)

    evidence = build_cached_direct_indexed_alias_local_evidence_8616(
        project,
        _function(),
        deadline=deadline,
    )

    assert evidence.closed
    assert evidence.stats.failure_count == 1
    assert evidence.refusals[0].failure is (
        local_cache.IndexedAliasProgramFailureKind8616.IR_BUILD_FAILED
    )
    assert calls == ["hydrate"]
    assert deadline_owner.active_direct_evidence_deadline_8616(project) is None


def test_expired_local_evidence_stops_program_requirement_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An expired local result does not start global requirement discovery."""
    deadline = 72.0
    now = [71.0]
    requirement_calls: list[int] = []
    monkeypatch.setattr(program_context.time, "monotonic", lambda: now[0])

    def expire_local(
        project: object,
        function: object,
        *,
        deadline: float | None = None,
    ) -> object:
        assert deadline == 72.0
        now[0] = 72.0
        return object()

    def collect_requirement(*args: object) -> object:
        requirement_calls.append(1)
        raise AssertionError("expired local evidence must stop this phase")

    monkeypatch.setattr(
        program_context,
        "build_cached_direct_indexed_alias_local_evidence_8616",
        expire_local,
    )
    monkeypatch.setattr(
        program_context,
        "collect_global_object_program_requirement_8616",
        collect_requirement,
    )

    result = program_context.prepare_direct_indexed_alias_program_context_8616(
        SimpleNamespace(),
        SimpleNamespace(),
        _function(),
        timeout=60,
        window=16,
        deadline=deadline,
    )

    assert result.status is program_context.IndexedAliasProgramContextStatus8616.DISCOVERY_INCOMPLETE
    assert result.program is None and result.requirement is None
    assert requirement_calls == []

