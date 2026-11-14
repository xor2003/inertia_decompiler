"""Candidate controls: fresh universal closure verdict consumption.

Runs identically against baseline and candidate workspaces. The single
observation-count test is RED on baseline (retention pays a second full
closure evaluation) and GREEN on candidate (the producer verdict is the
last observation). Every other test asserts identical refusal/pool
semantics on both modules.
"""

from dataclasses import replace
from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    build_x86_16_segment_state_artifact,
)
from inertia.ir import entry_domain_call_preservation as entry
from inertia.ir import segment_effect_closure as closure_owner
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
from tests.ir.test_x86_16_segment_effect_closure import (
    _CALLER_CODE,
    _decoded_block_8616,
    _load_native_bytes_8616,
)


def _closure_world() -> tuple:
    """Build the canonical complete-closure world (call $+3; ret)."""
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=_load_native_bytes_8616(_CALLER_CODE))),
    )
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("CALL", None, (), addr=0x1000),
        IRInstr("RET", None, (), addr=0x1003),
    )),))
    publish_function_ir_artifact_8616(project, artifact)
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 4, frozenset({0x1000}), frozenset({0x1000, 0x1003}), (),
        blocks=(_decoded_block_8616(0x1000, _CALLER_CODE, ((0x1000, 3), (0x1003, 1))),),
    )
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    state = build_x86_16_segment_state_artifact(artifact)
    return project, artifact, coverage, state


def _resolution() -> object:
    return entry._CalleeResolution8616(resolver=SimpleNamespace())


def _counting_evidence(monkeypatch) -> list:
    """Count _bounded_closure_evidence_8616 evaluations (module-global path)."""
    calls: list = []
    original = closure_owner._bounded_closure_evidence_8616

    def counted(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(closure_owner, "_bounded_closure_evidence_8616", counted)
    return calls


def test_retention_consumes_fresh_verdict_once(monkeypatch) -> None:
    """RED on baseline, GREEN on candidate: no second closure evaluation."""
    _project, artifact, coverage, state = _closure_world()
    closure = prove_segment_effect_closure_8616(coverage, state)
    assert closure.failure is None
    calls = _counting_evidence(monkeypatch)
    resolution = _resolution()
    entry._retain_callee_closure_8616(resolution, 0x1000, artifact, (), closure, None)
    assert resolution.retained_closures[0x1000] is closure
    assert calls == []


def test_fresh_refusal_not_retained() -> None:
    """Fresh producer refusal keeps identical pool exclusion on both modules."""
    _project, artifact, coverage, state = _closure_world()
    state.entry_states[0x1000].pop("ds")
    closure = prove_segment_effect_closure_8616(coverage, state)
    assert closure.failure is not None
    resolution = _resolution()
    entry._retain_callee_closure_8616(resolution, 0x1000, artifact, (), closure, None)
    assert 0x1000 not in resolution.retained_closures


def test_retained_hit_still_reauthenticates(monkeypatch) -> None:
    """Pool hits replay the full observation on both modules; mutation revokes."""
    project, artifact, coverage, state = _closure_world()
    closure = prove_segment_effect_closure_8616(coverage, state)
    resolution = _resolution()
    entry._retain_callee_closure_8616(resolution, 0x1000, artifact, (), closure, None)
    calls = _counting_evidence(monkeypatch)
    assert entry._retained_closure_bound_8616(project, 0x1000, closure) is True
    assert len(calls) == 1
    project.loader.memory.load = _load_native_bytes_8616(b"\x90\x90\x90\xc3")
    calls.clear()
    assert entry._retained_closure_bound_8616(project, 0x1000, closure) is False
    assert len(calls) == 1


def test_forged_census_not_retained(monkeypatch) -> None:
    """A replaced producer returning fabricated census tuples seeds nothing."""
    _project, artifact, coverage, state = _closure_world()
    real = prove_segment_effect_closure_8616(coverage, state)
    forged = replace(real, callsite_addrs=(0xDEAD,))
    monkeypatch.setattr(
        entry, "prove_segment_effect_closure_8616", lambda *_a, **_k: forged)
    resolution = _resolution()
    entry._retain_callee_closure_8616(resolution, 0x1000, artifact, (), forged, None)
    assert 0x1000 not in resolution.retained_closures


def test_scoped_request_still_revalidates(monkeypatch) -> None:
    """A non-None scope keeps the full complete_for replay on both modules."""
    _project, artifact, coverage, state = _closure_world()
    closure = prove_segment_effect_closure_8616(coverage, state)
    calls = _counting_evidence(monkeypatch)
    resolution = _resolution()
    scope = SimpleNamespace()
    entry._retain_callee_closure_8616(
        resolution, 0x1000, artifact, (), closure, scope)
    assert len(calls) == 1
    assert resolution.scoped_closures[(0x1000, id(scope))] is closure
    assert 0x1000 not in resolution.retained_closures
