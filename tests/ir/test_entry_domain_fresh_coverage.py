"""Fresh producer-result consumption in the caller-premise surface route.

The route must consume the typed failure of the coverage proof it just
constructed instead of running an immediately duplicated live observation.
Retained/public consumption still re-authenticates; nothing here caches a
verdict across requests.
"""

from dataclasses import replace

import inertia.ir.ir_boundary_cfg as _boundary_mod
from inertia.ir.entry_domain_call_preservation import _caller_premise_surface_8616
from tests.ir.test_segment_call_binding_regression import _project


def _observation_counting_project() -> tuple[object, list[tuple[object, int]]]:
    """Real native project plus a counter on the canonical coverage owner."""
    # call near 0x1003; ret — a caller head with real decoded blocks.
    project = _project(bytes.fromhex("e8 00 00 c3"))
    calls: list[tuple[object, int]] = []
    original = _boundary_mod._coverage_failure_8616

    def counted(project_arg, boundary, artifact):
        calls.append((project_arg, artifact.function_addr))
        return original(project_arg, boundary, artifact)

    _boundary_mod._coverage_failure_8616 = counted
    return project, calls


def _restore() -> None:
    _boundary_mod._coverage_failure_8616 = _coverage_failure_original_8616


_coverage_failure_original_8616 = _boundary_mod._coverage_failure_8616


def test_surface_consumes_fresh_verdict_once() -> None:
    """One surface resolution runs the live coverage observation exactly once.

    prove_ir_boundary_coverage_8616 already seals its typed failure from one
    observation; the immediate caller must not pay an identical second one.
    """
    project, calls = _observation_counting_project()
    try:
        surface = _caller_premise_surface_8616(project, 0x1000)
    finally:
        _restore()
    assert surface is not None
    artifact, _boundary, coverage = surface
    assert artifact.function_addr == 0x1000
    assert coverage.failure is None
    assert calls == [(project, 0x1000)]


def test_surface_refusal_uses_same_typed_failure() -> None:
    """A forged registered artifact still refuses before premise use."""
    project, _calls = _observation_counting_project()
    try:
        good = _caller_premise_surface_8616(project, 0x1000)
        assert good is not None
        forged = replace(good[0], blocks=())
        project._inertia_function_ir_artifacts_8616[0x1000] = forged
        refused = _caller_premise_surface_8616(project, 0x1000)
    finally:
        _restore()
    assert refused is None


def test_retained_result_still_reauthenticates_at_consumption() -> None:
    """Skipping the caller's duplicate observation does not weaken downstream.

    The returned coverage keeps full replay: a registry replacement after
    the surface returned still revokes ``complete``, and a second surface
    request pays its own fresh observation (no cross-request retention).
    """
    project, calls = _observation_counting_project()
    try:
        surface = _caller_premise_surface_8616(project, 0x1000)
        assert surface is not None
        coverage = surface[2]
        assert coverage.complete
        project._inertia_function_ir_artifacts_8616[0x1000] = replace(surface[0])
        assert not coverage.complete
        # A fresh request still observes and legitimately authenticates the
        # replacement artifact — no stale verdict is retained across requests.
        before = len(calls)
        fresh = _caller_premise_surface_8616(project, 0x1000)
        assert len(calls) > before
        assert fresh is not None and fresh[0] is not surface[0]
    finally:
        _restore()
