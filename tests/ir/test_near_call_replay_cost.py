"""Replay-cost controls for the conditional near-call preservation seal.

Layer: tests.
Responsibility: pin the consolidated consumption shape — exactly one full
theorem re-proof plus one bounded native re-authentication per
preservation operation instead of two end-to-end factory replays — while
the detached caller snapshot still seals every owned caller, theorem and
obligation fact around the callback boundary and mutated native bytes or
caller IR still refuse with the same typed failures.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from inertia.ir import near_call_preservation as ncp
from inertia.ir import source_graph_binding as sgb
from inertia.semantics import conditional_near_call_target as ccnt
from tests.ir.test_near_call_preservation import (
    _FAILURE,
    _OUTGOING,
    _consume,
    _prove_step,
    _prove_theorem,
    _surface,
)

pytestmark = pytest.mark.decompiler


def _counted(counter: dict[str, int], key: str, function: Any) -> Any:
    """Return a wrapper incrementing ``counter[key]`` per real call."""

    def wrapped(*args: object, **kwargs: object) -> object:
        counter[key] += 1
        return function(*args, **kwargs)

    return wrapped


def _install_counters(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, int]:
    """Count theorem replays, native re-authentications and graph captures.

    The counters bind through each owning module's imported names so they
    observe only the caller-artifact serialization and replay work this
    consolidation owns; callee-side closures counted through other module
    bindings stay outside this ledger.
    """
    counts = {
        "consume": 0,
        "reauth": 0,
        "prove": 0,
        "caller_capture": 0,
        "theorem_capture": 0,
    }
    monkeypatch.setattr(
        ncp,
        "consume_conditional_near_call_target_8616",
        _counted(counts, "consume", ccnt.consume_conditional_near_call_target_8616),
    )
    monkeypatch.setattr(
        ncp,
        "reauthenticate_conditional_near_call_target_8616",
        _counted(
            counts,
            "reauth",
            ccnt.reauthenticate_conditional_near_call_target_8616,
        ),
    )
    monkeypatch.setattr(
        ccnt,
        "prove_conditional_near_call_target_8616",
        _counted(counts, "prove", ccnt.prove_conditional_near_call_target_8616),
    )
    monkeypatch.setattr(
        ncp,
        "capture_immutable_source_graph_facts_8616",
        _counted(
            counts,
            "caller_capture",
            sgb.capture_immutable_source_graph_facts_8616,
        ),
    )
    monkeypatch.setattr(
        ccnt,
        "capture_immutable_source_graph_facts_8616",
        _counted(
            counts,
            "theorem_capture",
            sgb.capture_immutable_source_graph_facts_8616,
        ),
    )
    return counts


def _mutating_chain(
    monkeypatch: pytest.MonkeyPatch, action: Callable[[], None]
) -> None:
    """Run ``action`` inside the first post-resolution callee chain check."""
    original = ncp._callee_chain_failure_8616
    fired = {"done": False}

    def wrapped(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        if not fired["done"]:
            fired["done"] = True
            action()
        return result

    monkeypatch.setattr(ncp, "_callee_chain_failure_8616", wrapped)


def test_consume_replays_theorem_once_with_bounded_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One consume performs one factory replay, not two.

    The consumer defers its one full target replay to the final seal.
    Caller facts are captured at entry and after the last callback; the
    intermediate check reads only owned scalar and identity projections.
    Target replay retains its own two captures. There is no additional
    native-only target replay on this consumer route.
    """
    surface = _surface()
    step = _prove_step(surface)
    counts = _install_counters(monkeypatch)
    assert _consume(surface, step)
    assert counts == {
        "consume": 1,
        "reauth": 0,
        "prove": 1,
        "caller_capture": 2,
        "theorem_capture": 2,
    }


def test_prove_replays_theorem_once_with_bounded_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The prove path keeps the same single-replay seal structure."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    counts = _install_counters(monkeypatch)
    step = _prove_step(surface, theorem)
    assert step.verdict is ncp.ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert counts == {
        "consume": 1,
        "reauth": 1,
        "prove": 1,
        "caller_capture": 2,
        "theorem_capture": 2,
    }


def test_native_mutation_during_callee_work_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seal's native re-authentication still revokes a byte-mutated
    theorem after the callee callbacks run."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    step = _prove_step(surface, theorem)
    _mutating_chain(
        monkeypatch,
        lambda: surface.project.loader.memory.store(
            _OUTGOING, bytes.fromhex("e8f0ff")
        ),
    )
    assert not _consume(surface, step)
    fresh = _surface()
    _mutating_chain(
        monkeypatch,
        lambda: fresh.project.loader.memory.store(
            _OUTGOING, bytes.fromhex("e8f0ff")
        ),
    )
    refused = _prove_step(fresh, _prove_theorem(fresh))
    assert refused.verdict is ncp.ConditionalNearCallPreservationVerdict8616.REFUSED
    assert refused.failure is _FAILURE.THEOREM_NOT_AUTHENTICATED


def test_caller_ir_mutation_during_callee_work_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bracketing snapshot still seals owned-IR drift the bounded
    re-authentication cannot see."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    step = _prove_step(surface, theorem)
    _mutating_chain(
        monkeypatch,
        lambda: object.__setattr__(surface.artifact, "function_addr", 0x1020),
    )
    assert not _consume(surface, step)
    fresh = _surface()
    _mutating_chain(
        monkeypatch,
        lambda: object.__setattr__(fresh.artifact, "function_addr", 0x1020),
    )
    refused = _prove_step(fresh, _prove_theorem(fresh))
    assert refused.verdict is ncp.ConditionalNearCallPreservationVerdict8616.REFUSED
    assert refused.failure is _FAILURE.SEAL_SOURCE_CHANGED


def test_record_integrity_drift_inside_operation_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned theorem integrity facts cover the drift a retained-versus-
    fresh reconciliation previously caught inside the seal."""
    surface = _surface()
    theorem = _prove_theorem(surface)
    step = _prove_step(surface, theorem)
    _mutating_chain(
        monkeypatch, lambda: object.__setattr__(theorem, "shape", None)
    )
    assert not _consume(surface, step)
    fresh = _surface()
    fresh_theorem = _prove_theorem(fresh)
    _mutating_chain(
        monkeypatch, lambda: object.__setattr__(fresh_theorem, "shape", None)
    )
    refused = _prove_step(fresh, fresh_theorem)
    assert refused.verdict is ncp.ConditionalNearCallPreservationVerdict8616.REFUSED
    assert refused.failure is _FAILURE.SEAL_SOURCE_CHANGED
