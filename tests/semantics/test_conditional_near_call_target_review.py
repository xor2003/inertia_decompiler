"""Parent controls for contradictory and stale conditional CALL evidence."""
from dataclasses import replace

import pytest

from inertia.ir.core import IRValue, MemSpace
from inertia.semantics import conditional_near_call_target as owner
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBindingFailure8616,
)
from tests.semantics.test_conditional_near_call_target import _consume, _prove, _surface

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("field", ["failure", "preflight_failure"])
def test_consumer_rejects_conditional_record_with_failure(field: str) -> None:
    """A conditional verdict cannot erase a retained failure field."""
    surface = _surface()
    theorem = _prove(surface)
    assert theorem.verdict is owner.ConditionalNearCallTargetVerdict8616.CONDITIONAL
    failure = (owner.ConditionalNearCallTargetFailure8616.REQUEST_EXPIRED
               if field == "failure"
               else DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED)
    contradictory = replace(theorem, **{field: failure})
    assert not _consume(surface, contradictory)


@pytest.mark.parametrize("mutation", [
    "root", "incoming_bytes", "operand", "operand_in_place",
    "block_membership", "context_interval",
])
def test_last_native_callback_cannot_leave_stale_theorem(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Native target validation cannot revoke earlier facts unnoticed."""
    surface = _surface()
    original = owner.direct_near_call_target_is_bound_8616

    def mutate_after_check(*args: object, **kwargs: object) -> bool:
        result = original(*args, **kwargs)
        assert result
        if mutation == "root":
            object.__setattr__(surface.artifact, "function_addr", 0x1020)
        elif mutation == "incoming_bytes":
            surface.project.loader.memory.store(0x1000, b"\x90")
        elif mutation == "operand":
            object.__setattr__(surface.call, "args", (IRValue(MemSpace.CONST, const=0, size=4),))
        elif mutation == "operand_in_place":
            object.__setattr__(surface.call.args[0], "size", 1)
        elif mutation == "block_membership":
            object.__setattr__(surface.artifact, "blocks", ())
        else:
            object.__setattr__(surface.context, "selector_high", 0)
        return result

    monkeypatch.setattr(owner, "direct_near_call_target_is_bound_8616", mutate_after_check)
    theorem = _prove(surface)
    assert theorem.verdict is owner.ConditionalNearCallTargetVerdict8616.REFUSED


def test_seal_recaptures_graph_once_after_final_context_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seal runs exactly one full graph recapture — the final one.

    The pre-rebind reconciliation is cheap (identity/scalars/context)
    and the single fresh source graph is captured only after the last
    native context consume, never twice per seal.
    """
    surface = _surface()
    order = []
    consume = owner.consume_native_near_call_entry_8616
    graph_equal = owner._graph_facts_equal_8616

    def seen_consume(*args: object, **kwargs: object) -> bool:
        order.append("consume")
        return consume(*args, **kwargs)

    def seen_graph(*args: object, **kwargs: object) -> bool:
        order.append("graph")
        return graph_equal(*args, **kwargs)

    monkeypatch.setattr(
        owner, "consume_native_near_call_entry_8616", seen_consume)
    monkeypatch.setattr(owner, "_graph_facts_equal_8616", seen_graph)
    theorem = _prove(surface)
    assert theorem.verdict is owner.ConditionalNearCallTargetVerdict8616.CONDITIONAL
    assert order.count("graph") == 1
    assert order[-1] == "graph"
    assert order.index("graph") > len(order) - order[::-1].index("consume") - 1


@pytest.mark.parametrize("mutation", [
    "operand", "operand_in_place", "operand_removed", "context_interval",
])
def test_final_context_replay_reconciles_full_ir(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """The final context check may not invalidate the preceding raw-IR check."""
    surface = _surface()
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def mutate_after_final_replay(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            assert result
            if mutation == "operand":
                object.__setattr__(surface.call, "args", (IRValue(MemSpace.CONST, const=0, size=4),))
            elif mutation == "operand_in_place":
                object.__setattr__(surface.call.args[0], "size", 1)
            elif mutation == "operand_removed":
                object.__setattr__(surface.call, "args", ())
            else:
                object.__setattr__(surface.context, "selector_high", 0)
        return result

    monkeypatch.setattr(owner, "consume_native_near_call_entry_8616", mutate_after_final_replay)
    theorem = _prove(surface)
    assert calls >= 2
    assert theorem.verdict is owner.ConditionalNearCallTargetVerdict8616.REFUSED


@pytest.mark.parametrize("address", [0x1000, 0x1010, 0x1013])
def test_final_native_change_refuses(monkeypatch: pytest.MonkeyPatch, address: int) -> None:
    """Final context replay cannot revoke incoming, outgoing, or root bytes."""
    surface = _surface()
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def mutate(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            assert result
            surface.project.loader.memory.store(address, b"\x90")
        return result

    monkeypatch.setattr(owner, "consume_native_near_call_entry_8616", mutate)
    result = _prove(surface)
    assert calls >= 2
    assert result.verdict is owner.ConditionalNearCallTargetVerdict8616.REFUSED


def test_non_json_boundary_metadata_preserves_target_admission() -> None:
    """Optional native cache-key eligibility is not conditional target authority."""
    surface = _surface()
    info = dict(surface.context.boundary.info)
    info['opaque_annotation'] = object()
    object.__setattr__(surface.context.boundary, 'info', info)
    theorem = _prove(surface)
    assert theorem.verdict is owner.ConditionalNearCallTargetVerdict8616.CONDITIONAL


def test_final_context_cannot_remove_available_native_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A final callback cannot erase previously retained native-key evidence."""
    surface = _surface()
    original = owner.consume_native_near_call_entry_8616
    calls = 0

    def mutate_after_final(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            info = dict(surface.context.boundary.info)
            info['opaque_annotation'] = object()
            object.__setattr__(surface.context.boundary, 'info', info)
        return result

    monkeypatch.setattr(owner, 'consume_native_near_call_entry_8616', mutate_after_final)
    assert _prove(surface).verdict is owner.ConditionalNearCallTargetVerdict8616.REFUSED


@pytest.mark.parametrize("mutation", ["graph", "context"])
def test_native_snapshot_read_cannot_bypass_final_owned_seal(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Native freshness reads precede the last owned graph/context seal."""
    surface = _surface()
    original = owner._capture_native_facts_8616
    calls = 0

    def mutate(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            if mutation == "graph":
                object.__setattr__(surface.call.args[0], "size", 1)
            else:
                object.__setattr__(surface.context, "selector_high", 0)
        return result

    monkeypatch.setattr(owner, "_capture_native_facts_8616", mutate)
    result = _prove(surface)
    assert calls == 2
    assert result.verdict is owner.ConditionalNearCallTargetVerdict8616.REFUSED
