"""Parent controls for stale and incomplete conditional callee evidence."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir import near_call_preservation as owner
from tests.ir.test_near_call_preservation import _consume, _prove_step, _surface

pytestmark = pytest.mark.decompiler


def test_supplied_session_is_visible_to_nested_imports() -> None:
    """Nested imports must share the supplied aggregate callee budget."""
    project = SimpleNamespace(_inertia_entry_domain_call_resolution_8616=None)

    def resolver(instruction: object) -> None:
        return None

    session = owner._CalleeResolution8616(resolver=resolver)
    with owner._resolution_scope_8616(project, resolver, session) as active:
        assert active is session
        assert owner._active_resolution_8616(project) is session
    assert owner._active_resolution_8616(project) is None


def test_nested_session_cannot_reset_budget() -> None:
    """Nested scopes retain the outer session and reject replacement budgets."""
    project = SimpleNamespace(_inertia_entry_domain_call_resolution_8616=None)

    def resolver(instruction: object) -> None:
        return None

    session = owner._CalleeResolution8616(resolver=resolver)
    replacement = owner._CalleeResolution8616(resolver=resolver)
    with owner._resolution_scope_8616(project, resolver, session):
        for supplied in (None, session):
            with owner._resolution_scope_8616(project, resolver, supplied) as nested:
                assert nested is session
            assert owner._active_resolution_8616(project) is session
        with (
            pytest.raises(ValueError, match="active callee resolution budget"),
            owner._resolution_scope_8616(project, resolver, replacement),
        ):
            pytest.fail("A nested replacement must not be entered")
        assert owner._active_resolution_8616(project) is session
    assert owner._active_resolution_8616(project) is None


def test_supplied_session_is_removed_after_exception() -> None:
    """An aborted resolution must not leak its session into later requests."""
    project = SimpleNamespace(_inertia_entry_domain_call_resolution_8616=None)

    def resolver(instruction: object) -> None:
        return None

    session = owner._CalleeResolution8616(resolver=resolver)
    with pytest.raises(RuntimeError, match="abort"), owner._resolution_scope_8616(project, resolver, session):
        raise RuntimeError("abort")
    assert owner._active_resolution_8616(project) is None


def test_missing_target_theorem_refuses_without_crashing() -> None:
    """A removed retained theorem is a non-result, not an AttributeError."""
    surface = _surface()
    step = _prove_step(surface)
    assert step.verdict is owner.ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert not _consume(surface, replace(step, theorem=None))


@pytest.mark.parametrize("consume", [False, True])
def test_callee_check_cannot_revoke_caller_unnoticed(
    monkeypatch: pytest.MonkeyPatch, consume: bool,
) -> None:
    """Late callee checks must not invalidate already authenticated caller facts."""
    surface = _surface()
    step = _prove_step(surface)
    assert step.verdict is owner.ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    original = owner._callee_chain_failure_8616

    def change_caller_after_callee_check(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        assert result == (None, None)
        object.__setattr__(surface.artifact, "function_addr", 0x1020)
        return result

    monkeypatch.setattr(owner, "_callee_chain_failure_8616", change_caller_after_callee_check)
    if consume:
        assert not _consume(surface, step)
    else:
        result = _prove_step(surface, step.theorem)
        assert result.verdict is owner.ConditionalNearCallPreservationVerdict8616.REFUSED


def _fresh_step(surface, **overrides):
    """Derive target and preservation in one synchronous owner operation."""
    from tests.ir.test_near_call_preservation import _resolver

    arguments = {"artifact": surface.artifact, "context": surface.context,
        "block": surface.block, "instruction": surface.call, "coordinates": surface.coordinates,
        "direct_target_resolver": _resolver(surface.project)}
    arguments.update(overrides)
    return owner.prove_near_call_preservation_from_coordinates_8616(
        surface.project, **arguments,
    )


def test_fresh_factory_avoids_replaying_just_derived_target(monkeypatch):
    """Fresh composition proves once; arbitrary retained evidence still replays."""
    from inertia.semantics import conditional_near_call_target as target_owner

    surface = _surface()
    original = target_owner.prove_conditional_near_call_target_8616
    calls = []

    def track(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(target_owner, 'prove_conditional_near_call_target_8616', track)
    monkeypatch.setattr(owner, 'prove_conditional_near_call_target_8616', track, raising=False)
    step = _fresh_step(surface)
    assert step.verdict is owner.ConditionalNearCallPreservationVerdict8616.CONDITIONAL
    assert len(calls) == 1
    assert _consume(surface, step)
    assert len(calls) == 2
    retained = _prove_step(surface, step.theorem)
    assert retained.verdict is step.verdict
    assert len(calls) == 3


@pytest.mark.parametrize('hook', ['_callee_chain_failure_8616', 'reauthenticate_conditional_near_call_target_8616'])
def test_fresh_factory_seals_late_context_mutation(monkeypatch, hook):
    """Skipping redundant initial replay must not bypass final callback seals."""
    surface = _surface()
    original = getattr(owner, hook)

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        object.__setattr__(surface.context, 'selector_high', -1)
        return result

    monkeypatch.setattr(owner, hook, mutate)
    assert _fresh_step(surface).verdict is owner.ConditionalNearCallPreservationVerdict8616.REFUSED


def test_fresh_factory_rejects_foreign_block_without_callee(monkeypatch):
    """A failed target derivation cannot start callee composition."""
    surface = _surface()

    def unexpected(*args, **kwargs):
        pytest.fail('callee resolution entered for foreign caller')

    monkeypatch.setattr(owner, '_resolve_and_seal_8616', unexpected)
    assert _fresh_step(surface, block=replace(surface.block)).verdict is owner.ConditionalNearCallPreservationVerdict8616.REFUSED


@pytest.mark.parametrize('field_name', ['near_call_scope', 'scoped_view'])
def test_universal_callee_rejects_native_conditional_state(field_name):
    """Universal closures cannot acquire a conditional scope or view."""
    surface = _surface()
    step = _prove_step(surface)
    callee = step.callee
    assert callee is not None
    scoped = replace(callee, state=replace(callee.state, **{field_name: object()}))
    failure, _ = owner._callee_chain_failure_8616(
        surface.project, scoped, step.callee_addr, (step.callee_addr,),
    )
    assert failure is owner.ConditionalNearCallPreservationFailure8616.CALLEE_FOREIGN_CONTEXT


def test_fresh_factory_expired_request_stops_before_native(monkeypatch):
    """Fresh composition shares the existing request deadline without work."""
    import time

    from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616

    surface = _surface()

    def unexpected(*args, **kwargs):
        pytest.fail('target factory called after expiration')

    monkeypatch.setattr(owner, 'prove_conditional_near_call_target_8616', unexpected)
    with direct_evidence_deadline_scope_8616(surface.project, time.monotonic() - 1):
        result = _fresh_step(surface)
    assert result.failure is owner.ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED


def test_consumer_defers_single_full_target_replay_to_final_seal(monkeypatch):
    """Retained steps replay fully after census; no redundant native-only pass."""
    surface = _surface()
    step = _prove_step(surface)
    events = []
    original = owner.consume_conditional_near_call_target_8616
    census = owner._callsite_evidence_8616

    def full(*args, **kwargs):
        events.append('full')
        return original(*args, **kwargs)

    def indexed(*args, **kwargs):
        events.append('census')
        return census(*args, **kwargs)

    def redundant(*args, **kwargs):
        pytest.fail('consumer repeated native-only target authentication')

    monkeypatch.setattr(owner, 'consume_conditional_near_call_target_8616', full)
    monkeypatch.setattr(owner, '_callsite_evidence_8616', indexed)
    monkeypatch.setattr(owner, 'reauthenticate_conditional_near_call_target_8616', redundant)
    assert _consume(surface, step)
    assert events == ['census', 'full']


@pytest.mark.parametrize('mutation', ['operand', 'context', 'incoming_bytes', 'outgoing_bytes', 'callee'])
def test_deferred_consume_refuses_census_callback_mutation(monkeypatch, mutation):
    """No source or callee fact may change before the deferred full replay."""
    surface = _surface()
    step = _prove_step(surface)
    original = owner._callsite_evidence_8616

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        if mutation == 'operand':
            object.__setattr__(surface.call.args[0], 'size', 1)
        elif mutation == 'context':
            object.__setattr__(surface.context, 'selector_high', -1)
        elif mutation == 'incoming_bytes':
            surface.project.loader.memory.store(surface.context.callsite_addr, b'\x90')
        elif mutation == 'outgoing_bytes':
            surface.project.loader.memory.store(surface.call.addr, b'\x90')
        else:
            object.__setattr__(step.callee.state, 'near_call_scope', object())
        return result

    monkeypatch.setattr(owner, '_callsite_evidence_8616', mutate)
    assert not _consume(surface, step)


@pytest.mark.parametrize('mutation', ['caller', 'callee'])
def test_deferred_consume_seals_after_final_target_callback(monkeypatch, mutation):
    """Full target replay cannot revoke an earlier caller/callee check."""
    surface = _surface()
    step = _prove_step(surface)
    original = owner.consume_conditional_near_call_target_8616

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result
        if mutation == 'caller':
            object.__setattr__(surface.context, 'selector_high', -1)
        else:
            object.__setattr__(step.callee.state, 'near_call_scope', object())
        return result

    monkeypatch.setattr(owner, 'consume_conditional_near_call_target_8616', mutate)
    assert not _consume(surface, step)


@pytest.mark.parametrize("consume", [False, True])
def test_no_graph_capture_after_authentication_expires(
    monkeypatch: pytest.MonkeyPatch, consume: bool,
) -> None:
    """A callback that exhausts the budget cannot trigger another graph walk."""
    surface = _surface()
    step = _prove_step(surface)
    snapshot = owner._capture_caller_facts_8616(step.theorem)
    assert snapshot is not None
    expired = False
    original = owner._stale_caller_facts_8616
    def stale(*args, **kwargs):
        assert not expired, "whole-graph capture after budget expired"
        return original(*args, **kwargs)
    def authenticate(*args, **kwargs):
        nonlocal expired
        expired = True
        return True
    monkeypatch.setattr(owner, "_stale_caller_facts_8616", stale)
    monkeypatch.setattr(owner, "direct_evidence_deadline_expired_8616", lambda project: expired)
    name = "consume_conditional_near_call_target_8616" if consume else "reauthenticate_conditional_near_call_target_8616"
    monkeypatch.setattr(owner, name, authenticate)
    seal = owner._consume_evidence_seal_8616 if consume else owner._evidence_seal_8616
    result = seal(surface.project, step.theorem, snapshot, step.callee, step.callee_addr, (step.callee_addr,))
    assert result == (owner.ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED, None)
