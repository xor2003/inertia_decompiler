"""Tests for Types/Lowering-owned direct-stack replay scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
import inertia.lowering.direct_stack_replay as direct_stack_replay
from inertia.lowering.direct_stack_replay import (
    DirectStackMaterializationResult8616,
    DirectStackReplayOptions8616,
    DirectStackReplayState8616,
    advance_direct_stack_consumer_generation_8616,
    begin_direct_stack_consumer_generation_scope_8616,
    end_direct_stack_consumer_generation_scope_8616,
    execute_direct_stack_replay_8616,
)


class _FixtureNode8616:
    """Minimal dynamic structured-codegen node for generation tests."""

    __module__ = "angr.analyses.decompiler.structured_codegen.fixture"

    def __init__(self, **fields: object) -> None:
        self.__dict__.update(fields)


@dataclass(frozen=True, slots=True)
class _Fact8616:
    """Value-based direct-stack fact fixture."""

    offset: int


def _surface() -> tuple[SimpleNamespace, SimpleNamespace, _FixtureNode8616]:
    """Return one codegen, function, and mutable AST leaf."""
    leaf = _FixtureNode8616(value=1)
    cfunc = _FixtureNode8616(addr=0x10554, statements=[leaf])
    codegen = SimpleNamespace(
        cfunc=cfunc,
        _inertia_direct_stack_move_facts_8616=(),
    )
    function = SimpleNamespace(
        addr=0x10554,
        _inertia_direct_stack_move_instruction_facts_8616=(),
    )
    return codegen, function, leaf


def _options(*, materialize_reloads: bool = True) -> DirectStackReplayOptions8616:
    """Return one complete full-replay option fixture."""
    return DirectStackReplayOptions8616(
        allow_stack_slot_fallback=True,
        source_kind_values=None,
        materialize_reloads=materialize_reloads,
    )


def test_changed_replay_requires_one_stable_confirmation_before_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mutation invalidates stability until one witnessed stable replay."""
    codegen, function, leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})
    calls = 0

    def operation(_function: object | None) -> bool:
        """Mutate once as one complete direct-stack materializer would."""
        nonlocal calls
        calls += 1
        if leaf.value == 1:
            leaf.value = 2
            return True
        return False

    assert execute_direct_stack_replay_8616(codegen, object(), function, _options(), operation)
    assert not execute_direct_stack_replay_8616(codegen, object(), function, _options(), operation)
    assert not execute_direct_stack_replay_8616(codegen, object(), function, _options(), operation)
    assert calls == 2
    state = codegen._inertia_direct_stack_replay_state_8616
    assert isinstance(state, DirectStackReplayState8616)
    assert state.stats.closed
    assert state.stats.attempt_count == 2
    assert state.stats.changed_count == 1
    assert state.stats.stable_count == 1
    assert state.stats.skipped_count == 1


def test_replay_options_and_external_ast_mutation_invalidate_stability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct policy or a changed AST must execute the Lowering owner."""
    codegen, function, leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})
    calls = 0

    def stable_operation(_function: object | None) -> bool:
        """Record execution without mutating the fixture."""
        nonlocal calls
        calls += 1
        return False

    assert not execute_direct_stack_replay_8616(
        codegen, object(), function, _options(), stable_operation
    )
    assert not execute_direct_stack_replay_8616(
        codegen,
        object(),
        function,
        _options(materialize_reloads=False),
        stable_operation,
    )
    leaf.value = 3
    assert not execute_direct_stack_replay_8616(
        codegen,
        object(),
        function,
        _options(materialize_reloads=False),
        stable_operation,
    )
    assert calls == 3


def test_replay_witness_upgrades_a_misreported_ast_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A false pass result cannot hide a changed structured-AST generation."""
    codegen, function, leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})

    def misreported_operation(_function: object | None) -> bool:
        """Mutate the AST while reproducing a false stable report."""
        leaf.value = 9
        return False

    assert execute_direct_stack_replay_8616(
        codegen,
        object(),
        function,
        _options(),
        misreported_operation,
    )
    state = codegen._inertia_direct_stack_replay_state_8616
    assert state.stats.changed_count == 1
    assert state.stats.stable_count == 0


def test_replay_evidence_publication_does_not_report_ast_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """New typed replay evidence invalidates the cache without changing C."""
    codegen, function, _leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})

    def publish_evidence(_function: object | None) -> bool:
        """Publish one collected fact while leaving the structured AST stable."""
        codegen._inertia_direct_stack_move_facts_8616 = (_Fact8616(4),)
        return False

    assert not execute_direct_stack_replay_8616(
        codegen,
        object(),
        function,
        _options(),
        publish_evidence,
    )
    state = codegen._inertia_direct_stack_replay_state_8616
    assert state.stable_request is not None
    assert state.stable_request.generation.attached_facts == (_Fact8616(4),)
    assert state.stats.stable_count == 1


def test_replay_generation_uses_fact_values_instead_of_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Equal fact replacement stays stable while changed evidence executes."""
    codegen, function, _leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})
    calls = 0

    def stable_operation(_function: object | None) -> bool:
        """Record one exact request execution."""
        nonlocal calls
        calls += 1
        return False

    codegen._inertia_direct_stack_move_facts_8616 = (_Fact8616(2),)
    assert not execute_direct_stack_replay_8616(
        codegen, object(), function, _options(), stable_operation
    )
    codegen._inertia_direct_stack_move_facts_8616 = (_Fact8616(2),)
    assert not execute_direct_stack_replay_8616(
        codegen, object(), function, _options(), stable_operation
    )
    codegen._inertia_direct_stack_move_facts_8616 = (_Fact8616(4),)
    assert not execute_direct_stack_replay_8616(
        codegen, object(), function, _options(), stable_operation
    )
    assert calls == 2


def test_failed_replay_clears_stability_and_closes_failure_accounting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception cannot publish a stable request or an open counter lane."""
    codegen, function, _leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})

    def fail(_function: object | None) -> bool:
        """Raise from the scheduled materializer."""
        raise RuntimeError("failed replay")

    with pytest.raises(RuntimeError, match="failed replay"):
        execute_direct_stack_replay_8616(codegen, object(), function, _options(), fail)

    state = codegen._inertia_direct_stack_replay_state_8616
    assert state.stable_request is None
    assert state.stats.closed
    assert state.stats.attempt_count == 1
    assert state.stats.failure_count == 1


def test_covered_generation_skips_without_building_exact_ast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed owner scope uses its generation instead of a whole-AST digest."""
    codegen, function, _leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})
    monkeypatch.setattr(
        direct_stack_replay,
        "structured_ast_generation_8616",
        lambda _codegen: pytest.fail("covered generation built an exact AST witness"),
    )
    calls = 0

    def stable_operation(_function: object | None) -> DirectStackMaterializationResult8616:
        """Return one typed closed stable owner result."""
        nonlocal calls
        calls += 1
        return DirectStackMaterializationResult8616(changed=False)

    scope = begin_direct_stack_consumer_generation_scope_8616(codegen)
    try:
        assert not execute_direct_stack_replay_8616(
            codegen, object(), function, _options(), stable_operation
        )
        assert not execute_direct_stack_replay_8616(
            codegen, object(), function, _options(), stable_operation
        )
        advance_direct_stack_consumer_generation_8616(codegen)
        assert not execute_direct_stack_replay_8616(
            codegen, object(), function, _options(), stable_operation
        )
    finally:
        end_direct_stack_consumer_generation_scope_8616(codegen, scope)

    assert calls == 2
    state = codegen._inertia_direct_stack_replay_state_8616
    assert state.stats.attempt_count == 2
    assert state.stats.stable_count == 2
    assert state.stats.skipped_count == 1


def test_covered_generation_refuses_untyped_owner_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cheap generation cannot suppress the exact witness for an untyped owner."""
    codegen, function, _leaf = _surface()
    monkeypatch.setattr(direct_stack_replay, "callsite_summary_inventory_8616", lambda _codegen: {})
    scope = begin_direct_stack_consumer_generation_scope_8616(codegen)
    try:
        with pytest.raises(TypeError, match="requires a typed owner result"):
            execute_direct_stack_replay_8616(
                codegen,
                object(),
                function,
                _options(),
                lambda _function: False,
            )
    finally:
        end_direct_stack_consumer_generation_scope_8616(codegen, scope)

    state = codegen._inertia_direct_stack_replay_state_8616
    assert state.stats.closed
    assert state.stats.failure_count == 1
