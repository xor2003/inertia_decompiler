"""Native terminal reuse must preserve source isolation and request lifetime."""
from __future__ import annotations

from dataclasses import replace

import pytest
from angr.factory import AngrObjectFactory

import inertia.semantics.direct_near_call_target_binding as binding
from inertia.ir.native_import_surface_cache import native_import_request_8616
from tests.lowering.test_x86_16_near_return_expression import _project
from tests.semantics.test_direct_near_call_target_binding import _fixture


def test_repeated_native_terminal_check_lifts_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real unchanged terminal shares decoding, not the origin verdict."""
    fixture = _fixture(_project(), 0x10F1, 0x110D, 0x10F7)
    origin = fixture.call.origin
    assert origin is not None
    original = AngrObjectFactory.block
    calls = []

    def counted(self, *args, **kwargs):
        calls.append(args)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(AngrObjectFactory, "block", counted)
    with native_import_request_8616():
        for _ in range(2):
            assert binding._native_terminal_failure_8616(
                fixture.project, fixture.block, origin, 0x10F7, 0x10FA,
            ) is None
        altered = replace(origin, statement_index=origin.statement_index + 1)
        assert binding._native_terminal_failure_8616(
            fixture.project, fixture.block, altered, 0x10F7, 0x10FA,
        ) is binding.DirectNearCallTargetBindingFailure8616.TERMINAL_POSITION_MISMATCH
    assert len(calls) == 1


def test_native_terminal_request_does_not_cross_projects() -> None:
    """The same address in another image must use that image's instructions."""
    fixture = _fixture(_project(), 0x10F1, 0x110D, 0x10F7)
    other = _project()
    other.loader.memory.store(0x10F7, b"\xc3\x90\x90")
    origin = fixture.call.origin
    assert origin is not None
    with native_import_request_8616():
        assert binding._native_terminal_failure_8616(
            fixture.project, fixture.block, origin, 0x10F7, 0x10FA,
        ) is None
        assert binding._native_terminal_failure_8616(
            other, fixture.block, origin, 0x10F7, 0x10FA,
        ) is binding.DirectNearCallTargetBindingFailure8616.NATIVE_TERMINAL_MISMATCH


def test_native_terminal_mutation_during_lift_is_not_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    """A returned old lift cannot be retained under a subsequent byte snapshot."""
    fixture = _fixture(_project(), 0x10F1, 0x110D, 0x10F7)
    origin = fixture.call.origin
    assert origin is not None
    original = AngrObjectFactory.block
    pending = True

    def mutate_after_lift(self, *args, **kwargs):
        nonlocal pending
        block = original(self, *args, **kwargs)
        if pending and self.project is fixture.project:
            pending = False
            _ = block.vex
            fixture.project.loader.memory.store(0x10F7, b"\xc3\x90\x90")
        return block

    monkeypatch.setattr(AngrObjectFactory, "block", mutate_after_lift)
    with native_import_request_8616():
        assert binding._native_terminal_failure_8616(
            fixture.project, fixture.block, origin, 0x10F7, 0x10FA,
        ) is None
        assert binding._native_terminal_failure_8616(
            fixture.project, fixture.block, origin, 0x10F7, 0x10FA,
        ) is binding.DirectNearCallTargetBindingFailure8616.NATIVE_TERMINAL_MISMATCH


def test_completed_request_releases_retained_native_sources() -> None:
    """Even an observer retaining the map cannot keep completed source records."""
    from inertia.ir.native_import_surface_cache import native_terminal_fact_store_8616

    fixture = _fixture(_project(), 0x10F1, 0x110D, 0x10F7)
    origin = fixture.call.origin
    assert origin is not None
    with native_import_request_8616():
        records = native_terminal_fact_store_8616()
        assert records is not None
        assert binding._native_terminal_failure_8616(
            fixture.project, fixture.block, origin, 0x10F7, 0x10FA,
        ) is None
        assert records
    assert not records
    assert native_terminal_fact_store_8616() is None
