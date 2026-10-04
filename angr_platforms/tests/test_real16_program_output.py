"""Typed INT21/AH=40 output contract controls for declared program replay.

These tests exercise the pure admission boundary: declared handles and byte
budgets, exact arena reads, typed refusals ahead of any memory access, and
stream comparison over concatenated per-handle bytes.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tools.dosunit.real16_program_output import (
    OutputAccepted,
    OutputPolicy,
    OutputRefusal,
    OutputRefused,
    output_stream_bytes,
    program_output_call,
    same_output_streams,
)
from tools.dosunit.real16_replay_model import LinearRange

ARENA = LinearRange(0x10000, 0x2000)


def _policy(
    handles: frozenset[int] = frozenset({1, 2}),
    per_call_bytes: int = 0x40,
    aggregate_bytes: int = 0x100,
) -> OutputPolicy:
    """Default output declaration admitting both streams under tight caps."""
    return OutputPolicy(handles, per_call_bytes, aggregate_bytes)


def _memory() -> tuple[bytearray, Callable[[int, int], bytes], list[tuple[int, int]]]:
    """Arena-backed read plus a call log for before-read refusal controls."""
    store = bytearray(b"\x41" * ARENA.size)
    calls: list[tuple[int, int]] = []

    def read(address: int, size: int) -> bytes:
        calls.append((address, size))
        return bytes(store[address - ARENA.address : address - ARENA.address + size])

    return store, read, calls


def _call(
    policy: OutputPolicy,
    read: Callable[[int, int], bytes],
    *,
    handle: int = 1,
    segment: int = 0x1000,
    offset: int = 0x100,
    count: int = 4,
    allocation: LinearRange = ARENA,
    aggregate_remaining: int = 0x80,
) -> OutputAccepted | OutputRefused:
    """One service call against the default buffer inside the arena."""
    return program_output_call(
        policy,
        handle=handle,
        segment=segment,
        offset=offset,
        count=count,
        allocation=allocation,
        aggregate_remaining=aggregate_remaining,
        read=read,
    )


def _accepted(handle: int, payload: bytes) -> OutputAccepted:
    """An accepted record carrying the contract's register effects."""
    return OutputAccepted(handle, payload, len(payload), False)


def test_accepted_write_reads_exact_bytes_and_returns_count_and_clear_carry():
    store, read, calls = _memory()
    store[0x100:0x104] = b"WXYZ"
    result = _call(_policy(), read)
    assert isinstance(result, OutputAccepted)
    assert result == _accepted(1, b"WXYZ")
    assert result.ax == 4 and result.carry is False
    assert calls == [(0x10100, 4)]


def test_stderr_handle_is_admitted_only_when_declared():
    _, read, _ = _memory()
    accepted = _call(_policy(), read, handle=2)
    assert isinstance(accepted, OutputAccepted) and accepted.handle == 2
    refused = _call(_policy(handles=frozenset({1})), read, handle=2)
    assert refused == OutputRefused(2, OutputRefusal.UNSUPPORTED_HANDLE)


def test_zero_count_emits_empty_write_without_dereferencing_buffer():
    _, read, calls = _memory()
    result = _call(_policy(), read, count=0, segment=0, offset=0, aggregate_remaining=0)
    assert isinstance(result, OutputAccepted)
    assert result == _accepted(1, b"")
    assert result.ax == 0 and result.carry is False
    assert calls == []


@pytest.mark.parametrize("handle", [0, 3, 5, 0xFFFF])
def test_undeclared_handles_refuse_before_any_read(handle: int):
    _, read, calls = _memory()
    result = _call(_policy(), read, handle=handle)
    assert result == OutputRefused(handle, OutputRefusal.UNSUPPORTED_HANDLE)
    assert calls == []


def test_empty_policy_declares_no_output_service():
    _, read, calls = _memory()
    result = _call(_policy(handles=frozenset()), read)
    assert result == OutputRefused(1, OutputRefusal.UNSUPPORTED_HANDLE)
    assert calls == []


@pytest.mark.parametrize("count", [0x41, 0xFFFF])
def test_per_call_cap_refuses_before_any_read(count: int):
    _, read, calls = _memory()
    result = _call(_policy(), read, count=count)
    assert result == OutputRefused(1, OutputRefusal.PER_CALL_EXCEEDED)
    assert calls == []


def test_per_call_cap_boundary_is_accepted():
    _, read, _ = _memory()
    result = _call(_policy(), read, count=0x40)
    assert isinstance(result, OutputAccepted) and len(result.payload) == 0x40


@pytest.mark.parametrize("remaining", [0, 3])
def test_aggregate_budget_refuses_before_any_read(remaining: int):
    _, read, calls = _memory()
    result = _call(_policy(), read, aggregate_remaining=remaining)
    assert result == OutputRefused(1, OutputRefusal.AGGREGATE_EXCEEDED)
    assert calls == []


def test_aggregate_boundary_is_accepted():
    _, read, _ = _memory()
    result = _call(_policy(), read, aggregate_remaining=4)
    assert isinstance(result, OutputAccepted) and result.ax == 4


def test_buffer_ending_at_segment_top_is_accepted_but_straddle_refuses():
    _, read, calls = _memory()
    # DS=0x0100 resolves 0xFFF0 to linear 0x10FF0, inside the arena; the
    # 16-byte buffer ends exactly at the 64 KiB segment top without wrapping.
    accepted = _call(_policy(), read, segment=0x0100, offset=0xFFF0, count=0x10)
    assert isinstance(accepted, OutputAccepted)
    assert calls == [(0x10FF0, 0x10)]
    calls.clear()
    refused = _call(_policy(), read, segment=0x0100, offset=0xFFF0, count=0x11)
    assert refused == OutputRefused(1, OutputRefusal.SEGMENT_WRAP)
    assert calls == []


def test_buffer_at_arena_end_is_accepted_but_beyond_refuses():
    _, read, calls = _memory()
    accepted = _call(_policy(), read, segment=0x1000, offset=0x1FF0, count=0x10)
    assert isinstance(accepted, OutputAccepted)
    refused = _call(_policy(), read, segment=0x1000, offset=0x1FF0, count=0x11)
    assert refused == OutputRefused(1, OutputRefusal.OUTSIDE_ARENA)
    low = _call(_policy(), read, segment=0x0FF0, offset=0x10, count=4)
    assert low == OutputRefused(1, OutputRefusal.OUTSIDE_ARENA)
    assert calls == [(0x11FF0, 0x10)]


@pytest.mark.parametrize("size", [3, 5])
def test_short_or_long_read_is_a_typed_refusal(size: int):
    def partial(_address: int, _size: int) -> bytes:
        return b"\x41" * size

    result = _call(_policy(), partial)
    assert result == OutputRefused(1, OutputRefusal.SHORT_READ)


def test_reader_failure_propagates_unchanged():
    def failing(_address: int, _size: int) -> bytes:
        raise RuntimeError("backend exploded")

    with pytest.raises(RuntimeError, match="backend exploded"):
        _call(_policy(), failing)


@pytest.mark.parametrize(
    "field",
    [{"handle": True}, {"segment": 0x10000}, {"offset": -1}, {"count": True}, {"count": -1}],
)
def test_malformed_scalar_fields_raise_before_any_read(field: dict[str, object]):
    _, read, calls = _memory()
    with pytest.raises(ValueError):
        _call(_policy(), read, **field)  # type: ignore[arg-type]
    assert calls == []


@pytest.mark.parametrize("remaining", [-1, True, 0x101])
def test_remaining_allowance_must_stay_inside_the_declared_cap(remaining: int):
    _, read, calls = _memory()
    with pytest.raises(ValueError):
        _call(_policy(), read, aggregate_remaining=remaining)
    assert calls == []


def test_non_policy_non_arena_and_non_reader_are_refused_loudly():
    _, read, _ = _memory()
    with pytest.raises(ValueError):
        _call(object(), read)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _call(_policy(), read, allocation=(0x10000, 0x2000))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _call(_policy(), b"\x00" * 4)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "policy",
    [
        (frozenset({0}), 0x40, 0x100),
        (frozenset({1, 3}), 0x40, 0x100),
        (frozenset({True}), 0x40, 0x100),
        (frozenset({1}), 0, 0x100),
        (frozenset({1}), True, 0x100),
        (frozenset({1}), 0x40, -1),
    ],
)
def test_policy_must_declare_output_handles_and_positive_caps(
    policy: tuple[frozenset[int], int, int],
):
    with pytest.raises(ValueError):
        OutputPolicy(*policy)


def test_policy_handles_must_be_a_frozenset():
    with pytest.raises(ValueError):
        OutputPolicy([1, 2], 0x40, 0x100)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "record",
    [
        (1, b"AB", 3, False),
        (1, b"AB", True, False),
        (1, b"AB", 2, True),
        (5, b"AB", 2, False),
        (1, "AB", 2, False),
    ],
)
def test_accepted_record_cannot_violate_the_complete_write_invariant(
    record: tuple[int, bytes, int, bool],
):
    with pytest.raises(ValueError):
        OutputAccepted(*record)  # type: ignore[arg-type]


def test_refused_record_requires_a_typed_reason():
    with pytest.raises(ValueError):
        OutputRefused(1, "unsupported_handle")  # type: ignore[arg-type]


def test_split_and_interleaved_writes_compare_as_equal_streams():
    oracle = [_accepted(1, b"ab"), _accepted(1, b"cd"), _accepted(2, b"e")]
    candidate = [_accepted(2, b"e"), _accepted(1, b"abcd")]
    assert output_stream_bytes(oracle) == {1: b"abcd", 2: b"e"}
    assert same_output_streams(oracle, candidate)


@pytest.mark.parametrize(
    "candidate",
    [
        [_accepted(1, b"abdc")],
        [_accepted(1, b"ab"), _accepted(1, b"dc")],
        [_accepted(2, b"abcd")],
        [_accepted(1, b"abcd"), _accepted(2, b"x")],
        [_accepted(1, b"abc")],
    ],
)
def test_changed_per_handle_streams_are_not_equal(candidate: list[OutputAccepted]):
    oracle = [_accepted(1, b"ab"), _accepted(1, b"cd")]
    assert not same_output_streams(oracle, candidate)
