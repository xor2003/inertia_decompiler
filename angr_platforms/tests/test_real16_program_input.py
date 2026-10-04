"""Typed INT21/AH=3F/42 input contract controls for declared program replay.

These tests exercise the pure admission boundary: declared immutable files,
unique handles and byte budgets, exact arena destinations, typed refusals
ahead of any runtime mutation, seek basis semantics and record invariants.
"""

from __future__ import annotations

import pytest

from tools.dosunit.real16_program_input import (
    S32_MAX,
    S32_MIN,
    InputFile,
    InputPolicy,
    InputRefusal,
    InputRefused,
    InputRuntime,
    ReadAccepted,
    SeekAccepted,
    SeekOrigin,
    program_input_read,
    program_input_runtime,
    program_input_seek,
)
from tools.dosunit.real16_replay_model import LinearRange, SegOffset

ARENA = LinearRange(0x10000, 0x2000)
CONTENT = b"abcdefghij"


def _file(handle: int = 5, data: bytes = CONTENT, cursor: int = 0) -> InputFile:
    """One declared preopened file with the default ten-byte content."""
    return InputFile(handle, data, cursor)


def _policy(
    files: tuple[InputFile, ...] | None = None,
    per_call_bytes: int = 0x40,
    total_bytes: int = 0x100,
) -> InputPolicy:
    """Default input declaration admitting one file under tight caps."""
    return InputPolicy((_file(),) if files is None else files, per_call_bytes, total_bytes)


def _runtime(policy: InputPolicy) -> InputRuntime:
    """Fresh runtime state for the declared policy."""
    return program_input_runtime(policy)


def _read(
    policy: InputPolicy,
    runtime: InputRuntime,
    *,
    handle: int = 5,
    segment: int = 0x1000,
    offset: int = 0x100,
    count: int = 4,
    allocation: LinearRange = ARENA,
) -> ReadAccepted | InputRefused:
    """One read call against the default destination inside the arena."""
    return program_input_read(
        policy, runtime, handle=handle, segment=segment, offset=offset,
        count=count, allocation=allocation,
    )


def _seek(
    policy: InputPolicy,
    runtime: InputRuntime,
    *,
    handle: int = 5,
    origin: SeekOrigin = SeekOrigin.CURRENT,
    distance: int = 0,
) -> SeekAccepted | InputRefused:
    """One seek call against the default declared handle."""
    return program_input_seek(policy, runtime, handle=handle, origin=origin, distance=distance)


def _accepted_read(handle: int, segment: int, offset: int, payload: bytes, cursor: int) -> ReadAccepted:
    """An accepted read receipt carrying the contract's register effects."""
    return ReadAccepted(handle, SegOffset(segment, offset), payload, len(payload), False, cursor)


def test_accepted_read_serves_content_and_advances_runtime():
    policy = _policy()
    runtime = _runtime(policy)
    result = _read(policy, runtime)
    assert result == _accepted_read(5, 0x1000, 0x100, b"abcd", 4)
    assert isinstance(result, ReadAccepted)
    assert result.ax == 4 and result.carry is False
    assert result.destination.linear() == 0x10100
    assert runtime.cursors[5] == 4 and runtime.served == 4


def test_second_read_continues_from_the_advanced_cursor():
    policy = _policy()
    runtime = _runtime(policy)
    _read(policy, runtime)
    result = _read(policy, runtime)
    assert isinstance(result, ReadAccepted)
    assert result.payload == b"efgh" and result.next_cursor == 8
    assert runtime.served == 8


def test_read_at_file_end_is_short_and_lands_on_eof():
    policy = _policy(files=(_file(cursor=8),))
    runtime = _runtime(policy)
    result = _read(policy, runtime, count=8)
    assert result == _accepted_read(5, 0x1000, 0x100, b"ij", 10)
    assert runtime.cursors[5] == 10 and runtime.served == 2


def test_read_at_eof_serves_empty_payload_without_touching_memory():
    policy = _policy(files=(_file(cursor=len(CONTENT)),))
    runtime = _runtime(policy)
    result = _read(policy, runtime, segment=0, offset=0xFFFF, allocation=LinearRange(0x2000, 4))
    assert result == _accepted_read(5, 0, 0xFFFF, b"", len(CONTENT))
    assert runtime.cursors[5] == len(CONTENT) and runtime.served == 0


def test_declared_cursor_may_start_past_eof_and_reads_empty():
    policy = _policy(files=(_file(cursor=0x100000),))
    runtime = _runtime(policy)
    result = _read(policy, runtime)
    assert isinstance(result, ReadAccepted)
    assert result.payload == b"" and result.ax == 0
    assert result.next_cursor == 0x100000 and runtime.cursors[5] == 0x100000


def test_zero_count_is_accepted_without_any_memory_requirement():
    policy = _policy()
    runtime = _runtime(policy)
    result = _read(policy, runtime, count=0, segment=0, offset=0)
    assert result == _accepted_read(5, 0, 0, b"", 0)
    assert runtime.cursors[5] == 0 and runtime.served == 0


def test_empty_policy_declares_no_input_service():
    policy = _policy(files=())
    runtime = _runtime(policy)
    assert runtime.cursors == {}
    assert _read(policy, runtime) == InputRefused(5, InputRefusal.UNSUPPORTED_HANDLE)
    assert _seek(policy, runtime) == InputRefused(5, InputRefusal.UNSUPPORTED_HANDLE)


@pytest.mark.parametrize("handle", [0, 3, 4, 6, 0xFFFF])
def test_undeclared_handles_refuse_before_any_mutation(handle: int):
    policy = _policy()
    runtime = _runtime(policy)
    assert _read(policy, runtime, handle=handle) == InputRefused(handle, InputRefusal.UNSUPPORTED_HANDLE)
    assert _seek(policy, runtime, handle=handle) == InputRefused(handle, InputRefusal.UNSUPPORTED_HANDLE)
    assert runtime.cursors == {5: 0} and runtime.served == 0


def test_second_declared_handle_is_admitted_independently():
    policy = _policy(files=(_file(5, b"ab"), _file(9, b"xy", 1)))
    runtime = _runtime(policy)
    result = _read(policy, runtime, handle=9, count=4)
    assert result == _accepted_read(9, 0x1000, 0x100, b"y", 2)
    assert runtime.cursors == {5: 0, 9: 2} and runtime.served == 1


@pytest.mark.parametrize("count", [0x41, 0xFFFF])
def test_per_call_cap_refuses_before_any_mutation(count: int):
    policy = _policy()
    runtime = _runtime(policy)
    assert _read(policy, runtime, count=count) == InputRefused(5, InputRefusal.PER_CALL_EXCEEDED)
    assert runtime.cursors == {5: 0} and runtime.served == 0


def test_per_call_cap_boundary_is_accepted():
    policy = _policy()
    runtime = _runtime(policy)
    result = _read(policy, runtime, count=0x40)
    assert isinstance(result, ReadAccepted) and result.payload == CONTENT


def test_total_cap_refuses_only_the_bytes_that_would_be_served():
    policy = _policy(total_bytes=2)
    runtime = _runtime(policy)
    assert _read(policy, runtime, count=4) == InputRefused(5, InputRefusal.TOTAL_EXCEEDED)
    assert runtime.cursors == {5: 0} and runtime.served == 0
    result = _read(policy, runtime, count=2)
    assert isinstance(result, ReadAccepted) and runtime.served == 2
    assert _read(policy, runtime, count=1) == InputRefused(5, InputRefusal.TOTAL_EXCEEDED)
    assert _read(policy, runtime, count=0) == _accepted_read(5, 0x1000, 0x100, b"", 2)


def test_total_cap_counts_served_bytes_not_requested_bytes():
    policy = _policy(files=(_file(cursor=8),), total_bytes=2)
    runtime = _runtime(policy)
    result = _read(policy, runtime, count=0x40)
    assert isinstance(result, ReadAccepted) and len(result.payload) == 2
    assert runtime.served == 2


def test_payload_ending_at_segment_top_is_accepted_but_straddle_refuses():
    policy = _policy(files=(_file(data=b"z" * 0x20),))
    accepted = _read(policy, _runtime(policy), segment=0x0100, offset=0xFFF0, count=0x10)
    assert isinstance(accepted, ReadAccepted)
    assert accepted.destination == SegOffset(0x0100, 0xFFF0)
    assert len(accepted.payload) == 0x10
    runtime = _runtime(policy)
    refused = _read(policy, runtime, segment=0x0100, offset=0xFFF0, count=0x11)
    assert refused == InputRefused(5, InputRefusal.SEGMENT_WRAP)
    assert runtime.cursors == {5: 0} and runtime.served == 0


def test_wrap_check_uses_served_length_not_requested_count():
    policy = _policy(files=(_file(cursor=6),))
    runtime = _runtime(policy)
    result = _read(policy, runtime, segment=0x0100, offset=0xFFFC, count=0x40)
    assert isinstance(result, ReadAccepted) and len(result.payload) == 4


def test_destination_at_arena_end_is_accepted_but_beyond_refuses():
    policy = _policy(files=(_file(data=b"z" * 0x20),))
    accepted = _read(policy, _runtime(policy), segment=0x1000, offset=0x1FF0, count=0x10)
    assert isinstance(accepted, ReadAccepted)
    runtime = _runtime(policy)
    refused = _read(policy, runtime, segment=0x1000, offset=0x1FF0, count=0x11)
    assert refused == InputRefused(5, InputRefusal.OUTSIDE_ARENA)
    low = _read(policy, runtime, segment=0x0FF0, offset=0x10, count=4)
    assert low == InputRefused(5, InputRefusal.OUTSIDE_ARENA)
    assert runtime.cursors == {5: 0} and runtime.served == 0


@pytest.mark.parametrize(
    ("origin", "distance", "expected"),
    [
        (SeekOrigin.BEGIN, 3, 3),
        (SeekOrigin.CURRENT, 2, 5),
        (SeekOrigin.END, -1, len(CONTENT) - 1),
        (SeekOrigin.END, 5, len(CONTENT) + 5),
        (SeekOrigin.BEGIN, 0x12345, 0x12345),
    ],
)
def test_seek_origins_compute_over_their_basis(origin: SeekOrigin, distance: int, expected: int):
    policy = _policy(files=(_file(cursor=3),))
    runtime = _runtime(policy)
    result = _seek(policy, runtime, origin=origin, distance=distance)
    assert result == SeekAccepted(5, expected & 0xFFFF, expected >> 16, False, expected)
    assert runtime.cursors[5] == expected and runtime.served == 0


def test_seek_reports_new_cursor_in_dx_ax_words():
    policy = _policy()
    runtime = _runtime(policy)
    result = _seek(policy, runtime, origin=SeekOrigin.BEGIN, distance=0x12345)
    assert isinstance(result, SeekAccepted)
    assert result.dx == 0x1 and result.ax == 0x2345 and result.carry is False


@pytest.mark.parametrize(
    ("origin", "distance"),
    [(SeekOrigin.BEGIN, -1), (SeekOrigin.CURRENT, -4), (SeekOrigin.END, -(len(CONTENT) + 1))],
)
def test_seek_before_position_zero_refuses_without_mutation(origin: SeekOrigin, distance: int):
    policy = _policy(files=(_file(cursor=3),))
    runtime = _runtime(policy)
    assert _seek(policy, runtime, origin=origin, distance=distance) == InputRefused(
        5, InputRefusal.CURSOR_BEFORE_START
    )
    assert runtime.cursors[5] == 3


@pytest.mark.parametrize(
    ("cursor", "distance"),
    [(0x80000001, S32_MAX), (0xFFFFFFFF, 1)],
)
def test_seek_past_the_u32_domain_refuses_without_mutation(cursor: int, distance: int):
    policy = _policy(files=(_file(cursor=cursor),))
    runtime = _runtime(policy)
    result = _seek(policy, runtime, origin=SeekOrigin.CURRENT, distance=distance)
    assert result == InputRefused(5, InputRefusal.CURSOR_OVERFLOW)
    assert runtime.cursors[5] == cursor


def test_seek_to_u32_max_boundary_is_accepted():
    policy = _policy(files=(_file(cursor=0x80000000),))
    runtime = _runtime(policy)
    result = _seek(policy, runtime, origin=SeekOrigin.CURRENT, distance=S32_MAX)
    assert result == SeekAccepted(5, 0xFFFF, 0xFFFF, False, 0xFFFFFFFF)
    assert runtime.cursors[5] == 0xFFFFFFFF


def test_seek_at_u32_max_is_accepted_and_splits_across_dx_ax():
    policy = _policy(files=(_file(cursor=0xFFFFFFFE),))
    runtime = _runtime(policy)
    result = _seek(policy, runtime, origin=SeekOrigin.CURRENT, distance=1)
    assert result == SeekAccepted(5, 0xFFFF, 0xFFFF, False, 0xFFFFFFFF)
    assert runtime.cursors[5] == 0xFFFFFFFF


def test_seek_distance_domain_edges_are_signed_32_bit():
    policy = _policy()
    runtime = _runtime(policy)
    accepted = _seek(policy, runtime, origin=SeekOrigin.BEGIN, distance=S32_MAX)
    assert isinstance(accepted, SeekAccepted) and accepted.next_cursor == S32_MAX
    for distance in (S32_MIN - 1, S32_MAX + 1):
        with pytest.raises(ValueError):
            _seek(policy, runtime, distance=distance)


def test_seek_after_eof_read_still_serves_from_the_new_position():
    policy = _policy()
    runtime = _runtime(policy)
    _seek(policy, runtime, origin=SeekOrigin.BEGIN, distance=6)
    result = _read(policy, runtime, count=4)
    assert isinstance(result, ReadAccepted) and result.payload == b"ghij"


def test_declared_content_is_an_immutable_snapshot():
    source = bytearray(b"abcde")
    file = InputFile(5, source, 0)  # type: ignore[arg-type]
    source[0] = 0x7A
    policy = InputPolicy((file,), 0x40, 0x100)
    runtime = _runtime(policy)
    result = _read(policy, runtime, count=2)
    assert isinstance(result, ReadAccepted) and result.payload == b"ab"


def test_runtime_starts_from_each_declared_cursor():
    with pytest.raises(ValueError):
        program_input_runtime(object())  # type: ignore[arg-type]
    policy = _policy(files=(_file(5, b"ab"), _file(7, b"cd", 9)))
    runtime = _runtime(policy)
    assert isinstance(runtime, InputRuntime)
    assert runtime.cursors == {5: 0, 7: 9} and runtime.served == 0


@pytest.mark.parametrize(
    "field",
    [{"handle": True}, {"handle": -1}, {"segment": 0x10000}, {"offset": -1},
     {"count": True}, {"count": 0x10000}, {"handle": "5"}],
)
def test_malformed_read_fields_raise(field: dict[str, object]):
    policy = _policy()
    runtime = _runtime(policy)
    with pytest.raises(ValueError):
        _read(policy, runtime, **field)  # type: ignore[arg-type]
    assert runtime.cursors == {5: 0} and runtime.served == 0


@pytest.mark.parametrize(
    "field",
    [{"handle": True}, {"origin": 0}, {"origin": "begin"}, {"distance": True}, {"distance": "3"}],
)
def test_malformed_seek_fields_raise(field: dict[str, object]):
    policy = _policy()
    runtime = _runtime(policy)
    with pytest.raises(ValueError):
        _seek(policy, runtime, **field)  # type: ignore[arg-type]
    assert runtime.cursors[5] == 0


def test_non_policy_non_runtime_and_non_arena_raise_loudly():
    policy = _policy()
    runtime = _runtime(policy)
    with pytest.raises(ValueError):
        _read(object(), runtime)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _read(policy, object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _read(policy, runtime, allocation=(0x10000, 0x2000))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _seek(object(), runtime)  # type: ignore[arg-type]


@pytest.mark.parametrize("served", [-1, True, 0x101])
def test_runtime_served_must_stay_inside_the_declared_total(served: int):
    policy = _policy()
    runtime = _runtime(policy)
    runtime.served = served
    with pytest.raises(ValueError):
        _read(policy, runtime)


@pytest.mark.parametrize("cursor", [True, -1, 0x100000000])
def test_declared_handle_without_a_u32_runtime_cursor_raises(cursor: int):
    policy = _policy()
    runtime = _runtime(policy)
    runtime.cursors[5] = cursor
    with pytest.raises(ValueError):
        _read(policy, runtime)
    with pytest.raises(ValueError):
        _seek(policy, runtime, origin=SeekOrigin.CURRENT, distance=0)


def test_declared_handle_missing_from_runtime_raises():
    policy = _policy()
    runtime = _runtime(policy)
    del runtime.cursors[5]
    with pytest.raises(ValueError):
        _read(policy, runtime)


@pytest.mark.parametrize(
    "record",
    [(4, b"ab", 0), (True, b"ab", 0), (5, "ab", 0), (5, b"ab", -1), (5, b"ab", 0x100000000)],
)
def test_input_file_record_validates_handle_data_and_cursor(record: tuple[int, bytes, int]):
    with pytest.raises(ValueError):
        InputFile(*record)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "policy",
    [
        ((_file(5), _file(5, b"x")), 0x40, 0x100),
        ((_file(),), 0, 0x100),
        ((_file(),), True, 0x100),
        ((_file(),), 0x10000, 0x100),
        ((_file(),), 0x40, 0),
        ((_file(),), 0x40, -1),
        ((_file(),), 0x40, 0x400001),
        (("not-a-file",), 0x40, 0x100),
    ],
)
def test_policy_must_declare_valid_files_and_bounded_caps(
    policy: tuple[tuple[InputFile, ...], int, int],
):
    with pytest.raises(ValueError):
        InputPolicy(*policy)  # type: ignore[arg-type]


def test_policy_files_must_be_a_tuple():
    with pytest.raises(ValueError):
        InputPolicy([_file()], 0x40, 0x100)  # type: ignore[arg-type]


def test_policy_admits_at_most_32_files_and_4mib_content():
    too_many = tuple(_file(5 + index) for index in range(33))
    with pytest.raises(ValueError):
        InputPolicy(too_many, 0x40, 0x100)
    with pytest.raises(ValueError):
        InputPolicy((_file(5, b"x" * 0x400001),), 0x40, 0x100)
    boundary = tuple(_file(5 + index, b"y") for index in range(32))
    assert len(InputPolicy(boundary, 0x40, 0x100).files) == 32


@pytest.mark.parametrize(
    "record",
    [
        (5, SegOffset(0x1000, 0x100), b"AB", 3, False, 2),
        (5, SegOffset(0x1000, 0x100), b"AB", True, False, 2),
        (5, SegOffset(0x1000, 0x100), b"AB", 2, True, 2),
        (5, (0x1000, 0x100), b"AB", 2, False, 2),
        (5, SegOffset(0x1000, 0x100), "AB", 2, False, 2),
        (5, SegOffset(0x1000, 0x100), b"AB", 2, False, -1),
    ],
)
def test_read_receipt_cannot_violate_the_served_byte_invariant(
    record: tuple[int, SegOffset, bytes, int, bool, int],
):
    with pytest.raises(ValueError):
        ReadAccepted(*record)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "record",
    [(5, 0x2345, 0x2, False, 0x12345), (5, 0x2345, 0x1, True, 0x12345), (5, 0x2345, 0x1, False, -1)],
)
def test_seek_receipt_must_match_dx_ax_and_clear_carry(
    record: tuple[int, int, int, bool, int],
):
    with pytest.raises(ValueError):
        SeekAccepted(*record)


def test_refused_record_requires_a_typed_reason():
    with pytest.raises(ValueError):
        InputRefused(5, "unsupported_handle")  # type: ignore[arg-type]
