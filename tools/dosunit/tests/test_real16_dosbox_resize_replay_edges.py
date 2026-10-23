"""Concrete allocator boundary refusals and preserved split-header bytes."""

import pytest

from tools.dosunit.runtime.real16_dosbox_resize_receipt import dosbox_resize_receipt_complete
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_program_model import (
    ProgramAgreement,
    ProgramEventKind,
    ProgramObservation,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_replay_model import LinearRange
from tools.dosunit.tests.test_real16_dosbox_resize_replay import _environment
from tools.dosunit.tests.test_real16_program_replay import mz

pytestmark = pytest.mark.dosunit


@pytest.mark.parametrize("paragraphs", [0, 0x180])
def test_split_preserves_reserved_header_bytes(paragraphs):
    code = b"\xbb" + paragraphs.to_bytes(2, "little") + bytes.fromhex("b44acd21b8004ccd21")
    env = _environment()
    split = 0x10000 + paragraphs * 16
    expected_tail = env.allocation[paragraphs * 16 + 5:paragraphs * 16 + 16]
    result = replay_program(
        program_from_mz_bytes(mz(code), env),
        observations=(ProgramObservation("split", LinearRange(split, 16)),),
    )
    assert result.status is ProgramStatus.TERMINATED
    resize = next(event for event in result.events if event.kind is ProgramEventKind.DOS_RESIZE)
    assert dosbox_resize_receipt_complete(resize.data)
    image = dict(result.observations)["split"]
    assert image[0] == ord("Z")
    assert image[1:3] == bytes(2)
    assert int.from_bytes(image[3:5], "little") == 0x200 - paragraphs - 1
    assert image[5:] == expected_tail
    assert compare_programs(result, result) is ProgramAgreement.AGREED


@pytest.mark.parametrize("paragraphs,sp,event_kind", [
    (0x10, 0x1000, ProgramEventKind.CODE_WRITE),
    (0x10F, 0x1000, ProgramEventKind.UNSUPPORTED_INSTRUCTION),
    (0x110, 0x1006, ProgramEventKind.UNSUPPORTED_INSTRUCTION),
])
def test_allocator_aliases_refuse_before_resize_event(paragraphs, sp, event_kind):
    code = b"\xbb" + paragraphs.to_bytes(2, "little") + bytes.fromhex("b44acd21b8004ccd21")
    result = replay_program(program_from_mz_bytes(mz(code, stack_sp=sp), _environment()))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert any(event.kind is event_kind for event in result.events)
    assert not any(event.kind is ProgramEventKind.DOS_RESIZE for event in result.events)
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE
    # Prefix writes are allowed, but allocator metadata must remain untouched.
    assert not any(0xFFF0 <= address < 0x10000 for address, _ in result.writes)


def test_second_resize_rejects_the_changed_chain():
    code = bytes.fromhex("bb8001b44acd21bb7001b44acd21b8004ccd21")
    result = replay_program(program_from_mz_bytes(mz(code), _environment()))
    assert result.status is ProgramStatus.UNSUPPORTED
    events = [event for event in result.events if event.kind is ProgramEventKind.DOS_RESIZE]
    assert len(events) == 1
    assert dosbox_resize_receipt_complete(events[0].data)
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE
