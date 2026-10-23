"""Concrete DOSBox resize effects and verified process-event agreement."""

from dataclasses import replace

import pytest

from inertia.frontend.real16_dosbox_entry_policy import DosBoxInt21EntryPolicy8616
from inertia.frontend.real16_dosbox_resize import DosboxMcbEntry, DosboxResizePolicy
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
from tools.dosunit.tests.test_real16_program_replay import environment, mz

pytestmark = pytest.mark.dosunit


def _environment():
    base = environment()
    header = b"Z" + base.psp_segment.to_bytes(2, "little") + (len(base.allocation) // 16).to_bytes(2, "little") + b"\x66" * 11
    policy = DosboxResizePolicy(base.psp_segment, (DosboxMcbEntry(base.psp_segment - 1, header),))
    return replace(base, resize_policy=policy, dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(base.psp_segment))


@pytest.mark.parametrize("paragraphs,ax,bx,carry", [(0x180, 0x1000, 0x180, 0), (0x200, 0x1000, 0x200, 0), (0x201, 8, 0x200, 1)])
def test_resize_effects_retain_verified_event(paragraphs, ax, bx, carry):
    code = b"\xbb" + paragraphs.to_bytes(2, "little") + bytes.fromhex("b400b44acd21a31002891e12029c58a31402b8004ccd21")
    boot = program_from_mz_bytes(mz(code), _environment())
    observed = ProgramObservation("old_header", LinearRange(0xFFF0, 16))
    result = replay_program(boot, observations=(observed, ProgramObservation("answer", LinearRange(0x10210, 6))))
    assert result.status is ProgramStatus.TERMINATED
    resize = next(event for event in result.events if event.kind is ProgramEventKind.DOS_RESIZE)
    from tools.dosunit.runtime.real16_dosbox_resize_receipt import dosbox_resize_receipt_complete
    assert dosbox_resize_receipt_complete(resize.data)
    assert compare_programs(result, result) is ProgramAgreement.AGREED
    answer = dict(result.observations)["answer"]
    assert int.from_bytes(answer[:2], "little") == ax
    assert int.from_bytes(answer[2:4], "little") == bx
    assert int.from_bytes(answer[4:], "little") & 1 == carry
    # The saved AX/BX words retain the pre-service request, not returned values.
    assert any(address == 0x110E8 for address, _ in result.writes)
    assert result.exit_code == 0


def test_changed_chain_refuses_instead_of_emitting_success():
    # The PSP owner is 1000h; changing its low byte from zero to one is
    # a real metadata mutation, rather than writing its existing value.
    code = bytes.fromhex("b8ff0f8ec026c606010001b800108ec0bb8001b44acd21b8004ccd21")
    result = replay_program(program_from_mz_bytes(mz(code), _environment()))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert not any(event.kind is ProgramEventKind.DOS_RESIZE for event in result.events)
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE
