"""DOSBox INT21 frame effects checked against native saved-register receipts."""

import pytest

from inertia.frontend.real16_dosbox_int21_frame import (
    DosBoxInt21FrameFailure8616,
    DosBoxInt21Registers8616,
    dosbox_int21_frame_effects_8616,
)


def _registers(**changes):
    values = {"ax": 0x4AFF, "bx": 0x10A2, "cx": 4, "dx": 0x192, "si": 0x1234,
              "di": 0x234, "bp": 0x91C, "ds": 0x192, "es": 0x192}
    values.update(changes)
    return DosBoxInt21Registers8616(**values)


def test_native_resize_register_save_and_psp_pointer():
    # Exact native before/after receipt: MSC CMP16, DOSBox source/runtime hashes
    # retained in .cache/coverage-environment-20261008/msc-resize-capture/.
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x192, ss=0x234, sp=0x9DE, registers=_registers(),
    )
    assert result.failure is None
    assert len(result.writes) == 11
    words = result.writes[2:11]
    assert b"".join(write.data for write in words) == bytes.fromhex(
        "ff4aa21004009201341234021c0992019201"
    )
    assert words[0].linear == 11526
    assert words[-1].linear == 11542
    pointer = result.writes[1]
    assert (pointer.segment, pointer.offset, pointer.linear) == (0x192, 0x2E, 6478)
    assert pointer.data == bytes.fromhex("c6093402")
    frame = result.writes[0]
    assert (frame.linear, frame.size, frame.data) == (11544, 6, None)


def test_different_stack_and_psp_spaces_are_retained():
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x300, ss=0x500, sp=0x80,
        registers=_registers(ax=0x3000),
    )
    assert result.failure is None
    assert all(write.segment == 0x500 for write in (result.writes[0], *result.writes[2:]))
    assert result.writes[1].segment == 0x300
    assert result.writes[1].data == bytes.fromhex("68000005")


def test_unproved_saved_word_is_an_explicit_unknown_write():
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x192, ss=0x234, sp=0x9DE,
        registers=_registers(dx=None),
    )
    assert result.failure is None
    assert result.writes[5].data is None
    assert result.writes[5].size == 2
    assert result.writes[6].data == bytes.fromhex("3412")


@pytest.mark.parametrize("sp", [0, 5, 6, 17, 23])
def test_stack_wrap_refuses_without_partial_effects(sp):
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x192, ss=0x234, sp=sp, registers=_registers(),
    )
    assert result.failure is DosBoxInt21FrameFailure8616.STACK_WRAP
    assert not result.writes


def test_stack_boundary_24_is_supported():
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x192, ss=0x234, sp=24, registers=_registers(),
    )
    assert result.failure is None
    assert result.writes[2].offset == 0


@pytest.mark.parametrize("ax", [None, 0, 0x0900, 0x5000, 0x6200, 0x6C00])
def test_undeclared_service_refuses(ax):
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x192, ss=0x234, sp=0x9DE,
        registers=_registers(ax=ax),
    )
    assert result.failure is DosBoxInt21FrameFailure8616.SERVICE_UNPROVED
    assert not result.writes


@pytest.mark.parametrize("field,value", [("psp_segment", 0), ("ss", -1), ("sp", 0x10000)])
def test_invalid_coordinates_refuse(field, value):
    values = {"psp_segment": 0x192, "ss": 0x234, "sp": 0x9DE}
    values[field] = value
    result = dosbox_int21_frame_effects_8616(**values, registers=_registers())
    assert result.failure is DosBoxInt21FrameFailure8616.COORDINATES_UNPROVED
    assert not result.writes


def test_alias_preserves_native_psp_then_saved_register_order():
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x300, ss=0x300, sp=0x46, registers=_registers(),
    )
    memory = bytearray(0x100)
    for write in result.writes:
        if write.data is not None:
            memory[write.offset:write.offset+write.size] = write.data
    # AX/BX overwrite the PSP save pointer because the native handler stores
    # that pointer before the register words. Sorting writes changes behavior.
    assert memory[0x2E:0x32] == bytes.fromhex("ff4aa210")


@pytest.mark.parametrize("psp_segment,ss,sp", [(0xFFFF, 0x234, 24), (0x192, 0xFFFF, 24)])
def test_unproved_twenty_bit_address_wrap_refuses(psp_segment, ss, sp):
    result = dosbox_int21_frame_effects_8616(
        psp_segment=psp_segment, ss=ss, sp=sp, registers=_registers(),
    )
    assert result.failure is DosBoxInt21FrameFailure8616.ADDRESS_WRAP
    assert not result.writes


@pytest.mark.parametrize("value", [True, -1, 0x10000])
def test_malformed_saved_register_refuses(value):
    result = dosbox_int21_frame_effects_8616(
        psp_segment=0x192, ss=0x234, sp=0x9DE,
        registers=_registers(dx=value),
    )
    assert result.failure is DosBoxInt21FrameFailure8616.REGISTER_UNPROVED
    assert not result.writes
