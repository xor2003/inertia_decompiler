"""The DOSBox final-block resize contract keeps exact spans and typed refusals."""

import subprocess
import sys
from pathlib import Path

import pytest

from inertia.frontend.real16_dosbox_resize import (
    DOSBOX_ERR_INSUFFICIENT_MEMORY,
    DOSBOX_MCB_BYTES,
    DOSBOX_MCB_FINAL_MARKER,
    DOSBOX_MCB_MIDDLE_MARKER,
    DosboxMcbEntry,
    DosboxResizePolicy,
    DosboxResizeRefusal,
    DosboxResizeResponse,
    DosboxResizeWrite,
    dosbox_resize_response,
)

pytestmark = pytest.mark.runtime

PSP = 0x0402
FINAL_SEGMENT = PSP - 1
OLD_SIZE = 0x9E6D
# Retained MS-captured final MCB shape: Z marker, owner word, size 0x9E6D,
# zeroed reserved bytes and the "CMP16" name field.
CAPTURED_FINAL = bytes.fromhex("5a92016d9e000000434d503136000000")


def mcb(marker: int, owner: int, size: int, tail: bytes = bytes(11)) -> bytes:
    """Build one exact 16-byte MCB image: marker, owner word, size word, tail."""
    return bytes((marker,)) + owner.to_bytes(2, "little") + size.to_bytes(2, "little") + tail


def policy(*entries: DosboxMcbEntry, psp: int = PSP) -> DosboxResizePolicy:
    """Declare a chain policy from explicit entries."""
    return DosboxResizePolicy(psp, tuple(entries))


FINAL_MCB = mcb(DOSBOX_MCB_FINAL_MARKER, PSP, OLD_SIZE, b"\0\0\0CMP16\0\0\0")
SINGLE = policy(DosboxMcbEntry(FINAL_SEGMENT, FINAL_MCB))
SINGLE_IMAGES = tuple(entry.image for entry in SINGLE.chain)
ES = FINAL_SEGMENT + 1
AX = 0x4A01


def test_module_imports_without_angr() -> None:
    """The pure contract must stay importable when angr cannot load."""
    code = (
        "import sys; sys.modules['angr'] = None;"
        "import inertia.frontend.real16_dosbox_resize"
    )
    subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[2], check=True)


def test_policy_accepts_native_captured_final_mcb() -> None:
    """A native-shaped final MCB declares cleanly under its owning PSP."""
    declared = DosboxResizePolicy(0x0192, (DosboxMcbEntry(0x0191, CAPTURED_FINAL),))
    assert declared.final_entry.size == OLD_SIZE
    assert declared.final_entry.owner == 0x0192
    assert declared.final_entry.data_segment == 0x0192


def test_policy_accepts_multi_entry_contiguous_chain() -> None:
    """Middle M blocks ahead of one owned final Z block are admissible."""
    first = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0x0008, 0x0100))
    second = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_MIDDLE_MARKER, PSP, 0x0200))
    final = DosboxMcbEntry(0x0382, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0400))
    declared = policy(first, second, final)
    assert declared.final_entry is final


@pytest.mark.parametrize("image", [
    mcb(0x4A, PSP, 1),   # invalid marker
    FINAL_MCB[:15],      # incomplete 16-byte image
])
def test_policy_rejects_malformed_entry(image: bytes) -> None:
    """Every declared entry must carry a native marker and full 16 bytes."""
    with pytest.raises(ValueError):
        DosboxMcbEntry(FINAL_SEGMENT, image)


def test_policy_rejects_terminal_m_marker() -> None:
    """The single final block must carry the Z marker."""
    with pytest.raises(ValueError):
        policy(DosboxMcbEntry(FINAL_SEGMENT, mcb(DOSBOX_MCB_MIDDLE_MARKER, PSP, OLD_SIZE)))


def test_policy_rejects_nonfinal_z_marker() -> None:
    """Only one Z marker is allowed and it must be the last entry."""
    first = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0100))
    second = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0200))
    with pytest.raises(ValueError):
        policy(first, second)


def test_policy_rejects_noncontiguous_chain() -> None:
    """Every next MCB must sit exactly at segment + size + 1."""
    first = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0x0008, 0x0100))
    second = DosboxMcbEntry(0x0182, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0200))
    with pytest.raises(ValueError):
        policy(first, second)


def test_policy_rejects_adjacent_free_pair() -> None:
    """Adjacent free blocks would make DOS_CompressMemory mutate the chain."""
    first = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0, 0x0100))
    second = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0200))
    assert policy(first, second).final_entry is second
    second_free = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0, 0x0200))
    final = DosboxMcbEntry(0x0382, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0400))
    with pytest.raises(ValueError):
        policy(first, second_free, final)


def test_policy_rejects_free_tail_and_foreign_owner() -> None:
    """The final block must be owned by the declared nonzero PSP."""
    with pytest.raises(ValueError):
        policy(DosboxMcbEntry(FINAL_SEGMENT, mcb(DOSBOX_MCB_FINAL_MARKER, 0, OLD_SIZE)))
    with pytest.raises(ValueError):
        policy(DosboxMcbEntry(FINAL_SEGMENT, mcb(DOSBOX_MCB_FINAL_MARKER, 0x0999, OLD_SIZE)))


def test_policy_rejects_zero_psp_and_empty_chain() -> None:
    """PSP segment zero and an absent chain are malformed declarations."""
    with pytest.raises(ValueError):
        policy(DosboxMcbEntry(FINAL_SEGMENT, FINAL_MCB), psp=0)
    with pytest.raises(ValueError):
        DosboxResizePolicy(PSP, ())


def test_policy_rejects_wrapping_chain() -> None:
    """Segment arithmetic must stay inside the 16-bit paragraph space."""
    first = DosboxMcbEntry(0xFFF0, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0x0008, 0x0020))
    second = DosboxMcbEntry(0x0011, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0100))
    with pytest.raises(ValueError):
        policy(first, second)
    with pytest.raises(ValueError):
        policy(DosboxMcbEntry(0xF000, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x1000)))
    with pytest.raises(ValueError):
        policy(DosboxMcbEntry(0xFFFF, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0)))


def test_equal_size_succeeds_with_no_writes() -> None:
    """BX equal to the final size returns AX=ES, BX unchanged, CF clear."""
    result = dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=OLD_SIZE, ax=AX, current_chain=SINGLE_IMAGES)
    assert result == DosboxResizeResponse(ES, OLD_SIZE, False, ())


def test_equal_size_succeeds_on_multi_entry_chain() -> None:
    """Same-size success holds with declared middle blocks ahead."""
    first = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0x0008, 0x0100))
    final = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0200))
    declared = policy(first, final)
    images = tuple(entry.image for entry in declared.chain)
    result = dosbox_resize_response(
        declared, segment=final.data_segment, paragraphs=0x0200, ax=AX, current_chain=images)
    assert result == DosboxResizeResponse(final.data_segment, 0x0200, False, ())


def test_shrink_emits_exact_native_write_spans_in_order() -> None:
    """Shrink writes type/owner/size spans in DOS_ResizeMemory order."""
    before = bytes(range(0xA0, 0xA0 + DOSBOX_MCB_BYTES))
    result = dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=0x0100, ax=AX,
        current_chain=SINGLE_IMAGES, new_header_before=before)
    base = FINAL_SEGMENT << 4
    header = (ES + 0x0100) << 4
    assert result == DosboxResizeResponse(ES, 0x0100, False, (
        DosboxResizeWrite(base + 3, (0x0100).to_bytes(2, "little")),
        DosboxResizeWrite(header, b"Z"),
        DosboxResizeWrite(base, b"M"),
        DosboxResizeWrite(header + 3, (OLD_SIZE - 0x0100 - 1).to_bytes(2, "little")),
        DosboxResizeWrite(header + 1, b"\0\0"),
        DosboxResizeWrite(base + 1, PSP.to_bytes(2, "little")),
    ))


def test_shrink_to_zero_and_free_size_zero_boundaries() -> None:
    """BX=0 and remaining-free-size 0 are valid native boundaries."""
    for paragraphs, remaining in ((0, OLD_SIZE - 1), (OLD_SIZE - 1, 0)):
        before = bytes(DOSBOX_MCB_BYTES)
        result = dosbox_resize_response(
            SINGLE, segment=ES, paragraphs=paragraphs, ax=AX,
            current_chain=SINGLE_IMAGES, new_header_before=before)
        header = (ES + paragraphs) << 4
        assert isinstance(result, DosboxResizeResponse)
        assert not result.carry and result.ax == ES and result.bx == paragraphs
        assert result.writes[3] == DosboxResizeWrite(header + 3, remaining.to_bytes(2, "little"))


def test_shrink_preserves_supplied_reserved_header_bytes() -> None:
    """Modeled writes never touch the new header's reserved bytes 5..15."""
    before = bytes((0x55, 0x66, 0x77, 0x88)) + bytes(range(0x30, 0x30 + 12))
    result = dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=0x0100, ax=AX,
        current_chain=SINGLE_IMAGES, new_header_before=before)
    header = (ES + 0x0100) << 4
    merged = bytearray(before)
    assert isinstance(result, DosboxResizeResponse)
    for write in result.writes:
        if header <= write.address < header + DOSBOX_MCB_BYTES:
            offset = write.address - header
            merged[offset:offset + len(write.data)] = write.data
    assert bytes(merged[:5]) == b"Z\0\0" + (OLD_SIZE - 0x0100 - 1).to_bytes(2, "little")
    assert bytes(merged[5:]) == before[5:]


def test_overgrowth_fails_with_error8_and_old_size() -> None:
    """Growth beyond the final block clamps BX, sets CF and keeps the owner."""
    result = dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=OLD_SIZE + 1, ax=AX, current_chain=SINGLE_IMAGES)
    base = FINAL_SEGMENT << 4
    assert result == DosboxResizeResponse(DOSBOX_ERR_INSUFFICIENT_MEMORY, OLD_SIZE, True, (
        DosboxResizeWrite(base + 3, OLD_SIZE.to_bytes(2, "little")),
        DosboxResizeWrite(base + 1, PSP.to_bytes(2, "little")),
    ))


def test_overgrowth_at_word_boundary() -> None:
    """BX=0xFFFF against a smaller final block fails identically."""
    result = dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=0xFFFF, ax=AX, current_chain=SINGLE_IMAGES)
    assert isinstance(result, DosboxResizeResponse)
    assert result.carry and result.ax == 8 and result.bx == OLD_SIZE


@pytest.mark.parametrize("segment", [FINAL_SEGMENT, ES + 1, 0x0001, 0xFFFF])
def test_other_segment_refuses(segment: int) -> None:
    """ES naming anything but the declared final data segment refuses."""
    result = dosbox_resize_response(
        SINGLE, segment=segment, paragraphs=1, ax=AX, current_chain=SINGLE_IMAGES)
    assert result is DosboxResizeRefusal.OTHER_BLOCK


def test_nonfinal_declared_block_refuses() -> None:
    """ES naming a declared middle block's data segment still refuses."""
    first = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, PSP, 0x0100))
    final = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0200))
    declared = policy(first, final)
    images = tuple(entry.image for entry in declared.chain)
    result = dosbox_resize_response(
        declared, segment=first.data_segment, paragraphs=1, ax=AX, current_chain=images)
    assert result is DosboxResizeRefusal.OTHER_BLOCK


@pytest.mark.parametrize("ax", [0x4B00, 0x004A, 0x494A])
def test_wrong_function_rejected(ax: int) -> None:
    """Only proven AH=4Ah inputs are admitted."""
    with pytest.raises(ValueError):
        dosbox_resize_response(SINGLE, segment=ES, paragraphs=1, ax=ax, current_chain=SINGLE_IMAGES)


@pytest.mark.parametrize("field", ["segment", "paragraphs", "ax"])
@pytest.mark.parametrize("value", [-1, 0x10000, True, 1.5])
def test_non_word_inputs_rejected(field: str, value: object) -> None:
    """Every proven input register must be an exact 16-bit integer."""
    kwargs = {"segment": ES, "paragraphs": 1, "ax": AX, field: value}
    with pytest.raises(ValueError):
        dosbox_resize_response(SINGLE, current_chain=SINGLE_IMAGES, **kwargs)


def test_absent_current_chain_refuses() -> None:
    """No supplied current chain means no model, never a guess."""
    result = dosbox_resize_response(SINGLE, segment=ES, paragraphs=1, ax=AX, current_chain=None)
    assert result is DosboxResizeRefusal.CURRENT_CHAIN_ABSENT


def test_incomplete_current_chain_refuses() -> None:
    """Fewer entries or a truncated entry image refuse as incomplete."""
    assert dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX, current_chain=()) is (
        DosboxResizeRefusal.CURRENT_CHAIN_INCOMPLETE)
    assert dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX,
        current_chain=(FINAL_MCB[:15],)) is DosboxResizeRefusal.CURRENT_CHAIN_INCOMPLETE


def test_changed_current_chain_refuses() -> None:
    """Mutated or extended current metadata refuses; it never silently passes."""
    corrupted = FINAL_MCB[:7] + b"X" + FINAL_MCB[8:]
    assert dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX,
        current_chain=(corrupted,)) is DosboxResizeRefusal.CURRENT_CHAIN_CHANGED
    extra = mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 1)
    assert dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX,
        current_chain=(*SINGLE_IMAGES, extra)) is DosboxResizeRefusal.CURRENT_CHAIN_CHANGED


def test_corrupted_current_marker_refuses_not_dos_error() -> None:
    """A destroyed-marker current MCB is corrupted evidence, not a DOS error."""
    corrupted = b"Q" + FINAL_MCB[1:]
    result = dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX, current_chain=(corrupted,))
    assert result is DosboxResizeRefusal.CURRENT_CHAIN_CHANGED
    assert not isinstance(result, DosboxResizeResponse)


def test_free_prefix_remains_separated_by_owned_resized_block() -> None:
    """Free predecessors cannot merge across the PSP-owned original block."""
    free = DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0, 0x0100))
    final = DosboxMcbEntry(0x0181, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, 0x0200))
    declared = policy(free, final)
    images = tuple(entry.image for entry in declared.chain)
    for paragraphs in (1, 0x0200, 0x0300):
        result = dosbox_resize_response(
            declared, segment=final.data_segment, paragraphs=paragraphs, ax=AX,
            current_chain=images, new_header_before=bytes(DOSBOX_MCB_BYTES))
        assert isinstance(result, DosboxResizeResponse)
        assert result.carry is (paragraphs > final.size)


def test_shrink_requires_complete_new_header_image() -> None:
    """The prospective split header's 16 preexisting bytes must be supplied."""
    assert dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX,
        current_chain=SINGLE_IMAGES) is DosboxResizeRefusal.NEW_HEADER_UNPROVEN
    assert dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=1, ax=AX, current_chain=SINGLE_IMAGES,
        new_header_before=bytes(15)) is DosboxResizeRefusal.NEW_HEADER_UNPROVEN


def test_new_header_image_not_required_without_shrink() -> None:
    """Equal-size and growth failures never consult the split header bytes."""
    for paragraphs in (OLD_SIZE, OLD_SIZE + 1):
        result = dosbox_resize_response(
            SINGLE, segment=ES, paragraphs=paragraphs, ax=AX, current_chain=SINGLE_IMAGES)
        assert isinstance(result, DosboxResizeResponse)


def test_resize_response_is_deterministic() -> None:
    """Identical proven inputs produce identical staged outcomes."""
    before = bytes(DOSBOX_MCB_BYTES)
    calls = tuple(dosbox_resize_response(
        SINGLE, segment=ES, paragraphs=2, ax=AX,
        current_chain=SINGLE_IMAGES, new_header_before=before) for _ in range(2))
    assert calls[0] == calls[1]
