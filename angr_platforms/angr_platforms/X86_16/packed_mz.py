"""Detect packed DOS MZ inputs and decode the proven LZEXE 0.91 format.

Layer: frontend (loader).
Responsibility: classify evidence-backed packer signatures and recover an LZEXE 0.91 image with its
relocations, entry point, and initial stack intact.
Forbidden: generic stub emulation, guessed relocations, or treating an unsupported packer as decoded.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .mz_image import MZHeaderView, UnpackedMZImage

__all__ = (
    "MZHeaderView",
    "PackedMZError",
    "PackedMZErrorKind",
    "PackerDetection",
    "PackerType",
    "UnpackedMZImage",
    "detect_packer",
    "detect_packer_in_bytes",
    "unpack_lzexe_091",
)

_ENTRY_REGION_RADIUS = 2048


class PackerType(StrEnum):
    """Packer families supported by the bounded signature detector."""

    LZEXE = "LZEXE"
    EXEPACK = "EXEPACK"
    DIET = "DIET"
    PKLITE = "PKLITE"
    UPX = "UPX"


class PackedMZErrorKind(StrEnum):
    """Typed reason why packed-MZ recovery refused an input."""

    NOT_MZ = "not_mz"
    UNSUPPORTED_PACKER = "unsupported_packer"
    MALFORMED_LZEXE = "malformed_lzexe"
    MALFORMED_EXEPACK = "malformed_exepack"
    MALFORMED_PKLITE = "malformed_pklite"
    UNPACKER_UNAVAILABLE = "unpacker_unavailable"
    UNPACKER_TIMEOUT = "unpacker_timeout"


class PackedMZError(ValueError):
    """Evidence-backed refusal to decode a packed executable."""

    def __init__(self, kind: PackedMZErrorKind, detail: str) -> None:
        """Record the typed refusal and its diagnostic detail."""
        self.kind = kind
        self.detail = detail
        super().__init__(f"{kind.value}: {detail}")


@dataclass(frozen=True, slots=True)
class PackerDetection:
    """A packer signature tied to an exact file location."""

    packer_type: PackerType
    signature: str
    offset: int
    confidence: float

    @property
    def label(self) -> str:
        """Return the packer family with a version suffix when known."""
        if self.packer_type is PackerType.LZEXE and self.signature in {"LZ90", "LZ91"}:
            return f"LZEXE 0.{self.signature[2:]}"
        return self.packer_type.value


def detect_packer_in_bytes(data: bytes) -> PackerDetection | None:
    """Classify exact header signatures or a bounded entry-stub signature."""
    header = MZHeaderView.parse(data)
    if header is None:
        return None

    tag = data[0x1C:0x20]
    if tag in {b"LZ90", b"LZ91"}:
        return PackerDetection(PackerType.LZEXE, tag.decode("ascii"), 0x1C, 1.0)
    if tag.lower() == b"diet":
        return PackerDetection(PackerType.DIET, "diet", 0x1C, 1.0)

    if header.entry_ip in {16, 18}:
        exepack_header = header.header_size + (header.entry_cs << 4)
        signature_offset = exepack_header + header.entry_ip - 2
        if data[signature_offset : signature_offset + 2] == b"RB":
            return PackerDetection(PackerType.EXEPACK, "RB", signature_offset, 1.0)

    banner_end = max(0x1C, min(header.relocation_offset, header.header_size, len(data)))
    banner_offset = data[0x1C:banner_end].upper().find(b"PKLITE")
    if banner_offset >= 0:
        return PackerDetection(PackerType.PKLITE, "PKLITE", 0x1C + banner_offset, 1.0)

    entry = header.entry_file_offset
    start = max(0, entry - _ENTRY_REGION_RADIUS)
    end = min(len(data), entry + _ENTRY_REGION_RADIUS)
    upx_offset = data[start:end].find(b"UPX!")
    if upx_offset >= 0:
        return PackerDetection(PackerType.UPX, "UPX!", start + upx_offset, 0.8)
    return None


def detect_packer(path: Path) -> PackerDetection | None:
    """Classify a DOS MZ executable without mutating it."""
    try:
        return detect_packer_in_bytes(path.read_bytes())
    except OSError:
        return None


class _LZEXEBitStream:
    """LSB-first bit and byte reader used by the LZEXE 0.91 stream."""

    def __init__(self, data: bytes, offset: int) -> None:
        self._data = data
        self._position = offset
        self._remaining = 0
        self._buffer = 0
        self._load_word()

    def _malformed(self, detail: str) -> PackedMZError:
        return PackedMZError(PackedMZErrorKind.MALFORMED_LZEXE, detail)

    def _load_word(self) -> None:
        if self._position < 0 or self._position + 2 > len(self._data):
            raise self._malformed("compressed bitstream is truncated")
        self._remaining = 16
        self._buffer = self._data[self._position] | (self._data[self._position + 1] << 8)
        self._position += 2

    def bit(self) -> int:
        """Read one low-order bit."""
        value = self._buffer & 1
        self._buffer >>= 1
        self._remaining -= 1
        if self._remaining == 0:
            self._load_word()
        return value

    def byte(self) -> int:
        """Read one literal byte."""
        if self._position >= len(self._data):
            raise self._malformed("compressed byte stream is truncated")
        value = self._data[self._position]
        self._position += 1
        return value


def _require_slice(data: bytes, offset: int, size: int, detail: str) -> bytes:
    if offset < 0 or offset + size > len(data):
        raise PackedMZError(PackedMZErrorKind.MALFORMED_LZEXE, detail)
    return data[offset : offset + size]


def unpack_lzexe_091(data: bytes) -> UnpackedMZImage:
    """Decode LZEXE 0.91 while retaining relocations for the normal MZ loader."""
    header = MZHeaderView.parse(data)
    if header is None:
        raise PackedMZError(PackedMZErrorKind.NOT_MZ, "missing MZ signature or fixed header")
    if data[0x1C:0x20] != b"LZ91":
        raise PackedMZError(PackedMZErrorKind.UNSUPPORTED_PACKER, "only LZEXE 0.91 decoding is proven")

    lz_header_offset = (header.header_paragraphs + header.entry_cs) << 4
    lz_entry = lz_header_offset + header.entry_ip
    if _require_slice(data, lz_entry, 4, "LZEXE entry stub is truncated") != b"\x06\x0e\x1f\x8b":
        raise PackedMZError(PackedMZErrorKind.MALFORMED_LZEXE, "entry stub does not match LZEXE 0.91")

    info = _require_slice(data, lz_header_offset, 12, "LZEXE information block is truncated")
    entry_ip, entry_cs, stack_sp, stack_ss, packed_paragraphs, unpacked_paragraphs = struct.unpack("<6H", info)
    packed_stream_offset = lz_header_offset - (packed_paragraphs << 4)
    output = bytearray((unpacked_paragraphs * 2) << 4)
    stream = _LZEXEBitStream(data, packed_stream_offset)
    output_position = 0

    while True:
        if stream.bit():
            if output_position >= len(output):
                raise PackedMZError(PackedMZErrorKind.MALFORMED_LZEXE, "decoded image exceeds declared size")
            output[output_position] = stream.byte()
            output_position += 1
            continue

        if stream.bit() == 0:
            length = (stream.bit() << 1) | stream.bit()
            length += 2
            span = stream.byte() | ~0xFF
        else:
            span = stream.byte()
            encoded_length = stream.byte()
            span |= ((encoded_length & ~0x07) << 5) | ~0x1FFF
            length = (encoded_length & 0x07) + 2
            if length == 2:
                length = stream.byte()
                if length == 0:
                    break
                if length == 1:
                    continue
                length += 1

        for _ in range(length):
            source_position = output_position + span
            if source_position < 0 or source_position >= output_position or output_position >= len(output):
                raise PackedMZError(PackedMZErrorKind.MALFORMED_LZEXE, "invalid compressed back-reference")
            output[output_position] = output[source_position]
            output_position += 1

    relocation_position = lz_header_offset + 0x158
    relocation_linear = 0
    relocations: list[tuple[int, int]] = []
    while True:
        span_data = _require_slice(data, relocation_position, 1, "relocation stream is truncated")
        span = span_data[0]
        relocation_position += 1
        if span == 0:
            span = int.from_bytes(
                _require_slice(data, relocation_position, 2, "relocation span is truncated"), "little"
            )
            relocation_position += 2
            if span == 0:
                relocation_linear += 0x0FFF0
                continue
            if span == 1:
                break
        relocation_linear += span
        if relocation_linear + 2 > len(output):
            raise PackedMZError(PackedMZErrorKind.MALFORMED_LZEXE, "relocation lies outside decoded image")
        relocations.append((relocation_linear >> 4, relocation_linear & 0xF))

    relocation_image_size = max(((segment << 4) + offset + 2 for segment, offset in relocations), default=0)
    image_size = max(output_position, relocation_image_size)
    return UnpackedMZImage(
        image=bytes(output[:image_size]),
        relocations=tuple(relocations),
        entry_cs=entry_cs,
        entry_ip=entry_ip,
        stack_ss=stack_ss,
        stack_sp=stack_sp,
        min_alloc=header.min_alloc,
        max_alloc=header.max_alloc,
        overlay_number=header.overlay_number,
    )
