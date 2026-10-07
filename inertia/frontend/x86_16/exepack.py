"""Decode evidence-backed Microsoft EXEPACK DOS MZ executables.

Layer: frontend (loader).
Responsibility: recover the original MZ image, relocations, entry point, stack, and allocation metadata.
Forbidden: executing an unpacking stub, guessing relocation boundaries, or accepting malformed streams.

The format logic is adapted from David Fifield's CC0 ``exepack`` implementation at
https://github.com/viiri/exepack (revision a42f2c8fb1018feeb2c32fc7f7b1f01240d824c4).
"""

from __future__ import annotations

from dataclasses import dataclass

from .mz_image import MZHeaderView, UnpackedMZImage, paragraph_count
from .packed_mz import PackedMZError, PackedMZErrorKind

__all__ = ("unpack_exepack",)

_EXEPACK_SIGNATURE = 0x4252
_STUB_SUFFIX = b"\xcd\x21\xb8\xff\x4c\xcd\x21"
_ERROR_MESSAGE_LENGTH = 22


def _malformed(detail: str) -> PackedMZError:
    """Build a typed EXEPACK format error."""
    return PackedMZError(PackedMZErrorKind.MALFORMED_EXEPACK, detail)


def _read_word(data: bytes | bytearray, offset: int, detail: str) -> int:
    """Read a bounded little-endian word from an EXEPACK structure."""
    if offset < 0 or offset + 2 > len(data):
        raise _malformed(detail)
    return int.from_bytes(data[offset : offset + 2], "little")


@dataclass(frozen=True, slots=True)
class _EXEPACKHeader:
    """Fields stored between the compressed image and decompression stub."""

    real_ip: int
    real_cs: int
    exepack_size: int
    real_sp: int
    real_ss: int
    destination_paragraphs: int
    skip_paragraphs_plus_one: int

    @classmethod
    def parse(cls, data: bytes) -> _EXEPACKHeader:
        """Parse one of the two documented EXEPACK header layouts."""
        if len(data) not in {16, 18}:
            raise _malformed(f"unsupported EXEPACK header length {len(data)}")
        words = tuple(_read_word(data, offset, "EXEPACK header is truncated") for offset in range(0, len(data), 2))
        signature = words[-1]
        if signature != _EXEPACK_SIGNATURE:
            raise _malformed(f"invalid EXEPACK signature 0x{signature:04x}")
        skip = words[7] if len(words) == 9 else 1
        return cls(
            real_ip=words[0],
            real_cs=words[1],
            exepack_size=words[3],
            real_sp=words[4],
            real_ss=words[5],
            destination_paragraphs=words[6],
            skip_paragraphs_plus_one=skip,
        )


def _locate_relocation_table(stub: bytes) -> int:
    """Locate the packed relocation table after a recognized common stub suffix."""
    for position in range(len(stub) - len(_STUB_SUFFIX) + 1):
        if stub[position : position + len(_STUB_SUFFIX)] != _STUB_SUFFIX:
            continue
        table_offset = position + len(_STUB_SUFFIX) + _ERROR_MESSAGE_LENGTH
        if table_offset <= len(stub):
            return table_offset
    raise _malformed("EXEPACK decompression stub has no recognized terminal sequence")


def _parse_relocations(data: bytes) -> tuple[tuple[int, int], ...]:
    """Decode all 16 segment groups in the packed relocation table."""
    cursor = 0
    relocations: list[tuple[int, int]] = []
    for segment_index in range(16):
        count = _read_word(data, cursor, "EXEPACK relocation group count is truncated")
        cursor += 2
        for _ in range(count):
            offset = _read_word(data, cursor, "EXEPACK relocation offset is truncated")
            cursor += 2
            relocations.append((segment_index << 12, offset))
    if cursor != len(data):
        raise _malformed("EXEPACK relocation table has trailing bytes")
    return tuple(relocations)


def _decompress(data: bytearray, compressed_length: int, output_length: int) -> None:
    """Run the bounded backwards EXEPACK fill/copy command stream."""
    if compressed_length < 0 or compressed_length > len(data):
        raise _malformed("EXEPACK compressed length lies outside the image")
    if output_length < 0:
        raise _malformed("EXEPACK output length is negative")
    if output_length > len(data):
        data.extend(b"\x00" * (output_length - len(data)))

    source = compressed_length
    padding = 0
    while padding < 15 and source > 0 and data[source - 1] == 0xFF:
        source -= 1
        padding += 1
    destination = output_length

    while True:
        source, destination, done = _exepack_command_step(data, source, destination)
        if done:
            break

    if compressed_length < destination:
        raise _malformed("EXEPACK command stream leaves an uninitialized gap")
    del data[output_length:]


def _exepack_command_step(data: bytearray, source: int, destination: int) -> tuple[int, int, bool]:
    """Apply one EXEPACK fill/copy command and report stream completion."""
    if source < 3:
        raise _malformed("EXEPACK command stream is truncated")
    source -= 1
    command = data[source]
    source -= 2
    length = int.from_bytes(data[source : source + 2], "little")

    command_type = command & 0xFE
    if command_type == 0xB0:
        if source < 1:
            raise _malformed("EXEPACK fill command is truncated")
        source -= 1
        fill = data[source]
        if length > destination:
            raise _malformed("EXEPACK fill command exceeds the decoded image")
        destination -= length
        data[destination : destination + length] = bytes([fill]) * length
    elif command_type == 0xB2:
        if length > source or length > destination:
            raise _malformed("EXEPACK copy command exceeds the decoded image")
        source -= length
        destination -= length
        for index in range(length - 1, -1, -1):
            data[destination + index] = data[source + index]
    else:
        raise _malformed(f"unknown EXEPACK command 0x{command:02x}")

    return source, destination, bool(command & 1)


def _exepack_header_block(
    mz: MZHeaderView, packed_body: bytes
) -> tuple[_EXEPACKHeader, int, int, int]:
    """Parse the EXEPACK metadata block inside the packed image."""
    header_offset = mz.entry_cs << 4
    header_length = mz.entry_ip
    header_end = header_offset + header_length
    if header_offset > len(packed_body) or header_end > len(packed_body):
        raise _malformed("EXEPACK header lies beyond the packed image")
    header = _EXEPACKHeader.parse(packed_body[header_offset:header_end])
    block_end = header_offset + header.exepack_size
    if header.exepack_size < header_length or block_end > len(packed_body):
        raise _malformed("EXEPACK metadata block has an invalid size")
    return header, header_offset, header_end, block_end


def _exepack_stream_window(
    header: _EXEPACKHeader, packed_body: bytes, header_offset: int
) -> tuple[bytearray, int, int]:
    """Compute the bounded compressed stream and decoded output extents."""
    skip_value = header.skip_paragraphs_plus_one
    if skip_value == 0:
        raise _malformed("EXEPACK skip length cannot be zero")
    skipped_bytes = (skip_value - 1) * 16
    compressed = bytearray(packed_body[:header_offset])
    if skipped_bytes > len(compressed):
        raise _malformed("EXEPACK skip length exceeds the compressed image")
    compressed_length = len(compressed) - skipped_bytes
    output_length = header.destination_paragraphs * 16 - skipped_bytes
    if output_length < 0:
        raise _malformed("EXEPACK skip length exceeds the decoded image")
    return compressed, compressed_length, output_length


def unpack_exepack(data: bytes) -> UnpackedMZImage:
    """Decode a recognized EXEPACK MZ file without executing its unpacking stub."""
    mz = MZHeaderView.parse(data)
    if mz is None:
        raise PackedMZError(PackedMZErrorKind.NOT_MZ, "missing MZ signature or fixed header")
    declared_size = mz.declared_file_size
    if declared_size is None or declared_size > len(data):
        raise _malformed("invalid or truncated MZ file size")
    if mz.header_size < 0x1C or mz.header_size > declared_size:
        raise _malformed("invalid MZ header size")
    if mz.relocation_count != 0:
        raise _malformed("packed EXEPACK MZ files must not have outer relocations")

    packed_body = data[mz.header_size : declared_size]
    header, header_offset, header_end, block_end = _exepack_header_block(mz, packed_body)

    stub_and_relocations = packed_body[header_end:block_end]
    relocation_offset = _locate_relocation_table(stub_and_relocations)
    relocations = _parse_relocations(stub_and_relocations[relocation_offset:])

    compressed, compressed_length, output_length = _exepack_stream_window(
        header, packed_body, header_offset
    )
    _decompress(compressed, compressed_length, output_length)

    available_paragraphs = paragraph_count(len(packed_body)) + mz.min_alloc
    output_paragraphs = paragraph_count(len(compressed))
    min_alloc = max(0, available_paragraphs - output_paragraphs)
    if min_alloc > 0xFFFF:
        raise _malformed("decoded MZ minimum allocation exceeds 16 bits")

    return UnpackedMZImage(
        image=bytes(compressed),
        relocations=relocations,
        entry_cs=header.real_cs,
        entry_ip=header.real_ip,
        stack_ss=header.real_ss,
        stack_sp=header.real_sp,
        min_alloc=min_alloc,
        max_alloc=mz.max_alloc,
        overlay_number=mz.overlay_number,
    )
