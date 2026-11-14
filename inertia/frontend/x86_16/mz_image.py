# cython: language_level=3, infer_types=True
"""Represent the DOS MZ container fields needed by frontend decoders.

Layer: frontend (loader).
Responsibility: parse and serialize typed MZ container metadata without interpreting program semantics.
Forbidden: packer detection, decompression, relocation application, or semantic recovery.
"""

from __future__ import annotations
import typing
import cython

import struct
from dataclasses import dataclass
import dataclasses

__all__ = ("MZHeaderView", "UnpackedMZImage", "paragraph_count")

_MZ_FIXED_HEADER_SIZE = 0x1C
_MZ_RELOCATION_TABLE_OFFSET = _MZ_FIXED_HEADER_SIZE


@cython.ccall
def paragraph_count(size: cython.longlong) -> cython.longlong:
    """Return the number of 16-byte paragraphs required for ``size`` bytes."""
    if size < 0:
        raise ValueError("MZ size must be non-negative")
    return (size + 15) // 16


@dataclasses.dataclass(frozen=True, )
class MZHeaderView:
    """Typed view of the conventional 28-byte DOS MZ header."""

    bytes_in_last_page: cython.longlong
    page_count: cython.longlong
    relocation_count: cython.longlong
    header_paragraphs: cython.longlong
    min_alloc: cython.longlong
    max_alloc: cython.longlong
    stack_ss: cython.longlong
    stack_sp: cython.longlong
    checksum: cython.longlong
    entry_ip: cython.longlong
    entry_cs: cython.longlong
    relocation_offset: cython.longlong
    overlay_number: cython.longlong

    @classmethod
    def parse(cls, data: object) -> MZHeaderView | None:
        """Return a header view, or ``None`` for a non-MZ or truncated input."""
        if len(data) < _MZ_FIXED_HEADER_SIZE or data[:2] not in {b"MZ", b"ZM"}:
            return None
        fields = struct.unpack_from("<13H", data, 2)
        return cls(*fields)

    @property
    def header_size(self) -> cython.longlong:
        """Return the declared MZ header size in bytes."""
        return self.header_paragraphs * 16

    @property
    def declared_file_size(self) -> int | None:
        """Decode the MZ page fields, returning ``None`` for an invalid encoding."""
        if self.bytes_in_last_page > 511:
            return None
        if self.bytes_in_last_page == 0:
            return self.page_count * 512
        if self.page_count == 0:
            return None
        return (self.page_count - 1) * 512 + self.bytes_in_last_page

    @property
    def entry_file_offset(self) -> cython.longlong:
        """Return the entry-stub file offset relative to the executable file."""
        return self.header_size + (self.entry_cs << 4) + self.entry_ip


@dataclasses.dataclass(frozen=True, )
class UnpackedMZImage:
    """A decoded MZ load image with unapplied relocation and register evidence."""

    image: object
    relocations: object
    entry_cs: cython.longlong
    entry_ip: cython.longlong
    stack_ss: cython.longlong
    stack_sp: cython.longlong
    min_alloc: cython.longlong = 0
    max_alloc: cython.longlong = 0xFFFF
    overlay_number: cython.longlong = 0

    def to_mz_bytes(self) -> object:
        """Serialize the recovered evidence as a conventional DOS MZ executable."""
        index: object
        offset: object
        segment: object
        relocation_bytes = len(self.relocations) * 4
        header_size = paragraph_count(_MZ_RELOCATION_TABLE_OFFSET + relocation_bytes) * 16
        total_size = header_size + len(self.image)
        if total_size > 0x1FFFE00:
            raise ValueError("decoded MZ image is too large to serialize")
        if len(self.relocations) > 0xFFFF:
            raise ValueError("decoded MZ image has too many relocations")

        header = bytearray(header_size)
        struct.pack_into(
            "<2s13H",
            header,
            0,
            b"MZ",
            total_size % 512,
            (total_size + 511) // 512,
            len(self.relocations),
            header_size // 16,
            self.min_alloc,
            self.max_alloc,
            self.stack_ss,
            self.stack_sp,
            0,
            self.entry_ip,
            self.entry_cs,
            _MZ_RELOCATION_TABLE_OFFSET,
            self.overlay_number,
        )
        for index, (segment, offset) in enumerate(self.relocations):
            struct.pack_into("<HH", header, _MZ_RELOCATION_TABLE_OFFSET + index * 4, offset, segment)
        return bytes(header) + self.image
