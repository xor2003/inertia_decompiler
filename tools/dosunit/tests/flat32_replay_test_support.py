"""Layer: dosunit execution test support.

Responsibility: construct actual ELF32/PE32 binaries with independently declared
file permissions and expose typed replay fixture contracts for regression tests.
"""

from __future__ import annotations

import io
import struct

import angr

from tools.dosunit.runtime.flat32_memory_permissions import (
    DeclaredAccess,
    MappingOrigin,
    PageGrant,
)
from tools.dosunit.architectures.flat32_pe_loader import InclusivePE
from tools.dosunit.runtime.flat32_replay import (
    ReplayImage,
    ReplayResult,
    ReplayVector,
    image_from_project,
)

SCRATCH: DeclaredAccess = DeclaredAccess.READ | DeclaredAccess.WRITE
"""Explicit caller data mapping used by these fixtures, never a loader fact."""

ESP: int = 0x28000


ELF_CODE: int = 0x10000


ELF_RDATA: int = 0x20000


ELF_RWDATA: int = 0x30000


PE_IMAGE: int = 0x400000


PE_TEXT: int = PE_IMAGE + 0x1000


PE_DATA: int = PE_IMAGE + 0x2000


def _elf32(segments: list[tuple[int, bytes, int]]) -> bytes:
    """Minimal ET_EXEC i386 ELF: each ``(vaddr, bytes, p_flags)`` PT_LOAD."""
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 3, 1, segments[0][0], 52, 0, 0, 52, 32, len(segments), 40, 0, 0)
    phdrs = b""
    for index, (vaddr, data, flags) in enumerate(segments):
        offset = 0x1000 * (index + 1)
        phdrs += struct.pack("<IIIIIIII", 1, offset, vaddr, vaddr, len(data), len(data), flags, 0x1000)
    blob = (header + phdrs).ljust(0x1000, b"\x00")
    for index, (_vaddr, data, _flags) in enumerate(segments):
        blob = blob.ljust(0x1000 * (index + 1), b"\x00") + data
    return blob


def _pe32(sections: list[tuple[bytes, int, int, int, int, bytes]]) -> bytes:
    """Minimal PE32: each ``(name, vsize, rva, rawptr, characteristics, data)``."""
    file = bytearray(0x600)
    file[:2] = b"MZ"
    struct.pack_into("<I", file, 0x3C, 0x80)
    file[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", file, 0x84, 0x14C, len(sections), 0, 0, 0, 0xE0, 0x102)
    opt = 0x98
    struct.pack_into("<H", file, opt, 0x10B)
    size_of_image = 0x1000 * (1 + len(sections))
    for offset, value in (
        (4, 0x200),
        (16, 0x1000),
        (20, 0x1000),
        (28, PE_IMAGE),
        (32, 0x1000),
        (36, 0x200),
        (56, size_of_image),
        (60, 0x200),
        (72, 0x100000),
        (76, 0x1000),
        (80, 0x100000),
        (84, 0x1000),
        (92, 16),
    ):
        struct.pack_into("<I", file, opt + offset, value)
    struct.pack_into("<H", file, opt + 68, 3)
    struct.pack_into("<H", file, opt + 70, 0x140)
    for index, (name, vsize, rva, rawptr, characteristics, data) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            file,
            opt + 0xE0 + 40 * index,
            name,
            vsize,
            rva,
            len(data),
            rawptr,
            0,
            0,
            0,
            0,
            characteristics,
        )
        file[rawptr : rawptr + len(data)] = data
    return bytes(file)


def _elf_image(segments: list[tuple[int, bytes, int]]) -> ReplayImage:
    """Build the actual project and staged replay image for an ELF32."""
    project = angr.Project(io.BytesIO(_elf32(segments)), auto_load_libs=False)
    return image_from_project(project)


def _pe_image(sections: list[tuple[bytes, int, int, int, int, bytes]]) -> ReplayImage:
    """Build the actual project and staged replay image for a PE32."""
    project = angr.Project(
        io.BytesIO(_pe32(sections)),
        auto_load_libs=False,
        main_opts={"backend": InclusivePE, "max_mapped_bytes": 4 * 1024 * 1024},
    )
    return image_from_project(project)


def _vector(**registers: int) -> ReplayVector:
    """Vector with the declared harness ESP role and no extra declarations."""
    return ReplayVector((*(("esp", ESP),), *tuple(registers.items())))


def _grant(result: ReplayResult, address: int) -> PageGrant:
    """The resolved page grant containing ``address``, as typed evidence."""
    for grant in result.pages:
        if grant.address <= address < grant.address + 0x1000:
            return grant
    raise AssertionError(f"no page grant for {address:#x}")


def _file_denied(image: ReplayImage, address: int) -> bool:
    """Whether a retained FILE declaration explicitly denies ``address``."""
    return any(
        region.origin is MappingOrigin.FILE
        and region.access == DeclaredAccess.NONE
        and region.address <= address < region.address + region.size
        for region in image.declared
    )
