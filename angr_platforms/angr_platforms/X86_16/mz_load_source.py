"""Parse and relocate source-backed DOS MZ load modules.

Layer: Frontend.
Responsibility: own the architecture-neutral MZ format validation, exact
load-module bytes and relocation arithmetic shared by native execution and
source-derived invocation proofs. This owner knows no dosunit backend,
solver, program environment, inferred selector or success verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_MZ_RELOCATIONS: int = 0x4000

__all__ = ["MAX_MZ_RELOCATIONS", "MzExe", "parse_mz", "relocate_mz_load_module"]


@dataclass(frozen=True, slots=True)
class MzExe:
    """Parsed MZ header fields, the load-module bytes and relocation records.

    ``image`` is the byte range the DOS loader copies (everything after the
    header up to the declared exe size). ``relocations`` are ``(offset,
    segment)`` pairs whose stored words are relative to the image start.
    """

    image: bytes
    relocations: tuple[tuple[int, int], ...]
    minalloc: int
    maxalloc: int
    entry_cs: int
    entry_ip: int
    stack_ss: int
    stack_sp: int
    checksum: int


def parse_mz(data: bytes) -> MzExe:
    """Parse and validate a DOS MZ executable's load image and relocations."""
    if len(data) < 0x1C or data[:2] not in {b"MZ", b"ZM"}:
        raise ValueError("real16 replay requires a DOS MZ executable")
    lastsize = int.from_bytes(data[0x02:0x04], "little")
    nblocks = int.from_bytes(data[0x04:0x06], "little")
    nreloc = int.from_bytes(data[0x06:0x08], "little")
    hdr_paras = int.from_bytes(data[0x08:0x0A], "little")
    minalloc = int.from_bytes(data[0x0A:0x0C], "little")
    maxalloc = int.from_bytes(data[0x0C:0x0E], "little")
    stack_ss = int.from_bytes(data[0x0E:0x10], "little")
    stack_sp = int.from_bytes(data[0x10:0x12], "little")
    checksum = int.from_bytes(data[0x12:0x14], "little")
    entry_ip = int.from_bytes(data[0x14:0x16], "little")
    entry_cs = int.from_bytes(data[0x16:0x18], "little")
    reloc_pos = int.from_bytes(data[0x18:0x1A], "little")
    if nblocks == 0 or lastsize > 511 or minalloc > maxalloc:
        raise ValueError("invalid MZ page count, last-page size or allocation bounds")
    exe_size = ((nblocks - 1) << 9) + lastsize if lastsize else nblocks << 9
    header_size = hdr_paras << 4
    if header_size < 0x1C or exe_size <= header_size or exe_size > len(data):
        raise ValueError("bad MZ image/header sizes")
    if nreloc > MAX_MZ_RELOCATIONS or (nreloc and (reloc_pos < 0x1C or reloc_pos + nreloc * 4 > header_size)):
        raise ValueError("truncated or excessive MZ relocation table")
    relocs: list[tuple[int, int]] = []
    for index in range(nreloc):
        at = reloc_pos + index * 4
        relocs.append(
            (int.from_bytes(data[at:at + 2], "little"),
             int.from_bytes(data[at + 2:at + 4], "little"))
        )
    return MzExe(
        image=data[header_size:exe_size], relocations=tuple(relocs),
        minalloc=minalloc, maxalloc=maxalloc,
        entry_cs=entry_cs, entry_ip=entry_ip, stack_ss=stack_ss, stack_sp=stack_sp,
        checksum=checksum,
    )


def relocate_mz_load_module(exe: MzExe, load_segment: int) -> bytes:
    """Apply MZ relocations by adding the load paragraph to each stored word."""
    image = bytearray(exe.image)
    for offset, segment in exe.relocations:
        target = segment * 16 + offset
        if target + 2 > len(image):
            raise ValueError("MZ relocation outside load image")
        stored = int.from_bytes(image[target:target + 2], "little")
        image[target:target + 2] = ((stored + load_segment) & 0xFFFF).to_bytes(2, "little")
    return bytes(image)

