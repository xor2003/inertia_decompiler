"""Construct the existing minimal DOS MZ fixture shared by multiple test owners."""

from __future__ import annotations


def _mz_exe(image: bytes, *, relocs: tuple[tuple[int, int], ...] = (), minalloc: int = 0x1000) -> bytes:
    """Wrap bytes with the same header, allocation and relocation defaults as dosunit tests."""
    reloc_pos = 0x1C
    header_size = max(0x20, ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16)
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    for idx, (off, seg) in enumerate(relocs):
        at = reloc_pos + idx * 4
        header[at : at + 2] = off.to_bytes(2, "little")
        header[at + 2 : at + 4] = seg.to_bytes(2, "little")
    return bytes(header) + image
