"""Layer: Tests.

Responsibility: construct minimal MZ fixtures for isolated DOS worker tests.
"""

def mz_exe(image: bytes, *, minalloc: int = 0x1000) -> bytes:
    """Minimal MZ wrapper for the synthetic harnesses in this file."""
    header = bytearray(0x20)
    header[0:2] = b"MZ"
    size = 0x20 + len(image)
    blocks, last = divmod(size, 512)
    if last:
        blocks += 1
    header[0x02:0x04] = last.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    return bytes(header) + image


