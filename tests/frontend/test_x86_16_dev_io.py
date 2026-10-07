from __future__ import annotations

from inertia.frontend.x86_16.dev_io import MemoryIO


class _MemoryDevice(MemoryIO):
    """Test device that records byte reads and writes."""

    def __init__(self, values: dict[int, int] | None = None) -> None:
        """Initialize the test device with optional byte values."""
        super().__init__()
        self.values: dict[int, int] = dict(values or {})
        self.writes: list[tuple[int, int]] = []

    def read8(self, offset: int) -> int:
        """Read one byte from the test value map."""
        return self.values[offset]

    def write8(self, offset: int, value: int) -> None:
        """Record one byte write."""
        self.writes.append((offset, value))
        self.values[offset] = value


def test_memory_io_read_helpers_are_little_endian() -> None:
    device = _MemoryDevice({4: 0x78, 5: 0x56, 6: 0x34, 7: 0x12})

    assert device.read16(4) == 0x5678
    assert device.read32(4) == 0x12345678


def test_memory_io_write_helpers_are_little_endian() -> None:
    device = _MemoryDevice()

    device.write16(2, 0xBEEF)
    device.write32(8, 0x12345678)

    assert device.writes == [
        (2, 0xEF),
        (3, 0xBE),
        (8, 0x78),
        (9, 0x56),
        (10, 0x34),
        (11, 0x12),
    ]
