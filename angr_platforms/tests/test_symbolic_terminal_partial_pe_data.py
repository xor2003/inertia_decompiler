"""Actual-PE initial-data premise controls across partial native stores."""

import struct

import test_symbolic_terminal as fixtures

from tools.dosunit import symbolic_terminal as terminal


def data_image(initial: bytes) -> bytes:
    """Build separate executable text and writable initialized PE data."""
    prefix = bytes.fromhex('c6050020400041a100204000')
    binary = bytearray(fixtures.pe32_bytes(fixtures.exit_code(prefix=prefix)))
    binary.extend(bytes(0x200))
    struct.pack_into('<H', binary, 0x86, 2)
    struct.pack_into('<I', binary, 0x98 + 8, 0x200)
    struct.pack_into('<I', binary, 0x98 + 56, 0x3000)
    struct.pack_into('<8sIIIIIIHHI', binary, 0x178 + 40,
                     b'.data\0\0\0', 4, 0x2000, 0x200, 0x400,
                     0, 0, 0, 0, 0xC0000040)
    binary[0x400:0x404] = initial
    return bytes(binary)


def test_native_partial_store_keeps_changed_initial_bytes_observable() -> None:
    """Equal code cannot establish shared data when three read lanes survive."""
    environment = fixtures.pe_environment()
    result = terminal.compare_symbolic_terminals(
        data_image(bytes.fromhex('aabbccdd')), environment,
        data_image(bytes.fromhex('aa99ccdd')), environment,
    )
    assert result.status is terminal.TerminalComparisonStatus.PREMISE_MISMATCH, result.detail


def test_native_overwritten_initial_byte_is_irrelevant() -> None:
    """A changed byte overwritten before its only read needs no assumption."""
    environment = fixtures.pe_environment()
    result = terminal.compare_symbolic_terminals(
        data_image(bytes.fromhex('aabbccdd')), environment,
        data_image(bytes.fromhex('99bbccdd')), environment,
    )
    assert result.status is terminal.TerminalComparisonStatus.EQUIVALENT, result.detail
