"""Real serialized PE import tables at the compiler-corpus intake boundary."""

import struct

import pefile
import pytest

from tools.dosunit.runtime.pe32_import_service import parse_pe32_imports
from tools.dosunit.tests.test_pe32_import_service import pe32_import_bytes


def import_table_bytes(count: int) -> bytes:
    """Build distinct by-name imports with separate terminated ILT/IAT arrays."""
    data = bytearray(pe32_import_bytes(b"\xc3"))
    data.extend(bytes(0x1C00 - len(data)))
    data[0x400:] = bytes(len(data) - 0x400)
    struct.pack_into("<I", data, 0x98 + 56, 0x4000)
    struct.pack_into("<I", data, 0x1A0 + 8, 0x1800)
    struct.pack_into("<I", data, 0x1A0 + 16, 0x1800)
    struct.pack_into("<II", data, 0xF8 + 96, 0x2300, 4 * (count + 1))
    struct.pack_into("<IIIII", data, 0x400, 0x2100, 0, 0, 0x2050, 0x2300)
    data[0x450:0x45D] = b"kernel32.dll\0"
    for index in range(count):
        name_rva = 0x2500 + index * 32
        struct.pack_into("<I", data, 0x500 + index * 4, name_rva)
        struct.pack_into("<I", data, 0x700 + index * 4, name_rva)
        name = f"Function{index:03d}".encode("ascii") + b"\0"
        offset = name_rva - 0x2000 + 0x400 + 2
        data[offset:offset + len(name)] = name
    return bytes(data)


@pytest.mark.parametrize("count", [47, 64])
def test_compiler_sized_import_table(count: int) -> None:
    """Admit complete tables larger than the former 32-slot boot limit."""
    symbols = parse_pe32_imports(pefile.PE(data=import_table_bytes(count)))
    assert len(symbols) == count
    assert [symbol.name for symbol in symbols] == [f"Function{i:03d}" for i in range(count)]
    assert [symbol.slot for symbol in symbols] == [0x402300 + 4 * i for i in range(count)]


def test_import_capacity_still_bounded() -> None:
    """An oversized table refuses instead of silently returning a prefix."""
    with pytest.raises(ValueError, match="import slot count exceeds"):
        parse_pe32_imports(pefile.PE(data=import_table_bytes(65)))
