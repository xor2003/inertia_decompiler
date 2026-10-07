from __future__ import annotations

import pytest
import pyvex
from angr.ailment import IRSBConverter, Manager
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from pyvex.lifting.util.vex_helper import Type

from inertia.frontend.x86_16.compat import _normalize_x86_16_io_dirty_statements
from inertia.frontend.x86_16.dev_io import MemoryIO, PortIO
from inertia.frontend.x86_16.io import IO


class _PortDevice(PortIO):
    def in8(self, addr: int) -> int:
        return addr & 0xFF

    def out8(self, addr: int, value: int) -> None:
        self.last_write = (addr, value)


class _MemoryDevice(MemoryIO):
    def __init__(self) -> None:
        super().__init__()
        self.values: dict[int, int] = {}

    def read8(self, offset: int) -> int:
        return self.values[offset]

    def write8(self, offset: int, value: int) -> None:
        self.values[offset] = value


class _DirtyRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str, list[object]]] = []

    def dirty(self, type_: object, name: str, args: list[object]) -> object:
        call = (type_, name, args)
        self.calls.append(call)
        return call


class _TestIO(IO):
    def __init__(self) -> None:
        super().__init__(memory=object())
        self.lifter_instruction = _DirtyRecorder()

    def constant(self, value: int, type_: object = Type.int_8) -> tuple[str, int, object]:
        return ("const", value, type_)


def test_port_io_registration_uses_even_base_and_range_lookup() -> None:
    io = _TestIO()
    device = _PortDevice()

    io.set_portio(0x3F9, 8, device)

    assert io.port_io[0x3F8] is device
    assert io.get_portio_base(0x3F8) == 0x3F8
    assert io.get_portio_base(0x3FF) == 0x3F8
    assert io.get_portio_base(0x400) is None


def test_unregistered_concrete_port_reads_return_default_constants() -> None:
    io = _TestIO()

    assert io.in_io8(0x60) == ("const", 0xFF, "Ity_I8")
    assert io.in_io16(pyvex.expr.Const(pyvex.const.U16(0x60))) == ("const", 0xFFFF, "Ity_I16")


def test_registered_pyvex_const_port_read_emits_dirty_helper() -> None:
    io = _TestIO()
    io.set_portio(0x3F8, 8, _PortDevice())

    result = io.in_io32(pyvex.expr.Const(pyvex.const.U16(0x3F8)))

    assert result == io.lifter_instruction.calls[-1]
    _, name, args = io.lifter_instruction.calls[-1]
    assert name == "x86g_dirtyhelper_IN"
    assert args[0] == ("const", 0x3F8, "Ity_I16")
    assert args[1] == ("const", 32, "Ity_I8")


@pytest.mark.parametrize(("encoding", "width"), (("ee", 8), ("ef", 16), ("66ef", 32)))
def test_out_dirty_helper_has_complete_ail_effect_metadata(encoding: str, width: int) -> None:
    arch = Arch86_16()
    irsb = pyvex.lift(bytes.fromhex(encoding), 0x1000, arch, max_inst=1, opt_level=0)
    dirty = next(statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.Dirty))

    assert dirty.cee.name == "x86g_dirtyhelper_OUT"
    assert dirty.tmp == 0xFFFFFFFF
    assert dirty.mFx == "Ifx_None"
    assert dirty.mSize == 0
    assert dirty.nFxState == 0
    ail = IRSBConverter.convert(irsb, Manager(arch=arch))
    assert any("x86g_dirtyhelper_OUT" in repr(statement) for statement in ail.statements)

    ail, raw, normalized, materialized, failures = _normalize_x86_16_io_dirty_statements(ail)

    assert (raw, normalized, materialized, failures) == (1, 1, 1, 0)
    assert any(f"inertia_io_out{width}" in repr(statement) for statement in ail.statements)


def test_memory_io_registration_maps_pages_and_forwards_accesses() -> None:
    io = _TestIO()
    device = _MemoryDevice()

    io.set_memio(0xA0000, 0x3000, device)
    io.write_memio16(0xA0000, 4, 0xBEEF)

    assert io.get_memio_base(0xA0123) == 0xA0000
    assert io.get_memio_base(0xA2000) == 0xA0000
    assert io.get_memio_base(0xA3000) is None
    assert io.read_memio16(0xA0000, 4) == 0xBEEF
