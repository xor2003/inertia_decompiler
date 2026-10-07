"""Layer: Frontend/runtime.

Responsibility: model port and memory-mapped IO behavior for lifting/emulation.
Forbidden: decompiler helper recovery, source-backed IO semantics, or validation acceptance.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol

from pyvex.expr import Const as PyVexConst
from pyvex.lifting.util.vex_helper import Type

from inertia.frontend.x86_16.dev_io import MemoryIO, PortIO

from .memory import Memory

__all__ = ("IO", "retained_port_events")


#: Scoped declaration that the bound environment models every scalar port
#: access as an ordered event.  ``retained_port_events`` is the only writer;
#: the concrete-port fold checks below are the only readers.  Outside the
#: scope the default unregistered-device model is unchanged: a concrete port
#: with no registered ``PortIO`` device reads the canonical all-ones value
#: instead of producing a lifted event.
_PORT_EVENT_RETENTION: ContextVar[bool] = ContextVar(
    "x86_16_port_event_retention", default=False
)


@contextmanager
def retained_port_events() -> Iterator[None]:
    """Declare one bounded lifting scope that retains concrete port events.

    Inside the scope, lifting an IN form with a concrete port emits the
    ``x86g_dirtyhelper_IN`` event helper instead of folding to the canonical
    unregistered-device constant, so ordered-event evidence observes the real
    port access.  Concrete (non-lifting) execution is unchanged: with no
    lifted statement to carry an event, the device model still supplies the
    default value.  The binding is context-local and restored by token, so a
    concurrent or later comparison cannot inherit the declared scope.
    """
    token = _PORT_EVENT_RETENTION.set(True)
    try:
        yield
    finally:
        _PORT_EVENT_RETENTION.reset(token)


def _lifting_retains_port_events(io: IO) -> bool:
    """Return whether this instruction lifts under declared event retention.

    Retention applies only while a lifter instruction can emit the event
    helper; in concrete execution there is no lifted statement to carry the
    event and the unregistered-device model must still answer the read.
    """
    return _PORT_EVENT_RETENTION.get() and io.lifter_instruction is not None


class _CastablePortArg(Protocol):
    """Port expression that can be narrowed to the 16-bit I/O port width."""

    def cast_to(self, _type: object) -> object:
        """Return this expression cast to the requested VEX type."""


class _DirtyEmitter(Protocol):
    """Subset of the lifter instruction facade needed for dirty I/O helpers."""

    def dirty(self, _type: object, _name: str, _args: list[object]) -> object:
        """Emit a VEX dirty helper call."""


type _PortArg = int | PyVexConst | _CastablePortArg


class IO:
    """Route frontend port and memory-mapped I/O through registered devices."""

    lifter_instruction: _DirtyEmitter

    def __init__(self, memory: Memory) -> None:
        """Initialize empty port and memory-mapped I/O registries."""
        self.memory = memory
        self.port_io: dict[int, PortIO] = {}
        self.port_io_map: dict[int, int] = {}
        self.mem_io: dict[int, MemoryIO] = {}
        self.mem_io_map: dict[int, int] = {}

    def __del__(self) -> None:
        """Best-effort cleanup for scan-safe timeout unwinding."""
        try:
            self.port_io.clear()
            self.mem_io.clear()
            self.mem_io_map.clear()
        except Exception:
            # Keep destructor cleanup quiet during scan-safe timeout unwinding.
            pass

    def constant(self, value: int, _type: object = Type.int_8) -> object:
        """Return a frontend constant expression supplied by the Processor mixin."""
        raise NotImplementedError("IO.constant is provided by Processor in Hardware")

    def set_portio(self, addr: int, length: int, dev: PortIO) -> None:
        """Register a port I/O device at an even-aligned base address."""
        addr &= ~1
        self.port_io[addr] = dev
        self.port_io_map[addr] = length

    def get_portio_base(self, addr: int) -> int | None:
        """Return the registered port I/O base covering an address."""
        for i in range(5):  # max_mask: 0xfff0
            base = (addr & ~1) - (2 * i)
            if base in self.port_io_map:
                return base if addr < base + self.port_io_map[base] else None
        return None

    def _port_arg(self, addr: _PortArg) -> object:
        if isinstance(addr, int):
            return self.constant(addr, Type.int_16)
        if isinstance(addr, PyVexConst):
            return self.constant(addr.con.value, Type.int_16)
        return addr.cast_to(Type.int_16)

    def _concrete_port_value(self, addr: _PortArg) -> int | None:
        if isinstance(addr, int):
            return addr
        if isinstance(addr, PyVexConst):
            return int(addr.con.value)
        return None

    def in_io32(self, addr: _PortArg) -> object:
        """Read a 32-bit value from a port or emit the frontend dirty helper."""
        # If caller passed a concrete port and no PortIO is registered for it,
        # return a deterministic canonical value instead of emitting a dirty
        # helper. This matches test expectations for default input behaviour
        # when no device is present. Accept both Python ints and pyvex Consts.
        # A declared retained-port-events scope lifts the event helper instead.
        port_val = self._concrete_port_value(addr)
        if (
            port_val is not None
            and not _lifting_retains_port_events(self)
            and self.get_portio_base(port_val) is None
        ):
            return self.constant(0xFFFFFFFF & ((1 << 32) - 1), Type.int_32)
        port_arg = self._port_arg(addr)
        return self.lifter_instruction.dirty(Type.int_32, "x86g_dirtyhelper_IN", [port_arg, self.constant(32)])

    def in_io16(self, addr: _PortArg) -> object:
        """Read a 16-bit value from a port or emit the frontend dirty helper."""
        port_val = self._concrete_port_value(addr)
        if (
            port_val is not None
            and not _lifting_retains_port_events(self)
            and self.get_portio_base(port_val) is None
        ):
            return self.constant(0xFFFF & ((1 << 16) - 1), Type.int_16)
        port_arg = self._port_arg(addr)
        return self.lifter_instruction.dirty(Type.int_16, "x86g_dirtyhelper_IN", [port_arg, self.constant(16)])

    def in_io8(self, addr: _PortArg) -> object:
        """Read an 8-bit value from a port or emit the frontend dirty helper."""
        port_val = self._concrete_port_value(addr)
        if (
            port_val is not None
            and not _lifting_retains_port_events(self)
            and self.get_portio_base(port_val) is None
        ):
            return self.constant(0xFF & ((1 << 8) - 1), Type.int_8)
        port_arg = self._port_arg(addr)
        return self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_IN", [port_arg, self.constant(8)])

    def out_io32(self, addr: _PortArg, value: object) -> None:
        """Emit a 32-bit port write dirty helper."""
        port_arg = self._port_arg(addr)
        self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_OUT", [port_arg, value, self.constant(32)])

    def out_io16(self, addr: _PortArg, value: object) -> None:
        """Emit a 16-bit port write dirty helper."""
        port_arg = self._port_arg(addr)
        self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_OUT", [port_arg, value, self.constant(16)])

    def out_io8(self, addr: _PortArg, value: object) -> None:
        """Emit an 8-bit port write dirty helper."""
        port_arg = self._port_arg(addr)
        self.lifter_instruction.dirty(Type.int_8, "x86g_dirtyhelper_OUT", [port_arg, value, self.constant(8)])

    def set_memio(self, base: int, length: int, dev: MemoryIO) -> None:
        """Register a page-aligned memory-mapped I/O device."""
        assert base & ((1 << 12) - 1) == 0

        dev.set_mem(self.memory, base, length)
        self.mem_io[base] = dev

        for addr in range(base, base + length, 1 << 12):
            self.mem_io_map[addr] = base

    def get_memio_base(self, addr: int) -> int | None:
        """Return the registered memory I/O base covering an address."""
        addr &= ~((1 << 12) - 1)
        return self.mem_io_map.get(addr)

    def read_memio32(self, base: int, offset: int) -> int:
        """Read a 32-bit value from a registered memory-mapped device."""
        assert base in self.mem_io
        return int(self.mem_io[base].read32(offset))

    def read_memio16(self, base: int, offset: int) -> int:
        """Read a 16-bit value from a registered memory-mapped device."""
        assert base in self.mem_io
        return int(self.mem_io[base].read16(offset))

    def read_memio8(self, base: int, offset: int) -> int:
        """Read an 8-bit value from a registered memory-mapped device."""
        assert base in self.mem_io
        return int(self.mem_io[base].read8(offset))

    def write_memio32(self, base: int, offset: int, value: int) -> None:
        """Write a 32-bit value to a registered memory-mapped device."""
        assert base in self.mem_io
        self.mem_io[base].write32(offset, value)

    def write_memio16(self, base: int, offset: int, value: int) -> None:
        """Write a 16-bit value to a registered memory-mapped device."""
        assert base in self.mem_io
        self.mem_io[base].write16(offset, value)

    def write_memio8(self, base: int, offset: int, value: int) -> None:
        """Write an 8-bit value to a registered memory-mapped device."""
        assert base in self.mem_io
        self.mem_io[base].write8(offset, value)

    def chk_memio(self, addr: int) -> int | None:
        """Return the memory I/O device base covering an address."""
        return self.get_memio_base(addr)
