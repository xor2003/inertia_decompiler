"""Async GDB Remote Serial Protocol (RSP) client.

Speaks directly to gdbserver / QEMU GDB stub over TCP.
Implements the minimal RSP packet set needed for a debugger TUI:
  - Connection / ack / nack
  - Register read/write  (g / G / p / P)
  - Memory read/write    (m / M / X)
  - Execution control    (c / s / ? / vCont)
  - Breakpoints          (Z / z)
  - Thread info          (qC / qfThreadInfo / Hg / Hc)
  - Stop reason parsing
"""

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class StopReason(Enum):
    """Why the target stopped."""
    UNKNOWN = auto()
    SIGTRAP = auto()       # 05 – breakpoint / single-step
    SIGINT = auto()        # 02 – interrupt
    SIGSEGV = auto()       # 0b
    SIGILL = auto()        # 04
    SIGFPE = auto()        # 08
    EXITED = auto()        # Wxx
    SIGNALLED = auto()     # Xxx


@dataclass
class StopInfo:
    """Parsed stop-reply."""
    reason: StopReason = StopReason.UNKNOWN
    signal: int = 0
    thread: str = ""
    watch_addr: int = 0
    frame: dict[str, str] = field(default_factory=dict)


@dataclass
class RegisterDef:
    """Register metadata."""
    name: str
    size: int          # bytes
    group: str = "general"   # general, float, vector, segment, flags


@dataclass
class MemoryRegion:
    address: int
    data: bytes

    def hexdump(self, width: int = 16) -> str:
        lines: list[str] = []
        for i in range(0, len(self.data), width):
            chunk = self.data[i : i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {self.address + i:08x}  {hex_part:<{width*3}}  {ascii_part}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# x86 / x86-64 register definitions  (g-packet order)
# ---------------------------------------------------------------------------

X86_REGS: list[RegisterDef] = [
    RegisterDef("eax", 4), RegisterDef("ecx", 4), RegisterDef("edx", 4),
    RegisterDef("ebx", 4), RegisterDef("esp", 4), RegisterDef("ebp", 4),
    RegisterDef("esi", 4), RegisterDef("edi", 4), RegisterDef("eip", 4),
    RegisterDef("eflags", 4),
    RegisterDef("cs", 4), RegisterDef("ss", 4), RegisterDef("ds", 4),
    RegisterDef("es", 4), RegisterDef("fs", 4), RegisterDef("gs", 4),
]

X86_16_REGS: list[RegisterDef] = [
    RegisterDef("ax", 2), RegisterDef("cx", 2), RegisterDef("dx", 2),
    RegisterDef("bx", 2), RegisterDef("sp", 2), RegisterDef("bp", 2),
    RegisterDef("si", 2), RegisterDef("di", 2),
    RegisterDef("ip", 2), RegisterDef("flags", 2),
    RegisterDef("cs", 2), RegisterDef("ss", 2), RegisterDef("ds", 2),
    RegisterDef("es", 2), RegisterDef("fs", 2), RegisterDef("gs", 2),
]

X86_64_REGS: list[RegisterDef] = [
    RegisterDef("rax", 8), RegisterDef("rbx", 8), RegisterDef("rcx", 8),
    RegisterDef("rdx", 8), RegisterDef("rsi", 8), RegisterDef("rdi", 8),
    RegisterDef("rbp", 8), RegisterDef("rsp", 8),
    RegisterDef("r8", 8), RegisterDef("r9", 8), RegisterDef("r10", 8),
    RegisterDef("r11", 8), RegisterDef("r12", 8), RegisterDef("r13", 8),
    RegisterDef("r14", 8), RegisterDef("r15", 8),
    RegisterDef("rip", 8), RegisterDef("rflags", 8),
    RegisterDef("cs", 8), RegisterDef("ss", 8), RegisterDef("ds", 8),
    RegisterDef("es", 8), RegisterDef("fs", 8), RegisterDef("gs", 8),
]

# ---------------------------------------------------------------------------
# RSP packet helpers
# ---------------------------------------------------------------------------

def _checksum(data: str) -> str:
    return f"{sum(ord(c) for c in data) & 0xFF:02x}"


def _encode_mem(value: int, nbytes: int) -> str:
    """Encode integer as little-endian hex (RSP byte order)."""
    return value.to_bytes(nbytes, "little").hex()


def _decode_mem(hexstr: str, nbytes: int) -> int:
    """Decode little-endian hex to integer."""
    raw = bytes.fromhex(hexstr)
    # Pad if shorter than expected
    raw = raw.ljust(nbytes, b"\x00")
    return int.from_bytes(raw[:nbytes], "little")


# ---------------------------------------------------------------------------
# GDB RSP Client
# ---------------------------------------------------------------------------

class GDBClientError(Exception):
    pass


class GDBClient:
    """Async GDB Remote Serial Protocol client.

    Connects directly to a gdbserver / QEMU GDB stub.

    Usage::

        client = GDBClient()
        await client.connect("127.0.0.1", 1234)
        await client.set_arch("x86")

        regs = await client.read_registers()
        await client.step()
        await client.continue_()
        await client.insert_breakpoint(0x1000)
        mem = await client.read_memory(0x1000, 64)
    """

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._stopped = True

        # Architecture
        self._arch: str = "x86"
        self._reg_defs: list[RegisterDef] = X86_REGS

        # Event callbacks
        self._on_stop: Callable[[StopInfo], None] | None = None
        self._on_output: Callable[[str], None] | None = None

    # -- properties --------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def is_stopped(self) -> bool:
        return self._stopped

    @property
    def arch(self) -> str:
        return self._arch

    # -- connection --------------------------------------------------------

    async def connect(self, host: str, port: int) -> None:
        self._reader, self._writer = await asyncio.open_connection(host, port)
        self._connected = True
        # Read initial stop reply
        reply = await self._read_packet()
        self._parse_stop_reply(reply)

    async def disconnect(self) -> None:
        if self._writer:
            self._writer.close()
            await self._writer.wait_closed()
        self._connected = False

    # -- architecture ------------------------------------------------------

    def set_arch(self, arch: str) -> None:
        """Set target architecture for register decoding.

        Args:
            arch: 'x86', 'x86_16', or 'x86_64'
        """
        self._arch = arch
        if arch == "x86_64":
            self._reg_defs = X86_64_REGS
        elif arch == "x86_16":
            self._reg_defs = X86_16_REGS
        else:
            self._reg_defs = X86_REGS

    # -- low-level packet I/O ----------------------------------------------

    async def _read_packet(self) -> str:
        """Read one RSP packet (handles $...#cc and acks)."""
        assert self._reader is not None
        while True:
            ch = await self._reader.read(1)
            if not ch:
                raise GDBClientError("Connection closed")
            if ch == b"$":
                break
            if ch == b"+":
                continue  # ack – skip

        data = bytearray()
        while True:
            b = await self._reader.read(1)
            if not b:
                raise GDBClientError("Connection closed")
            if b == b"#":
                break
            if b == b"}":
                # escaped byte – next byte is XOR 0x20
                esc = await self._reader.read(1)
                if not esc:
                    raise GDBClientError("Connection closed")
                data.append(esc[0] ^ 0x20)
            else:
                data.append(b[0])

        # Read checksum
        cc = (await self._reader.read(2)).decode("ascii", errors="replace")
        expected = _checksum(data.decode("ascii", errors="replace"))

        # Send ack
        assert self._writer is not None
        if cc == expected:
            self._writer.write(b"+")
        else:
            self._writer.write(b"-")
        await self._writer.drain()

        return data.decode("ascii", errors="replace")

    async def _send_packet(self, data: str) -> str:
        """Send packet and return reply."""
        assert self._writer is not None
        pkt = f"${data}#{_checksum(data)}"
        self._writer.write(pkt.encode("ascii"))
        await self._writer.drain()
        return await self._read_packet()

    # -- stop reply parsing -----------------------------------------------

    def _parse_stop_reply(self, reply: str) -> StopInfo:
        info = StopInfo()
        if not reply:
            return info

        if reply.startswith("S"):
            # Sxx  – signal
            try:
                info.signal = int(reply[1:3], 16)
            except ValueError:
                pass
            mapping = {
                0x02: StopReason.SIGINT,
                0x04: StopReason.SIGILL,
                0x05: StopReason.SIGTRAP,
                0x08: StopReason.SIGFPE,
                0x0B: StopReason.SIGSEGV,
            }
            info.reason = mapping.get(info.signal, StopReason.UNKNOWN)
            # Optional key:value pairs after signal
            if ";" in reply:
                for kv in reply[3:].split(";"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        info.frame[k] = v
                    elif k == "thread":
                        info.thread = v

        elif reply.startswith("T"):
            # Txx  – signal with extra info
            try:
                info.signal = int(reply[1:3], 16)
            except ValueError:
                pass
            mapping = {
                0x02: StopReason.SIGINT,
                0x04: StopReason.SIGILL,
                0x05: StopReason.SIGTRAP,
                0x08: StopReason.SIGFPE,
                0x0B: StopReason.SIGSEGV,
            }
            info.reason = mapping.get(info.signal, StopReason.UNKNOWN)
            for kv in reply[3:].split(";"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    info.frame[k] = v
                elif kv.startswith("thread:"):
                    info.thread = kv[7:]
                elif kv.startswith("watch:"):
                    try:
                        info.watch_addr = int(kv[6:], 16)
                    except ValueError:
                        pass

        elif reply.startswith("W"):
            info.reason = StopReason.EXITED
            try:
                info.signal = int(reply[1:3], 16)
            except ValueError:
                pass
        elif reply.startswith("X"):
            info.reason = StopReason.SIGNALLED
            try:
                info.signal = int(reply[1:3], 16)
            except ValueError:
                pass
        elif reply.startswith("O"):
            # Console output
            hex_out = reply[1:]
            try:
                text = bytes.fromhex(hex_out).decode("utf-8", errors="replace")
                if self._on_output:
                    self._on_output(text)
            except ValueError:
                pass

        self._stopped = True
        if self._on_stop:
            self._on_stop(info)
        return info

    # -- execution control -------------------------------------------------

    async def continue_(self) -> StopInfo:
        """Continue execution until next stop."""
        self._stopped = False
        reply = await self._send_packet("c")
        return self._parse_stop_reply(reply)

    async def continue_with_signal(self, sig: int = 0) -> StopInfo:
        """Continue with a signal."""
        self._stopped = False
        reply = await self._send_packet(f"c{sig:02x}")
        return self._parse_stop_reply(reply)

    async def step(self) -> StopInfo:
        """Single-step one instruction."""
        self._stopped = False
        reply = await self._send_packet("s")
        return self._parse_stop_reply(reply)

    async def step_n(self, count: int) -> StopInfo:
        """Single-step multiple instructions."""
        info = StopInfo()
        steps = max(1, count)
        for _ in range(steps):
            info = await self.step()
            if info.reason in {StopReason.EXITED, StopReason.SIGNALLED, StopReason.SIGSEGV, StopReason.SIGILL}:
                break
        return info

    async def step_with_signal(self, sig: int = 0) -> StopInfo:
        self._stopped = False
        reply = await self._send_packet(f"s{sig:02x}")
        return self._parse_stop_reply(reply)

    async def interrupt(self) -> StopInfo:
        """Send ^C to interrupt running target."""
        assert self._writer is not None
        self._writer.write(b"\x03")
        await self._writer.drain()
        reply = await self._read_packet()
        return self._parse_stop_reply(reply)

    async def status(self) -> StopInfo:
        """Query stop reason (?)."""
        reply = await self._send_packet("?")
        return self._parse_stop_reply(reply)

    # -- registers ---------------------------------------------------------

    async def read_registers(self) -> dict[str, int]:
        """Read all general registers (g packet)."""
        reply = await self._send_packet("g")
        regs: dict[str, int] = {}
        offset = 0
        for rdef in self._reg_defs:
            hex_val = reply[offset : offset + rdef.size * 2]
            if len(hex_val) == rdef.size * 2:
                regs[rdef.name] = _decode_mem(hex_val, rdef.size)
            else:
                regs[rdef.name] = 0
            offset += rdef.size * 2
        return regs

    async def read_register(self, reg_num: int) -> int:
        """Read single register by index (p packet)."""
        reply = await self._send_packet(f"p{reg_num:x}")
        if reply == "xxxxxxxx":
            return 0
        try:
            return _decode_mem(reply, self._reg_defs[reg_num].size)
        except (IndexError, ValueError):
            return int(reply, 16) if reply else 0

    async def write_register(self, reg_num: int, value: int) -> str:
        """Write single register (P packet)."""
        rdef = self._reg_defs[reg_num]
        hex_val = _encode_mem(value, rdef.size)
        return await self._send_packet(f"P{reg_num:x}={hex_val}")

    async def write_registers(self, regs: dict[str, int]) -> str:
        """Write all registers (G packet)."""
        parts: list[str] = []
        for rdef in self._reg_defs:
            val = regs.get(rdef.name, 0)
            parts.append(_encode_mem(val, rdef.size))
        return await self._send_packet("G" + "".join(parts))

    # -- memory ------------------------------------------------------------

    async def read_memory(self, addr: int, length: int) -> MemoryRegion:
        """Read memory (m packet)."""
        reply = await self._send_packet(f"m{addr:x},{length:x}")
        if reply.startswith("E"):
            raise GDBClientError(f"Memory read error at 0x{addr:x}: {reply}")
        data = bytes.fromhex(reply)
        return MemoryRegion(address=addr, data=data)

    async def write_memory(self, addr: int, data: bytes) -> str:
        """Write memory (X packet – binary)."""
        # Escape data for X packet
        escaped = bytearray()
        for b in data:
            if b in (ord("$"), ord("#"), ord("}"), ord("*")):
                escaped.append(ord("}"))
                escaped.append(b ^ 0x20)
            else:
                escaped.append(b)
        return await self._send_packet(f"X{addr:x},{len(data):x}:" + escaped.decode("latin-1"))

    async def write_memory_hex(self, addr: int, data: bytes) -> str:
        """Write memory (M packet – hex encoded)."""
        hex_str = data.hex()
        return await self._send_packet(f"M{addr:x},{len(data):x}:{hex_str}")

    # -- breakpoints -------------------------------------------------------

    async def insert_breakpoint(self, addr: int, kind: int = 0) -> str:
        """Insert software breakpoint (Z0)."""
        return await self._send_packet(f"Z0,{addr:x},{kind:x}")

    async def remove_breakpoint(self, addr: int, kind: int = 0) -> str:
        """Remove software breakpoint (z0)."""
        return await self._send_packet(f"z0,{addr:x},{kind:x}")

    async def insert_hw_breakpoint(self, addr: int, kind: int = 0) -> str:
        """Insert hardware breakpoint (Z1)."""
        return await self._send_packet(f"Z1,{addr:x},{kind:x}")

    async def remove_hw_breakpoint(self, addr: int, kind: int = 0) -> str:
        """Remove hardware breakpoint (z1)."""
        return await self._send_packet(f"z1,{addr:x},{kind:x}")

    async def insert_watchpoint(self, addr: int, length: int, wp_type: int = 2) -> str:
        """Insert watchpoint.

        wp_type: 2=write, 3=read, 4=access
        """
        return await self._send_packet(f"Z{wp_type},{addr:x},{length:x}")

    async def remove_watchpoint(self, addr: int, length: int, wp_type: int = 2) -> str:
        return await self._send_packet(f"z{wp_type},{addr:x},{length:x}")

    # -- threads -----------------------------------------------------------

    async def get_current_thread(self) -> str:
        """Get current thread ID (qC)."""
        reply = await self._send_packet("qC")
        return reply[2:] if reply.startswith("QC") else "1"

    async def list_threads(self) -> list[str]:
        """List thread IDs (qfThreadInfo / qsThreadInfo)."""
        reply = await self._send_packet("qfThreadInfo")
        if reply.startswith("m"):
            return reply[1:].split(",")
        if reply == "l":
            return []
        return [reply[1:]]

    async def set_thread(self, thread_id: str, op: str = "c") -> str:
        """Set thread for subsequent operations.

        op: 'c' for continue/step, 'g' for register/memory
        """
        return await self._send_packet(f"H{op}{thread_id}")

    # -- query -------------------------------------------------------------

    async def query_supported_features(self) -> dict[str, str]:
        """Query gdbserver features (qSupported)."""
        reply = await self._send_packet("qSupported")
        features: dict[str, str] = {}
        for item in reply.split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                features[k] = v
            elif item.endswith("+"):
                features[item[:-1]] = "1"
            elif item.endswith("-"):
                features[item[:-1]] = "0"
        return features

    async def query_helper_info(self) -> dict[str, Any]:
        """Fetch debugger-specific helper metadata for the current stop."""
        reply = await self._send_packet("qInertiaHelpers")
        if not reply:
            return {}
        try:
            payload = json.loads(reply)
        except json.JSONDecodeError as exc:
            raise GDBClientError(f"Invalid helper metadata: {exc}") from exc
        if not isinstance(payload, dict):
            raise GDBClientError("Invalid helper metadata payload")
        return payload

    async def read_offsets(self) -> tuple[int, int]:
        """Read section offsets (qOffsets)."""
        reply = await self._send_packet("qOffsets")
        text = 0
        data = 0
        for item in reply.split(";"):
            if item.startswith("Text="):
                text = int(item[5:], 16)
            elif item.startswith("Data="):
                data = int(item[5:], 16)
        return text, data

    # -- event callbacks ---------------------------------------------------

    def on_stop(self, callback: Callable[[StopInfo], None]) -> None:
        """Register callback for stop events."""
        self._on_stop = callback

    def on_output(self, callback: Callable[[str], None]) -> None:
        """Register callback for target console output."""
        self._on_output = callback


__all__ = [
    "GDBClient",
    "GDBClientError",
    "StopReason",
    "StopInfo",
    "RegisterDef",
    "MemoryRegion",
    "X86_REGS",
    "X86_64_REGS",
]
