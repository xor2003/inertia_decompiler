"""Textual-based debugger for angr x86-16 simulation.

Architecture:
- GDB server: Remote Serial Protocol (RSP) backend, wraps angr SimState
- TUI client: textual-based frontend with panels for:
  - Disassembly/code view
  - Registers (general purpose, segment, flags)
  - Memory/stack inspector
  - Breakpoints and command prompt
  - Variable/local inspection

Commands:
- c/continue: Resume execution
- s/step: Single step (into calls)
- n/next: Step over calls
- b <addr>: Set breakpoint
- d <bp#>: Delete breakpoint
- r: Print registers
- m <addr> [len]: Dump memory
- p <expr>: Print variable/expression
"""

from __future__ import annotations

import socket
import struct
import threading
import json
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import angr
import claripy

from angr_platforms.X86_16.analysis_helpers import preferred_known_helper_signature_decl


class GDBStopReason(Enum):
    """Why the debuggee stopped"""
    TRAP = "S05"  # SIGTRAP (breakpoint/step)
    SEGFAULT = "S11"  # SIGSEGV
    ABRT = "S06"  # SIGABRT
    EXITED = "W00"  # Exited normally


@dataclass
class Breakpoint:
    """Debugger breakpoint"""
    address: int
    enabled: bool = True
    hit_count: int = 0

    def __repr__(self) -> str:
        return f"BP@0x{self.address:05x} (hits={self.hit_count})"


class GDBServer:
    """GDB RSP (Remote Serial Protocol) server wrapping angr SimState.

    DOS environment setup (matching libdosbox behavior):
    - DOS_MEM_START = 0x16f (first segment DOS can use)
    - IVT at 0x0000 (256 vectors * 4 bytes)
    - PSP at segment 0x1000 (Program Segment Prefix, 256 bytes)
    - MCB chain starting at DOS_MEM_START
    - Segment registers: CS=DS=ES=SS=PSP segment
    - Stack at top of available memory

    Implements GDB protocol:
    - Query: qSupported, qXfer, qC, qfThreadInfo, qOffsets, vCont
    - Registers: g (read all), G (write all), p/P (read/write single)
    - Memory: m (read), M (write hex), X (write binary)
    - Execution: c (continue), s (step), ? (status)
    - Breakpoints: Z0/z0 (software), Z1/z1 (hardware)
    """

    # DOSBox-compatible constants
    DOS_MEM_START = 0x16f    # First segment DOS can use
    PSP_SEGMENT = 0x1000     # Default PSP segment
    PSP_SIZE = 0x100         # 256 bytes
    IVT_SIZE = 0x400         # 256 vectors * 4 bytes
    MCB_TYPE_LAST = 0x5a     # Last MCB in chain
    MCB_TYPE_NORMAL = 0x4d   # Normal MCB (more follow)
    MCB_FREE = 0x0000        # Free block

    def __init__(self, project: angr.Project, port: int = 1234, host: str = '127.0.0.1'):
        self.project = project
        self.port = port
        self.host = host
        self.socket = None
        self.client = None
        self.running = False

        # Simulation state
        self.state: Optional[angr.SimState] = None
        self.breakpoints: dict[int, Breakpoint] = {}
        self.b_idx_counter = 0

        # Thread management
        self.current_thread = 1
        self.threads = {1: "angr_main"}

        # DOS environment
        self.psp_segment = self.PSP_SEGMENT
        self.dos_mem_start = self.DOS_MEM_START

    def _helper_name_for_addr(self, addr: int) -> str | None:
        """Return a best-effort helper name for a concrete address."""
        if self.project.is_hooked(addr):
            proc = self.project.hooked_by(addr)
            if proc is not None:
                name = getattr(proc, "INT_NAME", None)
                if isinstance(name, str) and name:
                    return name
                name = getattr(proc, "display_name", None)
                if isinstance(name, str) and name:
                    return name
                return proc.__class__.__name__

        kb = getattr(self.project, "kb", None)
        functions = getattr(kb, "functions", None)
        func = functions.function(addr=addr) if functions is not None else None
        if func is not None:
            name = getattr(func, "name", None)
            if isinstance(name, str) and name:
                return name
        return None

    def _build_helper_info(self) -> dict[str, object]:
        """Build helper metadata for the current execution point."""
        info: dict[str, object] = {
            "address": None,
            "symbol": None,
            "signature": None,
            "kind": "none",
            "notes": [],
        }
        if not self.state:
            return info

        addr = self.state.solver.eval(self.state.regs.ip)
        info["address"] = addr
        helper_name = self._helper_name_for_addr(addr)
        if helper_name is None:
            return info

        signature = preferred_known_helper_signature_decl(helper_name)
        if signature is None and helper_name.startswith("_"):
            signature = preferred_known_helper_signature_decl(helper_name.lstrip("_"))

        info["symbol"] = helper_name
        info["signature"] = signature
        if self.project.is_hooked(addr):
            info["kind"] = "hook"
            info["notes"] = ["execution is inside a hooked helper target"]
        elif signature is not None:
            info["kind"] = "known_helper"
            info["notes"] = ["signature recovered from known helper catalog"]
        else:
            info["kind"] = "function"
            info["notes"] = ["named function at current address"]
        return info

    def start(self) -> None:
        """Start listening for GDB client connections."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.running = True

        print(f"[GDB] Listening on {self.host}:{self.port}")

        # Accept connection in thread
        thread = threading.Thread(target=self._accept_and_serve, daemon=True)
        thread.start()

    def _setup_dos_environment(self, state: angr.SimState) -> None:
        """Set up DOS-like environment matching libdosbox behavior.

        Memory layout (matching DOSBox):
        0x00000-0x003ff: IVT (Interrupt Vector Table, 1KB)
        0x00400-0x004ff: BDA (BIOS Data Area, 256 bytes)
        0x00500-0x016ef: DOS data / free
        0x016f0-...:     MCB chain starts here (DOS_MEM_START << 4)
        0x10000-0x100ff: PSP (Program Segment Prefix, 256 bytes)
        """
        m = state.memory

        # Helper: create concrete bitvectors
        def bv8(val: int) -> claripy.Bits:
            return claripy.BVV(val, 8)

        def bv16(val: int) -> claripy.Bits:
            return claripy.BVV(val, 16)

        def bv32(val: int) -> claripy.Bits:
            return claripy.BVV(val, 32)

        # 1. IVT at 0x0000 (256 vectors, each 4 bytes: offset + segment)
        for vec in range(256):
            vec_addr = vec * 4
            m.store(vec_addr, bv16(0xfff0))       # offset
            m.store(vec_addr + 2, bv16(0xf000))   # segment

        # INT 0x21 (DOS services)
        m.store(0x21 * 4, bv16(0x0000))
        m.store(0x21 * 4 + 2, bv16(0x2000))

        # INT 0x20 (Program terminate)
        m.store(0x20 * 4, bv16(0x0000))
        m.store(0x20 * 4 + 2, bv16(0x2000))

        # 2. BDA (BIOS Data Area) at 0x0400
        m.store(0x0400, bv8(0x00))
        m.store(0x0449, bv8(0x03))
        m.store(0x044a, bv16(0x50))
        m.store(0x044c, bv16(0x19))

        # 3. MCB chain
        mcb_addr = self.dos_mem_start << 4
        m.store(mcb_addr, bv8(ord('M')))
        m.store(mcb_addr + 1, bv16(0x0000))
        mcb_size = self.psp_segment - self.dos_mem_start - 1
        m.store(mcb_addr + 3, bv16(mcb_size))

        psp_mcb_addr = self.psp_segment << 4
        m.store(psp_mcb_addr, bv8(ord('Z')))
        m.store(psp_mcb_addr + 1, bv16(self.psp_segment))
        remaining = 0xA000 - self.psp_segment
        m.store(psp_mcb_addr + 3, bv16(remaining))

        # 4. PSP at PSP_SEGMENT
        psp_addr = self.psp_segment << 4
        m.store(psp_addr, bv8(0xCD))
        m.store(psp_addr + 1, bv8(0x20))
        m.store(psp_addr + 2, bv16(0xFFFF))
        m.store(psp_addr + 5, bv8(0xCB))
        m.store(psp_addr + 0x16, bv16(0x0000))
        for i in range(20):
            m.store(psp_addr + 0x18 + i, bv8(0xFF))
        m.store(psp_addr + 0x2C, bv16(self.psp_segment))
        m.store(psp_addr + 0x2E, bv16(0xFFFE))
        m.store(psp_addr + 0x30, bv16(0x0000))
        m.store(psp_addr + 0x32, bv8(0x14))
        m.store(psp_addr + 0x34, bv32(psp_addr + 0x18))
        m.store(psp_addr + 0x80, bv8(0x00))

        # 5. DOS INT 0x21 handler
        dos_handler_addr = 0x20000
        m.store(dos_handler_addr, bv8(0xCF))

        # 6. Set up segment registers
        state.regs.cs = self.psp_segment
        state.regs.ds = self.psp_segment
        state.regs.es = self.psp_segment
        state.regs.ss = self.psp_segment

        # 7. Set up stack (top of PSP area)
        state.regs.sp = 0xFFFE
        state.regs.ss = self.psp_segment

        # 8. Set up flags (interrupts enabled)
        state.regs.flags = 0x0200  # IF set

        # 9. Clear general purpose registers
        state.regs.ax = 0
        state.regs.bx = 0
        state.regs.cx = 0
        state.regs.dx = 0
        state.regs.si = 0
        state.regs.di = 0
        state.regs.bp = 0

    def _accept_and_serve(self) -> None:
        """Accept client connections and serve GDB protocol."""
        self._initialize_state_if_needed()
        while self.running and self.socket is not None:
            try:
                self.client, addr = self.socket.accept()
                print(f"[GDB] Client connected from {addr}")

                # Send signal (stopped at entry)
                self._send_packet("S05")

                # Command loop
                while self.running and self.client is not None:
                    data = self.client.recv(1024)
                    if not data:
                        break

                    commands = data.decode('utf-8', errors='ignore').strip().split('\n')
                    for cmd in commands:
                        self._handle_command(cmd)

            except OSError:
                break
            except Exception as e:
                print(f"[GDB] Error: {e}")
            finally:
                if self.client is not None:
                    try:
                        self.client.close()
                    except OSError:
                        pass
                    self.client = None

    def _initialize_state_if_needed(self) -> None:
        """Create the initial DOS execution state once."""
        if self.state is not None:
            return

        # For DOS executables, entry is at CS:0100 (COM) or CS:IP from MZ header
        entry = self.project.loader.main_object.entry
        if entry == 0:
            # Blob loader doesn't know entry - default to CS:0100 for COM files
            entry = 0x100

        phys_entry = entry
        self.state = self.project.factory.blank_state(addr=phys_entry)
        self._setup_dos_environment(self.state)

        self.state.regs.cs = self.psp_segment
        self.state.regs.ip = entry & 0xFFFF
        self.state.regs.ss = self.psp_segment
        self.state.regs.sp = 0xFFFE
        self.state.regs.ds = self.psp_segment
        self.state.regs.es = self.psp_segment
        self.state.regs.ax = 0
        self.state.regs.bx = 0
        self.state.regs.cx = 0xFF
        self.state.regs.dx = self.psp_segment
        self.state.regs.si = 0
        self.state.regs.di = 0
        self.state.regs.bp = 0
        self.state.regs.flags = 0x0200

        print(f"[GDB] DOS environment setup: PSP=0x{self.psp_segment:04x}, "
              f"MEM_START=0x{self.dos_mem_start:04x}, "
              f"Entry CS:IP = 0x{self.psp_segment:04x}:0x{entry:04x} "
              f"(phys 0x{phys_entry:x})")

    def _send_packet(self, data: str) -> None:
        """Send GDB RSP packet (with checksum)."""
        if not self.client:
            return

        checksum = sum(ord(c) for c in data) & 0xFF
        packet = f"${data}#{checksum:02x}"
        self.client.sendall(packet.encode())

    def _handle_command(self, cmd: str) -> None:
        """Dispatch GDB RSP command."""
        if not cmd or cmd.startswith('+'):
            return

        if cmd.startswith('$'):
            cmd = cmd[1:].split('#')[0]

        # === Cutter/rizin compatible queries ===
        # qSupported - feature negotiation
        if cmd.startswith('qSupported'):
            self._send_packet(
                "PacketSize=3fff;qXfer:memory-map:read+;"
                "qXfer:features:read+;vContSupported+;"
                "multiprocess-;swbreak+;hwbreak+;"
                "ConditionalBreakpoints+;UnconditionalBreakpoints+;"
                "ExtendedMode+;QStartNoAckMode+"
            )

        # qXfer - extended data transfer
        elif cmd.startswith('qXfer:memory-map:read::'):
            self._send_packet(self._get_memory_map_xml())
        elif cmd.startswith('qXfer:features:read:'):
            self._send_packet(self._get_target_description_xml())
        elif cmd.startswith('qXfer:'):
            self._send_packet("l")  # Empty/unsupported qXfer

        # qAttached - check if attached to existing process
        elif cmd == 'qAttached':
            self._send_packet("0")  # Not attached (we launched it)

        # qTStatus - trace status
        elif cmd == 'qTStatus':
            self._send_packet("")

        # qfThreadInfo / qsThreadInfo - thread list
        elif cmd == 'qfThreadInfo':
            threads_hex = ','.join(f"{tid:x}" for tid in self.threads.keys())
            self._send_packet(f"m{threads_hex}")
        elif cmd == 'qsThreadInfo':
            self._send_packet("l")  # End of list

        # qC - current thread
        elif cmd == 'qC':
            self._send_packet(f"QC{self.current_thread:x}")

        # qOffsets - section offsets
        elif cmd == 'qOffsets':
            self._send_packet("Text=0;Data=0;Bss=0")
        elif cmd == 'qInertiaHelpers':
            self._send_packet(json.dumps(self._build_helper_info(), separators=(",", ":")))

        # qSymbol - symbol lookup (we don't have symbols)
        elif cmd.startswith('qSymbol'):
            self._send_packet("OK")

        # vCont - verbose continue (Cutter uses this)
        elif cmd == 'vCont?':
            self._send_packet("vCont;s;c")
        elif cmd.startswith('vCont'):
            if ':s' in cmd or cmd == 'vCont;s':
                self._handle_step()
            elif ':c' in cmd or cmd == 'vCont;c':
                self._handle_continue()
            else:
                self._handle_continue()  # Default to continue

        # Hg/Hc - thread selection
        elif cmd.startswith('Hg') or cmd.startswith('Hc'):
            self._send_packet("OK")

        # Registers
        elif cmd == 'g':
            self._handle_read_all_registers()
        elif cmd.startswith('p'):
            self._handle_read_register(cmd)
        elif cmd.startswith('P'):
            self._handle_write_register(cmd)

        # Memory
        elif cmd.startswith('m'):
            self._handle_read_memory(cmd)
        elif cmd.startswith('M'):
            self._handle_write_memory(cmd)
        elif cmd.startswith('X'):
            self._handle_write_memory_binary(cmd)

        # Execution
        elif cmd == 'c':
            self._handle_continue()
        elif cmd == 's':
            self._handle_step()
        elif cmd == '?':
            self._send_packet("S05")  # Always stopped for now

        # Breakpoints
        elif cmd.startswith('Z0,') or cmd.startswith('Z1,'):
            self._handle_set_breakpoint(cmd)
        elif cmd.startswith('z0,') or cmd.startswith('z1,'):
            self._handle_remove_breakpoint(cmd)
        elif cmd.startswith('Z') or cmd.startswith('z'):
            self._send_packet("")  # Watchpoints not supported

        # Start no-ack mode
        elif cmd == 'QStartNoAckMode':
            self._send_packet("OK")

        # Fallback
        else:
            self._send_packet("")  # Not supported

    def _handle_read_all_registers(self) -> None:
        """Read all registers (x86-16 format, little-endian byte order)."""
        if not self.state:
            return

        s = self.state
        ev = s.solver.eval

        # x86-16 registers (16-bit names used by 86_16 arch)
        registers = [
            ev(s.regs.ax) & 0xFFFF,   # ax
            ev(s.regs.cx) & 0xFFFF,   # cx
            ev(s.regs.dx) & 0xFFFF,   # dx
            ev(s.regs.bx) & 0xFFFF,   # bx
            ev(s.regs.sp) & 0xFFFF,   # sp
            ev(s.regs.bp) & 0xFFFF,   # bp
            ev(s.regs.si) & 0xFFFF,   # si
            ev(s.regs.di) & 0xFFFF,   # di
            ev(s.regs.ip) & 0xFFFF,   # ip (PC)
            ev(s.regs.flags) & 0xFFFF,  # flags
            ev(s.regs.cs) & 0xFFFF,   # cs
            ev(s.regs.ss) & 0xFFFF,   # ss
            ev(s.regs.ds) & 0xFFFF,   # ds
            ev(s.regs.es) & 0xFFFF,   # es
            ev(s.regs.fs) & 0xFFFF,   # fs
            ev(s.regs.gs) & 0xFFFF,   # gs
        ]

        # GDB RSP uses little-endian byte order
        reg_hex = "".join(struct.pack("<H", r).hex() for r in registers)
        self._send_packet(reg_hex)

    def _handle_read_register(self, cmd: str) -> None:
        """Read single register (little-endian byte order)."""
        try:
            reg_num = int(cmd[1:], 16)
            if not self.state:
                self._send_packet("ffffffff")
                return

            # x86-16 register names (g-packet order)
            reg_names = [
                'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                'ip', 'flags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs',
            ]

            if 0 <= reg_num < len(reg_names):
                val = self.state.solver.eval(getattr(self.state.regs, reg_names[reg_num])) & 0xFFFF
                # Little-endian byte order
                self._send_packet(struct.pack("<H", val).hex())
            else:
                self._send_packet("ffffffff")
        except (ValueError, AttributeError):
            self._send_packet("ffffffff")

    def _handle_read_memory(self, cmd: str) -> None:
        """Read memory: m<addr>,<len>"""
        try:
            parts = cmd[1:].split(',')
            addr = int(parts[0], 16)
            length = int(parts[1], 16)

            if not self.state or length > 1024:
                self._send_packet("")
                return

            data = self.state.memory.load(addr, length)
            # Resolve to concrete bytes
            concrete = self.state.solver.eval(data, cast_to=bytes)
            hex_str = concrete.hex()
            self._send_packet(hex_str)
        except (ValueError, IndexError, Exception):
            self._send_packet("")

    def _handle_write_memory(self, cmd: str) -> None:
        """Write memory: M<addr>,<len>:<data>"""
        try:
            parts = cmd[1:].split(':')
            header = parts[0].split(',')
            addr = int(header[0], 16)
            length = int(header[1], 16)
            data = bytes.fromhex(parts[1])

            if self.state:
                self.state.memory.store(addr, data)
            self._send_packet("OK")
        except (ValueError, IndexError):
            self._send_packet("E00")

    def _handle_continue(self) -> None:
        """Continue execution until breakpoint."""
        if not self.state:
            return

        try:
            # Execute until breakpoint or max steps
            for _ in range(10000):
                ip = self.state.solver.eval(self.state.regs.ip)
                if ip in self.breakpoints:
                    self.breakpoints[ip].hit_count += 1
                    self._send_packet("S05")  # Breakpoint
                    return

                succ = self.project.factory.successors(self.state)
                if succ.successors:
                    self.state = succ.successors[0]
                    ip = self.state.solver.eval(self.state.regs.ip)
                else:
                    break

            # Timeout
            self._send_packet("S05")
        except Exception:
            self._send_packet("S05")

    def _handle_step(self) -> None:
        """Single step instruction (step into)."""
        if not self.state:
            return

        try:
            succ = self.project.factory.successors(self.state, num_inst=1)
            if succ.successors:
                self.state = succ.successors[0]
            self._send_packet("S05")
        except Exception:
            self._send_packet("S05")

    def _handle_step_over(self) -> None:
        """Step over instruction (execute calls without stepping into)."""
        if not self.state:
            return

        try:
            # Get current IP
            ip = self.state.solver.eval(self.state.regs.ip)
            
            # Read instruction at current IP
            mem = self.state.memory.load(ip, 15)
            concrete = self.state.solver.eval(mem, cast_to=bytes)
            
            # Check if it's a call instruction (0xE8 = call rel32, 0xFF/2 = call r/m)
            is_call = False
            insn_len = 0
            
            if concrete[0] == 0xE8:
                # call rel32
                is_call = True
                if len(concrete) >= 5:
                    insn_len = 5
                    next_ip = ip + insn_len
            elif concrete[0] == 0xFF and len(concrete) >= 2:
                # call r/m - check modrm
                modrm = concrete[1]
                if (modrm >> 3) & 0x7 == 2:  # call
                    is_call = True
                    # Approximate length
                    insn_len = 2
                    if (modrm & 0xC0) == 0x00:
                        if (modrm & 0x07) == 0x05:
                            insn_len = 6  # disp32
                        else:
                            insn_len = 2
                    elif (modrm & 0xC0) == 0x40:
                        insn_len = 3  # disp8
                    elif (modrm & 0xC0) == 0x80:
                        insn_len = 6  # disp32
                    else:
                        insn_len = 2
                    next_ip = ip + insn_len
            
            if is_call and insn_len > 0:
                # Set temporary breakpoint at next instruction
                next_ip = ip + insn_len
                self.breakpoints[next_ip] = Breakpoint(next_ip)
                print(f"[GDB] Step over: setting temp BP at 0x{next_ip:x}")
                
                # Continue until breakpoint
                self._handle_continue()
                
                # Remove temporary breakpoint
                self.breakpoints.pop(next_ip, None)
            else:
                # Not a call, just step
                succ = self.project.factory.successors(self.state, num_inst=1)
                if succ.successors:
                    self.state = succ.successors[0]
                self._send_packet("S05")
        except Exception as e:
            print(f"[GDB] Step over error: {e}")
            self._send_packet("S05")

    def _handle_set_breakpoint(self, cmd: str) -> None:
        """Set breakpoint: Z0,<addr>,<kind>"""
        try:
            parts = cmd[2:].split(',')
            addr = int(parts[0], 16)
            bp = Breakpoint(addr)
            self.breakpoints[addr] = bp
            self._send_packet("OK")
        except (ValueError, IndexError):
            self._send_packet("E00")

    def _handle_remove_breakpoint(self, cmd: str) -> None:
        """Remove breakpoint: z0,<addr>,<kind>"""
        try:
            parts = cmd[2:].split(',')
            addr = int(parts[0], 16)
            if addr in self.breakpoints:
                del self.breakpoints[addr]
            self._send_packet("OK")
        except (ValueError, IndexError):
            self._send_packet("E00")

    def _handle_write_register(self, cmd: str) -> None:
        """Write single register: P<regnum>=<value>"""
        try:
            eq_pos = cmd.index('=')
            reg_num = int(cmd[1:eq_pos], 16)
            hex_val = cmd[eq_pos + 1:]
            value = int(hex_val, 16)

            if self.state:
                reg_names = [
                    'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                    'ip', 'flags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs',
                ]
                if 0 <= reg_num < len(reg_names):
                    setattr(self.state.regs, reg_names[reg_num], value)
                    self._send_packet("OK")
                    return
            self._send_packet("E00")
        except (ValueError, IndexError):
            self._send_packet("E00")

    def _handle_write_memory_binary(self, cmd: str) -> None:
        """Write memory binary: X<addr>,<len>:<data>"""
        try:
            colon_pos = cmd.index(':')
            header = cmd[1:colon_pos]
            addr_str, len_str = header.split(',')
            addr = int(addr_str, 16)
            length = int(len_str, 16)
            data = cmd[colon_pos + 1:].encode('latin-1')

            if self.state and len(data) == length:
                self.state.memory.store(addr, data)
                self._send_packet("OK")
            else:
                self._send_packet("E00")
        except (ValueError, IndexError):
            self._send_packet("E00")

    def _get_memory_map_xml(self) -> str:
        """Generate memory map XML for Cutter/rizin."""
        # Get memory size from project
        try:
            mem_size = self.project.loader.main_object.max_addr - self.project.loader.main_object.min_addr
        except Exception:
            mem_size = 0x100000  # Default 1MB for real mode

        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE memory-map PUBLIC '
            '"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN"'
            '"http://sourceware.org/gdb/gdb-memory-map.dtd">'
            '<memory-map>'
            f'<memory type="ram" start="0x0" length="0x{mem_size:x}"/>'
            '</memory-map>'
        )
        return f"l{xml}"

    def _get_target_description_xml(self) -> str:
        """Generate target description XML for Cutter/rizin."""
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE target SYSTEM "gdb-target.dtd">'
            '<target>'
            '<architecture>i8086</architecture>'
            '<feature name="org.gnu.gdb.i386.core">'
            '<reg name="ax" bitsize="16" type="int16"/>'
            '<reg name="cx" bitsize="16" type="int16"/>'
            '<reg name="dx" bitsize="16" type="int16"/>'
            '<reg name="bx" bitsize="16" type="int16"/>'
            '<reg name="sp" bitsize="16" type="int16"/>'
            '<reg name="bp" bitsize="16" type="int16"/>'
            '<reg name="si" bitsize="16" type="int16"/>'
            '<reg name="di" bitsize="16" type="int16"/>'
            '<reg name="ip" bitsize="16" type="code_ptr"/>'
            '<reg name="flags" bitsize="16" type="int16"/>'
            '<reg name="cs" bitsize="16" type="int16"/>'
            '<reg name="ss" bitsize="16" type="int16"/>'
            '<reg name="ds" bitsize="16" type="int16"/>'
            '<reg name="es" bitsize="16" type="int16"/>'
            '<reg name="fs" bitsize="16" type="int16"/>'
            '<reg name="gs" bitsize="16" type="int16"/>'
            '</feature>'
            '</target>'
        )
        return f"l{xml}"

    def stop(self) -> None:
        """Stop the server."""
        self.running = False
        if self.client:
            self.client.close()
        if self.socket:
            self.socket.close()


__all__ = [
    'GDBServer',
    'GDBStopReason',
    'Breakpoint',
]
