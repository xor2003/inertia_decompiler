"""GDB Client TUI – Textual-based debugger frontend.

Connects to a gdbserver / QEMU GDB stub via RSP.

Key bindings (adapted):
    F4      Go to cursor (current IP)
    F5      Redraw screen
    F6      Skip instruction
    F7      Single step (into)
    F8      Step over (proc trace)
    F2      Toggle breakpoint
    F3      Load / restart
    Ctrl+F9 Run
    Ctrl+F2 Reset
    Ctrl+G  Go to address
    Ctrl+S  Search
    Alt+C   Dump CS:IP
    Alt+S   Dump SS:SP
    Alt+D   Dump DS:SI
    Alt+E   Dump ES:DI
    Alt+1-9 Code marks
    Enter   Follow / execute
    Esc     Quit

Usage:
    python -m inertia_decompiler.gdb_tui --host 127.0.0.1 --port 1234
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Header, Input, Label, Static

from inertia_decompiler.gdb_client import GDBClient, GDBClientError, MemoryRegion, StopInfo, StopReason
from inertia_decompiler.tui_widgets import (
    BreakpointWidget,
    ConsoleWidget,
    DisasmWidget,
    HelperWidget,
    MemoryWidget,
    RegisterWidget,
    StackWidget,
)


# ---------------------------------------------------------------------------
# Capstone disassembler
# ---------------------------------------------------------------------------

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_16
except ModuleNotFoundError:
    Cs = None
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = CS_MODE_16 = None

def _make_cs(arch: str) -> Cs:
    """Create a Capstone Cs handle for the given architecture."""
    if Cs is None:
        raise RuntimeError("capstone is not installed")
    if arch == "x86_64":
        return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86_16":
        return Cs(CS_ARCH_X86, CS_MODE_16)
    return Cs(CS_ARCH_X86, CS_MODE_32)


def disasm_x86(data: bytes, addr: int, count: int = 20, arch: str = "x86") -> list[tuple[int, str, str]]:
    """Disassemble with Capstone. Returns [(addr, mnemonic, operands)]."""
    if Cs is None:
        return [
            (addr + index, "db", f"0x{byte:02x}")
            for index, byte in enumerate(data[: max(1, min(count, len(data)))])
        ]
    md = _make_cs(arch)
    md.detail = False
    lines: list[tuple[int, str, str]] = []
    for insn in md.disasm(data, addr, count):
        lines.append((insn.address, insn.mnemonic, insn.op_str))
    return lines


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class GDBTUIApp(App):
    """GDB client TUI – insight.124 inspired layout."""

    CSS = """
    Screen {
        layout: vertical;
    }

    #top-bar {
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }

    #main-area {
        height: 1fr;
        layout: horizontal;
    }

    #left-pane {
        width: 65fr;
        height: 100%;
        layout: vertical;
    }

    #right-pane {
        width: 35fr;
        height: 100%;
        layout: vertical;
    }

    #disasm-container {
        height: 1fr;
    }

    #dump-container {
        height: 6;
    }

    #reg-container {
        height: auto;
    }

    #bp-container {
        height: auto;
    }

    #stack-container {
        height: auto;
    }

    #cmd-input {
        dock: bottom;
        height: 1;
    }

    #status-bar {
        height: 1;
        background: $surface-darken-2;
        padding: 0 1;
    }

    #key-hints {
        height: 2;
        background: $surface-darken-3;
        color: $text-muted;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("f4", "go_to_cursor", "F4 Go to IP"),
        ("f5", "refresh", "F5 Redraw"),
        ("f6", "skip", "F6 Skip"),
        ("f7", "step", "F7 Step"),
        ("f8", "step_over", "F8 StepOver"),
        ("f2", "toggle_bp", "F2 Toggle BP"),
        ("f3", "restart", "F3 Restart"),
        ("ctrl+f9", "run", "Ctrl+F9 Run"),
        ("ctrl+f2", "reset", "Ctrl+F2 Reset"),
        ("ctrl+g", "go_to_addr", "Ctrl+G Go Addr"),
        ("ctrl+s", "search", "Ctrl+S Search"),
        ("escape", "quit", "Esc Quit"),
    ]

    def __init__(self, host: str = "127.0.0.1", port: int = 1234, arch: str = "x86"):
        super().__init__()
        self._host = host
        self._port = port
        self._arch = arch
        self._client: Optional[GDBClient] = None
        self._regs: dict[str, int] = {}
        self._bps: dict[int, dict] = {}
        self._helper_info: dict[str, object] = {}
        self._current_ip: int = 0
        self._mem_addr: int = 0
        self._status: str = "disconnected"
        self._code_marks: dict[str, int] = {}  # Alt+1..9 marks

    # -- compose -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(id="header")
        yield Label(f" GDB TUI  │  {self._host}:{self._port}  │  {self._arch}", id="top-bar")

        with Horizontal(id="main-area"):
            with Vertical(id="left-pane"):
                yield DisasmWidget(id="disasm")
                yield MemoryWidget(id="dump")

            with VerticalScroll(id="right-pane"):
                yield RegisterWidget(id="registers")
                yield BreakpointWidget(id="breakpoints")
                yield HelperWidget(id="helpers")
                yield StackWidget(id="stack")
                yield ConsoleWidget(id="console")

        yield Label("", id="key-hints")
        yield Label("", id="status-bar")
        yield Input(placeholder="F7=step  F8=over  F2=BP  F4=goto  Ctrl+G=addr  Esc=quit", id="cmd-input")
        yield Footer()

    # -- lifecycle ---------------------------------------------------------

    async def on_mount(self) -> None:
        self.title = "GDB TUI"
        self.sub_title = f"{self._host}:{self._port}"
        self._update_key_hints()

        self._client = GDBClient()
        self._client.set_arch(self._arch)
        self._client.on_stop(self._on_stop)
        self._client.on_output(self._on_output)

        try:
            await self._client.connect(self._host, self._port)
            self._status = "connected"
            self._update_status("connected")
        except Exception as e:
            self._status = f"error: {e}"
            self._update_status(f"connect error: {e}")
            return

        await self._refresh_all()

    def on_resize(self) -> None:
        """Handle terminal resize - refresh all widgets."""
        self.refresh()

    # -- key-hint bar ------------------------------------------------------

    def _update_key_hints(self) -> None:
        widget = self.query_one("#key-hints", Label)
        widget.update(
            " F2=BP  F4=GotoIP  F5=Redraw  F6=Skip  F7=Step  F8=Over  "
            "Ctrl+F9=Run  Ctrl+G=Addr  Alt+C/S/D/E=Dump  Esc=Quit"
        )

    # -- key bindings (insight.124 style) ----------------------------------

    def action_step(self) -> None:
        self._action("step", count=1)

    def action_step_over(self) -> None:
        self._action("step_over", count=1)

    def action_go_to_cursor(self) -> None:
        if self._current_ip:
            self._action("refresh", count=1)

    def action_refresh(self) -> None:
        self._action("refresh", count=1)

    def action_skip(self) -> None:
        self._action("skip", count=1)

    def action_toggle_bp(self) -> None:
        if self._current_ip:
            self._toggle_breakpoint(self._current_ip)

    def action_restart(self) -> None:
        self._action("restart", count=1)

    def action_run(self) -> None:
        self._action("continue", count=1)

    def action_reset(self) -> None:
        self._action("reset", count=1)

    def action_go_to_addr(self) -> None:
        self._append_console("Go to address: use 'g <addr>' in command line")

    def action_search(self) -> None:
        self._append_console("Search: use 'm <addr> <len>' to examine memory")

    def action_quit(self) -> None:
        self.exit()

    # -- command input -----------------------------------------------------

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        event.input.clear()
        if not cmd:
            return

        parts = cmd.split()
        action = parts[0].lower()

        if action in ("s", "step", "si"):
            self._action("step", count=self._parse_count(parts))
        elif action in ("n", "next", "ni"):
            self._action("step_over", count=self._parse_count(parts))
        elif action in ("c", "continue", "cont"):
            self._action("continue", count=1)
        elif action in ("i", "interrupt", "int"):
            self._action("interrupt", count=1)
        elif action in ("b", "break", "breakpoint"):
            addr = int(parts[1], 0) if len(parts) >= 2 else self._current_ip
            if addr:
                self._toggle_breakpoint(addr)
        elif action in ("d", "delete"):
            if len(parts) >= 2:
                try:
                    await self._remove_breakpoint(int(parts[1], 0))
                except ValueError:
                    pass
        elif action in ("g", "go"):
            if len(parts) >= 2:
                try:
                    self._mem_addr = int(parts[1], 0)
                    await self._dump_memory(self._mem_addr, 64)
                except ValueError:
                    pass
        elif action in ("m", "mem", "x", "examine"):
            addr = int(parts[1], 0) if len(parts) >= 2 else self._current_ip
            length = int(parts[2], 0) if len(parts) >= 3 else 64
            await self._dump_memory(addr, length)
        elif action in ("r", "reg"):
            if len(parts) >= 2:
                val = self._regs.get(parts[1], 0)
                self._append_console(f"{parts[1]} = 0x{val:x}")
        elif action in ("p", "print", "?"):
            if len(parts) >= 2:
                expr = " ".join(parts[1:])
                try:
                    val = await self._client.read_register(int(expr, 0))
                    self._append_console(f"= 0x{val:x}")
                except (ValueError, GDBClientError):
                    self._append_console(f"Cannot evaluate: {expr}")
        elif action in ("q", "quit", "exit"):
            self.exit()
        elif action in ("h", "help"):
            self._append_console(
                "F7=step  F8=over  F2=BP  F4=gotoIP  F6=skip  "
                "Ctrl+F9=run  Ctrl+G=addr  b <addr>  m <addr> [len]  g <addr>  q=quit"
            )
        else:
            self._append_console(f"Unknown: {action}")

    # -- GDB actions -------------------------------------------------------

    def _action(self, name: str, count: int = 1) -> None:
        asyncio.create_task(self._do_action(name, count=max(1, count)))

    async def _do_action(self, name: str, count: int = 1) -> None:
        if not self._client:
            return
        try:
            if name == "step":
                info = await self._client.step_n(count)
                self._append_console(f"stopped: {info.reason.name}")
            elif name == "step_over":
                info = await self._step_over_n(count)
                self._append_console(f"stopped: {info.reason.name}")
            elif name == "continue":
                self._update_status("running...")
                info = await self._client.continue_()
                self._append_console(f"stopped: {info.reason.name}")
            elif name == "interrupt":
                info = await self._client.interrupt()
                self._append_console(f"interrupted: {info.reason.name}")
            elif name == "skip":
                # Skip: advance IP by one instruction
                await self._skip_instruction()
            elif name == "restart":
                self._append_console("Restart: reconnect")
                await self._client.disconnect()
                await self._client.connect(self._host, self._port)
            elif name == "reset":
                self._append_console("Reset: kill inferior")
                try:
                    await self._client.kill()
                except Exception:
                    pass

            await self._refresh_all()
        except GDBClientError as e:
            self._append_console(f"error: {e}")
            self._update_status("error")
        except Exception as e:
            self._append_console(f"exception: {e}")

    async def _skip_instruction(self) -> None:
        """Skip current instruction by advancing IP."""
        if not self._client or not self._current_ip:
            return
        try:
            mem = await self._client.read_memory(self._current_ip, 15)
            lines = disasm_x86(mem.data, self._current_ip, 1, self._arch)
            if lines:
                next_ip = lines[0][0] + len(mem.data)  # rough estimate
                # Better: decode actual length
                ip_name = "rip" if self._arch == "x86_64" else "eip"
                reg_num = self._client._reg_defs.index(
                    next(r for r in self._client._reg_defs if r.name == ip_name)
                )
                # Just step and let the user handle it
                self._append_console("Skip: use F7 step instead for now")
        except GDBClientError:
            pass

    async def _step_over_n(self, count: int) -> StopInfo:
        info = StopInfo()
        for _ in range(max(1, count)):
            info = await self._step_over_once()
            if info.reason in {StopReason.EXITED, StopReason.SIGNALLED, StopReason.SIGSEGV, StopReason.SIGILL}:
                break
        return info

    async def _step_over_once(self) -> StopInfo:
        if not self._client or not self._current_ip:
            return StopInfo()

        mem = await self._client.read_memory(self._current_ip, 16)
        lines = disasm_x86(mem.data, self._current_ip, 1, self._arch)
        if not lines:
            return await self._client.step()

        addr, mnemonic, _operands = lines[0]
        next_ip = self._instruction_fallthrough(addr, mem.data, mnemonic, self._arch)
        if next_ip is None or not self._looks_like_call(mnemonic):
            return await self._client.step()

        had_existing_breakpoint = next_ip in self._bps
        if not had_existing_breakpoint:
            await self._client.insert_breakpoint(next_ip)
        try:
            return await self._client.continue_()
        finally:
            if not had_existing_breakpoint:
                try:
                    await self._client.remove_breakpoint(next_ip)
                except GDBClientError:
                    pass

    @staticmethod
    def _parse_count(parts: list[str]) -> int:
        if len(parts) < 2:
            return 1
        try:
            return max(1, int(parts[1], 0))
        except ValueError:
            return 1

    @staticmethod
    def _looks_like_call(mnemonic: str) -> bool:
        return mnemonic.lower().startswith(("call", "lcall"))

    @staticmethod
    def _instruction_fallthrough(addr: int, raw: bytes, mnemonic: str, arch: str) -> int | None:
        if not raw:
            return None
        op = mnemonic.lower()
        first = raw[0]
        if op.startswith(("call", "jmp", "ret", "iret")):
            if op.startswith("call"):
                pass
            else:
                return None

        if first == 0xE8:
            size = 3 if arch == "x86_16" else 5
            if len(raw) >= size:
                return addr + size
            return None
        if first == 0x9A and len(raw) >= 5:
            return addr + 5
        if first == 0xFF and len(raw) >= 2:
            modrm = raw[1]
            reg = (modrm >> 3) & 0x7
            if reg not in (2, 3):
                return None
            length = 2
            mod = (modrm >> 6) & 0x3
            rm = modrm & 0x7
            if mod != 3 and rm == 4:
                if len(raw) < 3:
                    return None
                sib = raw[2]
                length += 1
                base = sib & 0x7
                if mod == 0 and base == 5:
                    length += 4
            if mod == 0 and rm == 6 and len(raw) >= length + 2:
                length += 2
            elif mod == 1 and len(raw) >= length + 1:
                length += 1
            elif mod == 2 and len(raw) >= length + 4:
                length += 4
            return addr + length

        return None

    # -- breakpoints -------------------------------------------------------

    def _toggle_breakpoint(self, addr: int) -> None:
        if addr in self._bps:
            asyncio.create_task(self._remove_breakpoint(addr))
        else:
            self._bps[addr] = {"enabled": True, "hits": 0}
            asyncio.create_task(self._insert_breakpoint(addr))
        self._refresh_breakpoints()

    async def _insert_breakpoint(self, addr: int) -> None:
        if self._client:
            try:
                await self._client.insert_breakpoint(addr)
            except GDBClientError:
                pass

    async def _remove_breakpoint(self, addr: int) -> None:
        if self._client:
            try:
                await self._client.remove_breakpoint(addr)
            except GDBClientError:
                pass
        self._bps.pop(addr, None)
        self._refresh_breakpoints()

    # -- refresh -----------------------------------------------------------

    async def _refresh_all(self) -> None:
        if not self._client:
            return
        try:
            await self._refresh_registers()
            await self._refresh_disasm()
            await self._refresh_stack()
            await self._refresh_memory()
            await self._refresh_helpers()
        except Exception as e:
            self._append_console(f"refresh error: {e}")

    async def _refresh_registers(self) -> None:
        if not self._client:
            return
        regs = await self._client.read_registers()
        self._regs = regs
        widget = self.query_one("#registers", RegisterWidget)
        widget.registers = regs
        # x86-16 uses 'ip', x86_64 uses 'rip'
        ip_name = "rip" if self._arch == "x86_64" else ("ip" if self._arch == "x86_16" else "eip")
        self._current_ip = regs.get(ip_name, 0)

    async def _refresh_disasm(self) -> None:
        if not self._client or not self._current_ip:
            return
        try:
            mem = await self._client.read_memory(self._current_ip, 80)
            lines = disasm_x86(mem.data, self._current_ip, 20, self._arch)
            widget = self.query_one("#disasm", DisasmWidget)
            widget.lines = lines
            widget.current_ip = self._current_ip
            widget.addr_size = 2 if self._arch == "x86_16" else 4
            # Set CS segment for CS:offset display
            cs_name = "cs"
            widget.cs = self._regs.get(cs_name, 0)
        except GDBClientError:
            pass

    async def _refresh_stack(self) -> None:
        if not self._client:
            return
        if self._arch == "x86_64":
            sp_name = "rsp"
        elif self._arch == "x86_16":
            sp_name = "sp"
        else:
            sp_name = "esp"
        esp = self._regs.get(sp_name, 0)
        if not esp:
            return
        try:
            mem = await self._client.read_memory(esp, 128)
            widget = self.query_one("#stack", StackWidget)
            widget.esp = esp
            widget.dump = mem.hexdump()
        except GDBClientError:
            pass

    async def _refresh_memory(self) -> None:
        if not self._client:
            return
        addr = self._mem_addr or self._current_ip
        if not addr:
            return
        try:
            mem = await self._client.read_memory(addr, 64)
            widget = self.query_one("#dump", MemoryWidget)
            widget.address = addr
            widget.dump = mem.hexdump()
        except GDBClientError:
            pass

    def _refresh_breakpoints(self) -> None:
        widget = self.query_one("#breakpoints", BreakpointWidget)
        widget.breakpoints = dict(self._bps)

    async def _refresh_helpers(self) -> None:
        if not self._client:
            return
        try:
            self._helper_info = await self._client.query_helper_info()
        except GDBClientError as e:
            self._helper_info = {"kind": "none", "notes": [f"helper metadata unavailable: {e}"]}
        widget = self.query_one("#helpers", HelperWidget)
        widget.helper_info = dict(self._helper_info)

    # -- callbacks ---------------------------------------------------------

    def _on_stop(self, info: StopInfo) -> None:
        self._append_console(f"stopped: {info.reason.name} (sig={info.signal:#04x})")
        self._update_status(f"stopped: {info.reason.name}")

    def _on_output(self, text: str) -> None:
        self._append_console(text.rstrip())

    # -- console / status --------------------------------------------------

    def _append_console(self, text: str) -> None:
        widget = self.query_one("#console", ConsoleWidget)
        widget.output = (widget.output + "\n" + text).strip()

    def _update_status(self, text: str) -> None:
        self._status = text
        widget = self.query_one("#status-bar", Label)
        widget.update(f"  {text}")

    async def _dump_memory(self, addr: int, length: int) -> None:
        self._mem_addr = addr
        if self._client:
            try:
                mem = await self._client.read_memory(addr, length)
                widget = self.query_one("#dump", MemoryWidget)
                widget.address = addr
                widget.length = length
                widget.dump = mem.hexdump()
                self._append_console(f"memory 0x{addr:x} ({length} bytes):")
                self._append_console(mem.hexdump())
            except GDBClientError as e:
                self._append_console(f"memory error: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="GDB Client TUI (insight.124 inspired)")
    parser.add_argument("--host", default="127.0.0.1", help="GDB server host")
    parser.add_argument("--port", type=int, default=1234, help="GDB server port")
    parser.add_argument("--arch", choices=["x86_16", "x86", "x86_64"], default="x86_16", help="Target architecture")
    args = parser.parse_args()

    app = GDBTUIApp(host=args.host, port=args.port, arch=args.arch)
    app.run()


if __name__ == "__main__":
    main()
