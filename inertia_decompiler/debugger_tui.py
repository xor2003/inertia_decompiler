"""Textual-based TUI debugger client for angr GDB server.

Similar to insight.124/src and Spice86 debuggers.
Uses textual library for UI components:
- Code/disassembly pane (top-left)
- Registers pane (top-right)
- Stack/memory pane (bottom-left)
- Command prompt (bottom)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TextArea,
)


class RegisterPane(Static):
    """Display CPU registers (general purpose, segment, flags)."""

    registers = reactive({})

    def render(self) -> str:
        """Render register display."""
        if not self.registers:
            return "No registers loaded"

        lines = ["╔════ REGISTERS ════╗"]
        lines.append(f"  EAX: {self.registers.get('eax', 0):08x}")
        lines.append(f"  EBX: {self.registers.get('ebx', 0):08x}")
        lines.append(f"  ECX: {self.registers.get('ecx', 0):08x}")
        lines.append(f"  EDX: {self.registers.get('edx', 0):08x}")
        lines.append("")
        lines.append(f"  ESP: {self.registers.get('esp', 0):08x}")
        lines.append(f"  EBP: {self.registers.get('ebp', 0):08x}")
        lines.append(f"  ESI: {self.registers.get('esi', 0):08x}")
        lines.append(f"  EDI: {self.registers.get('edi', 0):08x}")
        lines.append("")
        lines.append(f"  EIP: {self.registers.get('eip', 0):08x}")
        lines.append(f"  EFL: {self.registers.get('eflags', 0):04x}")
        lines.append("")
        lines.append(f"  CS: {self.registers.get('cs', 0):04x}")
        lines.append(f"  SS: {self.registers.get('ss', 0):04x}")
        lines.append(f"  DS: {self.registers.get('ds', 0):04x}")
        lines.append(f"  ES: {self.registers.get('es', 0):04x}")
        lines.append("╚═══════════════════╝")

        return "\n".join(lines)


class BreakpointPane(Static):
    """Display active breakpoints."""

    breakpoints = reactive([])

    def render(self) -> str:
        """Render breakpoint list."""
        if not self.breakpoints:
            return "╔════ BREAKPOINTS ════╗\n(none)\n╚════════════════════╝"

        lines = ["╔════ BREAKPOINTS ════╗"]
        for i, bp in enumerate(self.breakpoints, 1):
            status = "✓" if bp.get('enabled') else "✗"
            lines.append(f"  {i}: {status} @0x{bp.get('addr', 0):05x} (hits={bp.get('hits', 0)})")
        lines.append("╚════════════════════╝")

        return "\n".join(lines)


class MemoryPane(Static):
    """Display memory/stack contents."""

    memory_dump = reactive("")

    def render(self) -> str:
        """Render memory dump."""
        if not self.memory_dump:
            return "╔════ MEMORY VIEW ════╗\n(select address)\n╚════════════════════╝"

        return self.memory_dump


class StackPane(Static):
    """Display stack contents."""

    stack_data = reactive([])

    def render(self) -> str:
        """Render stack."""
        if not self.stack_data:
            return "╔════ STACK ════╗\n(empty)\n╚═══════════════╝"

        lines = ["╔════ STACK ════╗"]
        for addr, value in self.stack_data[:8]:
            lines.append(f"  0x{addr:05x}: {value:08x}")
        lines.append("╚═══════════════╝")

        return "\n".join(lines)


class DisassemblyPane(Static):
    """Display disassembled code."""

    disassembly = reactive("")
    current_ip = reactive(0)

    def render(self) -> str:
        """Render disassembly with current instruction highlighted."""
        if not self.disassembly:
            return "╔════ CODE ════╗\n(no code loaded)\n╚══════════════╝"

        lines = ["╔════ CODE ════╗"]
        for line in self.disassembly.split('\n')[:15]:
            # Highlight current instruction
            if f"0x{self.current_ip:05x}" in line:
                lines.append(f"→ {line}")
            else:
                lines.append(f"  {line}")
        lines.append("╚══════════════╝")

        return "\n".join(lines)


class DebuggerTUI(Static):
    """Main debugger TUI layout."""

    def compose(self) -> ComposeResult:
        """Compose TUI layout."""
        with Horizontal():
            with Vertical():
                yield DisassemblyPane(id="disasm")
                yield Label("Press 's' to step, 'c' to continue, 'b <addr>' to break")
            with Vertical():
                yield RegisterPane(id="registers")
                yield BreakpointPane(id="breakpoints")

        yield MemoryPane(id="memory")
        yield StackPane(id="stack")
        yield Input(placeholder="Command: s/c/n/b <addr>/p <expr>/r/m <addr>/d <bp#>", id="cmd")


class DebuggerApp:
    """Main debugger application.
    
    Usage:
        app = DebuggerApp(project, gdb_port=1234)
        app.run()
    """

    def __init__(self, project=None, gdb_port: int = 1234, gdb_host: str = '127.0.0.1'):
        """Initialize debugger.
        
        Args:
            project: angr project
            gdb_port: GDB server port
            gdb_host: GDB server host
        """
        self.project = project
        self.gdb_port = gdb_port
        self.gdb_host = gdb_host

        # GDB server (to be created when needed)
        self.gdb_server = None

        # UI state
        self.registers = {}
        self.breakpoints = []
        self.disassembly = ""
        self.memory_dump = ""
        self.stack_data = []
        self.current_ip = 0

    def start_gdb_server(self) -> None:
        """Start the GDB RSP server."""
        if not self.project:
            print("No project loaded")
            return

        from inertia_decompiler.debugger_gdb import GDBServer

        self.gdb_server = GDBServer(self.project, port=self.gdb_port, host=self.gdb_host)
        self.gdb_server.start()
        print(f"[TUI] GDB server started on {self.gdb_host}:{self.gdb_port}")
        print("[TUI] Connect with: gdb -ex 'target remote localhost:1234'")

    def run(self) -> None:
        """Run the debugger application (placeholder for full Textual app)."""
        print("[TUI] Debugger initialized")
        print(f"[TUI] Create textual.app.App subclass to render full UI")
        print(f"[TUI] GDB server ready on {self.gdb_host}:{self.gdb_port}")


__all__ = [
    'DebuggerApp',
    'DebuggerTUI',
    'RegisterPane',
    'DisassemblyPane',
    'MemoryPane',
    'StackPane',
    'BreakpointPane',
]
