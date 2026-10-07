"""Custom Textual widgets for the GDB debugger TUI.

Layer: CLI/fallback/reporting.
Responsibility: render debugger UI state without owning decompiler semantics.

Each widget is a focused, single-responsibility component:
- RegisterWidget: CPU register display with change highlighting
- DisasmWidget: Disassembly listing with current-IP marker
- MemoryWidget: Hex dump viewer
- StackWidget: Stack memory viewer
- BreakpointWidget: Breakpoint list manager
- HelperWidget: current helper/signature metadata
- ConsoleWidget: GDB console output log
"""

from __future__ import annotations

from typing import ClassVar

from textual.reactive import Reactive, reactive
from textual.widgets import Static

# ---------------------------------------------------------------------------
# RegisterWidget
# ---------------------------------------------------------------------------


# Textual supplies the runtime widget base dynamically.
class RegisterWidget(Static):  # type: ignore[misc]
    """Display CPU registers with change highlighting."""

    registers: ClassVar[Reactive[dict[str, int]]] = reactive({})
    _previous: ClassVar[Reactive[dict[str, int]]] = reactive({})

    DEFAULT_CSS: ClassVar[str] = """
    RegisterWidget {
        width: 100%;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    RegisterWidget > .reg-title {
        text-style: bold;
        color: $primary;
    }
    """

    def render(self) -> str:
        """Render the register pane."""
        if not self.registers:
            return "[b]Registers[/b]\n  (no data)"

        lines = ["[b]Registers[/b]"]
        # Group registers
        groups: dict[str, list[str]] = {}
        for name, value in self.registers.items():  # noqa: B007
            group = self._guess_group(name)
            groups.setdefault(group, []).append(name)

        for group in ("general", "segment", "flags", "other"):
            names = groups.get(group)
            if not names:
                continue
            lines.append(f"  [dim]── {group} ──[/dim]")
            for name in sorted(names):
                value = self.registers[name]
                changed = self._previous.get(name) != value
                marker = " *" if changed else "  "
                lines.append(
                    f"  {marker}{name:>8s}: [bold yellow]{value:#010x}[/]"
                    if changed
                    else f"  {marker}{name:>8s}: {value:#010x}"
                )

        return "\n".join(lines)

    def watch_registers(self, new_regs: dict[str, int]) -> None:
        """Track prior registers before Textual updates the reactive value."""
        del new_regs
        self._previous = dict(self.registers)  # type: ignore[misc]
        self.refresh()

    @staticmethod
    def _guess_group(name: str) -> str:
        general = {
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esp",
            "ebp",
            "esi",
            "edi",
            "eip",
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsp",
            "rbp",
            "rsi",
            "rdi",
            "rip",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "ax",
            "bx",
            "cx",
            "dx",
            "sp",
            "bp",
            "si",
            "di",
            "ip",
        }
        segment = {"cs", "ss", "ds", "es", "fs", "gs"}
        flags = {"eflags", "rflags", "flags"}
        if name in general:
            return "general"
        if name in segment:
            return "segment"
        if name in flags:
            return "flags"
        return "other"


# ---------------------------------------------------------------------------
# DisasmWidget
# ---------------------------------------------------------------------------


class DisasmWidget(Static):  # type: ignore[misc]
    """Disassembly listing with current-IP highlight."""

    lines: ClassVar[Reactive[list[tuple[int, str, str]]]] = reactive([])
    current_ip: ClassVar[Reactive[int]] = reactive(0)
    cs: ClassVar[Reactive[int]] = reactive(0)
    addr_size: ClassVar[Reactive[int]] = reactive(2)

    DEFAULT_CSS: ClassVar[str] = """
    DisasmWidget {
        width: 100%;
        height: 100%;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    """

    def render(self) -> str:
        """Render disassembly lines with the current instruction highlighted."""
        if not self.lines:
            return "[b]Disassembly[/b]\n  (no code)"

        # Format strings based on address size
        off_fmt = "{:04x}" if self.addr_size == 2 else "{:08x}"

        out = ["[b]Disassembly[/b]"]
        for addr, mnemonic, operands in self.lines:
            # Calculate offset from CS base for segment:offset display
            offset = addr - (self.cs << 4) if self.cs else addr
            seg_off = f"{self.cs:04x}:{off_fmt.format(offset)}" if self.cs else f"{addr:05x}"
            marker = ">>>" if addr == self.current_ip else "   "
            if addr == self.current_ip:
                out.append(f"  [reverse]{marker} {seg_off}  {mnemonic:<10s} {operands}[/]")
            else:
                out.append(f"  {marker} {seg_off}  {mnemonic:<10s} {operands}")
        return "\n".join(out)


# ---------------------------------------------------------------------------
# MemoryWidget
# ---------------------------------------------------------------------------


class MemoryWidget(Static):  # type: ignore[misc]
    """Hex memory dump viewer."""

    address: ClassVar[Reactive[int]] = reactive(0)
    length: ClassVar[Reactive[int]] = reactive(64)
    dump: ClassVar[Reactive[str]] = reactive("")

    DEFAULT_CSS: ClassVar[str] = """
    MemoryWidget {
        width: 100%;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    """

    def render(self) -> str:
        """Render the current memory dump."""
        lines = [f"[b]Memory  0x{self.address:08x}  ({self.length} bytes)[/b]"]
        if not self.dump:
            lines.append("  (empty)")
        else:
            lines.append(self.dump)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# StackWidget
# ---------------------------------------------------------------------------


class StackWidget(Static):  # type: ignore[misc]
    """Stack memory viewer."""

    esp: ClassVar[Reactive[int]] = reactive(0)
    dump: ClassVar[Reactive[str]] = reactive("")

    DEFAULT_CSS: ClassVar[str] = """
    StackWidget {
        width: 100%;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    """

    def render(self) -> str:
        """Render the current stack dump."""
        lines = [f"[b]Stack  ESP=0x{self.esp:08x}[/b]"]
        if not self.dump:
            lines.append("  (empty)")
        else:
            lines.append(self.dump)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# BreakpointWidget
# ---------------------------------------------------------------------------


class BreakpointWidget(Static):  # type: ignore[misc]
    """Breakpoint list."""

    breakpoints: ClassVar[Reactive[dict[int, dict[str, bool | int]]]] = reactive({})

    DEFAULT_CSS: ClassVar[str] = """
    BreakpointWidget {
        width: 100%;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    """

    def render(self) -> str:
        """Render the active breakpoint list."""
        lines = ["[b]Breakpoints[/b]"]
        if not self.breakpoints:
            lines.append("  (none)")
            return "\n".join(lines)

        for addr, info in sorted(self.breakpoints.items()):
            status = "[green]ON[/green]" if info.get("enabled") else "[red]OFF[/red]"
            hits = info.get("hits", 0)
            lines.append(f"  {status}  0x{addr:08x}  hits={hits}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# HelperWidget
# ---------------------------------------------------------------------------


class HelperWidget(Static):  # type: ignore[misc]
    """Current helper/signature metadata."""

    helper_info: ClassVar[Reactive[dict[str, object]]] = reactive({})

    DEFAULT_CSS: ClassVar[str] = """
    HelperWidget {
        width: 100%;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }
    """

    def render(self) -> str:
        """Render helper metadata for the current instruction."""
        lines = ["[b]Helpers[/b]"]
        if not self.helper_info:
            lines.append("  (no metadata)")
            return "\n".join(lines)

        kind = str(self.helper_info.get("kind", "none"))
        if kind == "none":
            lines.append("  current IP has no helper metadata")
            return "\n".join(lines)

        address = self.helper_info.get("address")
        symbol = self.helper_info.get("symbol") or "(unknown)"
        signature = self.helper_info.get("signature")
        notes_raw = self.helper_info.get("notes")
        notes = notes_raw if isinstance(notes_raw, tuple | list) else ()

        if isinstance(address, int):
            lines.append(f"  addr: 0x{address:08x}")
        lines.append(f"  kind: {kind}")
        lines.append(f"  name: {symbol}")
        if signature:
            lines.append(f"  sig:  {signature}")
        for note in notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# ConsoleWidget
# ---------------------------------------------------------------------------


class ConsoleWidget(Static):  # type: ignore[misc]
    """GDB console output log."""

    output: ClassVar[Reactive[str]] = reactive("")

    DEFAULT_CSS: ClassVar[str] = """
    ConsoleWidget {
        width: 100%;
        height: auto;
        background: $surface-darken-1;
        border: solid $primary;
        padding: 0 1;
    }
    """

    def render(self) -> str:
        """Render the debugger console output."""
        return f"[b]Console[/b]\n{self.output}" if self.output else "[b]Console[/b]\n  (quiet)"


__all__ = [
    "BreakpointWidget",
    "ConsoleWidget",
    "DisasmWidget",
    "HelperWidget",
    "MemoryWidget",
    "RegisterWidget",
    "StackWidget",
]
