"""Layer: Frontend/runtime.

Responsibility: execute instruction side effects against emulator state during lifting.
Forbidden: decompiler semantic repair, alias/type recovery, or rendered-C rewrite.
"""

from __future__ import annotations

from typing import cast

from inertia.frontend.x86_16.regs import sgreg_t
from inertia.frontend.x86_16.stack_helpers import (
    StackEmulator,
    pop_far_return_frame16,
    pop_far_return_frame32,
    push_far_return_frame16,
    push_far_return_frame32,
    push_privilege_stack32,
    return_interrupt16,
    return_interrupt32,
)

from .emulator import Emulator
from .exception import EXP_GP
from .instruction import InstrData, X86Instruction


class EmuInstr(X86Instruction):
    """Execute far control-transfer helper effects through shared stack helpers."""

    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool) -> None:
        """Initialize an emulator instruction helper for one decoded instruction."""
        super().__init__(emu, instr, mode32)

    def type_descriptor(self, _instr: dict[str, object], _sel: int) -> int:
        """Return a selector type descriptor when protected-mode support exists."""
        raise NotImplementedError

    def set_ldtr(self, _sel: int) -> None:
        """Set LDTR when protected-mode support exists."""
        raise NotImplementedError

    def set_tr(self, _sel: int) -> None:
        """Set TR when protected-mode task support exists."""
        raise NotImplementedError

    def switch_task(self, _sel: int) -> None:
        """Switch task state when protected-mode task support exists."""
        raise NotImplementedError

    def jmpf(self, _instr: dict[str, object], sel: int, eip: int) -> None:
        """Jump to a far code segment and instruction pointer."""
        self.emu.set_segment(sgreg_t.CS, sel)
        self.emu.set_eip(eip)

    def callf(self, _instr: dict[str, object], sel: int, eip: int, return_ip: object | None = None) -> None:
        """Push a far return frame and transfer to a far call target."""
        cs = cast(int, self.emu.get_segment(sgreg_t.CS))
        rpl = sel & 3
        cpl = cs & 3

        if cpl != rpl:
            if rpl < cpl:
                raise Exception(EXP_GP)
            push_privilege_stack32(cast(StackEmulator, self.emu))

        if self.mode32:
            push_far_return_frame32(cast(StackEmulator, self.emu), return_ip)
        else:
            push_far_return_frame16(cast(StackEmulator, self.emu), return_ip)

        self.emu.set_segment(sgreg_t.CS, sel)
        self.emu.set_eip(eip)

    def retf(self, _instr: dict[str, object]) -> None:
        """Pop a far return frame and restore CS:IP/EIP."""
        if self.mode32:
            eip, cs = pop_far_return_frame32(cast(StackEmulator, self.emu))
            self.emu.set_segment(sgreg_t.CS, cs)
            self.emu.set_eip(eip)
        else:
            ip, cs = pop_far_return_frame16(cast(StackEmulator, self.emu))
            self.emu.set_segment(sgreg_t.CS, cs)
            self.emu.set_ip(ip)

    def iret(self, _instr: dict[str, object]) -> None:
        """Pop an interrupt return frame and restore flags plus CS:IP/EIP."""
        if self.mode32:
            return_interrupt32(cast(StackEmulator, self.emu))
        else:
            return_interrupt16(cast(StackEmulator, self.emu))

    def chk_ring(self, _dpl: int) -> bool:
        """Return whether the current privilege level permits an operation."""
        raise NotImplementedError
