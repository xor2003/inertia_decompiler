"""Layer: Frontend/runtime.

Responsibility: register the 16-bit SimOS, calling conventions, and interrupt procedures.
Forbidden: decompiler semantic recovery, source-backed signatures, or rewrite ownership.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, cast

import claripy
from angr import Project, SimProcedure
from angr.calling_conventions import (
    SimCC,
    SimRegArg,
    SimStackArg,
    register_default_cc,
    register_syscall_cc,
)
from angr.simos import SimOS, register_simos
from claripy.ast.bv import BV

from .arch_86_16 import Arch86_16
from .interrupt_contract import (
    INTERRUPT_CORE_VECTOR_BASE,
    INTERRUPT_CORE_VECTOR_COUNT,
    interrupt_core_addr_8616,
)

__all__ = (
    "INTERRUPT_BASE_ADDR",
    "INTERRUPT_VECTOR_COUNT",
    "BIOSInt12MemorySize",
    "DOSInt21",
    "InterruptHandler",
    "SimCC8616MSC",
    "SimCC8616MSCmedium",
    "SimCC8616MSCsmall",
    "SimDOS86_16",
    "SimDOSintcall",
    "get_interrupt_handler_class",
    "interrupt_addr",
    "runtime_interrupt_addr",
)

INTERRUPT_BASE_ADDR: int = INTERRUPT_CORE_VECTOR_BASE
INTERRUPT_VECTOR_COUNT: int = INTERRUPT_CORE_VECTOR_COUNT


def interrupt_addr(vector: int) -> int:
    """Return the synthetic linear interrupt target used by the DOS SimOS."""
    return int(interrupt_core_addr_8616(vector & 0xFF))


def runtime_interrupt_addr(vector: int) -> int:
    """Return the 16-bit wrapped interrupt target used by lifted real-mode code."""
    return interrupt_addr(vector) & 0xFFFF


class InterruptHandler(SimProcedure):  # type: ignore[misc, unused-ignore] # dynamic angr SimProcedure base
    """Base symbolic interrupt handler for DOS/BIOS interrupt vectors."""

    INT_VECTOR: ClassVar[int | None] = None
    INT_NAME: ClassVar[str] = "interrupt"
    IS_BIOS: ClassVar[bool] = False
    IS_DOS: ClassVar[bool] = False
    NO_RET: ClassVar[bool] = False

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Return a symbolic AX value for unmodeled interrupt behavior."""
        return claripy.BVS(f"{self.INT_NAME}_ax", 16, explicit_name=True)


class _SyscallRegs(Protocol):
    """Minimal register file surface for syscall-number lookup."""

    ax: object


class _SyscallState(Protocol):
    """Minimal angr state surface used for synthetic DOS syscall dispatch."""

    regs: _SyscallRegs


class BIOSInterruptHandler(InterruptHandler):
    """Base class for BIOS interrupt handlers."""

    IS_BIOS: ClassVar[bool] = True


class DOSInterruptHandler(InterruptHandler):
    """Base class for DOS interrupt handlers."""

    IS_DOS: ClassVar[bool] = True


class BIOSInt10Video(BIOSInterruptHandler):
    """BIOS video interrupt handler with minimal text-output semantics."""

    INT_VECTOR: ClassVar[int] = 0x10
    INT_NAME: ClassVar[str] = "bios_int10_video"

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Handle modeled text output or return symbolic AX."""
        ah = self.state.regs.ah
        # Common text-mode services can be treated as pure side-effect stubs.
        if self.state.solver.is_true(ah == 0x0E):
            return claripy.ZeroExt(8, cast(BV, self.state.regs.al))
        return claripy.BVS("bios_int10_ax", 16, explicit_name=True)


class BIOSInt11Equipment(BIOSInterruptHandler):
    """BIOS equipment-list interrupt handler."""

    INT_VECTOR: ClassVar[int] = 0x11
    INT_NAME: ClassVar[str] = "bios_int11_equipment"

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Return a deterministic empty equipment bitmask."""
        self.state.regs.ax = claripy.BVV(0, 16)
        return self.state.regs.ax


class BIOSInt12MemorySize(BIOSInterruptHandler):
    """BIOS conventional-memory-size interrupt handler."""

    INT_VECTOR: ClassVar[int] = 0x12
    INT_NAME: ClassVar[str] = "bios_int12_memory_size"

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Return the conventional 640 KiB memory size."""
        # Conventional memory size in KiB.
        self.state.regs.ax = claripy.BVV(640, 16)
        return self.state.regs.ax


class BIOSInt13Disk(BIOSInterruptHandler):
    """BIOS disk interrupt symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x13
    INT_NAME: ClassVar[str] = "bios_int13_disk"


class BIOSInt14Serial(BIOSInterruptHandler):
    """BIOS serial-port interrupt symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x14
    INT_NAME: ClassVar[str] = "bios_int14_serial"


class BIOSInt15System(BIOSInterruptHandler):
    """BIOS system-services interrupt symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x15
    INT_NAME: ClassVar[str] = "bios_int15_system"


class BIOSInt16Keyboard(BIOSInterruptHandler):
    """BIOS keyboard interrupt handler with minimal read-key semantics."""

    INT_VECTOR: ClassVar[int] = 0x16
    INT_NAME: ClassVar[str] = "bios_int16_keyboard"

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Return deterministic no-key data for function 00h or symbolic AX."""
        ah = self.state.regs.ah
        if self.state.solver.is_true(ah == 0x00):
            self.state.regs.ax = claripy.BVV(0, 16)
            return self.state.regs.ax
        return claripy.BVS("bios_int16_ax", 16, explicit_name=True)


class BIOSInt17Printer(BIOSInterruptHandler):
    """BIOS printer interrupt symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x17
    INT_NAME: ClassVar[str] = "bios_int17_printer"


class BIOSInt1AClock(BIOSInterruptHandler):
    """BIOS clock interrupt handler with deterministic tick query behavior."""

    INT_VECTOR: ClassVar[int] = 0x1A
    INT_NAME: ClassVar[str] = "bios_int1a_clock"

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Return zeroed clock registers for function 00h or symbolic AX."""
        ah = self.state.regs.ah
        if self.state.solver.is_true(ah == 0x00):
            self.state.regs.ax = claripy.BVV(0, 16)
            self.state.regs.cx = claripy.BVV(0, 16)
            self.state.regs.dx = claripy.BVV(0, 16)
            return self.state.regs.ax
        return claripy.BVS("bios_int1a_ax", 16, explicit_name=True)


class DOSInt20Terminate(DOSInterruptHandler):
    """DOS terminate-program interrupt handler."""

    INT_VECTOR: ClassVar[int] = 0x20
    INT_NAME: ClassVar[str] = "dos_int20_terminate"
    NO_RET: ClassVar[bool] = True

    def run(self) -> None:  # pylint:disable=arguments-differ
        """Exit the simulated process with status 0."""
        self.exit(0)


class DOSInt21(DOSInterruptHandler):
    """DOS API interrupt handler for a small modeled service subset."""

    INT_VECTOR: ClassVar[int] = 0x21
    INT_NAME: ClassVar[str] = "dos_int21"

    def run(self) -> object:  # pylint:disable=arguments-differ
        """Handle modeled DOS services or return symbolic AX."""
        ah = self.state.regs.ah

        if self.state.solver.is_true(ah == 0x09):
            self.state.regs.al = claripy.BVV(ord("$"), 8)
            return claripy.BVV(ord("$"), 16)

        if self.state.solver.is_true(ah == 0x19):
            self.state.regs.al = claripy.BVV(2, 8)
            return claripy.BVV(2, 16)

        if self.state.solver.is_true(ah == 0x30):
            self.state.regs.al = claripy.BVV(5, 8)
            self.state.regs.ah = claripy.BVV(0, 8)
            return claripy.BVV(0x0005, 16)

        if self.state.solver.is_true(ah == 0x35):
            self.state.regs.es = claripy.BVV(0, 16)
            self.state.regs.bx = claripy.BVV(0, 16)
            self.state.regs.ax = claripy.BVV(0, 16)
            return self.state.regs.ax

        if self.state.solver.is_true(ah == 0x25):
            self.state.regs.ax = claripy.BVV(0, 16)
            return self.state.regs.ax

        if self.state.solver.is_true(ah == 0x4C):
            self.exit(claripy.ZeroExt(8, cast(BV, self.state.regs.al)))

        carry = claripy.BVS("dos_int21_cf", 1, explicit_name=True)
        flags = cast(BV, self.state.regs.flags)
        flags_width = flags.size()
        self.state.regs.flags = (
            flags & claripy.BVV((1 << flags_width) - 2, flags_width)
        ) | claripy.ZeroExt(flags_width - 1, carry)
        return claripy.BVS("dos_int21_ax", 16, explicit_name=True)


class DOSInt25AbsoluteDiskRead(DOSInterruptHandler):
    """DOS absolute disk read symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x25
    INT_NAME: ClassVar[str] = "dos_int25_abs_disk_read"


class DOSInt26AbsoluteDiskWrite(DOSInterruptHandler):
    """DOS absolute disk write symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x26
    INT_NAME: ClassVar[str] = "dos_int26_abs_disk_write"


class DOSInt27TerminateStayResident(DOSInterruptHandler):
    """DOS terminate-and-stay-resident interrupt handler."""

    INT_VECTOR: ClassVar[int] = 0x27
    INT_NAME: ClassVar[str] = "dos_int27_tsr"
    NO_RET: ClassVar[bool] = True

    def run(self) -> None:  # pylint:disable=arguments-differ
        """Exit the simulated process with status 0."""
        self.exit(0)


class DOSInt2FMultiplex(DOSInterruptHandler):
    """DOS multiplex interrupt symbolic handler."""

    INT_VECTOR: ClassVar[int] = 0x2F
    INT_NAME: ClassVar[str] = "dos_int2f_multiplex"


def _generic_interrupt_class(vector: int) -> type[InterruptHandler]:
    """Build a generic interrupt handler class for an unmodeled vector."""
    category = "bios" if 0x10 <= vector <= 0x1F else "dos" if 0x20 <= vector <= 0x2F else "interrupt"
    base = (
        BIOSInterruptHandler if category == "bios" else DOSInterruptHandler if category == "dos" else InterruptHandler
    )
    return cast(type[InterruptHandler], type(
        f"Interrupt{vector:02X}",
        (base,),
        {
            "INT_VECTOR": vector,
            "INT_NAME": f"{category}_int{vector:02x}",
        },
    ))


_HANDLER_CLASSES: dict[int, type[InterruptHandler]] = {
    cls.INT_VECTOR: cls
    for cls in (
        BIOSInt10Video,
        BIOSInt11Equipment,
        BIOSInt12MemorySize,
        BIOSInt13Disk,
        BIOSInt14Serial,
        BIOSInt15System,
        BIOSInt16Keyboard,
        BIOSInt17Printer,
        BIOSInt1AClock,
        DOSInt20Terminate,
        DOSInt21,
        DOSInt25AbsoluteDiskRead,
        DOSInt26AbsoluteDiskWrite,
        DOSInt27TerminateStayResident,
        DOSInt2FMultiplex,
    )
}


def get_interrupt_handler_class(vector: int) -> type[InterruptHandler]:
    """Return the concrete or generic handler class for an interrupt vector."""
    vector &= 0xFF
    return _HANDLER_CLASSES.setdefault(vector, _generic_interrupt_class(vector))


class SimDOSintcall(SimCC):  # type: ignore[misc, unused-ignore] # dynamic angr calling-convention base
    """Synthetic DOS interrupt calling convention."""

    ARG_REGS: ClassVar[list[str]] = ["ax", "bx", "cx", "dx"]
    RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("ax", 2)
    ARCH: ClassVar[type[Arch86_16]] = Arch86_16

    @staticmethod
    def _match(arch: object, args: list[object], sp_delta: object) -> bool:  # pylint: disable=unused-argument
        """Disable automatic matching; this convention is registered explicitly."""
        return False

    @staticmethod
    def syscall_num(state: _SyscallState) -> object:
        """Return AX as the synthetic syscall selector."""
        return state.regs.ax


class SimDOS86_16(SimOS):  # type: ignore[misc, unused-ignore] # dynamic angr SimOS base
    """DOS SimOS that hooks every real-mode interrupt vector."""

    def __init__(self, project: Project, **kwargs: object) -> None:
        """Initialize the DOS SimOS with angr's third-party project object."""
        super().__init__(project, name="DOS", **kwargs)

    def configure_project(self) -> None:
        """Install concrete and wrapped interrupt hooks into the project."""
        super().configure_project()
        for vector in range(INTERRUPT_VECTOR_COUNT):
            handler_cls = get_interrupt_handler_class(vector)
            self.project.hook(interrupt_addr(vector), handler_cls(), replace=True)
            runtime_addr = runtime_interrupt_addr(vector)
            if runtime_addr != interrupt_addr(vector):
                self.project.hook(runtime_addr, handler_cls(), replace=True)


class SimCC8616MSCsmall(SimCC):  # type: ignore[misc, unused-ignore] # dynamic angr calling-convention base
    """Microsoft C small-model 16-bit caller-cleanup convention."""

    ARG_REGS: ClassVar[list[str]] = []
    FP_ARG_REGS: ClassVar[list[str]] = []
    STACKARG_SP_DIFF: ClassVar[int] = 2
    RETURN_ADDR: ClassVar[SimStackArg] = SimStackArg(0, 2)
    RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("dx", 2)
    ARCH: ClassVar[type[Arch86_16]] = Arch86_16
    STACK_ALIGNMENT: ClassVar[int] = 2
    CALLEE_CLEANUP: ClassVar[bool] = False


class SimCC8616MSCmedium(SimCC):  # type: ignore[misc, unused-ignore] # dynamic angr calling-convention base
    """Microsoft C medium-model 16-bit caller-cleanup convention."""

    ARG_REGS: ClassVar[list[str]] = []
    FP_ARG_REGS: ClassVar[list[str]] = []
    STACKARG_SP_DIFF: ClassVar[int] = 2
    RETURN_ADDR: ClassVar[SimStackArg] = SimStackArg(0, 2)
    RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("dx", 2)
    ARCH: ClassVar[type[Arch86_16]] = Arch86_16
    STACK_ALIGNMENT: ClassVar[int] = 2
    CALLEE_CLEANUP: ClassVar[bool] = False


class SimCC8616MSClarge(SimCC):  # type: ignore[misc, unused-ignore] # dynamic angr calling-convention base
    """Microsoft C far-function 16-bit caller-cleanup convention.

    A ``retf`` frame pushes a four-byte return address (IP then CS), so the
    first stack argument sits two bytes deeper than the near frame: ``SP+4`` at
    entry, ``BP+6`` after the prologue, instead of ``SP+2``/``BP+4``.
    """

    ARG_REGS: ClassVar[list[str]] = []
    FP_ARG_REGS: ClassVar[list[str]] = []
    STACKARG_SP_DIFF: ClassVar[int] = 4
    RETURN_ADDR: ClassVar[SimStackArg] = SimStackArg(0, 4)
    RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL: ClassVar[SimRegArg] = SimRegArg("dx", 2)
    ARCH: ClassVar[type[Arch86_16]] = Arch86_16
    STACK_ALIGNMENT: ClassVar[int] = 2
    CALLEE_CLEANUP: ClassVar[bool] = False


# Legacy compatibility alias for callers that imported the pre-memory-model
# default Microsoft C calling convention by the unsuffixed name.
SimCC8616MSC: type[SimCC8616MSCsmall] = SimCC8616MSCsmall


register_simos("DOS", SimDOS86_16)
register_default_cc("86_16", SimCC8616MSCsmall)
register_default_cc("86_16", SimCC8616MSCsmall, platform="DOS")
register_syscall_cc("86_16", "Linux", SimDOSintcall)
register_syscall_cc("86_16", "default", SimDOSintcall)
