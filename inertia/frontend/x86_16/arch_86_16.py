"""Layer: Frontend/runtime.

Responsibility: define the 16-bit x86 archinfo register and toolchain surface.
Forbidden: decompiler semantic recovery, alias/type ownership, or rewrite cleanup.
"""

from __future__ import annotations

import os
from typing import Any, ClassVar, cast

from archinfo import ArchError, Endness, RegisterOffset

from .control_coordinates import ControlAddressDomain

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

import pyvex
from archinfo.arch import Arch, Register, register_arch

__all__ = ("Arch86_16",)


class Arch86_16(Arch):  # type: ignore[misc, unused-ignore] # dynamic archinfo base
    """16-bit x86 archinfo definition for real-mode DOS lifting and runtime setup."""

    def __init__(
        self, endness: Endness = Endness.LE, *,
        control_address_domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
    ) -> None:
        """Bind the register layout and the execution adapter's PC domain."""
        import logging

        self.logger = logging.getLogger(__name__)
        if not isinstance(control_address_domain, ControlAddressDomain):
            raise TypeError("control_address_domain must be a ControlAddressDomain")
        self.control_address_domain: ControlAddressDomain = control_address_domain
        super().__init__(endness)
        self_any = cast(Any, self)
        self_any.endness = "Iend_LE"
        self.reg_blacklist: list[str] = []
        self.reg_blacklist_offsets: list[int] = []
        self.vex_archinfo = None
        self.vex_cc_regs = None
        self.vex_to_unicorn_map = None
        # self.registers = self.register_list

        # Enforce 16-bit primary types
        self.bits = 16

        # Arch builds ``registers`` during super().__init__. The offsets declared
        # on register_list must therefore remain unchanged for every instance.
        self.logger.info("Arch86_16 init: using declared 16-bit register offsets")
        for reg in self.register_list:
            self.logger.debug(f"Reg {reg.name}: size {reg.size}, vex_offset {reg.vex_offset}")

        self.vex_offsets: dict[str, int] = {}
        for reg in self.register_list:
            self.vex_offsets[reg.name.lower()] = reg.vex_offset
            for alias_name in reg.alias_names:
                self.vex_offsets[alias_name.lower()] = reg.vex_offset
            for subregister_name, subregister_offset, _subregister_size in reg.subregisters:
                self.vex_offsets[subregister_name.lower()] = reg.vex_offset + subregister_offset

    def lifting_semantics_key_8616(self) -> tuple[object, ...]:
        """Return immutable frontend fields that determine exact-byte lifting."""
        runtime_endness = cast(Any, self).endness
        return (
            type(self),
            self.name,
            int(self.bits),
            runtime_endness,
            self.instruction_endness,
            self.memory_endness,
            self.register_endness,
            self.vex_arch,
            self.control_address_domain,
            os.environ.get("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS") == "1",
        )

    name: str = "86_16"
    bits: int = 16
    stack_change: int = -2
    vex_arch: Any = cast(Any, pyvex.ARCH_X86)
    vex_support: Any = cast(Any, True)
    vex_conditional_helpers: bool = False
    sizeof: ClassVar[dict[str, int]] = {"short": 16, "int": 16, "long": 32, "long long": 32}
    ld_linux_name: str | None = None
    linux_name: str | None = None
    lib_paths: list[str] = []  # noqa: RUF012
    # max_inst_bytes = 4
    # ip_offset = 0x80000000
    # sp_offset = 16
    call_pushes_ret: bool = True
    instruction_endness: Endness = Endness.LE
    # FIXME: something in angr assumes that sizeof(long) == sizeof(return address on stack)
    # initial_sp = 0x7fff
    call_sp_fix: ClassVar[int] = -2
    instruction_alignment: int = 1
    # ioreg_offset = 0x20
    memory_endness: Endness = Endness.LE
    register_endness: Endness = Endness.LE

    elf_tls: None = None
    if _capstone:
        cs_arch = _capstone.CS_ARCH_X86  # Disassembler
        cs_mode = _capstone.CS_MODE_16 + _capstone.CS_MODE_LITTLE_ENDIAN
    _cs_x86_syntax = None  # Set it to 'att' in order to use AT&T syntax for x86
    if _keystone:
        ks_arch = _keystone.KS_ARCH_X86  # Assembler
        ks_mode = _keystone.KS_MODE_16 + _keystone.KS_MODE_LITTLE_ENDIAN
    _ks_x86_syntax = None
    uc_arch: int | None = _unicorn.UC_ARCH_X86 if _unicorn else None  # Emulator
    uc_mode: int | None = (_unicorn.UC_MODE_16 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const: Any = _unicorn.x86_const if _unicorn else None
    uc_prefix: str | None = "UC_X86_" if _unicorn else None
    function_prologs: ClassVar[set[bytes]] = {rb"\x55\x8b\xec", rb"\xc8"}  # push bp; mov bp, sp
    function_epilogs: ClassVar[set[bytes]] = {
        rb"\xc9\xc3",
        rb"\xc9\xcb",  # leave; ret
        rb"\x5d\xc3",
        rb"\x5d\xcb",
    }  # pop <reg>; ret
    ret_offset: RegisterOffset = RegisterOffset(0)  # ax - syscall return register?
    ret_instruction: bytes = b"\xc3"
    nop_instruction: bytes = b"\x90"

    register_list: ClassVar[list[Register]] = [
        # 80386 storage is 32-bit. Legacy names are overlapping subregister views,
        # not aliases: writing AX must preserve the high half of EAX.
        Register(
            name="eax",
            size=4,
            subregisters=[("ax", 0, 2), ("al", 0, 1), ("ah", 1, 1)],
            general_purpose=True,
            argument=True,
            vex_offset=0,
        ),
        Register(
            name="ecx",
            size=4,
            subregisters=[("cx", 0, 2), ("cl", 0, 1), ("ch", 1, 1)],
            general_purpose=True,
            vex_offset=4,
        ),
        Register(
            name="edx",
            size=4,
            subregisters=[("dx", 0, 2), ("dl", 0, 1), ("dh", 1, 1)],
            general_purpose=True,
            vex_offset=8,
        ),
        Register(
            name="ebx",
            size=4,
            subregisters=[("bx", 0, 2), ("bl", 0, 1), ("bh", 1, 1)],
            general_purpose=True,
            vex_offset=12,
        ),
        Register(
            name="esp",
            size=4,
            subregisters=[("sp", 0, 2)],
            alias_names=("stack_base",),
            general_purpose=True,
            default_value=(0x7FFF, True, "global"),
            vex_offset=16,
        ),
        Register(
            name="ebp",
            size=4,
            subregisters=[("bp", 0, 2)],
            general_purpose=True,
            argument=True,
            vex_offset=20,
        ),
        Register(
            name="esi",
            size=4,
            subregisters=[("si", 0, 2)],
            vex_offset=24,
            general_purpose=True,
        ),
        Register(
            name="edi",
            size=4,
            subregisters=[("di", 0, 2)],
            vex_offset=28,
            general_purpose=True,
        ),
        Register(
            name="eip",
            size=4,
            subregisters=[("ip", 0, 2)],
            alias_names=("pc",),
            vex_offset=32,
        ),
        Register(
            name="eflags",
            size=4,
            subregisters=[("flags", 0, 2)],
            vex_offset=36,
        ),
        Register(name="cs", size=2, vex_offset=40),
        Register(name="ds", size=2, vex_offset=42),
        Register(name="es", size=2, vex_offset=44),
        Register(name="fs", size=2, default_value=(0, False, None), concrete=False, vex_offset=46),
        Register(name="gs", size=2, default_value=(0, False, None), concrete=False, vex_offset=48),
        Register(name="ss", size=2, vex_offset=50),
        # Flags and helpers (4-byte, artificial, no subregs)
        Register(
            name="d",
            size=4,
            alias_names=("dflag",),
            default_value=(1, False, None),
            concrete=False,
            artificial=True,
            vex_offset=52,
        ),
        Register(
            name="id",
            size=4,
            alias_names=("idflag",),
            default_value=(1, False, None),
            concrete=False,
            artificial=True,
            vex_offset=56,
        ),
        Register(
            name="ac",
            size=4,
            alias_names=("acflag",),
            default_value=(0, False, None),
            concrete=False,
            artificial=True,
            vex_offset=60,
        ),
        Register(name="cmstart", size=4, vex_offset=64),
        Register(name="cmlen", size=4, vex_offset=68),
        Register(name="nraddr", size=4, artificial=True, vex_offset=72),
        Register(name="sc_class", size=4, artificial=True, vex_offset=76),
        Register(name="ip_at_syscall", size=4, concrete=False, artificial=True, vex_offset=80),
        # FPU (unchanged, offset after)
        Register(
            name="fpreg",
            size=64,
            alias_names=("fpu_regs",),
            floating_point=True,
            concrete=False,
            vex_offset=84,
        ),
        Register(
            name="fptag",
            size=8,
            alias_names=("fpu_tags",),
            floating_point=True,
            default_value=(0, False, None),
            vex_offset=148,
        ),
        Register(name="fpround", size=4, floating_point=True, default_value=(0, False, None), vex_offset=156),
        Register(name="fc3210", size=4, floating_point=True, vex_offset=160),
        Register(name="cr0", size=4, vex_offset=164),
        Register(name="cr2", size=4, vex_offset=168),
        Register(name="cr3", size=4, vex_offset=172),
    ]

    @property
    def capstone_x86_syntax(self) -> str | None:
        """Get the current syntax Capstone uses for x86.

        :return: Capstone's current x86 syntax
        :rtype: str
        """
        return self._cs_x86_syntax

    @capstone_x86_syntax.setter
    def capstone_x86_syntax(self, new_syntax: str) -> None:
        """Set the syntax that Capstone outputs for x86."""
        if new_syntax not in ("intel", "at&t"):
            raise ArchError('Unsupported Capstone x86 syntax. It must be either "intel" or "at&t".')

        if new_syntax != self._cs_x86_syntax:
            self._cs = None
            self._cs_x86_syntax = new_syntax

    def _configure_capstone(self) -> None:
        capstone_mod = cast(Any, _capstone)
        cast(Any, self._cs).syntax = (
            capstone_mod.CS_OPT_SYNTAX_ATT if self._cs_x86_syntax == "at&t" else capstone_mod.CS_OPT_SYNTAX_INTEL
        )

    @property
    def keystone_x86_syntax(self) -> str | None:
        """Get the current syntax Keystone uses for x86.

        :return: Keystone's current x86 syntax
        :rtype: str
        """
        return self._ks_x86_syntax

    @keystone_x86_syntax.setter
    def keystone_x86_syntax(self, new_syntax: str) -> None:
        """Set the syntax that Keystone uses for x86."""
        if new_syntax not in ("intel", "at&t", "nasm", "masm", "gas", "radix16"):
            raise ArchError(
                "Unsupported Keystone x86 syntax. It must be one of the following: "
                '"intel", "at&t", "nasm", "masm", "gas" or "radix16".',
            )

        if new_syntax != self._ks_x86_syntax:
            self._ks = None
            self._ks_x86_syntax = new_syntax

    def _configure_keystone(self) -> None:
        keystone_mod = cast(Any, _keystone)
        ks = cast(Any, self._ks)
        if self._ks_x86_syntax == "at&t":
            ks.syntax = keystone_mod.KS_OPT_SYNTAX_ATT
        elif self._ks_x86_syntax == "nasm":
            ks.syntax = keystone_mod.KS_OPT_SYNTAX_NASM
        elif self._ks_x86_syntax == "masm":
            ks.syntax = keystone_mod.KS_OPT_SYNTAX_MASM
        elif self._ks_x86_syntax == "gas":
            ks.syntax = keystone_mod.KS_OPT_SYNTAX_GAS
        elif self._ks_x86_syntax == "radix16":
            ks.syntax = keystone_mod.KS_OPT_SYNTAX_RADIX16
        else:
            ks.syntax = keystone_mod.KS_OPT_SYNTAX_INTEL


register_arch([r"86_16"], 16, cast(Any, "Iend_LE"), Arch86_16)
