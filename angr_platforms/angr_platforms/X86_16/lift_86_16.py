"""Layer: Frontend/runtime.

Responsibility: lift 16-bit x86 bytes into VEX/typed IR facts without later-stage repair.
Forbidden: postprocess cleanup, source/COD-backed recovery, or validation acceptance.
Dynamic attribute access here is a third-party pyvex/Gymrat, Capstone, and
emulator telemetry boundary; owned Inertia facts must be explicit typed IR.
"""

from __future__ import annotations

import contextlib
import logging
import os
from abc import update_abstractmethods
from dataclasses import dataclass, replace
from typing import Any, ClassVar, cast

import bitstring
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter, Instruction, JumpKind, ParseError
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import Type
from pyvex.stmt import Dirty

from inertia_decompiler.runtime_support import AnalysisTimeout

from .arch_86_16 import Arch86_16
from .compiler_helpers import is_x86_16_registered_stack_probe_target_8616
from .emulator import Emulator
from .instr16 import Instr16
from .instr32 import Instr32
from .instruction import InstrData
from .ir.condition_ir import (
    _JCC_COMPARISON_MNEMONICS_8616,
    JCC_EQ_MNEMONICS_8616,
    JCC_NE_MNEMONICS_8616,
    JCC_SGE_MNEMONICS_8616,
    JCC_SGT_MNEMONICS_8616,
    JCC_SLE_MNEMONICS_8616,
    JCC_SLT_MNEMONICS_8616,
    JCC_UGE_MNEMONICS_8616,
    JCC_UGT_MNEMONICS_8616,
    JCC_ULE_MNEMONICS_8616,
    JCC_ULT_MNEMONICS_8616,
    ConditionFailure,
    ConditionIR,
    ConditionSource,
    build_condition_from_cmp_8616,
    build_condition_from_test_8616,
    condition_sort_key_8616,
)
from .ir.condition_register_bindings import snapshot_condition_register_bindings_8616
from .ir.core import AddressStatus, IRAddress, IRBinaryValue, IRCondition, IRValue, MemSpace, SegmentOrigin
from .ir.status_flag_lift_context import cfg_status_flag_dead_write_mask_8616
from .jcc_condition import _direct_jcc_condition_from_last_condition_8616
from .parse import CHSZ_AD, CHSZ_OP
from .regs import reg16_t
from .segment_offset_execution import advance_segment_offset_8616
from .semantics.status_flag_liveness import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    STATUS_FLAGS_8616,
    StatusFlag8616,
    binop_status_flag_writes_8616,
    decoded_status_flag_instruction_8616,
    status_flags_dead_before_use_8616,
)
from .vex_value_contract import require_vex_value_8616

logger: logging.Logger = logging.getLogger(__name__)

_BPMemorySpec8616 = tuple[str, int, int]


@dataclass(frozen=True)
class _ConditionRegisterValueState8616:
    """Carry one exact register value within a decoded basic block until clobbered."""

    value: IRValue | IRBinaryValue
    next_addr: int


def _affine_switch_conditions_enabled_8616() -> bool:
    return os.environ.get("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS") == "1"


def _bitstream_is_empty(bitstrm: bitstring.ConstBitStream) -> bool:
    try:
        bitstrm.peek(1)
        return False
    except bitstring.ReadError:
        return True


class _LifterInstructionFacade:
    """Combine the raw IRSB customizer API with the higher-level Instruction helpers.
    Modern pyvex exposes jump/get/put on Instruction, but low-level IR building
    helpers like _append_stmt() and _settmp() still live on the IRSB customizer.
    """

    def __init__(self, irsb_c: Any, instruction: Instruction) -> None:
        self._irsb_c = irsb_c
        self._instruction = instruction

    def __getattr__(self, name: str) -> Any:
        try:
            return getattr(self._instruction, name)
        except AttributeError:
            return getattr(self._irsb_c, name)


class Instruction_ANY(Instruction):  # type: ignore[misc]  # dynamic pyvex base
    """Dynamic pyvex instruction bridge for 16-bit x86 instruction lifting."""

    bitstrm: Any
    arch: Any
    addr: int
    start: int
    cs: Any
    emu: Emulator
    irsb_c: Any
    instr: InstrData
    instr16: Instr16
    instr32: Instr32 | None
    simple_semantics: tuple[Any, ...] | None
    condition_value_semantics: tuple[Any, ...] | None
    _past_instructions: Any = ()

    def dirty(self, ret_type: object, func_name: str, args: list[object]) -> Any:
        """Emit one Dirty helper with complete no-memory-effect metadata."""
        result = super().dirty(ret_type, func_name, args)
        statement = self.irsb_c.irsb.statements[-1]
        if isinstance(statement, Dirty):
            if func_name == "x86g_dirtyhelper_OUT":
                statement.tmp = 0xFFFFFFFF
            statement.mFx = "Ifx_None"
            statement.mSize = 0
            statement.nFxState = 0
        return result
    _future_instructions: Any = ()
    _inertia_consumed_last_condition_8616: IRCondition
    _inertia_consumed_last_condition_addr_8616: int | None
    bitwidth: int
    is_mode32: bool
    chsz_op: int | bool
    reg_offsets: dict[int, int]

    _REG8_NAMES: ClassVar[set[str]] = {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"}
    _REG16_NAMES: ClassVar[set[str]] = {"ax", "bx", "cx", "dx", "sp", "bp", "si", "di", "ip", "flags"}
    _REG32_NAMES: ClassVar[set[str]] = {"eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi"}
    _LOW8_PARENT_REGS: ClassVar[dict[str, str]] = {"al": "ax", "bl": "bx", "cl": "cx", "dl": "dx"}
    _SIMPLE_JCC_8616: ClassVar[frozenset[str]] = frozenset(
        JCC_EQ_MNEMONICS_8616
        | JCC_NE_MNEMONICS_8616
        | JCC_ULT_MNEMONICS_8616
        | JCC_UGE_MNEMONICS_8616
        | JCC_ULE_MNEMONICS_8616
        | JCC_UGT_MNEMONICS_8616
        | JCC_SLT_MNEMONICS_8616
        | JCC_SGE_MNEMONICS_8616
        | JCC_SLE_MNEMONICS_8616
        | JCC_SGT_MNEMONICS_8616
        | _JCC_COMPARISON_MNEMONICS_8616
    )
    _BLOCK_TERMINATORS: ClassVar[set[str]] = {
        "call",
        "jmp",
        *_SIMPLE_JCC_8616,
        "ret",
        "retf",
        "iret",
        "int",
        "int3",
        "hlt",
    }
    _REG_OFFSETS: ClassVar[dict[reg16_t | int, int]] = {
        reg16_t.AX: 0,
        reg16_t.CX: 4,
        reg16_t.DX: 8,
        reg16_t.BX: 12,
        reg16_t.SP: 16,
        reg16_t.BP: 20,
        reg16_t.SI: 24,
        reg16_t.DI: 28,
        reg16_t.IP: 32,
        reg16_t.FLAGS: 36,
        20: 50,  # SS offset
        22: 40,  # CS offset
    }

    def lift(self, irsb_c: Any, past_instructions: Any, future_instructions: Any) -> None:
        """Lift one decoded pyvex instruction into the active IRSB customizer."""

        self.irsb_c = irsb_c
        self._past_instructions = past_instructions
        self._future_instructions = future_instructions
        if past_instructions and self.instr.repeat_class != "none":
            self.jump(None, self.addr)
            return
        self.mark_instruction_start()
        self.emu.irsb = irsb_c
        # Set the block address on the emulator so facts are keyed by block.
        # The actual IRSB is available via self.emu.irsb.irsb (pyvex pattern).
        # Fall back to self.addr (instruction address).
        actual_irsb = getattr(self.emu.irsb, "irsb", self.emu.irsb)
        block_addr = getattr(actual_irsb, "addr", self.addr)
        cast(Any, self.emu)._inertia_current_block_addr = block_addr
        self.emu.set_lifter_instruction(_LifterInstructionFacade(irsb_c, self))
        if self.instr.invalid_lock or self.instr.invalid_opcode_extension:
            guard = cast(VexValue, self.emu.constant(1, Type.int_1))
            target = cast(VexValue, self.emu.constant(0, Type.int_32))
            irsb_c.add_exit(guard.rdt, target.rdt, "Ijk_SigILL", self.arch.ip_offset)
            return
        if self.simple_semantics is not None:
            self._lift_simple()
            return
        self.compute_result()

    def __init__(self, bitstrm: Any, arch: Any, addr: int) -> None:
        self.bitstrm = bitstrm
        self.arch = arch
        self.addr = addr
        self.instr = InstrData()
        self.emu = Emulator(arch, None)
        # Set block address and function address on emulator so _record_semantic_memory_access
        # can key facts into _inertia_module_alias_fact_cache and evidence_cache
        emu_dynamic = cast(Any, self.emu)
        emu_dynamic._inertia_current_block_addr = addr
        emu_dynamic._inertia_current_function_addr = addr
        self.instr16 = Instr16(self.emu, self.instr)
        self.instr32 = None
        self.emu.set_lifter_instruction(None)
        self.emu.set_bitstream(bitstrm)
        self.simple_semantics = None
        self.condition_value_semantics = None
        super().__init__(bitstrm, arch, addr)

        self.reg_offsets = self._REG_OFFSETS

    def _ensure_instr32(self) -> Instr32:
        if self.instr32 is None:
            self.instr32 = Instr32(self.emu, self.instr)
        return self.instr32

    def parse(self, bitstrm: Any) -> dict[str, str]:
        """Parse one 16-bit instruction and prepare either simple or full semantics."""

        def _impl() -> dict[str, str]:
            try:
                self.start = bitstrm.bytepos
                raw = bytes(bitstrm[self.start * 8 : self.start * 8 + 15 * 8])
                cs_prefix_len = 0
                try:
                    instr = list(self.arch.capstone.disasm(raw, self.addr, 1))
                except AnalysisTimeout as ex:
                    raise ParseError("Instruction disassembly timed out") from ex
                capstone_rejected_full = not instr
                prefix_bytes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
                prefix_index = 0
                while prefix_index < len(raw) and raw[prefix_index] in prefix_bytes:
                    prefix_index += 1
                invalid_pop_extension = (
                    prefix_index + 1 < len(raw)
                    and raw[prefix_index] == 0x8F
                    and ((raw[prefix_index + 1] >> 3) & 7) != 0
                )
                if not instr and invalid_pop_extension:
                    sanitized = bytearray(raw)
                    sanitized[prefix_index + 1] &= 0xC7
                    instr = list(self.arch.capstone.disasm(bytes(sanitized), self.addr, 1))
                if not instr:
                    # Capstone rejects several LOCK-prefixed forms that the real 286 still
                    # executes, and also segment-override + LOCK combinations.
                    # Decode the underlying opcode for mnemonic discovery, but let our
                    # own parser consume the real prefix byte stream below.
                    for strip_len in range(1, min(4, len(raw))):
                        try:
                            instr = list(self.arch.capstone.disasm(raw[strip_len:], self.addr + strip_len, 1))
                        except AnalysisTimeout as ex:
                            raise ParseError("Instruction disassembly timed out") from ex
                        if instr:
                            cs_prefix_len = strip_len
                            break
                if not instr:
                    raise ParseError("Couldn't disassemble instruction")
                self.cs = instr[0]
                logger.debug("cs dis: %s %s", self.cs.mnemonic, self.cs.op_str)
                cast(Any, self).name = self.cs.insn_name()
                matched_semantics = self._match_simple_semantics()
                prefix_index = 0
                width_override = False
                segment_override = False
                while prefix_index < len(raw) and raw[prefix_index] in prefix_bytes:
                    width_override |= raw[prefix_index] in {0x66, 0x67}
                    segment_override |= raw[prefix_index] in {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65}
                    prefix_index += 1
                wide_memory_operand = any(operand.type == 3 and operand.size > 1 for operand in self.cs.operands)
                self.instr.invalid_lock = capstone_rejected_full and 0xF0 in raw[:prefix_index]
                self.instr.invalid_opcode_extension = invalid_pop_extension
                full_lift_value_semantics = (
                    matched_semantics
                    if wide_memory_operand
                    and not (segment_override or width_override)
                    and not self.instr.invalid_lock
                    and not self.instr.invalid_opcode_extension
                    and matched_semantics
                    and str(matched_semantics[0]).startswith(
                        ("add_reg_", "and_reg_", "cmp_", "mov_reg_", "or_reg_", "sub_reg_", "test_", "xor_reg_")
                    )
                    else None
                )
                dead_flags_wide_register_semantics = bool(
                    matched_semantics
                    and matched_semantics[0] == "ror_reg_imm32_dead_flags"
                )
                if (
                    segment_override
                    or (
                        wide_memory_operand
                        and not (
                            matched_semantics is not None
                            and str(matched_semantics[0]).startswith("cmp_")
                        )
                    )
                    or (width_override and not dead_flags_wide_register_semantics)
                    or self.instr.invalid_lock
                    or self.instr.invalid_opcode_extension
                ):
                    matched_semantics = None
                self.simple_semantics = matched_semantics
                self.condition_value_semantics = full_lift_value_semantics
                if self.simple_semantics is not None:
                    bitstrm.bytepos = self.start + cs_prefix_len + self.cs.size
                    self.bitwidth = (cs_prefix_len + self.cs.size) * 8
                    self.is_mode32 = self.emu.is_mode32()
                    self.chsz_op = False
                    return {"x": "00000000"}

                self.instr.size = cs_prefix_len + self.cs.size
                self.is_mode32 = self.emu.is_mode32()
                prefix = self._ensure_instr32().parse_prefix() if self.is_mode32 else self.instr16.parse_prefix()
                self.chsz_op = prefix & CHSZ_OP
                chsz_ad = prefix & CHSZ_AD

                if self.is_mode32 ^ bool(self.chsz_op):
                    instr32 = self._ensure_instr32()
                    instr32.chsz = prefix
                    instr32.set_chsz_ad(bool(chsz_ad))
                    instr32.parse()
                else:
                    self.instr16.chsz = prefix
                    self.instr16.set_chsz_ad(bool(chsz_ad))
                    self.instr16.parse()
                self.bitwidth = (bitstrm.bytepos - self.start) * 8
                return {"x": "00000000"}
            except AnalysisTimeout as ex:
                raise ParseError("Instruction parse timed out") from ex

        return _impl()

    def _match_simple_semantics(self) -> tuple[Any, ...] | None:
        ops = getattr(self.cs, "operands", ())
        unary = self._match_simple_unary_semantics_8616(ops)
        if unary is not None:
            return unary
        if len(ops) != 2:
            return None
        return self._match_simple_binary_semantics_8616(ops)

    def _match_simple_unary_semantics_8616(self, ops: Any) -> tuple[Any, ...] | None:
        def _impl() -> tuple[Any, ...] | None:
            if self.cs.mnemonic == "nop":
                return ("nop",)
            if self.cs.mnemonic == "ret":
                if len(ops) == 1 and ops[0].type == 2:
                    return ("ret_imm16", ops[0].imm & 0xFFFF)
                return ("ret",)
            if self.cs.mnemonic == "leave":
                return ("leave",)
            if self.cs.mnemonic in {"cbw", "cwde"} and not ops:
                instruction_bytes = bytes(self.cs.bytes)
                if 0x66 in instruction_bytes[:-1]:
                    return ("sign_extend_ax_eax",)
                return ("sign_extend_al_ax",)
            if self.cs.mnemonic == "enter" and len(ops) == 2 and all(op.type == 2 for op in ops):
                return ("enter", ops[0].imm & 0xFFFF, ops[1].imm & 0xFF)
            if self.cs.mnemonic in {"push", "pop"} and len(ops) == 1:
                reg_name = self._reg16_name(ops[0])
                mem = self._bp_mem(ops[0])
                if reg_name:
                    return (f"{self.cs.mnemonic}_reg16", reg_name)
                if self.cs.mnemonic == "push" and ops[0].type == 2:
                    return ("push_imm16", ops[0].imm & 0xFFFF)
                if self.cs.mnemonic == "push" and mem:
                    return ("push_mem16", mem)
            if self.cs.mnemonic == "call" and len(ops) == 1:
                if ops[0].type == 2:
                    return ("call", ops[0].imm)
                mem = self._bp_mem(ops[0])
                if mem:
                    return ("call_mem16", mem)
            if self.cs.mnemonic == "inc" and len(ops) == 1 and (
                _affine_switch_conditions_enabled_8616() or self._next_instruction_is_simple_jcc_from_bytes_8616()
            ):
                reg_name = self._reg16_name(ops[0])
                if reg_name and reg_name not in {"sp", "bp"}:
                    return ("inc_reg16", reg_name)
            if (
                self.cs.mnemonic == "dec"
                and len(ops) == 1
                and (
                    _affine_switch_conditions_enabled_8616()
                    or self._next_instruction_is_simple_jcc_from_bytes_8616()
                    or self._next_instruction_is_incdec_reg16_from_bytes_8616()
                )
            ):
                reg_name = self._reg16_name(ops[0])
                if reg_name and reg_name not in {"sp", "bp"}:
                    return ("dec_reg16", reg_name)
            if self.cs.mnemonic in {"jmp", *self._SIMPLE_JCC_8616} and len(ops) == 1 and ops[0].type == 2:
                return (self.cs.mnemonic, ops[0].imm)
            return None

        return _impl()

    def _next_instruction_is_simple_jcc_from_bytes_8616(self) -> bool:
        def _impl() -> bool:
            next_bytepos = self.start + self.cs.size
            raw = bytes(self.bitstrm[next_bytepos * 8 : next_bytepos * 8 + 2 * 8])
            if not raw:
                return False
            opcode = raw[0]
            if 0x70 <= opcode <= 0x7F:
                return True
            return len(raw) >= 2 and opcode == 0x0F and 0x80 <= raw[1] <= 0x8F

        return _impl()

    def _next_instruction_is_incdec_reg16_from_bytes_8616(self) -> bool:
        def _impl() -> bool:
            next_bytepos = self.start + self.cs.size
            raw = bytes(self.bitstrm[next_bytepos * 8 : next_bytepos * 8 + 8])
            if not raw:
                return False
            return 0x40 <= raw[0] <= 0x4F

        return _impl()

    @staticmethod
    def _register_family_8616(reg_name: str) -> frozenset[str]:
        """Return the x86 register names that overlap one 16-bit register."""
        families = {
            "ax": frozenset({"al", "ah", "ax", "eax"}),
            "bx": frozenset({"bl", "bh", "bx", "ebx"}),
            "cx": frozenset({"cl", "ch", "cx", "ecx"}),
            "dx": frozenset({"dl", "dh", "dx", "edx"}),
            "sp": frozenset({"sp", "esp"}),
            "bp": frozenset({"bp", "ebp"}),
            "si": frozenset({"si", "esi"}),
            "di": frozenset({"di", "edi"}),
        }
        return families.get(str(reg_name).lower(), frozenset({str(reg_name).lower()}))

    def _same_preceding_incdec_reg16_count_8616(self, reg_name: str, *, mnemonic: str) -> int:
        if mnemonic not in {"inc", "dec"}:
            return 1
        try:
            current_byte = bytes(self.bitstrm[self.start * 8 : self.start * 8 + 8])[0]
        except Exception:
            return 1
        base_opcode = 0x40 if mnemonic == "inc" else 0x48
        try:
            reg_index = int(reg16_t[reg_name.upper()].value)
        except Exception:
            return 1
        expected_opcode = base_opcode + reg_index
        if current_byte != expected_opcode:
            return 1
        count = 1
        bytepos = self.start - 1
        while bytepos >= 0:
            try:
                prev_byte = bytes(self.bitstrm[bytepos * 8 : bytepos * 8 + 8])[0]
            except Exception:
                break
            if prev_byte != expected_opcode:
                break
            count += 1
            bytepos -= 1
        return count

    def _match_simple_binary_semantics_8616(self, ops: Any) -> tuple[Any, ...] | None:
        """Classify one two-operand instruction into typed frontend semantics."""
        dst, src = ops
        mnemonic = self.cs.mnemonic
        dst_reg = self._reg16_name(dst)
        src_reg = self._reg16_name(src)
        src_imm = self._imm16_value(src)
        src_imm8 = self._imm8_value(src)
        dst_mem = self._bp_mem(dst)
        dst_mem8 = self._bp_mem(dst, width_bytes=1)
        src_mem = self._bp_mem(src)
        src_mem8 = self._bp_mem(src, width_bytes=1)
        dst_abs_mem = self._direct_mem16(dst)
        src_abs_mem = self._direct_mem16(src)
        dst_abs_mem8 = self._direct_mem8(dst)
        src_abs_mem8 = self._direct_mem8(src)
        dst_indexed_mem8 = self._indexed_mem(dst, width_bytes=1)
        src_indexed_mem8 = self._indexed_mem(src, width_bytes=1)
        dst_indexed_mem16 = self._indexed_mem(dst, width_bytes=2)
        src_indexed_mem16 = self._indexed_mem(src, width_bytes=2)
        src_reg8 = self._reg8_name(src)
        dst_reg8 = self._reg8_name(dst)
        dst_reg32 = self._reg32_name(dst)

        if mnemonic == "ror" and dst_reg32 and src_imm8 is not None:
            count = src_imm8 & 0x1F
            written = StatusFlag8616.CARRY | StatusFlag8616.OVERFLOW
            if count == 0 or self.status_flag_write_is_dead_8616(written):
                return ("ror_reg_imm32_dead_flags", dst_reg32, count)

        if mnemonic == "mov" and dst_reg8:
            if src_indexed_mem8 is not None:
                return ("mov_reg_indexed_abs8", dst_reg8, src_indexed_mem8)
            if src_abs_mem8 is not None:
                return ("mov_reg_abs8", dst_reg8, src_abs_mem8)
        if mnemonic == "mov" and dst_reg and src_indexed_mem16 is not None:
            return ("mov_reg_indexed_abs16", dst_reg, src_indexed_mem16)
        mov_sem = self._match_mov_lea_binary_semantics_8616(dst_reg, src_imm, src_reg, src_mem, src_abs_mem, dst_mem)
        if mov_sem is not None:
            return mov_sem
        cmp_sem = self._match_cmp_binary_semantics_8616(
            dst_reg,
            src_reg,
            src_mem,
            src_imm,
            dst_mem,
            dst_abs_mem,
            src_abs_mem,
            dst_abs_mem8,
            src_imm8,
            src_reg8,
            dst_reg8,
            dst_indexed_mem8,
            src_indexed_mem8,
            dst_indexed_mem16,
            src_indexed_mem16,
            src,
        )
        if cmp_sem is not None:
            return cmp_sem
        if mnemonic == "test" and self._next_instruction_is_simple_jcc_from_bytes_8616():
            if dst_mem8 is not None and src_imm8 is not None:
                return ("test_mem_imm8", dst_mem8, src_imm8)
            if dst_mem is not None and src_imm is not None:
                return ("test_mem_imm16", dst_mem, src_imm)
            if dst_abs_mem8 is not None and src_imm8 is not None:
                return ("test_abs_imm8", dst_abs_mem8, src_imm8)
            if dst_abs_mem is not None and src_imm is not None:
                return ("test_abs_imm16", dst_abs_mem, src_imm)
        if mnemonic == "xor" and dst_reg8 and src_mem8 is not None:
            return ("xor_reg_mem8", dst_reg8, src_mem8)
        if mnemonic in {"add", "sub", "xor", "and", "or"}:
            if dst_reg and dst_reg not in {"sp", "bp"} and mnemonic in {"add", "sub"}:
                if src_reg:
                    return (f"{mnemonic}_reg_reg16", dst_reg, src_reg)
                if src_mem:
                    return (f"{mnemonic}_reg_mem16", dst_reg, src_mem)
                if src_abs_mem is not None:
                    return (f"{mnemonic}_reg_abs16", dst_reg, src_abs_mem)
                if src_imm is not None:
                    return (f"{mnemonic}_reg_imm16", dst_reg, src_imm)
            if (
                dst_reg
                and dst_reg not in {"sp", "bp"}
                and mnemonic in {"xor", "and", "or"}
                and self._next_instruction_is_simple_jcc_from_bytes_8616()
            ):
                if src_reg:
                    return (f"{mnemonic}_reg_reg16", dst_reg, src_reg)
                if src_mem:
                    return (f"{mnemonic}_reg_mem16", dst_reg, src_mem)
                if src_abs_mem is not None and mnemonic in {"xor", "and", "or"}:
                    return (f"{mnemonic}_reg_abs16", dst_reg, src_abs_mem)
                if src_imm is not None:
                    return (f"{mnemonic}_reg_imm16", dst_reg, src_imm)
            if dst_abs_mem is not None and src_imm is not None:
                return (f"{mnemonic}_abs_imm16", dst_abs_mem, src_imm)
            if dst_abs_mem is not None and src_reg:
                return (f"{mnemonic}_abs_reg16", dst_abs_mem, src_reg)
        return None

    def _match_mov_lea_binary_semantics_8616(
        self,
        dst_reg: Any,
        src_imm: Any,
        src_reg: Any,
        src_mem: Any,
        src_abs_mem: Any,
        dst_mem: Any,
    ) -> tuple[Any, ...] | None:
        def _impl() -> tuple[Any, ...] | None:
            if self.cs.mnemonic == "mov" and dst_reg and src_imm is not None:
                return ("mov_reg_imm16", dst_reg, src_imm)
            if self.cs.mnemonic == "mov" and dst_reg and src_reg:
                return ("mov_reg_reg16", dst_reg, src_reg)
            if self.cs.mnemonic == "mov" and dst_reg and src_mem:
                return ("mov_reg_mem16", dst_reg, src_mem)
            if self.cs.mnemonic == "mov" and dst_reg and src_abs_mem is not None:
                return ("mov_reg_abs16", dst_reg, src_abs_mem)
            if self.cs.mnemonic == "mov" and dst_mem and src_reg:
                return ("mov_mem_reg16", dst_mem, src_reg)
            if self.cs.mnemonic == "mov" and dst_mem and src_imm is not None:
                return ("mov_mem_imm16", dst_mem, src_imm)
            if self.cs.mnemonic == "lea" and dst_reg and src_mem:
                return ("lea_reg_bpdisp16", dst_reg, src_mem)
            return None

        return _impl()

    def _match_cmp_binary_semantics_8616(
        self,
        dst_reg: Any,
        src_reg: Any,
        src_mem: Any,
        src_imm: Any,
        dst_mem: Any,
        dst_abs_mem: Any,
        src_abs_mem: Any,
        dst_abs_mem8: Any,
        src_imm8: Any,
        src_reg8: Any,
        dst_reg8: Any,
        dst_indexed_mem8: Any,
        src_indexed_mem8: Any,
        dst_indexed_mem16: Any,
        src_indexed_mem16: Any,
        src: Any,
    ) -> tuple[Any, ...] | None:
        """Classify CMP operands while preserving exact memory-address shape."""
        def _impl() -> tuple[Any, ...] | None:
            if self.cs.mnemonic != "cmp":
                return None
            if dst_reg:
                if src_reg:
                    return ("cmp_reg_reg16", dst_reg, src_reg)
                if src_mem:
                    return ("cmp_reg_mem16", dst_reg, src_mem)
                if src_imm is not None:
                    return ("cmp_reg_imm16", dst_reg, src_imm)
                if src_abs_mem is not None:
                    return ("cmp_reg_abs16", dst_reg, src_abs_mem)
            if dst_mem:
                if src_reg:
                    return ("cmp_mem_reg16", dst_mem, src_reg)
                if src_imm is not None:
                    return ("cmp_mem_imm16", dst_mem, src_imm)
            if dst_abs_mem is not None:
                if src_imm is not None:
                    return ("cmp_abs_imm16", dst_abs_mem, src_imm)
                if src_reg:
                    return ("cmp_abs_reg16", dst_abs_mem, src_reg)
            if dst_abs_mem8 is not None:
                if src_imm8 is not None:
                    return ("cmp_abs_imm8", dst_abs_mem8, src_imm8)
                if src_reg8:
                    return ("cmp_abs_reg8", dst_abs_mem8, src_reg8)
            if dst_reg8 and src_imm8 is not None:
                return ("cmp_reg_imm8", dst_reg8, src_imm8)
            if dst_indexed_mem8 is not None and src_reg8:
                return ("cmp_indexed_abs_reg8", dst_indexed_mem8, src_reg8)
            if dst_reg8 and src_indexed_mem8 is not None:
                return ("cmp_reg_indexed_abs8", dst_reg8, src_indexed_mem8)
            if dst_indexed_mem16 is not None and src_imm is not None:
                return ("cmp_mem_imm16", dst_indexed_mem16, src_imm)
            if dst_indexed_mem16 is not None and src_reg:
                return ("cmp_indexed_abs_reg16", dst_indexed_mem16, src_reg)
            if dst_reg and src_indexed_mem16 is not None:
                return ("cmp_reg_indexed_abs16", dst_reg, src_indexed_mem16)
            if dst_reg8:
                src_abs_mem8 = self._direct_mem8(src)
                if src_abs_mem8 is not None:
                    return ("cmp_reg_abs8", dst_reg8, src_abs_mem8)
            return None

        return _impl()

    def _lift_simple_cmp_8616(self, kind: str) -> bool:
        """Lift one classified CMP and retain normalized condition operands."""
        def _impl() -> bool:
            semantics = cast(tuple[Any, ...], self.simple_semantics)
            if kind == "cmp_mem_reg16":
                _, mem_spec, src_reg = semantics
                lhs_val = self._load_mem16(mem_spec)
                rhs_val = self._get_reg16(src_reg)
                self._record_cmp_condition_source(lhs_val, rhs_val)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_mem_imm16":
                _, mem_spec, imm = semantics
                lhs_val = self._load_mem16(mem_spec)
                rhs_val = self._const16(imm)
                self._record_cmp_condition_source(lhs_val, rhs_val)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_abs_reg16":
                _, offset, src_reg = semantics
                lhs_val = self._load_abs16(offset)
                rhs_val = self._get_reg16(src_reg)
                self._record_cmp_condition_source(lhs_val, rhs_val)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_abs_imm16":
                _, offset, imm = semantics
                lhs_val = self._load_abs16(offset)
                rhs_val = self._const16(imm)
                self._record_cmp_condition_source(lhs_val, rhs_val)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_reg_abs16":
                _, lhs_reg, offset = semantics
                lhs_val = self._get_reg16(lhs_reg)
                rhs_val = self._load_abs16(offset)
                self._record_cmp_condition_source(lhs_val, rhs_val)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_reg_imm8":
                _, dst_reg, immediate = semantics
                lhs_val = self.get(dst_reg, Type.int_8)
                rhs_val = self.constant(immediate, Type.int_8)
                self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind in {"cmp_reg_abs8", "cmp_abs_reg8", "cmp_abs_imm8"}:
                if kind == "cmp_reg_abs8":
                    _, dst_reg, offset = semantics
                    lhs_val = self.get(dst_reg, Type.int_8)
                    rhs_val = self._load_abs8(offset)
                elif kind == "cmp_abs_reg8":
                    _, offset, src_reg = semantics
                    lhs_val = self._load_abs8(offset)
                    rhs_val = self.get(src_reg, Type.int_8)
                else:
                    _, offset, imm = semantics
                    lhs_val = self._load_abs8(offset)
                    rhs_val = self.constant(imm, Type.int_8)
                self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_indexed_abs_reg8":
                _, mem_spec, src_reg = semantics
                lhs_val = self._load_indexed_abs(mem_spec, width_bytes=1)
                rhs_val = self.get(src_reg, Type.int_8)
                self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind == "cmp_reg_indexed_abs8":
                _, lhs_reg, mem_spec = semantics
                lhs_val = self.get(lhs_reg, Type.int_8)
                rhs_val = self._load_indexed_abs(mem_spec, width_bytes=1)
                self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=8)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            if kind in {"cmp_indexed_abs_reg16", "cmp_reg_indexed_abs16"}:
                _, first, second = semantics
                if kind == "cmp_indexed_abs_reg16":
                    lhs_val = self._load_indexed_abs(first, width_bytes=2)
                    rhs_val = self._get_reg16(second)
                else:
                    lhs_val = self._get_reg16(first)
                    rhs_val = self._load_indexed_abs(second, width_bytes=2)
                self._record_cmp_condition_source(lhs_val, rhs_val)
                if not self._next_instruction_is_simple_jcc():
                    self._update_binop_flags16("sub", lhs_val, rhs_val)
                return True
            return False

        return _impl()

    def _lift_simple_jcc_8616(self, kind: str) -> bool:
        def _impl() -> bool:
            if kind not in (self._SIMPLE_JCC_8616 | {"jmp"}):
                return False
            semantics = cast(tuple[Any, ...], self.simple_semantics)
            _, abs_target = semantics
            linear_target = self._linear_near_target_8616(int(abs_target))
            target = self._code_address_constant_8616(linear_target)
            if kind == "jmp":
                if linear_target == self.addr + self.cs.size:
                    return True
                self.jump(None, target, JumpKind.Boring)
                return True
            cond = self._direct_jcc_condition(kind)
            if cond is not None:
                self._emit_simple_jcc(cond, target)
                return True
            zf = self._flag_is_set(6)
            cf = self._flag_is_set(0)
            sf = self._flag_is_set(7)
            of = self._flag_is_set(11)
            nof = self._flag_is_clear(11)
            nzf = self._flag_is_clear(6)
            ncf = self._flag_is_clear(0)
            if kind in JCC_EQ_MNEMONICS_8616:
                cond = zf
            elif kind in JCC_NE_MNEMONICS_8616:
                cond = nzf
            elif kind in JCC_SLE_MNEMONICS_8616:
                cond = zf | (sf != of)
            elif kind in JCC_SGT_MNEMONICS_8616:
                cond = nzf & (sf == of)
            elif kind in JCC_SLT_MNEMONICS_8616:
                cond = sf != of
            elif kind in JCC_SGE_MNEMONICS_8616:
                cond = sf == of
            elif kind in JCC_ULT_MNEMONICS_8616:
                cond = cf
            elif kind in JCC_UGE_MNEMONICS_8616:
                cond = ncf
            elif kind in JCC_ULE_MNEMONICS_8616:
                cond = cf | zf
            elif kind in JCC_UGT_MNEMONICS_8616:
                cond = ncf & nzf
            elif kind == "jo":
                cond = of
            elif kind == "jno":
                cond = nof
            elif kind == "js":
                cond = sf
            elif kind == "jns":
                cond = self._flag_is_clear(7)
            elif kind in {"jp", "jpe"}:
                cond = self._flag_is_set(2)
            elif kind in {"jnp", "jpo"}:
                cond = self._flag_is_clear(2)
            else:
                raise NotImplementedError(kind)
            self._emit_simple_jcc(cond, target)
            return True

        return _impl()

    def _lift_simple_test_8616(self, kind: str) -> bool:
        """Lift a direct or frame-relative TEST into typed masked-condition evidence."""
        if kind not in {
            "test_abs_imm8",
            "test_abs_imm16",
            "test_mem_imm8",
            "test_mem_imm16",
        }:
            return False
        _kind, location, immediate = cast(tuple[str, object, int], self.simple_semantics)
        width_bits = 8 if kind.endswith("imm8") else 16
        if kind.startswith("test_mem_"):
            memory = cast(_BPMemorySpec8616, location)
            value = self._load_mem8(memory) if width_bits == 8 else self._load_mem16(memory)
            typed_value = self._condition_stack_value_8616(memory, width_bits=width_bits)
        else:
            offset = cast(int, location)
            value = self._load_abs8(offset) if width_bits == 8 else self._load_abs16(offset)
            typed_value = self._condition_direct_ds_value_8616(offset, width_bits=width_bits)
        if typed_value is None:
            return False
        mask = self.constant(immediate, Type.int_8) if width_bits == 8 else self._const16(immediate)
        result = value & mask
        typed_mask = self._condition_const_value_8616(immediate, width_bits=width_bits)
        normalized = IRBinaryValue(op="and", lhs=typed_value, rhs=typed_mask, size=width_bits // 8)
        self._record_test_condition_source(
            result,
            width_bits=width_bits,
            normalized_value=normalized,
            producer_semantics=(kind, location, immediate),
        )
        self.emu.set_last_condition(
            IRCondition(op="masked_zero", args=(typed_value, typed_mask), expr=(kind,))
        )
        self._update_binop_flags16("and", value, mask)
        return True

    def _reg8_name(self, operand: Any) -> str | None:
        if operand.type != 1 or operand.size != 1:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG8_NAMES else None

    def _reg16_name(self, operand: Any) -> str | None:
        if operand.type != 1 or operand.size != 2:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG16_NAMES else None

    def _reg32_name(self, operand: Any) -> str | None:
        """Return one exact 32-bit GP register name from a Capstone operand."""
        if operand.type != 1 or operand.size != 4:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG32_NAMES else None

    @staticmethod
    def _imm8_value(operand: Any) -> int | None:
        if operand.type != 2:
            return None
        return int(operand.imm) & 0xFF

    @staticmethod
    def _imm16_value(operand: Any) -> int | None:
        if operand.type != 2:
            return None
        return int(operand.imm) & 0xFFFF

    def _get_reg16(self, reg_name: str) -> Any:
        return self.get(reg_name, Type.int_16)

    def _const16(self, value: int) -> Any:
        return self.constant(value & 0xFFFF, Type.int_16)

    def _const32(self, value: int) -> Any:
        return self.constant(value & 0xFFFFFFFF, Type.int_32)

    def _linear_near_target_8616(self, target: int) -> int:
        """Project one 16-bit near target into the current linear code window."""
        if target > 0xFFFF:
            return target
        return (int(self.addr) & ~0xFFFF) | (target & 0xFFFF)

    def _code_address_constant_8616(self, value: int) -> Any:
        """Build a VEX code-address constant without truncating the loader base."""
        return self.constant(value, Type.int_16)

    def _bp_mem(self, operand: Any, *, width_bytes: int = 2) -> _BPMemorySpec8616 | None:
        if operand.type != 3 or operand.size != width_bytes:
            return None
        mem = operand.mem
        base = self.cs.reg_name(mem.base).lower() if mem.base else None
        index = self.cs.reg_name(mem.index).lower() if mem.index else None
        if index is not None:
            return None
        if base not in {"bp", "sp"}:
            return None
        return (base, mem.disp & 0xFFFF, mem.disp)

    def _direct_mem16(self, operand: Any) -> int | None:
        if operand.type != 3 or operand.size != 2:
            return None
        mem = operand.mem
        if mem.base or mem.index:
            return None
        return int(mem.disp) & 0xFFFF

    def _direct_mem8(self, operand: Any) -> int | None:
        if operand.type != 3 or operand.size != 1:
            return None
        mem = operand.mem
        if mem.base or mem.index:
            return None
        return int(mem.disp) & 0xFFFF

    def _indexed_mem(self, operand: Any, *, width_bytes: int) -> tuple[str, int, int] | None:
        """Return one register-indexed memory operand of the requested width."""
        if operand.type != 3 or operand.size != width_bytes:
            return None
        mem = operand.mem
        base = self.cs.reg_name(mem.base).lower() if mem.base else None
        index = self.cs.reg_name(mem.index).lower() if mem.index else None
        if index is not None:
            return None
        if base not in self._REG16_NAMES or base in {"sp", "bp", "ip", "flags"}:
            return None
        return (base, mem.disp & 0xFFFF, mem.disp)

    def _addr_from_bp_mem(self, mem_spec: _BPMemorySpec8616) -> Any:
        base, _, signed_disp = mem_spec
        addr = self._get_reg16(base)
        if signed_disp == 0:
            return addr
        return addr + self._const16(signed_disp)

    def _ss_addr_from_bp_mem(self, mem_spec: _BPMemorySpec8616) -> Any:
        return self._real_mode_linear("ss", self._addr_from_bp_mem(mem_spec))

    def _record_bp_mem_access(self, mem_spec: _BPMemorySpec8616, mode: int, *, size: int = 2) -> None:
        base, _, signed_disp = mem_spec
        self._record_mem_access(
            "ss",
            int(signed_disp),
            mode,
            base=(str(base),),
            size=size,
            segment_origin=SegmentOrigin.DEFAULTED,
            status=AddressStatus.STABLE,
        )

    def _load_mem16(self, mem_spec: _BPMemorySpec8616) -> Any:
        self._record_bp_mem_access(mem_spec, 0, size=2)
        return self._load_real_mode16("ss", self._addr_from_bp_mem(mem_spec))

    def _load_mem8(self, mem_spec: _BPMemorySpec8616) -> Any:
        """Load one byte through a proven SS frame-relative address."""
        self._record_bp_mem_access(mem_spec, 0, size=1)
        return self.load(self._ss_addr_from_bp_mem(mem_spec), Type.int_8)

    def _store_mem16(self, mem_spec: _BPMemorySpec8616, value: Any) -> None:
        self._record_bp_mem_access(mem_spec, 1, size=2)
        self._store_real_mode16("ss", self._addr_from_bp_mem(mem_spec), value)

    def _record_mem_access(
        self,
        seg: str,
        offset: int,
        mode: int = 0,
        *,
        base: tuple[str, ...] = (),
        size: int = 2,
        segment_origin: SegmentOrigin | None = None,
        status: AddressStatus | None = None,
        address_bits: int | None = None,
    ) -> None:
        """Record one operand; implicit stack accesses specify their own address size."""
        from .semantics.evidence_cache import (
            get_current_function_addr,
            record_access,
        )

        addr = IRAddress(
            space=MemSpace(seg.lower()),
            base=base,
            offset=offset,
            size=size,
            status=status if status is not None else AddressStatus.STABLE,
            segment_origin=segment_origin if segment_origin is not None else SegmentOrigin.PROVEN,
            expr=(seg, *base),
        )
        func_addr = get_current_function_addr()
        if isinstance(func_addr, int):
            record_access(
                func_addr,
                mode,
                addr,
                block_addr=self.emu._inertia_current_block_addr,
                insn_addr=self.addr,
                address_bits=(self.instr.address_bits or 16) if address_bits is None else address_bits,
            )

    def _load_abs16(self, offset: int) -> Any:
        self._record_mem_access("ds", offset, 0)
        return self._load_real_mode16("ds", self._const16(offset))

    def _store_abs16(self, offset: int, value: Any) -> None:
        self._record_mem_access("ds", offset, 1)
        self._store_real_mode16("ds", self._const16(offset), value)

    def _load_abs8(self, offset: int) -> Any:
        self._record_mem_access("ds", offset, 0)
        return self.load(self._real_mode_linear("ds", self._const16(offset)), Type.int_8)

    def _addr_from_indexed_mem(self, mem_spec: Any) -> Any:
        base, _, signed_disp = mem_spec
        addr = self._get_reg16(base)
        if signed_disp == 0:
            return addr
        return addr + self._const16(signed_disp)

    def _load_indexed_abs(self, mem_spec: Any, *, width_bytes: int) -> Any:
        """Load one typed DS value through an exact indexed address."""
        base, offset, _signed_disp = mem_spec
        self._record_mem_access(
            "ds",
            int(offset),
            0,
            base=(str(base),),
            size=width_bytes,
            status=AddressStatus.PROVISIONAL,
        )
        offset = self._addr_from_indexed_mem(mem_spec)
        if width_bytes == 2:
            return self._load_real_mode16("ds", offset)
        return self.load(self._real_mode_linear("ds", offset), Type.int_8)

    def _real_mode_linear(self, seg_reg: str, off16: Any) -> Any:
        seg = self._get_reg16(seg_reg).cast_to(Type.int_32)
        off32 = off16.cast_to(Type.int_32)
        return (seg << self.constant(4, Type.int_8)) + off32

    def _load_real_mode16(self, seg_reg: str, off16: Any) -> Any:
        """Load a word through independently wrapped 16-bit segment offsets."""
        low_address = self._real_mode_linear(seg_reg, off16)
        high_offset = advance_segment_offset_8616(off16, 1, 16, self._const16(1))
        high_address = self._real_mode_linear(seg_reg, high_offset)
        low = self.load(low_address, Type.int_8).cast_to(Type.int_16)
        high = self.load(high_address, Type.int_8).cast_to(Type.int_16)
        return low | (high << self.constant(8, Type.int_8))

    def _store_real_mode16(self, seg_reg: str, off16: Any, value: Any) -> None:
        """Store a word through independently wrapped 16-bit segment offsets."""
        low_address = self._real_mode_linear(seg_reg, off16)
        high_offset = advance_segment_offset_8616(off16, 1, 16, self._const16(1))
        high_address = self._real_mode_linear(seg_reg, high_offset)
        self.store(value.cast_to(Type.int_8), low_address)
        high = (value >> self.constant(8, Type.int_8)).cast_to(Type.int_8)
        self.store(high, high_address)

    def _stack_load16(self, off16: VexValue, *, offset: int, base: str = "sp") -> VexValue:
        """Read a stack word while retaining its instruction-entry coordinate."""
        self._record_mem_access("ss", offset, 0, base=(base,), size=2, address_bits=16)
        return require_vex_value_8616(self._load_real_mode16("ss", off16))

    def _stack_store16(self, off16: VexValue, value: VexValue, *, offset: int) -> None:
        """Write a stack word while retaining its instruction-entry SP displacement."""
        self._record_mem_access("ss", offset, 1, base=("sp",), size=2, address_bits=16)
        self._store_real_mode16("ss", off16, value)

    def _eflags_value_8616(self, value: Any) -> Any:
        """Rebind one PyVEX value to the emulator's active frontend host."""
        if not isinstance(value, VexValue):
            return value
        host = self.emu.lifter_instruction
        if host is None:
            raise RuntimeError("Eflags materialization requires an active frontend host")
        return VexValue(host, value.rdt)

    def _update_binop_flags16(self, op_name: str, lhs: Any, rhs: Any) -> None:
        """Delegate defined arithmetic flags to the shared Eflags semantics owner."""
        lhs = self._eflags_value_8616(lhs)
        rhs = self._eflags_value_8616(rhs)
        if op_name == "add":
            self.emu.update_eflags_add(lhs, rhs)
            return
        if op_name == "sub":
            self.emu.update_eflags_sub(lhs, rhs)
            return
        if op_name == "xor":
            self.emu.update_eflags_xor(lhs, rhs)
            return
        if op_name == "and":
            self.emu.update_eflags_and(lhs, rhs)
            return
        if op_name == "or":
            self.emu.update_eflags_or(lhs, rhs)
            return
        raise NotImplementedError(op_name)

    def _flag_is_set(self, bit: int) -> Any:
        return (self._get_reg16("flags") & self._const16(1 << bit)) != self._const16(0)

    def _flag_is_clear(self, bit: int) -> Any:
        return (self._get_reg16("flags") & self._const16(1 << bit)) == self._const16(0)

    def _binop_reg_reg(self, op_name: str, dst_reg: str, src_reg: str) -> None:
        """Lift register arithmetic with explicit zeroing values and original flag inputs."""
        dst = self._get_reg16(dst_reg)
        src = self._get_reg16(src_reg)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = self._const16(0) if dst_reg == src_reg else dst - src
            if self._next_instruction_is_simple_jcc():
                self._record_cmp_condition_source(dst, src)
        elif op_name == "xor":
            result = self._const16(0) if dst_reg == src_reg else dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
            if not self._next_instruction_is_simple_jcc():
                self._update_binop_flags16("sub", dst, src)
            return
        else:
            raise NotImplementedError(op_name)
        logical_condition_recorded = self._record_logical_result_condition_source_8616(
            op_name,
            dst_reg,
            result,
        )
        if self._should_update_binop_flags_8616(
            op_name,
            logical_condition_recorded=logical_condition_recorded,
        ):
            self._update_binop_flags16(op_name, dst, src)
        self.put(result, dst_reg)

    def _binop_reg_imm(self, op_name: str, dst_reg: str, imm: Any) -> None:
        dst = self._get_reg16(dst_reg)
        src = self._const16(imm)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = dst - src
            if self._next_instruction_is_simple_jcc():
                normalized_operands = (
                    self._normalized_reg_imm_condition_operands_8616(
                        dst_reg,
                        int(imm),
                        width_bits=16,
                    )
                    if _affine_switch_conditions_enabled_8616()
                    else None
                )
                self._record_cmp_condition_source(
                    dst,
                    src,
                    normalized_lhs=normalized_operands[0] if normalized_operands is not None else None,
                    normalized_rhs=normalized_operands[1] if normalized_operands is not None else None,
                )
        elif op_name == "xor":
            result = dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
            if not self._next_instruction_is_simple_jcc():
                self._update_binop_flags16("sub", dst, src)
            return
        else:
            raise NotImplementedError(op_name)
        logical_condition_recorded = self._record_logical_result_condition_source_8616(
            op_name,
            dst_reg,
            result,
        )
        if self._should_update_binop_flags_8616(
            op_name,
            logical_condition_recorded=logical_condition_recorded,
        ):
            self._update_binop_flags16(op_name, dst, src)
        self.put(result, dst_reg)
        if op_name == "sub" and _affine_switch_conditions_enabled_8616():
            self._update_condition_reg_affine_offset_8616(dst_reg, int(imm), width_bits=16)

    def _binop_reg_mem(self, op_name: str, dst_reg: str, mem_spec: _BPMemorySpec8616) -> None:
        dst = self._get_reg16(dst_reg)
        src = self._load_mem16(mem_spec)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = dst - src
            if self._next_instruction_is_simple_jcc():
                self._record_cmp_condition_source(dst, src)
        elif op_name == "xor":
            result = dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
            if not self._next_instruction_is_simple_jcc():
                self._update_binop_flags16("sub", dst, src)
            return
        else:
            raise NotImplementedError(op_name)
        logical_condition_recorded = self._record_logical_result_condition_source_8616(
            op_name,
            dst_reg,
            result,
        )
        if self._should_update_binop_flags_8616(
            op_name,
            logical_condition_recorded=logical_condition_recorded,
        ):
            self._update_binop_flags16(op_name, dst, src)
        self.put(result, dst_reg)

    def _xor_reg_mem8(self, dst_reg: str, mem_spec: _BPMemorySpec8616) -> None:
        """Lift byte XOR from a proven SS frame-relative source with exact flags."""
        dst = self.get(dst_reg, Type.int_8)
        src = self._load_mem8(mem_spec)
        result = dst ^ src
        self._update_binop_flags16("xor", dst, src)
        self.put(result, dst_reg)

    def _binop_reg_abs(self, op_name: str, dst_reg: str, offset: int) -> None:
        """Lift a register/direct-memory ALU operation with typed JCC evidence."""
        dst = self._get_reg16(dst_reg)
        src = self._load_abs16(offset)
        result = self._binop_result16(op_name, dst, src)
        logical_condition_recorded = self._record_logical_result_condition_source_8616(
            op_name,
            dst_reg,
            result,
        )
        if self._should_update_binop_flags_8616(
            op_name,
            logical_condition_recorded=logical_condition_recorded,
        ):
            self._update_binop_flags16(op_name, dst, src)
        self.put(result, dst_reg)

    def _binop_abs_imm(self, op_name: str, offset: int, imm: int) -> None:
        dst = self._load_abs16(offset)
        src = self._const16(imm)
        result = self._binop_result16(op_name, dst, src)
        if self._next_instruction_is_simple_jcc():
            self._update_binop_flags16(op_name, dst, src)
        self._store_abs16(offset, result)

    def _binop_abs_reg(self, op_name: str, offset: int, src_reg: str) -> None:
        dst = self._load_abs16(offset)
        src = self._get_reg16(src_reg)
        result = self._binop_result16(op_name, dst, src)
        if self._next_instruction_is_simple_jcc():
            self._update_binop_flags16(op_name, dst, src)
        self._store_abs16(offset, result)

    def _binop_result16(self, op_name: str, dst: Any, src: Any) -> Any:
        if op_name == "add":
            return dst + src
        if op_name == "sub":
            return dst - src
        if op_name == "xor":
            return dst ^ src
        if op_name == "and":
            return dst & src
        if op_name == "or":
            return dst | src
        raise NotImplementedError(op_name)

    def _cmp_operands_from_semantics(self, semantics: tuple[Any, ...]) -> tuple[Any, Any] | None:
        """Rebuild VEX operands for a previously classified CMP instruction."""
        def _impl() -> tuple[Any, Any] | None:
            kind = semantics[0]
            if kind == "cmp_reg_reg16":
                _, lhs_reg, rhs_reg = semantics
                return self._get_reg16(lhs_reg), self._get_reg16(rhs_reg)
            if kind == "cmp_reg_imm16":
                _, lhs_reg, imm = semantics
                return self._get_reg16(lhs_reg), self._const16(imm)
            if kind == "cmp_reg_mem16":
                _, lhs_reg, mem_spec = semantics
                return self._get_reg16(lhs_reg), self._load_mem16(mem_spec)
            if kind == "cmp_reg_abs16":
                _, lhs_reg, offset = semantics
                return self._get_reg16(lhs_reg), self._load_abs16(offset)
            if kind == "cmp_mem_reg16":
                _, mem_spec, rhs_reg = semantics
                return self._load_mem16(mem_spec), self._get_reg16(rhs_reg)
            if kind == "cmp_mem_imm16":
                _, mem_spec, imm = semantics
                return self._load_mem16(mem_spec), self._const16(imm)
            if kind == "cmp_abs_reg16":
                _, offset, rhs_reg = semantics
                return self._load_abs16(offset), self._get_reg16(rhs_reg)
            if kind == "cmp_abs_imm16":
                _, offset, imm = semantics
                return self._load_abs16(offset), self._const16(imm)
            if kind == "cmp_reg_abs8":
                _, lhs_reg, offset = semantics
                return self.get(lhs_reg, Type.int_8), self._load_abs8(offset)
            if kind == "cmp_abs_reg8":
                _, offset, rhs_reg = semantics
                return self._load_abs8(offset), self.get(rhs_reg, Type.int_8)
            if kind == "cmp_abs_imm8":
                _, offset, imm = semantics
                return self._load_abs8(offset), self.constant(imm, Type.int_8)
            if kind == "cmp_indexed_abs_reg8":
                _, mem_spec, rhs_reg = semantics
                return self._load_indexed_abs(mem_spec, width_bytes=1), self.get(rhs_reg, Type.int_8)
            if kind == "cmp_reg_indexed_abs8":
                _, lhs_reg, mem_spec = semantics
                return self.get(lhs_reg, Type.int_8), self._load_indexed_abs(mem_spec, width_bytes=1)
            if kind == "cmp_indexed_abs_reg16":
                _, mem_spec, rhs_reg = semantics
                return self._load_indexed_abs(mem_spec, width_bytes=2), self._get_reg16(rhs_reg)
            if kind == "cmp_reg_indexed_abs16":
                _, lhs_reg, mem_spec = semantics
                return self._get_reg16(lhs_reg), self._load_indexed_abs(mem_spec, width_bytes=2)
            return None

        return _impl()

    def _next_instruction_is_simple_jcc(self) -> bool:
        if not self._future_instructions:
            return False
        nxt = self._future_instructions[0]
        nxt_semantics = nxt.simple_semantics
        if nxt_semantics is None:
            return False
        return nxt_semantics[0] in self._SIMPLE_JCC_8616

    def _flags_fully_overwritten_before_use_8616(
        self,
        written: StatusFlag8616 = STATUS_FLAGS_8616,
    ) -> bool:
        """Prove current status-flag definitions die in this decoded block."""
        return self.status_flag_write_is_dead_8616(written)

    def status_flag_write_is_dead_8616(self, written: StatusFlag8616) -> bool:
        """Return whether the active instruction may omit these status bits."""
        normalized_written = written & STATUS_FLAGS_8616
        return bool(self.status_flag_dead_write_mask_8616(written) == normalized_written)

    def status_flag_dead_write_mask_8616(self, written: StatusFlag8616) -> StatusFlag8616:
        """Return status bits proven dead by CFG or decoded-block evidence."""
        try:
            instruction_address = int(self.addr)
        except (AttributeError, TypeError, ValueError):
            instruction_address = -1
        cfg_dead = cfg_status_flag_dead_write_mask_8616(instruction_address, written)
        if cfg_dead is not None:
            return cfg_dead
        future = []
        for instruction in self._future_instructions:
            decoded = decoded_status_flag_instruction_8616(instruction)
            if decoded is None:
                return StatusFlag8616.NONE
            future.append(decoded)
        if status_flags_dead_before_use_8616(written, tuple(future)):
            return written & STATUS_FLAGS_8616
        return StatusFlag8616.NONE

    def _should_update_binop_flags_8616(self, op_name: str, *, logical_condition_recorded: bool) -> bool:
        """Keep live execution flags even when a logical condition was published."""
        written = binop_status_flag_writes_8616(op_name)
        return not (written is not None and self._flags_fully_overwritten_before_use_8616(written))

    def _direct_jcc_condition(self, kind: str) -> Any | None:
        def _impl() -> Any | None:
            past_instructions = getattr(self, "_past_instructions", None)
            prev = past_instructions[-1] if past_instructions else None
            prev_emu = getattr(prev, "emu", None) if prev is not None else None
            last_condition = getattr(prev_emu, "get_last_condition", lambda: None)()

            def _finish(result: Any) -> Any:
                if isinstance(last_condition, IRCondition) and prev_emu is not None:
                    cast(Any, self)._inertia_consumed_last_condition_8616 = last_condition
                    cast(Any, self)._inertia_consumed_last_condition_addr_8616 = getattr(prev, "addr", None)
                    if self._next_instruction_is_simple_jcc():
                        with contextlib.suppress(Exception):
                            self.emu.set_last_condition(last_condition)
                    else:
                        with contextlib.suppress(Exception):
                            prev_emu.clear_last_condition()
                return result

            if isinstance(last_condition, IRCondition):
                branch_cond = _direct_jcc_condition_from_last_condition_8616(cast(Any, self), kind, last_condition)
                if branch_cond is not None:
                    return _finish(branch_cond)
            prev_semantics = getattr(prev, "simple_semantics", None) if prev is not None else None
            if prev_semantics is None:
                pending = Instruction_ANY._inertia_pending_condition_sources_by_addr.get(int(self.addr))
                if isinstance(pending, ConditionSource) and pending.kind == "cmp":
                    prev_semantics = pending.semantics
            if prev_semantics is None:
                return None
            operands = self._cmp_operands_from_semantics(prev_semantics)
            if operands is None:
                return None
            lhs, rhs = operands

            if kind in JCC_EQ_MNEMONICS_8616:
                return _finish(lhs == rhs)
            if kind in JCC_NE_MNEMONICS_8616:
                return _finish(lhs != rhs)
            if kind in JCC_SLE_MNEMONICS_8616:
                return _finish(lhs.signed <= rhs.signed)
            if kind in JCC_SGT_MNEMONICS_8616:
                return _finish(lhs.signed > rhs.signed)
            if kind in JCC_SLT_MNEMONICS_8616:
                return _finish(lhs.signed < rhs.signed)
            if kind in JCC_SGE_MNEMONICS_8616:
                return _finish(lhs.signed >= rhs.signed)
            if kind in JCC_ULT_MNEMONICS_8616:
                return _finish(lhs < rhs)
            if kind in JCC_UGE_MNEMONICS_8616:
                return _finish(lhs >= rhs)
            if kind in JCC_ULE_MNEMONICS_8616:
                return _finish(lhs <= rhs)
            if kind in JCC_UGT_MNEMONICS_8616:
                return _finish(lhs > rhs)
            return None

        return _impl()

    def _condition_reg_value_8616(self, reg_name: str, *, width_bits: int = 16) -> IRValue | None:
        reg = getattr(self.arch, "registers", {}).get(reg_name.lower())
        if reg is None:
            return None
        return IRValue(
            MemSpace.REG,
            name=reg_name.lower(),
            offset=int(reg[0]),
            size=max(1, int(width_bits) // 8),
            expr=("cmp-reg",),
        )

    @staticmethod
    def _condition_unshifted_index_reg_value_8616(reg_name: str, *, width_bits: int = 16) -> IRValue | None:
        """Return one width-matched unshifted scalar index register value."""
        state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(str(reg_name).lower())
        if state is None:
            return None
        value, shift = state
        if not isinstance(value, IRValue):
            return None
        if int(shift) != 0 or value.space not in {MemSpace.SS, MemSpace.DS}:
            return None
        if value.size != max(1, int(width_bits) // 8):
            return None
        return value

    def _condition_proven_reg_value_8616(
        self,
        reg_name: str,
        *,
        width_bits: int = 16,
    ) -> IRValue | IRBinaryValue | None:
        """Return exact block-local value provenance retained for one register."""
        instruction_addr = getattr(self, "addr", None)
        if not isinstance(instruction_addr, int):
            return None
        emu = getattr(self, "emu", None)
        block_addr = getattr(
            emu,
            "_inertia_current_block_addr",
            instruction_addr,
        )
        if not isinstance(block_addr, int):
            return None
        normalized = str(reg_name).lower()
        parent = self._LOW8_PARENT_REGS.get(normalized, normalized)
        state = Instruction_ANY._inertia_condition_reg_value_state_8616.get(
            (int(block_addr), parent)
        )
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
            logger.warning(
                "[condition-provenance] lookup block=%#x reg=%s state=%r",
                int(block_addr),
                parent,
                state,
            )
        if (
            not isinstance(state, _ConditionRegisterValueState8616)
            or state.next_addr > instruction_addr
        ):
            return None
        value = state.value
        target_size = max(1, int(width_bits) // 8)
        return value if value.size == target_size else None

    @staticmethod
    def _condition_const_value_8616(value: int, *, width_bits: int = 16) -> IRValue:
        return IRValue(
            MemSpace.CONST,
            const=int(value) & ((1 << int(width_bits)) - 1),
            size=max(1, int(width_bits) // 8),
            expr=("cmp-imm",),
        )

    def _condition_direct_ds_value_8616(self, offset: int, *, width_bits: int = 16) -> IRValue:
        """Build a direct DS value tied to this instruction's memory access."""
        instruction_addr = getattr(self, "addr", None)
        access_size = max(1, int(width_bits) // 8)
        return IRValue(
            MemSpace.DS,
            offset=int(offset) & 0xFFFF,
            size=access_size,
            expr=("cmp-ds",),
            memory_access_size=access_size,
            memory_access_insn=int(instruction_addr) if isinstance(instruction_addr, int) else None,
        )

    @staticmethod
    def _condition_stack_value_8616(
        mem_spec: _BPMemorySpec8616,
        *,
        width_bits: int = 16,
    ) -> IRValue | None:
        if not (isinstance(mem_spec, tuple) and len(mem_spec) >= 3):
            return None
        base, _offset, signed_disp = mem_spec
        if base not in {"bp", "sp"} or not isinstance(signed_disp, int):
            return None
        return IRValue(
            MemSpace.SS,
            name=str(base),
            offset=int(signed_disp),
            size=max(1, int(width_bits) // 8),
            expr=("cmp-stack", str(base)),
        )

    @staticmethod
    def _condition_indexed_ds_value_8616(
        mem_spec: Any,
        index_state: Any,
        *,
        width_bits: int = 8,
        memory_access_insn: int | None = None,
    ) -> IRValue | None:
        """Build an indexed DS value with optional exact access provenance."""
        if not (isinstance(mem_spec, tuple) and len(mem_spec) >= 3):
            return None
        _base_reg, offset, _signed_disp = mem_spec
        if not (
            isinstance(index_state, tuple)
            and len(index_state) == 2
            and isinstance(index_state[0], (IRValue, IRBinaryValue))
            and isinstance(index_state[1], int)
        ):
            return None
        index_value, shift = index_state
        if isinstance(index_value, IRValue):
            stack_index = index_value.space is MemSpace.SS and index_value.name in {"bp", "sp"}
            register_index = (
                index_value.space is MemSpace.REG
                and index_value.name in Instruction_ANY._REG16_NAMES
            )
            if not stack_index and not register_index:
                return None
        access_size = max(1, int(width_bits) // 8)
        return IRValue(
            MemSpace.DS,
            offset=int(offset) & 0xFFFF,
            size=access_size,
            index=index_value,
            index_shift=int(shift),
            memory_access_size=access_size,
            memory_access_insn=memory_access_insn,
        )

    def _condition_operands_from_cmp_semantics_8616(
        self,
        semantics: tuple[Any, ...] | None,
    ) -> tuple[IRValue | IRBinaryValue, IRValue | IRBinaryValue] | None:
        """Normalize classified CMP operands into typed condition IR values."""
        if not isinstance(semantics, tuple) or not semantics:
            return None
        kind = semantics[0]
        if kind == "cmp_reg_reg16":
            _, lhs_reg, rhs_reg = semantics
            lhs = self._condition_proven_reg_value_8616(
                lhs_reg, width_bits=16
            ) or self._condition_unshifted_index_reg_value_8616(
                lhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_proven_reg_value_8616(
                rhs_reg, width_bits=16
            ) or self._condition_unshifted_index_reg_value_8616(
                rhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(rhs_reg, width_bits=16)
            return (lhs, rhs) if lhs is not None and rhs is not None else None
        if kind == "cmp_reg_imm16":
            _, lhs_reg, imm = semantics
            lhs = self._condition_proven_reg_value_8616(
                lhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_const_value_8616(imm, width_bits=16)
            return (lhs, rhs) if lhs is not None else None
        if kind == "cmp_reg_mem16":
            _, lhs_reg, mem_spec = semantics
            lhs = self._condition_proven_reg_value_8616(
                lhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_stack_value_8616(mem_spec, width_bits=16)
            return (lhs, rhs) if lhs is not None and rhs is not None else None
        if kind == "cmp_reg_abs16":
            _, lhs_reg, offset = semantics
            lhs = self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_direct_ds_value_8616(offset, width_bits=16)
            return (lhs, rhs) if lhs is not None else None
        if kind == "cmp_mem_reg16":
            _, mem_spec, rhs_reg = semantics
            lhs = self._condition_stack_value_8616(mem_spec, width_bits=16)
            rhs = self._condition_unshifted_index_reg_value_8616(
                rhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(rhs_reg, width_bits=16)
            return (lhs, rhs) if lhs is not None and rhs is not None else None
        if kind == "cmp_mem_imm16":
            _, mem_spec, imm = semantics
            lhs = self._condition_stack_value_8616(mem_spec, width_bits=16)
            if lhs is None and isinstance(mem_spec, tuple) and mem_spec:
                base_reg = str(mem_spec[0]).lower()
                index_state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(base_reg)
                if index_state is None:
                    register_index = self._condition_reg_value_8616(base_reg, width_bits=16)
                    if register_index is not None:
                        index_state = (register_index, 0)
                lhs = self._condition_indexed_ds_value_8616(
                    mem_spec,
                    index_state,
                    width_bits=16,
                    memory_access_insn=self.addr,
                )
                if lhs is None:
                    register_index = self._condition_reg_value_8616(
                        base_reg,
                        width_bits=16,
                    )
                    if register_index is not None:
                        lhs = self._condition_indexed_ds_value_8616(
                            mem_spec,
                            (register_index, 0),
                            width_bits=16,
                            memory_access_insn=self.addr,
                        )
            rhs = self._condition_const_value_8616(imm, width_bits=16)
            return (lhs, rhs) if lhs is not None else None
        if kind == "cmp_abs_reg16":
            _, offset, rhs_reg = semantics
            lhs = self._condition_direct_ds_value_8616(offset, width_bits=16)
            rhs = self._condition_unshifted_index_reg_value_8616(
                rhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(rhs_reg, width_bits=16)
            return (lhs, rhs) if rhs is not None else None
        if kind == "cmp_abs_imm16":
            _, offset, imm = semantics
            return (
                self._condition_direct_ds_value_8616(offset, width_bits=16),
                self._condition_const_value_8616(imm, width_bits=16),
            )
        if kind == "cmp_reg_abs8":
            _, lhs_reg, offset = semantics
            lhs = self._condition_reg_value_8616(lhs_reg, width_bits=8)
            rhs = self._condition_direct_ds_value_8616(offset, width_bits=8)
            return (lhs, rhs) if lhs is not None else None
        if kind == "cmp_reg_imm8":
            _, lhs_reg, imm = semantics
            lhs = self._condition_proven_reg_value_8616(
                lhs_reg, width_bits=8
            ) or self._condition_reg_value_8616(lhs_reg, width_bits=8)
            rhs = self._condition_const_value_8616(imm, width_bits=8)
            return (lhs, rhs) if lhs is not None else None
        if kind == "cmp_abs_reg8":
            _, offset, rhs_reg = semantics
            lhs = self._condition_direct_ds_value_8616(offset, width_bits=8)
            rhs = self._condition_reg_value_8616(rhs_reg, width_bits=8)
            return (lhs, rhs) if rhs is not None else None
        if kind == "cmp_abs_imm8":
            _, offset, imm = semantics
            return (
                self._condition_direct_ds_value_8616(offset, width_bits=8),
                self._condition_const_value_8616(imm, width_bits=8),
            )
        if kind in {"cmp_indexed_abs_reg8", "cmp_reg_indexed_abs8"}:
            _, first, second = semantics
            mem_spec = first if kind == "cmp_indexed_abs_reg8" else second
            reg_name = second if kind == "cmp_indexed_abs_reg8" else first
            base_reg = str(mem_spec[0]).lower() if isinstance(mem_spec, tuple) and mem_spec else ""
            index_state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(base_reg)
            indexed = Instruction_ANY._condition_indexed_ds_value_8616(
                mem_spec,
                index_state,
                width_bits=8,
                memory_access_insn=(
                    int(self.addr)
                    if isinstance(getattr(self, "addr", None), int)
                    else None
                ),
            )
            if indexed is None:
                register_index = self._condition_reg_value_8616(base_reg, width_bits=16)
                if register_index is not None:
                    indexed = Instruction_ANY._condition_indexed_ds_value_8616(
                        mem_spec,
                        (register_index, 0),
                        width_bits=8,
                        memory_access_insn=self.addr,
                    )
            register = self._condition_proven_reg_value_8616(
                reg_name,
                width_bits=8,
            ) or self._condition_reg_value_8616(reg_name, width_bits=8)
            if indexed is None or register is None:
                return None
            return (indexed, register) if kind == "cmp_indexed_abs_reg8" else (register, indexed)
        if kind in {"cmp_indexed_abs_reg16", "cmp_reg_indexed_abs16"}:
            _, first, second = semantics
            mem_spec = first if kind == "cmp_indexed_abs_reg16" else second
            reg_name = second if kind == "cmp_indexed_abs_reg16" else first
            base_reg = str(mem_spec[0]).lower()
            index_state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(base_reg)
            indexed = Instruction_ANY._condition_indexed_ds_value_8616(
                mem_spec,
                index_state,
                width_bits=16,
                memory_access_insn=self.addr,
            )
            if indexed is None:
                register_index = self._condition_reg_value_8616(base_reg, width_bits=16)
                if register_index is not None:
                    indexed = Instruction_ANY._condition_indexed_ds_value_8616(
                        mem_spec,
                        (register_index, 0),
                        width_bits=16,
                        memory_access_insn=self.addr,
                    )
            register = self._condition_proven_reg_value_8616(
                reg_name,
                width_bits=16,
            ) or self._condition_reg_value_8616(reg_name, width_bits=16)
            if indexed is None or register is None:
                return None
            return (indexed, register) if kind == "cmp_indexed_abs_reg16" else (register, indexed)
        if kind == "sub_reg_reg16":
            _, lhs_reg, rhs_reg = semantics
            lhs = self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_reg_value_8616(rhs_reg, width_bits=16)
            return (lhs, rhs) if lhs is not None and rhs is not None else None
        if kind == "sub_reg_mem16":
            _, lhs_reg, mem_spec = semantics
            lhs = self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_stack_value_8616(mem_spec, width_bits=16)
            return (lhs, rhs) if lhs is not None and rhs is not None else None
        if kind == "sub_reg_imm16":
            _, lhs_reg, imm = semantics
            lhs = self._condition_reg_value_8616(lhs_reg, width_bits=16)
            rhs = self._condition_const_value_8616(imm, width_bits=16)
            return (lhs, rhs) if lhs is not None else None
        if kind in {"inc_reg16", "dec_reg16"}:
            _, lhs_reg, operation_count = semantics
            lhs = self._condition_proven_reg_value_8616(
                lhs_reg, width_bits=16
            ) or self._condition_reg_value_8616(lhs_reg, width_bits=16)
            boundary = (
                (-int(operation_count)) & 0xFFFF
                if kind == "inc_reg16"
                else int(operation_count)
            )
            rhs = self._condition_const_value_8616(boundary, width_bits=16)
            return (lhs, rhs) if lhs is not None else None
        return None

    def _condition_reg_affine_state_8616(
        self,
        reg_name: str,
        *,
        width_bits: int = 16,
    ) -> tuple[IRValue, int] | None:
        reg_name = reg_name.lower()
        state = Instruction_ANY._inertia_condition_reg_affine_state_8616
        if not isinstance(state, dict):
            state = {}
            Instruction_ANY._inertia_condition_reg_affine_state_8616 = state
        current = state.get(reg_name)
        if (
            isinstance(current, tuple)
            and len(current) == 2
            and isinstance(current[0], IRValue)
            and isinstance(current[1], int)
        ):
            return current
        base = self._condition_reg_value_8616(reg_name, width_bits=width_bits)
        if base is None:
            return None
        current = (base, 0)
        state[reg_name] = current
        return current

    def _update_condition_reg_affine_offset_8616(
        self,
        reg_name: str,
        delta: int,
        *,
        width_bits: int = 16,
    ) -> None:
        state = Instruction_ANY._inertia_condition_reg_affine_state_8616
        current = self._condition_reg_affine_state_8616(reg_name, width_bits=width_bits)
        if current is None or not isinstance(state, dict):
            return
        base, offset = current
        mask = (1 << int(width_bits)) - 1
        state[reg_name.lower()] = (base, (int(offset) + int(delta)) & mask)

    def _restore_condition_reg_affine_snapshot_8616(self) -> None:
        if not _affine_switch_conditions_enabled_8616():
            return
        snapshot = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616.get(int(self.addr))
        if isinstance(snapshot, dict):
            Instruction_ANY._inertia_condition_reg_affine_state_8616 = dict(snapshot)

    @staticmethod
    def _condition_target_addr_8616(target: object) -> int | None:
        if isinstance(target, int):
            return int(target)
        value = getattr(target, "value", None)
        if isinstance(value, int):
            return int(value)
        con = getattr(target, "con", None)
        con_value = getattr(con, "value", None)
        if isinstance(con_value, int):
            return int(con_value)
        args = getattr(target, "args", None)
        if isinstance(args, tuple) and args and isinstance(args[0], int):
            return int(args[0])
        return None

    @staticmethod
    def _snapshot_condition_reg_affine_state_8616(target: object) -> None:
        if not _affine_switch_conditions_enabled_8616():
            return
        target_addr = Instruction_ANY._condition_target_addr_8616(target)
        if target_addr is None:
            return
        state = Instruction_ANY._inertia_condition_reg_affine_state_8616
        if isinstance(state, dict):
            Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616[target_addr] = dict(state)

    def _clear_condition_index_reg_state_8616(self, reg_name: str) -> None:
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if isinstance(state, dict):
            state.pop(str(reg_name).lower(), None)

    def _clear_condition_reg_value_state_8616(self, reg_name: str) -> None:
        """Forget transient exact-value provenance after a register write."""
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        if not isinstance(state, dict):
            return
        block_addr = getattr(
            self.emu,
            "_inertia_current_block_addr",
            self.addr,
        )
        if not isinstance(block_addr, int):
            return
        normalized = str(reg_name).lower()
        parent = self._LOW8_PARENT_REGS.get(normalized, normalized)
        state.pop((int(block_addr), parent), None)

    def _reset_condition_reg_value_state_at_block_entry_8616(self) -> None:
        """Discard stale provenance when a basic block is lifted again."""
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        instruction_addr = getattr(self, "addr", None)
        if not isinstance(instruction_addr, int):
            return
        emu = getattr(self, "emu", None)
        block_addr = getattr(
            emu,
            "_inertia_current_block_addr",
            instruction_addr,
        )
        if (
            not isinstance(state, dict)
            or not isinstance(block_addr, int)
            or instruction_addr != int(block_addr)
        ):
            return
        stale_keys = tuple(
            key
            for key in state
            if isinstance(key, tuple)
            and len(key) == 2
            and key[0] == int(block_addr)
        )
        for key in stale_keys:
            state.pop(key, None)

    def _set_condition_reg_value_state_8616(
        self,
        reg_name: str,
        value: IRValue | IRBinaryValue,
    ) -> None:
        """Bind one exact value to a register in the current basic block."""
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        block_addr = getattr(
            self.emu,
            "_inertia_current_block_addr",
            self.addr,
        )
        if not isinstance(state, dict) or not isinstance(block_addr, int):
            return
        normalized = str(reg_name).lower()
        parent = self._LOW8_PARENT_REGS.get(normalized, normalized)
        state[(int(block_addr), parent)] = _ConditionRegisterValueState8616(
            value=value,
            next_addr=int(self.addr) + int(self.cs.size),
        )

    def _copy_condition_reg_value_state_8616(
        self,
        dst_reg: str,
        src_reg: str,
    ) -> None:
        """Copy exact-value provenance between equal-width register views."""
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        if not isinstance(state, dict):
            return
        block_addr = getattr(
            self.emu,
            "_inertia_current_block_addr",
            self.addr,
        )
        if not isinstance(block_addr, int):
            return
        dst_name = str(dst_reg).lower()
        src_name = str(src_reg).lower()
        dst_key = self._LOW8_PARENT_REGS.get(dst_name, dst_name)
        src_key = self._LOW8_PARENT_REGS.get(src_name, src_name)
        if (dst_name in self._REG8_NAMES and dst_name not in self._LOW8_PARENT_REGS) or (
            src_name in self._REG8_NAMES and src_name not in self._LOW8_PARENT_REGS
        ):
            state.pop((int(block_addr), dst_key), None)
            return
        source = state.get((int(block_addr), src_key))
        if (
            isinstance(source, _ConditionRegisterValueState8616)
            and source.next_addr <= int(self.addr)
        ):
            state[(int(block_addr), dst_key)] = (
                _ConditionRegisterValueState8616(
                    value=source.value,
                    next_addr=int(self.addr) + int(self.cs.size),
                )
            )
        else:
            state.pop((int(block_addr), dst_key), None)

    def _widen_condition_reg_value_state_8616(self, reg_name: str) -> None:
        """Carry a contiguous low-byte provenance through CBW/CWDE."""
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        if not isinstance(state, dict):
            return
        block_addr = getattr(
            self.emu,
            "_inertia_current_block_addr",
            self.addr,
        )
        if not isinstance(block_addr, int):
            return
        key = (int(block_addr), str(reg_name).lower())
        source = state.get(key)
        if (
            not isinstance(source, _ConditionRegisterValueState8616)
            or source.next_addr > int(self.addr)
            or source.value.size != 1
        ):
            state.pop(key, None)
            return
        state[key] = _ConditionRegisterValueState8616(
            value=replace(source.value, size=2),
            next_addr=int(self.addr) + int(self.cs.size),
        )

    def _set_condition_reg_indexed_value_8616(
        self,
        reg_name: str,
        mem_spec: Any,
        *,
        width_bits: int,
    ) -> None:
        """Record a load whose DS address is proven from stack index state."""
        normalized = str(reg_name).lower()
        parent = self._LOW8_PARENT_REGS.get(normalized, normalized)
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        if parent not in self._REG16_NAMES or not isinstance(state, dict):
            return
        block_addr = getattr(
            self.emu,
            "_inertia_current_block_addr",
            self.addr,
        )
        if not isinstance(block_addr, int):
            return
        state_key = (int(block_addr), parent)
        base_reg = (
            str(mem_spec[0]).lower()
            if isinstance(mem_spec, tuple) and mem_spec
            else ""
        )
        value = self._condition_indexed_ds_value_8616(
            mem_spec,
            Instruction_ANY._inertia_condition_index_reg_state_8616.get(
                base_reg
            ),
            width_bits=width_bits,
            memory_access_insn=(
                int(self.addr)
                if isinstance(getattr(self, "addr", None), int)
                else None
            ),
        )
        if value is None:
            state.pop(state_key, None)
            if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                logger.warning(
                    "[condition-provenance] refuse indexed-load block=%#x reg=%s "
                    "base_reg=%s mem_spec=%r index_state=%r",
                    int(block_addr),
                    parent,
                    base_reg,
                    mem_spec,
                    Instruction_ANY._inertia_condition_index_reg_state_8616.get(
                        base_reg
                    ),
                )
            return
        state[state_key] = _ConditionRegisterValueState8616(
            value=value,
            next_addr=int(self.addr) + int(self.cs.size),
        )
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
            logger.warning(
                "[condition-provenance] record indexed-load block=%#x reg=%s value=%r",
                int(block_addr),
                parent,
                value,
            )

    def _set_condition_reg_direct_byte_value_8616(
        self,
        reg_name: str,
        offset: int,
    ) -> None:
        """Record a byte load from one exact DS offset."""
        normalized = str(reg_name).lower()
        parent = self._LOW8_PARENT_REGS.get(normalized)
        state = Instruction_ANY._inertia_condition_reg_value_state_8616
        if parent is None or not isinstance(state, dict):
            return
        block_addr = getattr(
            self.emu,
            "_inertia_current_block_addr",
            self.addr,
        )
        if not isinstance(block_addr, int):
            return
        state[(int(block_addr), parent)] = _ConditionRegisterValueState8616(
            value=self._condition_direct_ds_value_8616(
                offset,
                width_bits=8,
            ),
            next_addr=int(self.addr) + int(self.cs.size),
        )

    def _copy_condition_index_reg_state_8616(self, dst_reg: str, src_reg: str) -> None:
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if not isinstance(state, dict):
            return
        src_state = state.get(str(src_reg).lower())
        if src_state is None:
            state.pop(str(dst_reg).lower(), None)
            return
        state[str(dst_reg).lower()] = src_state

    def _set_condition_index_reg_stack_state_8616(self, reg_name: str, mem_spec: Any) -> None:
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        stack_value = self._condition_stack_value_8616(mem_spec, width_bits=16)
        if not isinstance(state, dict) or stack_value is None:
            return
        state[str(reg_name).lower()] = (stack_value, 0)
        self._set_condition_reg_value_state_8616(reg_name, stack_value)

    def _set_condition_index_reg_direct_state_8616(self, reg_name: str, offset: int) -> None:
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if not isinstance(state, dict):
            return
        value = self._condition_direct_ds_value_8616(offset, width_bits=16)
        state[str(reg_name).lower()] = (value, 0)
        self._set_condition_reg_value_state_8616(reg_name, value)

    def _arithmetic_result_value_from_semantics_8616(
        self,
        semantics: tuple[Any, ...],
    ) -> tuple[str, IRBinaryValue] | None:
        """Build one exact register arithmetic value from block-local provenance."""
        if not semantics:
            return None
        kind = str(semantics[0])
        operation = kind.partition("_")[0]
        if operation not in {"add", "sub"}:
            return None
        dst_reg = str(semantics[1]).lower()
        lhs = self._condition_proven_reg_value_8616(dst_reg, width_bits=16)
        if lhs is None:
            lhs = self._condition_unshifted_index_reg_value_8616(
                dst_reg,
                width_bits=16,
            )
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
            logger.warning(
                "[condition-provenance] arithmetic-input block=%r insn=%#x "
                "semantics=%r lhs=%r",
                getattr(
                    getattr(self, "emu", None),
                    "_inertia_current_block_addr",
                    None,
                ),
                int(self.addr),
                semantics,
                lhs,
            )
        if not isinstance(lhs, (IRValue, IRBinaryValue)):
            return None
        rhs: IRValue | IRBinaryValue | None = None
        operand = semantics[2]
        if kind in {"add_reg_mem16", "sub_reg_mem16"}:
            rhs = self._condition_stack_value_8616(operand, width_bits=16)
        elif kind in {"add_reg_reg16", "sub_reg_reg16"}:
            rhs_reg = str(operand).lower()
            rhs = self._condition_proven_reg_value_8616(
                rhs_reg,
                width_bits=16,
            ) or self._condition_unshifted_index_reg_value_8616(
                rhs_reg,
                width_bits=16,
            )
        elif kind in {"add_reg_imm16", "sub_reg_imm16"} and isinstance(operand, int):
            rhs = self._condition_const_value_8616(
                operand,
                width_bits=16,
            )
        if not isinstance(rhs, (IRValue, IRBinaryValue)):
            return None
        result = IRBinaryValue(operation, lhs, rhs, size=2)
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
            logger.warning(
                "[condition-provenance] arithmetic block=%r insn=%#x reg=%s value=%r",
                getattr(
                    getattr(self, "emu", None),
                    "_inertia_current_block_addr",
                    None,
                ),
                int(self.addr),
                dst_reg,
                result,
            )
        return dst_reg, result

    def _set_condition_arithmetic_result_state_8616(
        self,
        result: tuple[str, IRBinaryValue] | None,
    ) -> None:
        """Retain exact arithmetic value and index provenance after a register write."""
        if result is None:
            return
        reg_name, value = result
        index_state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if isinstance(index_state, dict):
            index_state[reg_name] = (value, 0)
        self._set_condition_reg_value_state_8616(reg_name, value)

    def _full_lift_written_condition_registers_8616(self) -> tuple[str, ...]:
        """Return Capstone-proven written register families tracked by ConditionIR."""
        try:
            _read_ids, write_ids = self.cs.regs_access()
        except Exception:
            return ()
        names: set[str] = set()
        for reg_id in write_ids:
            name = str(self.cs.reg_name(int(reg_id))).lower()
            names.add(self._LOW8_PARENT_REGS.get(name, name))
        return tuple(sorted(name for name in names if name in self._REG16_NAMES))

    def _transfer_full_lift_condition_value_semantics_8616(self) -> None:
        """Update typed value provenance after normal Instr16 machine lifting."""
        semantics = self.condition_value_semantics
        byte_copy: tuple[str, str] | None = None
        preserved_shift_reg: str | None = None
        if semantics is None:
            operands = tuple(self.cs.operands)
            if self.cs.mnemonic == "mov" and len(operands) == 2:
                dst_reg8 = self._reg8_name(operands[0])
                src_reg8 = self._reg8_name(operands[1])
                if dst_reg8 is not None and src_reg8 is not None:
                    byte_copy = dst_reg8, src_reg8
            if self.cs.mnemonic in {"inc", "dec"}:
                reg_name = self._reg16_name(operands[0]) if len(operands) == 1 else None
                if reg_name is not None and reg_name not in {"sp", "bp"}:
                    operation = "add" if self.cs.mnemonic == "inc" else "sub"
                    semantics = (f"{operation}_reg_imm16", reg_name, 1)
            if self.cs.mnemonic in {"sal", "shl"} and len(operands) == 2:
                reg_name = self._reg16_name(operands[0])
                shift = self._imm16_value(operands[1])
                if (
                    reg_name is not None
                    and shift is not None
                    and 0 <= shift < 16
                    and self._shift_condition_index_reg_state_8616(
                        reg_name,
                        shift,
                    )
                ):
                    preserved_shift_reg = reg_name
        result = self._arithmetic_result_value_from_semantics_8616(semantics) if semantics is not None else None
        logical_operation = str(semantics[0]).partition("_")[0] if semantics is not None else ""
        if semantics is not None and logical_operation in {"and", "or", "xor"}:
            self._record_logical_result_condition_source_8616(
                logical_operation,
                str(semantics[1]),
                object(),
            )
        if semantics is not None and str(semantics[0]).startswith("cmp_"):
            typed_operands = self._condition_operands_from_cmp_semantics_8616(semantics)
            if typed_operands is not None:
                self._record_cmp_condition_source(
                    *typed_operands,
                    normalized_lhs=typed_operands[0],
                    normalized_rhs=typed_operands[1],
                    producer_semantics=semantics,
                )
        if semantics is not None and str(semantics[0]).startswith("test_"):
            kind, location, immediate = cast(tuple[str, object, int], semantics)
            width_bits = 8 if kind.endswith("imm8") else 16
            typed_value = (
                self._condition_stack_value_8616(
                    cast(_BPMemorySpec8616, location),
                    width_bits=width_bits,
                )
                if kind.startswith("test_mem_")
                else self._condition_direct_ds_value_8616(
                    cast(int, location),
                    width_bits=width_bits,
                )
            )
            if typed_value is not None:
                typed_mask = self._condition_const_value_8616(
                    immediate,
                    width_bits=width_bits,
                )
                normalized = IRBinaryValue(
                    op="and",
                    lhs=typed_value,
                    rhs=typed_mask,
                    size=width_bits // 8,
                )
                self._record_test_condition_source(
                    normalized,
                    width_bits=width_bits,
                    normalized_value=normalized,
                    producer_semantics=semantics,
                )
        written_registers = set(self._full_lift_written_condition_registers_8616())
        if result is not None:
            written_registers.add(result[0])
        for reg_name in written_registers:
            if reg_name != preserved_shift_reg:
                self._clear_condition_index_reg_state_8616(reg_name)
            self._clear_condition_reg_value_state_8616(reg_name)
        self._set_condition_arithmetic_result_state_8616(result)
        if semantics is not None and str(semantics[0]) == "mov_reg_mem16":
            self._set_condition_index_reg_stack_state_8616(
                str(semantics[1]),
                semantics[2],
            )
        elif semantics is not None and str(semantics[0]) == "mov_reg_abs16":
            self._set_condition_index_reg_direct_state_8616(
                str(semantics[1]),
                int(semantics[2]),
            )
        elif semantics is not None and str(semantics[0]) == "mov_reg_indexed_abs16":
            self._set_condition_reg_indexed_value_8616(
                str(semantics[1]),
                semantics[2],
                width_bits=16,
            )
        if byte_copy is not None:
            self._copy_condition_reg_value_state_8616(*byte_copy)

    def _shift_condition_index_reg_state_8616(self, reg_name: str, shift: int) -> bool:
        """Apply one proven left shift to an exact typed index register."""
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        current = state.get(str(reg_name).lower()) if isinstance(state, dict) else None
        if (
            not isinstance(state, dict)
            or not isinstance(current, tuple)
            or len(current) != 2
            or not isinstance(current[0], (IRValue, IRBinaryValue))
            or not isinstance(current[1], int)
        ):
            return False
        state[str(reg_name).lower()] = (current[0], int(current[1]) + int(shift))
        return True

    def _normalized_reg_imm_condition_operands_8616(
        self,
        reg_name: str,
        imm: int,
        *,
        width_bits: int = 16,
    ) -> tuple[IRValue, IRValue] | None:
        current = self._condition_reg_affine_state_8616(reg_name, width_bits=width_bits)
        if current is None:
            return None
        base, offset = current
        return (
            base,
            self._condition_const_value_8616(int(offset) + int(imm), width_bits=width_bits),
        )

    def _record_cmp_condition_source(
        self,
        lhs: Any,
        rhs: Any,
        *,
        width_bits: int = 16,
        normalized_lhs: Any | None = None,
        normalized_rhs: Any | None = None,
        producer_semantics: tuple[Any, ...] | None = None,
    ) -> None:
        """Record CMP operands on the emulator for downstream JCC consumption."""
        semantics = producer_semantics if producer_semantics is not None else getattr(self, "simple_semantics", None)
        if (
            normalized_lhs is None
            and normalized_rhs is None
            and isinstance(semantics, tuple)
        ):
            typed_operands = self._condition_operands_from_cmp_semantics_8616(
                semantics
            )
            if typed_operands is not None:
                normalized_lhs, normalized_rhs = typed_operands
        if (
            _affine_switch_conditions_enabled_8616()
            and isinstance(semantics, tuple)
            and len(semantics) >= 3
            and semantics[0] == "cmp_reg_imm16"
        ):
            reg_name = str(semantics[1]).lower()
            base = self._condition_reg_value_8616(reg_name, width_bits=width_bits)
            if base is not None:
                Instruction_ANY._inertia_condition_reg_affine_state_8616[reg_name] = (base, 0)
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        source = ConditionSource(
            kind="cmp",
            lhs=lhs,
            rhs=rhs,
            normalized_lhs=normalized_lhs,
            normalized_rhs=normalized_rhs,
            semantics=semantics,
            width_bits=width_bits,
            addr=self.addr,
            block_addr=block_addr if isinstance(block_addr, int) else None,
            register_bindings=snapshot_condition_register_bindings_8616(
                Instruction_ANY._inertia_condition_reg_value_state_8616,
                block_addr if isinstance(block_addr, int) else None,
                self.addr,
            ),
        )
        cast(Any, self.emu)._inertia_last_condition_source = source

    def _record_test_condition_source(
        self,
        value: Any,
        *,
        width_bits: int = 16,
        normalized_value: IRValue | IRBinaryValue | None = None,
        bind_operand_at_jcc: bool = False,
        producer_semantics: tuple[Any, ...] | None = None,
    ) -> None:
        """Record TEST/self-test operands for downstream JCC consumption."""
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        source = ConditionSource(
            kind="test",
            lhs=value,
            rhs=None,
            normalized_lhs=normalized_value,
            semantics=producer_semantics,
            width_bits=width_bits,
            addr=self.addr,
            block_addr=block_addr if isinstance(block_addr, int) else None,
            bind_operand_at_jcc=bind_operand_at_jcc,
            register_bindings=snapshot_condition_register_bindings_8616(
                Instruction_ANY._inertia_condition_reg_value_state_8616,
                block_addr if isinstance(block_addr, int) else None,
                self.addr,
            ),
        )
        cast(Any, self.emu)._inertia_last_condition_source = source

    def _logical_result_value_from_semantics_8616(
        self,
        op_name: str,
        dst_reg: str,
    ) -> IRBinaryValue | None:
        """Build the typed value computed by a logical register ALU instruction."""
        semantics = self.simple_semantics or self.condition_value_semantics
        if not isinstance(semantics, tuple) or len(semantics) < 3:
            return None
        kind = str(semantics[0])
        expected_prefix = f"{op_name}_reg_"
        if not kind.startswith(expected_prefix):
            return None
        lhs = (
            self._condition_proven_reg_value_8616(dst_reg, width_bits=16)
            or self._condition_unshifted_index_reg_value_8616(dst_reg, width_bits=16)
            or self._condition_reg_value_8616(dst_reg, width_bits=16)
        )
        if lhs is None:
            return None
        rhs: IRValue | None = None
        operand = semantics[2]
        if kind.endswith("_reg16") and isinstance(operand, str):
            rhs = self._condition_unshifted_index_reg_value_8616(
                operand,
                width_bits=16,
            ) or self._condition_reg_value_8616(operand, width_bits=16)
        elif kind.endswith("_mem16"):
            rhs = self._condition_stack_value_8616(operand, width_bits=16)
        elif kind.endswith("_abs16") and isinstance(operand, int):
            rhs = self._condition_direct_ds_value_8616(operand, width_bits=16)
        elif kind.endswith("_imm16") and isinstance(operand, int):
            rhs = self._condition_const_value_8616(operand, width_bits=16)
        if rhs is None:
            return None
        return IRBinaryValue(op=op_name, lhs=lhs, rhs=rhs, size=2)

    def _record_logical_result_condition_source_8616(
        self,
        op_name: str,
        dst_reg: str,
        result: Any,
    ) -> bool:
        """Record a logical ALU result consumed immediately by a JCC."""
        if op_name not in {"xor", "and", "or"} or not self._next_instruction_is_simple_jcc():
            return False
        result_value = self._logical_result_value_from_semantics_8616(op_name, dst_reg)
        if result_value is None:
            return False
        semantics = self.simple_semantics if isinstance(self.simple_semantics, tuple) else None
        self._record_test_condition_source(
            result,
            normalized_value=result_value,
            producer_semantics=semantics,
        )
        self.emu.set_last_condition(IRCondition(op="zero", args=(result_value,), expr=("logical-result", op_name)))
        return True

    def _typed_condition_from_consumed_ir_condition_8616(
        self,
        condition: IRCondition,
        jcc_mnemonic: str,
        *,
        block_addr: int | None,
        taken_target: int | None,
        fallthrough_target: int | None,
    ) -> ConditionIR | ConditionFailure | None:
        args = tuple(condition.args or ())
        op = str(condition.op)
        producer_insn = getattr(self, "_inertia_consumed_last_condition_addr_8616", None)
        if condition.expr and condition.expr[0] in {"update_eflags_inc", "update_eflags_dec"}:  # noqa: SIM102
            if jcc_mnemonic not in JCC_EQ_MNEMONICS_8616 | JCC_NE_MNEMONICS_8616:
                return None
        if op in {"compare", "eq", "ne", "slt", "sle", "sgt", "sge", "ult", "ule", "ugt", "uge"} and len(args) == 2:
            return build_condition_from_cmp_8616(
                args[0],
                args[1],
                jcc_mnemonic,
                width_bits=max(1, int(getattr(args[0], "size", 0) or getattr(args[1], "size", 0) or 2)) * 8,
                src_insn=self.addr,
                block_addr=block_addr,
                producer_insn=producer_insn if isinstance(producer_insn, int) else None,
                taken_target=taken_target,
                fallthrough_target=fallthrough_target,
            )
        if op in {"zero", "nonzero", "masked_zero", "masked_nonzero"} and args:
            value = args[0]
            value_size = value.size if isinstance(value, (IRValue, IRBinaryValue)) else 2
            return build_condition_from_test_8616(
                value,
                jcc_mnemonic,
                width_bits=max(1, int(value_size or 2)) * 8,
                src_insn=self.addr,
                block_addr=block_addr,
                producer_insn=producer_insn if isinstance(producer_insn, int) else None,
                taken_target=taken_target,
                fallthrough_target=fallthrough_target,
            )
        return None

    def record_loop_counter_condition_8616(
        self,
        counter_name: str,
        counter_size: int,
        displacement: int,
        instruction_size: int,
    ) -> None:
        """Record the exact post-decrement counter condition owned by plain LOOP."""
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        counter_offset = int(self.arch.get_register_offset(counter_name))
        self._record_typed_condition_8616(
            ConditionIR(
                op="ne",
                lhs=IRValue(
                    MemSpace.REG,
                    name=counter_name,
                    offset=counter_offset,
                    size=counter_size,
                ),
                rhs=IRValue(MemSpace.CONST, const=1, size=counter_size),
                width_bits=counter_size * 8,
                source=("loop",),
                src_insn=self.addr,
                block_addr=block_addr,
                producer_insn=self.addr,
                operand_bind_insn=self.addr,
                producer_semantics=(
                    "loop_counter_predecrement",
                    counter_name,
                    1,
                ),
                taken_target=self.addr + instruction_size + displacement,
                fallthrough_target=self.addr + instruction_size,
            )
        )

    def _emit_simple_jcc(self, taken_cond: Any, target: Any) -> None:
        # Before emitting, record the typed ConditionIR if source available
        Instruction_ANY._snapshot_condition_reg_affine_state_8616(target)
        target_addr = Instruction_ANY._condition_target_addr_8616(target)
        fallthrough_addr: int | None = None
        with contextlib.suppress(Exception):
            fallthrough_size = int(getattr(getattr(self, "cs", None), "size", 0) or 2)
            candidate_fallthrough = int(self.addr) + fallthrough_size
            if candidate_fallthrough != int(self.addr):
                fallthrough_addr = candidate_fallthrough
        source = getattr(self.emu, "_inertia_last_condition_source", None)
        if not isinstance(source, ConditionSource) and getattr(self, "_past_instructions", None):
            prev_emu = getattr(self._past_instructions[-1], "emu", None)
            source = getattr(prev_emu, "_inertia_last_condition_source", None)
        if not isinstance(source, ConditionSource):
            source = Instruction_ANY._inertia_pending_condition_sources_by_addr.pop(int(self.addr), None)
        jcc_mnemonic = self.simple_semantics[0] if self.simple_semantics else ""
        block_addr = getattr(self.emu, "_inertia_current_block_addr", None)
        if isinstance(source, ConditionSource):
            if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                logger.warning(
                    "[condition-provenance] consume jcc=%#x block=%r semantics=%r "
                    "state_keys=%r",
                    int(self.addr),
                    block_addr,
                    source.semantics,
                    tuple(
                        sorted(
                            Instruction_ANY._inertia_condition_reg_value_state_8616
                        )
                    ),
                )
            if not isinstance(block_addr, int):
                block_addr = source.block_addr
            with contextlib.suppress(Exception):
                cast(Any, self.emu)._inertia_last_condition_source = source
            typed_cmp_operands = self._condition_operands_from_cmp_semantics_8616(source.semantics)
            lhs = source.lhs
            rhs = source.rhs
            if source.kind == "cmp" and typed_cmp_operands is not None:
                lhs, rhs = typed_cmp_operands
            if source.kind == "cmp" and source.normalized_lhs is not None and source.normalized_rhs is not None:
                lhs = source.normalized_lhs
                rhs = source.normalized_rhs
                source.lhs = lhs
                source.rhs = rhs
            if source.kind == "test" and source.normalized_lhs is not None:
                lhs = source.normalized_lhs
                source.lhs = lhs
            with contextlib.suppress(Exception):
                if fallthrough_addr is not None:
                    Instruction_ANY._inertia_pending_condition_sources_by_addr[fallthrough_addr] = ConditionSource(
                        kind=source.kind,
                        lhs=lhs,
                        rhs=rhs,
                        normalized_lhs=source.normalized_lhs,
                        normalized_rhs=source.normalized_rhs,
                        semantics=source.semantics,
                        fallthrough_from_jcc=jcc_mnemonic,
                        width_bits=source.width_bits,
                        addr=source.addr,
                        block_addr=source.block_addr,
                        bind_operand_at_jcc=source.bind_operand_at_jcc,
                        register_bindings=source.register_bindings,
                    )
                if isinstance(target_addr, int) and target_addr not in {int(self.addr), fallthrough_addr}:
                    Instruction_ANY._inertia_pending_condition_sources_by_addr[target_addr] = ConditionSource(
                        kind=source.kind,
                        lhs=lhs,
                        rhs=rhs,
                        normalized_lhs=source.normalized_lhs,
                        normalized_rhs=source.normalized_rhs,
                        semantics=source.semantics,
                        width_bits=source.width_bits,
                        addr=source.addr,
                        block_addr=source.block_addr,
                        bind_operand_at_jcc=source.bind_operand_at_jcc,
                        register_bindings=source.register_bindings,
                    )
            if source.kind == "cmp":
                cond_ir = build_condition_from_cmp_8616(
                    lhs,
                    rhs,
                    jcc_mnemonic,
                    width_bits=source.width_bits,
                    src_insn=self.addr,
                    block_addr=block_addr if isinstance(block_addr, int) else None,
                    producer_insn=source.addr,
                    taken_target=target_addr,
                    fallthrough_target=fallthrough_addr,
                    producer_semantics=source.semantics,
                    register_bindings=source.register_bindings,
                )
            elif source.kind == "test":
                cond_ir = build_condition_from_test_8616(
                    lhs,
                    jcc_mnemonic,
                    width_bits=source.width_bits,
                    src_insn=self.addr,
                    block_addr=block_addr if isinstance(block_addr, int) else None,
                    producer_insn=source.addr,
                    taken_target=target_addr,
                    fallthrough_target=fallthrough_addr,
                    operand_bind_insn=self.addr if source.bind_operand_at_jcc else None,
                    producer_semantics=source.semantics,
                    register_bindings=source.register_bindings,
                )
            else:
                cond_ir = ConditionFailure(
                    "unknown_condition_source_kind",
                    source=("jcc", jcc_mnemonic),
                    detail=f"kind={source.kind}",
                )
            self._record_typed_condition_8616(cond_ir)
        else:
            consumed_condition = getattr(self, "_inertia_consumed_last_condition_8616", None)
            if isinstance(consumed_condition, IRCondition):
                consumed_cond_ir = self._typed_condition_from_consumed_ir_condition_8616(
                    consumed_condition,
                    jcc_mnemonic,
                    block_addr=block_addr if isinstance(block_addr, int) else None,
                    taken_target=target_addr,
                    fallthrough_target=fallthrough_addr,
                )
                if consumed_cond_ir is not None:
                    self._record_typed_condition_8616(consumed_cond_ir)
        self.jump(taken_cond, target, JumpKind.Boring)

    # Module-level condition cache for transfer from lifter to codegen.
    # Keyed by block address → list[ConditionIR | ConditionFailure].
    _inertia_module_condition_cache: ClassVar[dict[int, list[ConditionIR | ConditionFailure]]] = {}
    _inertia_pending_condition_sources_by_addr: ClassVar[dict[int, ConditionSource]] = {}
    _inertia_condition_reg_affine_state_8616: ClassVar[dict[str, tuple[IRValue, int]]] = {}
    _inertia_condition_reg_affine_state_snapshots_8616: ClassVar[
        dict[int, dict[str, tuple[IRValue, int]]]
    ] = {}
    _inertia_condition_index_reg_state_8616: ClassVar[dict[
        str,
        tuple[IRValue | IRBinaryValue, int],
    ]] = {}
    _inertia_condition_reg_value_state_8616: ClassVar[dict[
        tuple[int, str],
        _ConditionRegisterValueState8616,
    ]] = {}

    def _record_typed_condition_8616(self, cond: ConditionIR | ConditionFailure) -> None:
        """Record a typed condition on the emulator AND module cache for function-level transfer."""
        log = getattr(self.emu, "_inertia_typed_conditions", None)
        if not isinstance(log, list):
            log = []
            cast(Any, self.emu)._inertia_typed_conditions = log
        log.append(cond)
        # Also write into module-level cache (keyed by block address)
        block_addr = getattr(self.emu, "_inertia_current_block_addr", self.addr)
        cache = Instruction_ANY._inertia_module_condition_cache
        block_conditions = cache.setdefault(block_addr, [])
        if isinstance(cond, ConditionIR):
            condition_key = condition_sort_key_8616(cond)
            if not any(
                isinstance(existing, ConditionIR)
                and condition_sort_key_8616(existing) == condition_key
                for existing in block_conditions
            ):
                block_conditions.append(cond)
        elif not any(
            isinstance(existing, ConditionFailure) and existing == cond
            for existing in block_conditions
        ):
            block_conditions.append(cond)

    def _lift_simple_incdec_reg16_8616(
        self,
        kind: str,
        semantics: tuple[Any, ...],
    ) -> bool:
        """Lift one simple INC/DEC and retain exact evidence for a following JCC."""
        if kind not in {"inc_reg16", "dec_reg16"}:
            return False
        self.status_flag_dead_write_mask_8616(INCDEC_STATUS_FLAG_WRITES_8616)
        _, reg_name = semantics
        is_increment = kind == "inc_reg16"
        mnemonic = "inc" if is_increment else "dec"
        zero_boundary = 0xFFFF if is_increment else 1
        value = self._get_reg16(reg_name)
        if is_increment:
            self.emu.update_eflags_inc(self._eflags_value_8616(value))
        else:
            self.emu.update_eflags_dec(self._eflags_value_8616(value))
        if self._next_instruction_is_simple_jcc():
            operation_count = self._same_preceding_incdec_reg16_count_8616(
                reg_name, mnemonic=mnemonic
            )
            original_boundary = (-operation_count) & 0xFFFF if is_increment else operation_count
            proven_value = self._condition_proven_reg_value_8616(
                reg_name, width_bits=16
            )
            normalized_operands = None
            if proven_value is not None:
                normalized_operands = (
                    proven_value,
                    self._condition_const_value_8616(original_boundary, width_bits=16),
                )
            elif _affine_switch_conditions_enabled_8616():
                normalized_operands = self._normalized_reg_imm_condition_operands_8616(
                    reg_name, zero_boundary, width_bits=16
                )
            self._record_cmp_condition_source(
                value,
                self._const16(zero_boundary),
                normalized_lhs=normalized_operands[0] if normalized_operands is not None else None,
                normalized_rhs=normalized_operands[1] if normalized_operands is not None else None,
                producer_semantics=(kind, reg_name, operation_count),
            )
        one = self._const16(1)
        arithmetic_result = self._arithmetic_result_value_from_semantics_8616(
            (
                "add_reg_imm16" if is_increment else "sub_reg_imm16",
                reg_name,
                1,
            )
        )
        self.put(value + one if is_increment else value - one, reg_name)
        if _affine_switch_conditions_enabled_8616():
            self._update_condition_reg_affine_offset_8616(
                reg_name, -1 if is_increment else 1, width_bits=16
            )
        self._clear_condition_index_reg_state_8616(reg_name)
        self._clear_condition_reg_value_state_8616(reg_name)
        self._set_condition_arithmetic_result_state_8616(arithmetic_result)
        return True

    def _lift_simple(self) -> None:
        """Emit optimized execution and typed evidence for the decoded operation."""
        def _impl() -> None:
            """Dispatch one operation without reconstructing symbolic operand constants."""
            self._restore_condition_reg_affine_snapshot_8616()
            self._reset_condition_reg_value_state_at_block_entry_8616()
            semantics = cast(tuple[Any, ...], self.simple_semantics)
            kind = semantics[0]
            if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                logger.warning(
                    "[condition-provenance] lift block=%r insn=%#x semantics=%r",
                    getattr(
                        getattr(self, "emu", None),
                        "_inertia_current_block_addr",
                        None,
                    ),
                    int(self.addr),
                    semantics,
                )
            if self._lift_simple_cmp_8616(kind):
                return
            if self._lift_simple_test_8616(kind):
                return
            if self._lift_simple_jcc_8616(kind):
                return
            if self._lift_simple_incdec_reg16_8616(kind, semantics):
                return
            if kind == "nop":
                return
            if kind == "sign_extend_al_ax":
                self.put(
                    self.get("al", Type.int_8).widen_signed(Type.int_16),
                    "ax",
                )
                self._widen_condition_reg_value_state_8616("ax")
                return
            if kind == "sign_extend_ax_eax":
                self.put(
                    self.get("ax", Type.int_16).widen_signed(Type.int_32),
                    "eax",
                )
                self._widen_condition_reg_value_state_8616("eax")
                return
            if kind == "ror_reg_imm32_dead_flags":
                _, reg_name, count = semantics
                value = self.get(reg_name, Type.int_32)
                if count:
                    rotate_count = self.constant(count, Type.int_8)
                    inverse_count = self.constant(32 - count, Type.int_8)
                    value = (value >> rotate_count) | (value << inverse_count)
                self.put(value, reg_name)
                self._clear_condition_index_reg_state_8616(reg_name)
                self._clear_condition_reg_value_state_8616(reg_name)
                return
            if kind == "push_reg16":
                _, reg_name = semantics
                value = self._get_reg16(reg_name)
                sp = self._get_reg16("sp") - self._const16(2)
                self.put(sp, "sp")
                if reg_name == "sp":
                    value = sp + self._const16(2)
                self._stack_store16(sp, value, offset=-2)
                return
            if kind == "push_imm16":
                _, imm = semantics
                sp = self._get_reg16("sp") - self._const16(2)
                self.put(sp, "sp")
                self._stack_store16(sp, self._const16(imm), offset=-2)
                return
            if kind == "push_mem16":
                _, mem_spec = semantics
                sp = self._get_reg16("sp") - self._const16(2)
                self.put(sp, "sp")
                self._stack_store16(sp, self._load_mem16(mem_spec), offset=-2)
                return
            if kind == "pop_reg16":
                _, reg_name = semantics
                sp = self._get_reg16("sp")
                value = self._stack_load16(sp, offset=0)
                next_sp = sp + self._const16(2)
                if reg_name == "sp":
                    self.put(value, "sp")
                else:
                    self.put(value, reg_name)
                    self.put(next_sp, "sp")
                self._clear_condition_reg_value_state_8616(reg_name)
                return
            if kind == "call":
                _, target = semantics
                ret_addr = self._const16(self.addr + self.cs.size)
                if is_x86_16_registered_stack_probe_target_8616(self.arch, target):
                    proven_ax = self._condition_proven_reg_value_8616("ax", width_bits=16)
                    allocation = proven_ax.const if isinstance(proven_ax, IRValue) else None
                    ax_value = self._const16(allocation) if allocation is not None else self._get_reg16("ax")
                    next_sp = self._get_reg16("sp") - ax_value
                    self.put(ret_addr, "cx")
                    self.put(next_sp, "bx")
                    if allocation != 0:
                        self.put(next_sp, "sp")
                    return
                sp = self._get_reg16("sp") - self._const16(2)
                self.put(sp, "sp")
                self._stack_store16(sp, ret_addr, offset=-2)
                self.jump(None, self._const16(target), JumpKind.Call)
                return
            if kind == "call_mem16":
                _, mem_spec = semantics
                target = self._load_mem16(mem_spec)
                ret_addr = self._const16(self.addr + self.cs.size)
                sp = self._get_reg16("sp") - self._const16(2)
                self.put(sp, "sp")
                self._stack_store16(sp, ret_addr, offset=-2)
                self.jump(None, target, JumpKind.Call)
                return
            if kind == "enter":
                _, frame_size, nesting = semantics
                nesting &= 0x1F
                old_bp = self._get_reg16("bp")
                sp = self._get_reg16("sp") - self._const16(2)
                self.put(sp, "sp")
                self._stack_store16(sp, old_bp, offset=-2)
                frame_temp = sp
                if nesting:
                    bp_cursor = old_bp
                    for level in range(1, nesting):
                        bp_cursor = bp_cursor - self._const16(2)
                        sp = sp - self._const16(2)
                        self._stack_store16(
                            sp, self._stack_load16(bp_cursor, offset=-2 * level, base="bp"), offset=-2 * (level + 1)
                        )
                    sp = sp - self._const16(2)
                    self._stack_store16(sp, frame_temp, offset=-2 * (nesting + 1))
                self.put(frame_temp, "bp")
                self.put(sp - self._const16(frame_size), "sp")
                return
            if kind == "leave":
                bp = self._get_reg16("bp")
                self.put(bp, "sp")
                self.put(self._stack_load16(bp, offset=0, base="bp"), "bp")
                self.put(bp + self._const16(2), "sp")
                return
            if kind == "mov_reg_imm16":
                _, reg_name, imm = semantics
                self.put(self._const16(imm), reg_name)
                self._clear_condition_index_reg_state_8616(reg_name)
                self._clear_condition_reg_value_state_8616(reg_name)
                self._set_condition_reg_value_state_8616(
                    reg_name,
                    self._condition_const_value_8616(int(imm), width_bits=16),
                )
                return
            if kind == "mov_reg_reg16":
                _, dst_reg, src_reg = semantics
                self.put(self._get_reg16(src_reg), dst_reg)
                self._copy_condition_index_reg_state_8616(dst_reg, src_reg)
                self._copy_condition_reg_value_state_8616(dst_reg, src_reg)
                return
            if kind == "mov_reg_mem16":
                _, dst_reg, mem_spec = semantics
                self.put(self._load_mem16(mem_spec), dst_reg)
                self._set_condition_index_reg_stack_state_8616(dst_reg, mem_spec)
                return
            if kind == "mov_reg_abs16":
                _, dst_reg, offset = semantics
                self.put(self._load_abs16(offset), dst_reg)
                self._set_condition_index_reg_direct_state_8616(dst_reg, offset)
                return
            if kind == "mov_reg_indexed_abs8":
                _, dst_reg, mem_spec = semantics
                self.put(self._load_indexed_abs(mem_spec, width_bytes=1), dst_reg)
                self._set_condition_reg_indexed_value_8616(
                    dst_reg,
                    mem_spec,
                    width_bits=8,
                )
                return
            if kind == "mov_reg_indexed_abs16":
                _, dst_reg, mem_spec = semantics
                self.put(self._load_indexed_abs(mem_spec, width_bytes=2), dst_reg)
                self._set_condition_reg_indexed_value_8616(
                    dst_reg,
                    mem_spec,
                    width_bits=16,
                )
                return
            if kind == "mov_reg_abs8":
                _, dst_reg, offset = semantics
                self.put(self._load_abs8(offset), dst_reg)
                self._set_condition_reg_direct_byte_value_8616(
                    dst_reg,
                    offset,
                )
                return
            if kind == "mov_mem_reg16":
                _, mem_spec, src_reg = semantics
                self._store_mem16(mem_spec, self._get_reg16(src_reg))
                return
            if kind == "mov_mem_imm16":
                _, mem_spec, imm = semantics
                self._store_mem16(mem_spec, self._const16(imm))
                return
            if kind == "lea_reg_bpdisp16":
                _, dst_reg, mem_spec = semantics
                self.put(self._addr_from_bp_mem(mem_spec), dst_reg)
                self._clear_condition_index_reg_state_8616(dst_reg)
                self._clear_condition_reg_value_state_8616(dst_reg)
                return
            if kind == "xor_reg_mem8":
                _, dst_reg, mem_spec = semantics
                self._xor_reg_mem8(dst_reg, mem_spec)
                self._clear_condition_reg_value_state_8616(dst_reg)
                return
            if kind == "add_reg_imm16":
                _, reg_name, imm = semantics
                self._binop_reg_imm("add", reg_name, imm)
                self._clear_condition_index_reg_state_8616(reg_name)
                self._clear_condition_reg_value_state_8616(reg_name)
                return
            if kind.endswith("_reg_reg16"):
                op_name, dst_reg, src_reg = semantics
                arithmetic_result = self._arithmetic_result_value_from_semantics_8616(
                    semantics,
                )
                self._binop_reg_reg(op_name[:-10], dst_reg, src_reg)
                self._clear_condition_index_reg_state_8616(dst_reg)
                self._clear_condition_reg_value_state_8616(dst_reg)
                self._set_condition_arithmetic_result_state_8616(arithmetic_result)
                return
            if kind.endswith("_reg_mem16"):
                op_name, dst_reg, mem_spec = semantics
                arithmetic_result = self._arithmetic_result_value_from_semantics_8616(
                    semantics,
                )
                self._binop_reg_mem(op_name[:-10], dst_reg, mem_spec)
                self._clear_condition_index_reg_state_8616(dst_reg)
                self._clear_condition_reg_value_state_8616(dst_reg)
                self._set_condition_arithmetic_result_state_8616(arithmetic_result)
                return
            if kind.endswith("_reg_abs16"):
                op_name, dst_reg, offset = semantics
                self._binop_reg_abs(op_name[:-10], dst_reg, offset)
                self._clear_condition_index_reg_state_8616(dst_reg)
                self._clear_condition_reg_value_state_8616(dst_reg)
                return
            if kind.endswith("_reg_imm16"):
                op_name, dst_reg, imm = semantics
                arithmetic_result = self._arithmetic_result_value_from_semantics_8616(
                    semantics,
                )
                self._binop_reg_imm(op_name[:-10], dst_reg, imm)
                self._clear_condition_index_reg_state_8616(dst_reg)
                self._clear_condition_reg_value_state_8616(dst_reg)
                self._set_condition_arithmetic_result_state_8616(arithmetic_result)
                return
            if kind.endswith("_abs_imm16"):
                op_name, offset, imm = semantics
                self._binop_abs_imm(op_name[:-10], offset, imm)
                return
            if kind.endswith("_abs_reg16"):
                op_name, offset, src_reg = semantics
                self._binop_abs_reg(op_name[:-10], offset, src_reg)
                return
            if kind == "ret":
                sp = self._get_reg16("sp")
                ret_addr = self._stack_load16(sp, offset=0)
                self.put(sp + self._const16(2), "sp")
                self.jump(None, ret_addr, JumpKind.Ret)
                return
            if kind == "ret_imm16":
                _, imm = semantics
                sp = self._get_reg16("sp")
                ret_addr = self._stack_load16(sp, offset=0)
                self.put(sp + self._const16(2 + imm), "sp")
                self.jump(None, ret_addr, JumpKind.Ret)
                return
            raise NotImplementedError(f"unknown simple semantics: {kind}")

        return _impl()

    def compute_result(self) -> None:
        """Execute the parsed instruction against the emulator-backed lifter facade."""

        def _impl() -> None:
            try:
                debug_enabled = logger.isEnabledFor(logging.DEBUG)
                if debug_enabled:
                    logger.debug("Lifting instruction at %04x: %s %s", self.addr, self.cs.mnemonic, self.cs.op_str)
                instr32 = self.instr32
                if self.is_mode32 ^ bool(self.chsz_op):
                    if instr32 is None:
                        instr32 = self._ensure_instr32()
                    instr32.exec()
                else:
                    self.instr16.exec()
                self._transfer_full_lift_condition_value_semantics_8616()

                if debug_enabled:
                    if hasattr(self.emu, "irsb") and self.emu.irsb:
                        logger.debug("IRSB at %04x: %s", self.addr, self.emu.irsb)
                        irsb_dynamic = cast(Any, self.emu.irsb)
                        irsb_obj = irsb_dynamic.irsb if hasattr(irsb_dynamic, "irsb") else irsb_dynamic
                        if hasattr(irsb_obj, "statements"):
                            for stmt in cast(Any, irsb_obj).statements:
                                logger.debug("Statement: %s (type: %s)", type(stmt).__name__, type(stmt))

                    logger.debug("IRSB generated successfully for %04x", self.addr)

            except Exception as ex:
                if ex.__class__.__name__ == "ScanTimeout":
                    logger.warning(
                        "Lifting timed out at %04x (bytes: %s)",
                        self.addr,
                        self.cs.bytes.hex(),
                    )
                    raise
                logger.error(f"Lifting failed at {self.addr:04x} (bytes: {self.cs.bytes.hex()}): {ex}")
                logger.exception("Exception during instruction execution")
                raise

        return _impl()

    def disassemble(self) -> tuple[int, str, list[str]]:
        """Return the pyvex disassembly tuple for the current instruction."""

        return self.start, self.cs.insn_name(), [str(i) for i in self.cs.operands]

    def ends_block(self) -> bool:
        """Return whether this instruction terminates the current lifted block."""

        if self.cs.mnemonic == "int":
            return getattr(self.instr, "control_flow_class", "interrupt") == "interrupt"
        return self.cs.mnemonic in self._BLOCK_TERMINATORS


# Dynamic pyvex/gymrat boundary: instruction metadata is discovered at runtime.
cast(Any, Instruction_ANY).bin_format = "xxxxxxxx"
cast(Any, Instruction_ANY).name = "nop"
update_abstractmethods(Instruction_ANY)


class Lifter86_16(GymratLifter):  # type: ignore[misc]  # dynamic pyvex base
    """Gymrat lifter entry point for the 16-bit x86 frontend."""

    instrs: ClassVar[list[type[Instruction_ANY]]] = [Instruction_ANY]

    def decode(self) -> list[Any]:
        """Decode a pyvex block into 16-bit instruction objects."""

        try:
            self.create_bitstrm()
            instructions = []
            addr = self.irsb.addr
            bitstrm = cast(bitstring.ConstBitStream, self.bitstrm)
            decode_next = self._decode_next_instruction
            bytepos = bitstrm.bytepos

            while not _bitstream_is_empty(bitstrm):
                instr = decode_next(addr)
                if not instr:
                    break
                instructions.append(instr)
                curr_bytepos = bitstrm.bytepos
                addr += curr_bytepos - bytepos
                bytepos = curr_bytepos
                if cast(Any, instr).ends_block():
                    break
            return instructions
        except Exception as exc:
            self.errors = str(exc)
            logger.exception("Error decoding x86-16 block:")
            raise


register(Lifter86_16, "86_16")


def main() -> None:
    """Run a local manual smoke test for the 16-bit lifter."""

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    tests = [
        b"\x90",  # NOP
        b"\xb8\x01\x02",  # MOV AX, 0x0201
        b"\xc3",  # RET
        b"\x01\xc0",  # ADD AX, AX
        b"\x89\xc1",  # MOV CX, AX
        b"\xeb\x01",  # JMP short +2 (example)
    ]
    print("Decoder test:")
    for num, test in enumerate(tests):
        print(num)
        lifter = Lifter86_16(cast(Any, Arch86_16()), 0)
        lifter.lift(data=test)

    print("Lifter test:")
    for test in tests:
        lifter = Lifter86_16(cast(Any, Arch86_16()), 0)
        lifter.lift(data=test)
        lifter.irsb.pp()

    print("Full tests:")
    fulltest = b"".join(tests)
    lifter = Lifter86_16(cast(Any, Arch86_16()), 0)
    lifter.lift(data=fulltest)
    lifter.irsb.pp()


if __name__ == "__main__":
    main()
