# cython: language_level=3, infer_types=True
"""Layer: Frontend/runtime.

Responsibility: lift 16-bit x86 bytes into VEX/typed IR facts without later-stage repair.
Forbidden: postprocess cleanup, source/COD-backed recovery, or validation acceptance.
Dynamic attribute access here is a third-party pyvex/Gymrat, Capstone, and
emulator telemetry boundary; owned Inertia facts must be explicit typed IR.
"""

from __future__ import annotations
import typing

import contextlib
import logging
import os
from abc import update_abstractmethods
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, cast

import bitstring
import cython
from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter, Instruction, JumpKind, ParseError
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import Type
from pyvex.stmt import Dirty

from inertia.cli.runtime_support import AnalysisTimeout
from inertia.frontend.x86_16.emulator import Emulator
from inertia.frontend.x86_16.instr16 import Instr16
from inertia.frontend.x86_16.instr32 import Instr32
from inertia.frontend.x86_16.instruction import InstrData
from inertia.frontend.x86_16.jcc_condition import _direct_jcc_condition_from_last_condition_8616
from inertia.frontend.x86_16.jcc_result_condition import direct_register_result_zero_jcc_8616
from inertia.frontend.x86_16.parse import CHSZ_AD, CHSZ_OP
from inertia.frontend.x86_16.regs import reg16_t
from inertia.frontend.x86_16.segment_offset_execution import advance_segment_offset_8616
from inertia.frontend.x86_16.vex_value_contract import require_vex_value_8616
from inertia.ir.condition_ir import (
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
from inertia.ir.condition_register_bindings import snapshot_condition_register_bindings_8616
from inertia.ir.condition_relative_edge import attach_relative_condition_edge
from inertia.ir.condition_value_extensions import sign_extend_condition_value_8616
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRCondition,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.status_flag_lift_context import cfg_status_flag_dead_write_mask_8616
from inertia.semantics.status_flag_liveness import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    STATUS_FLAGS_8616,
    StatusFlag8616,
    binop_status_flag_writes_8616,
    decoded_status_flag_instruction_8616,
    status_flags_dead_before_use_8616,
)

from .arch_86_16 import Arch86_16
from .control_coordinates import (
    ControlWidth,
    CoordinateConstant,
    CoordinateValue,
    architectural_offset,
    linear_continuation,
    relative_continuation,
)
import dataclasses
import operator
import builtins

logger: logging.Logger = logging.getLogger(__name__)

_BPMemorySpec8616 = tuple[str, int, int]
_BP_MEMORY_SPEC_FIELD_COUNT_8616 = 3


@dataclasses.dataclass(frozen=True)
class _ConditionRegisterValueState8616:
    """Carry one exact register value within a decoded basic block until clobbered."""

    value: IRValue | IRBinaryValue
    next_addr: cython.longlong


@cython.ccall
def _affine_switch_conditions_enabled_8616() -> cython.bint:
    return os.environ.get("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS") == "1"


@cython.ccall
def _bitstream_is_empty(bitstrm: bitstring.ConstBitStream) -> cython.bint:
    try:
        bitstrm.peek(1)
        return False
    except bitstring.ReadError:
        return True


_MISSING_FACADE_ATTRIBUTE: object = object()


class _LifterInstructionFacade:
    """Combine the raw IRSB customizer API with the higher-level Instruction helpers.
    Modern pyvex exposes jump/get/put on Instruction, but low-level IR building
    helpers like _append_stmt() and _settmp() still live on the IRSB customizer.
    """

    _irsb_c: Any
    _instruction: Any

    def __init__(self, irsb_c: Any, instruction: Instruction) -> None:
        """Keep live providers; never cache mutable helper methods or metadata."""
        self._irsb_c = irsb_c
        self._instruction = instruction

    @cython.locals(value=object)
    def __getattr__(self, name: object) -> Any:
        """Prefer instruction helpers and resolve absent ones on the customizer."""
        value = getattr(self._instruction, name, _MISSING_FACADE_ATTRIBUTE)
        if value is _MISSING_FACADE_ATTRIBUTE:
            return getattr(self._irsb_c, name)
        return value


class Instruction_ANY(Instruction):  # type: ignore[misc]  # dynamic pyvex base
    """Dynamic pyvex instruction bridge for 16-bit x86 instruction lifting."""

    bitstrm: Any
    arch: Any
    addr: cython.longlong
    start: cython.longlong
    cs: Any
    emu: Emulator
    irsb_c: Any
    instr: InstrData
    instr16: Instr16
    instr32: Instr32 | None
    simple_semantics: object
    condition_value_semantics: object
    _past_instructions: Any = ()

    def dirty(self, ret_type: object, func_name: object, args: object) -> Any:
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
    bitwidth: cython.longlong
    is_mode32: cython.bint
    chsz_op: int | bool
    reg_offsets: object

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
        actual_irsb: object
        block_addr: object

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
        self._reset_condition_reg_value_state_at_block_entry_8616()
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

    def __init__(self, bitstrm: Any, arch: Any, addr: cython.longlong) -> None:
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

    def parse(self, bitstrm: Any) -> object:
        """Parse one 16-bit instruction and prepare either simple or full semantics."""
        try:
            return _parse_insn_8616(self, bitstrm)
        except AnalysisTimeout as ex:
            raise ParseError("Instruction parse timed out") from ex

    def _match_simple_semantics(self) -> object:
        ops: object
        unary: object
        ops = getattr(self.cs, "operands", ())
        unary = self._match_simple_unary_semantics_8616(ops)
        if unary is not None:
            return unary
        if len(ops) != 2:
            return None
        return self._match_simple_binary_semantics_8616(ops)

    def _match_simple_unary_semantics_8616(self, ops: Any) -> object:
        matcher: object
        matchers = {
            "nop": lambda _self, _ops: ("nop",),
            "ret": _match_ret_8616,
            "leave": lambda _self, _ops: ("leave",),
            "cbw": _match_cbw_8616,
            "cwde": _match_cbw_8616,
            "enter": _match_enter_8616,
            "push": _match_push_pop_8616,
            "pop": _match_push_pop_8616,
            "call": _match_call_8616,
            "inc": _match_incdec_8616,
            "dec": _match_incdec_8616,
        }
        matcher = matchers.get(self.cs.mnemonic)
        if matcher is not None:
            return matcher(self, ops)
        if self.cs.mnemonic in {"jmp", *self._SIMPLE_JCC_8616} and len(ops) == 1 and ops[0].type == 2:
            return (self.cs.mnemonic, ops[0].imm)
        return None

    def _next_instruction_is_simple_jcc_from_bytes_8616(self) -> cython.bint:
        def _impl() -> cython.bint:
            next_bytepos = self.start + self.cs.size
            raw = bytes(self.bitstrm[next_bytepos * 8 : next_bytepos * 8 + 2 * 8])
            if not raw:
                return False
            opcode = raw[0]
            if 0x70 <= opcode <= 0x7F:
                return True
            return len(raw) >= 2 and opcode == 0x0F and 0x80 <= raw[1] <= 0x8F

        return _impl()

    def _next_instruction_is_incdec_reg16_from_bytes_8616(self) -> cython.bint:
        def _impl() -> cython.bint:
            next_bytepos = self.start + self.cs.size
            raw = bytes(self.bitstrm[next_bytepos * 8 : next_bytepos * 8 + 8])
            if not raw:
                return False
            return 0x40 <= raw[0] <= 0x4F

        return _impl()

    @staticmethod
    def _register_family_8616(reg_name: object) -> object:
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

    def _same_preceding_incdec_reg16_count_8616(self, reg_name: object, *, mnemonic: object) -> cython.longlong:
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

    def _lift_simple_test_8616(self, kind: object) -> cython.bint:
        """Lift a direct or frame-relative TEST into typed masked-condition evidence."""
        typed_value: object
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

    def _reg8_name(self, operand: Any) -> object:
        if operand.type != 1 or operand.size != 1:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG8_NAMES else None

    def _reg16_name(self, operand: Any) -> object:
        if operand.type != 1 or operand.size != 2:
            return None
        reg_name = self.cs.reg_name(operand.reg).lower()
        return reg_name if reg_name in self._REG16_NAMES else None

    def _reg32_name(self, operand: Any) -> object:
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

    def _get_reg16(self, reg_name: object) -> Any:
        return self.get(reg_name, Type.int_16)

    def _const16(self, value: cython.longlong) -> Any:
        return self.constant(value & 0xFFFF, Type.int_16)

    def _const32(self, value: cython.longlong) -> Any:
        return self.constant(value & 0xFFFFFFFF, Type.int_32)

    def _linear_near_target_8616(self, target: cython.longlong) -> cython.longlong:
        """Project one 16-bit near target into the current linear code window."""
        if target > 0xFFFF:
            return target
        return (int(self.addr) & ~0xFFFF) | (target & 0xFFFF)

    def _code_address_constant_8616(self, value: cython.longlong) -> Any:
        """Build a VEX code-address constant without truncating the loader base."""
        return self.constant(value, Type.int_16)

    def _bp_mem(self, operand: Any, *, width_bytes: cython.longlong = 2) -> _BPMemorySpec8616 | None:
        index: object
        if operand.type != 3 or operator.ne(operand.size, width_bytes):
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

    def _indexed_mem(self, operand: Any, *, width_bytes: cython.longlong) -> object:
        """Return one register-indexed memory operand of the requested width."""
        index: object
        if operand.type != 3 or operator.ne(operand.size, width_bytes):
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

    def _record_bp_mem_access(self, mem_spec: _BPMemorySpec8616, mode: cython.longlong, *, size: cython.longlong = 2) -> None:
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
        seg: object,
        offset: cython.longlong,
        mode: cython.longlong = 0,
        *,
        base: object = (),
        size: cython.longlong = 2,
        segment_origin: SegmentOrigin | None = None,
        status: AddressStatus | None = None,
        address_bits: int | None = None,
    ) -> None:
        """Record one operand; implicit stack accesses specify their own address size."""
        from inertia.semantics.evidence_cache import (
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
            expr=(seg, ) + tuple(base),
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

    def _load_abs16(self, offset: cython.longlong) -> Any:
        self._record_mem_access("ds", offset, 0)
        return self._load_real_mode16("ds", self._const16(offset))

    def _store_abs16(self, offset: cython.longlong, value: Any) -> None:
        self._record_mem_access("ds", offset, 1)
        self._store_real_mode16("ds", self._const16(offset), value)

    def _load_abs8(self, offset: cython.longlong) -> VexValue:
        """Load one DS byte and publish the same logical operand width."""
        self._record_mem_access("ds", offset, 0, size=1)
        return self.load(self._real_mode_linear("ds", self._const16(offset)), Type.int_8)

    def _addr_from_indexed_mem(self, mem_spec: Any) -> Any:
        base, _, signed_disp = mem_spec
        addr = self._get_reg16(base)
        if signed_disp == 0:
            return addr
        return addr + self._const16(signed_disp)

    def _load_indexed_abs(self, mem_spec: Any, *, width_bytes: cython.longlong) -> Any:
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

    def _real_mode_linear(self, seg_reg: object, off16: Any) -> Any:
        seg = self._get_reg16(seg_reg).cast_to(Type.int_32)
        off32 = off16.cast_to(Type.int_32)
        return (seg << self.constant(4, Type.int_8)) + off32

    def _load_real_mode16(self, seg_reg: object, off16: Any) -> Any:
        """Load a word through independently wrapped 16-bit segment offsets."""
        low_address = self._real_mode_linear(seg_reg, off16)
        high_offset = advance_segment_offset_8616(off16, 1, 16, self._const16(1))
        high_address = self._real_mode_linear(seg_reg, high_offset)
        low = self.load(low_address, Type.int_8).cast_to(Type.int_16)
        high = self.load(high_address, Type.int_8).cast_to(Type.int_16)
        return low | (high << self.constant(8, Type.int_8))

    def _store_real_mode16(self, seg_reg: object, off16: Any, value: Any) -> None:
        """Store a word through independently wrapped 16-bit segment offsets."""
        low_address = self._real_mode_linear(seg_reg, off16)
        high_offset = advance_segment_offset_8616(off16, 1, 16, self._const16(1))
        high_address = self._real_mode_linear(seg_reg, high_offset)
        self.store(value.cast_to(Type.int_8), low_address)
        high = (value >> self.constant(8, Type.int_8)).cast_to(Type.int_8)
        self.store(high, high_address)

    def _stack_load16(self, off16: VexValue, *, offset: cython.longlong, base: object = "sp") -> VexValue:
        """Read a stack word while retaining its instruction-entry coordinate."""
        self._record_mem_access("ss", offset, 0, base=(base,), size=2, address_bits=16)
        return require_vex_value_8616(self._load_real_mode16("ss", off16))

    def _stack_store16(self, off16: VexValue, value: VexValue, *, offset: cython.longlong) -> None:
        """Write a stack word while retaining its instruction-entry SP displacement."""
        self._record_mem_access("ss", offset, 1, base=("sp",), size=2, address_bits=16)
        self._store_real_mode16("ss", off16, value)

    def _eflags_value_8616(self, value: Any) -> Any:
        """Rebind one PyVEX value to the emulator's active frontend host."""
        host: object
        if not isinstance(value, VexValue):
            return value
        host = self.emu.lifter_instruction
        if host is None:
            raise RuntimeError("Eflags materialization requires an active frontend host")
        return VexValue(host, value.rdt)

    def _update_binop_flags16(self, op_name: object, lhs: Any, rhs: Any) -> None:
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

    def _flag_is_set(self, bit: cython.longlong) -> Any:
        return operator.ne((self._get_reg16("flags") & self._const16(1 << bit)), self._const16(0))

    def _flag_is_clear(self, bit: cython.longlong) -> Any:
        return operator.eq((self._get_reg16("flags") & self._const16(1 << bit)), self._const16(0))

    def _binop_reg_reg(self, op_name: object, dst_reg: object, src_reg: object) -> None:
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

    def _binop_reg_imm(self, op_name: object, dst_reg: object, imm: Any) -> None:
        """Lift word/immediate arithmetic and publish every live CMP flag effect."""
        dst = self._get_reg16(dst_reg)
        src = self._const16(imm)
        if op_name == "add":
            result = dst + src
        elif op_name == "sub":
            result = dst - src
            _record_sub_reg_imm_condition_8616(self, dst, src, dst_reg, imm)
        elif op_name == "xor":
            result = dst ^ src
        elif op_name == "and":
            result = dst & src
        elif op_name == "or":
            result = dst | src
        elif op_name == "cmp":
            self._record_cmp_condition_source(dst, src)
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

    def _binop_reg_mem(self, op_name: object, dst_reg: object, mem_spec: _BPMemorySpec8616) -> None:
        """Lift frame-memory arithmetic with explicit register and FLAGS effects."""
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

    def _xor_reg_mem8(self, dst_reg: object, mem_spec: _BPMemorySpec8616) -> None:
        """Lift byte XOR from a proven SS frame-relative source with exact flags."""
        dst: object
        dst = self.get(dst_reg, Type.int_8)
        src = self._load_mem8(mem_spec)
        result = dst ^ src
        self._update_binop_flags16("xor", dst, src)
        self.put(result, dst_reg)

    def _binop_reg_abs(self, op_name: object, dst_reg: object, offset: cython.longlong) -> None:
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

    def _binop_abs_imm(self, op_name: object, offset: cython.longlong, imm: cython.longlong) -> None:
        dst = self._load_abs16(offset)
        src = self._const16(imm)
        result = self._binop_result16(op_name, dst, src)
        if self._next_instruction_is_simple_jcc():
            self._update_binop_flags16(op_name, dst, src)
        self._store_abs16(offset, result)

    def _binop_abs_reg(self, op_name: object, offset: cython.longlong, src_reg: object) -> None:
        dst = self._load_abs16(offset)
        src = self._get_reg16(src_reg)
        result = self._binop_result16(op_name, dst, src)
        if self._next_instruction_is_simple_jcc():
            self._update_binop_flags16(op_name, dst, src)
        self._store_abs16(offset, result)

    def _binop_result16(self, op_name: object, dst: Any, src: Any) -> Any:
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

    def _cmp_operands_from_semantics(self, semantics: object) -> object:
        """Rebuild VEX operands for a previously classified CMP instruction."""
        shape: object
        shape = _CMP_OPERAND_SHAPES_8616.get(str(semantics[0]))
        if shape is None:
            return None
        lhs_role, rhs_role, _width = shape
        _, lhs_operand, rhs_operand = semantics
        return (
            _cmp_lift_operand_value_8616(self, lhs_role, lhs_operand),
            _cmp_lift_operand_value_8616(self, rhs_role, rhs_operand),
        )

    def _next_instruction_is_simple_jcc(self) -> cython.bint:
        nxt_semantics: object
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
    ) -> cython.bint:
        """Prove current status-flag definitions die in this decoded block."""
        return self.status_flag_write_is_dead_8616(written)

    def status_flag_write_is_dead_8616(self, written: StatusFlag8616) -> cython.bint:
        """Return whether the active instruction may omit these status bits."""
        normalized_written = written & STATUS_FLAGS_8616
        return bool(operator.eq(self.status_flag_dead_write_mask_8616(written), normalized_written))

    def status_flag_dead_write_mask_8616(self, written: StatusFlag8616) -> StatusFlag8616:
        """Return status bits proven dead by CFG or decoded-block evidence."""
        cfg_dead: object
        decoded: object
        instruction: object
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

    def _should_update_binop_flags_8616(self, op_name: object, *, logical_condition_recorded: cython.bint) -> cython.bint:
        """Keep live execution flags even when a logical condition was published."""
        written: object
        written = binop_status_flag_writes_8616(op_name)
        return not (written is not None and self._flags_fully_overwritten_before_use_8616(written))

    def _direct_jcc_condition(self, kind: object) -> Any | None:
        """Prefer proven typed predicates or adjacent arithmetic result tests."""
        cond: object
        past_instructions: object
        prev: object
        past_instructions = getattr(self, "_past_instructions", None)
        prev = past_instructions[-1] if past_instructions else None
        prev_emu = getattr(prev, "emu", None) if prev is not None else None
        last_condition = getattr(prev_emu, "get_last_condition", lambda: None)()
        cond = _resolve_jcc_condition_8616(self, kind, last_condition, prev)
        if cond is None:
            return None
        _consume_last_condition_8616(self, last_condition, prev_emu, prev)
        return cond

    def _condition_reg_value_8616(self, reg_name: object, *, width_bits: cython.longlong = 16) -> IRValue | None:
        reg: object
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
    def _condition_unshifted_index_reg_value_8616(reg_name: object, *, width_bits: cython.longlong = 16) -> IRValue | None:
        """Return one width-matched unshifted scalar index register value."""
        state: object
        state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(str(reg_name).lower())
        if state is None:
            return None
        value, shift = state
        if not isinstance(value, IRValue):
            return None
        if int(shift) != 0 or value.space not in {MemSpace.SS, MemSpace.DS}:
            return None
        if operator.ne(value.size, max(1, int(width_bits) // 8)):
            return None
        return value

    def _condition_proven_reg_value_8616(
        self,
        reg_name: object,
        *,
        width_bits: cython.longlong = 16,
    ) -> IRValue | IRBinaryValue | None:
        """Return exact block-local value provenance retained for one register."""
        block_addr: object
        emu: object
        instruction_addr: object
        parent: object
        state: object
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
        return value if operator.eq(value.size, target_size) else None

    @staticmethod
    def _condition_const_value_8616(value: cython.longlong, *, width_bits: cython.longlong = 16) -> IRValue:
        return IRValue(
            MemSpace.CONST,
            const=int(value) & ((1 << int(width_bits)) - 1),
            size=max(1, int(width_bits) // 8),
            expr=("cmp-imm",),
        )

    def _condition_direct_ds_value_8616(self, offset: cython.longlong, *, width_bits: cython.longlong = 16) -> IRValue:
        """Build a direct DS value tied to this instruction's memory access."""
        instruction_addr: object
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
        width_bits: cython.longlong = 16,
        memory_access_insn: int | None = None,
    ) -> IRValue | None:
        """Build a stack operand, retaining supplied exact memory-access evidence."""
        if not (isinstance(mem_spec, tuple) and len(mem_spec) >= _BP_MEMORY_SPEC_FIELD_COUNT_8616):
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
            memory_access_size=max(1, int(width_bits) // 8) if memory_access_insn is not None else None,
            memory_access_insn=memory_access_insn,
        )

    @staticmethod
    def _condition_indexed_ds_value_8616(
        mem_spec: Any,
        index_state: Any,
        *,
        width_bits: cython.longlong = 8,
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
        semantics: object,
    ) -> object:
        """Normalize classified CMP operands into typed condition IR values."""
        builder: object
        if not isinstance(semantics, tuple) or not semantics:
            return None
        kind = str(semantics[0])
        builders: dict[str, Callable[[Any, tuple[Any, ...]], tuple[Any, Any] | None]] = {
            "cmp_reg_reg16": _cond_cmp_reg_reg16_8616,
            "cmp_reg_imm16": _cond_cmp_reg_imm16_8616,
            "cmp_reg_mem16": _cond_cmp_reg_mem16_8616,
            "cmp_reg_abs16": _cond_cmp_reg_abs16_8616,
            "cmp_mem_reg16": _cond_cmp_mem_reg16_8616,
            "cmp_mem_imm16": _cond_cmp_mem_imm16_8616,
            "cmp_abs_reg16": _cond_cmp_abs_reg16_8616,
            "cmp_abs_imm16": _cond_cmp_abs_imm16_8616,
            "cmp_reg_abs8": _cond_cmp_reg_abs8_8616,
            "cmp_reg_imm8": _cond_cmp_reg_imm8_8616,
            "cmp_abs_reg8": _cond_cmp_abs_reg8_8616,
            "cmp_abs_imm8": _cond_cmp_abs_imm8_8616,
            "cmp_indexed_abs_reg8": lambda _self, sem: _cond_cmp_indexed8_8616(_self, kind, sem),
            "cmp_reg_indexed_abs8": lambda _self, sem: _cond_cmp_indexed8_8616(_self, kind, sem),
            "cmp_indexed_abs_reg16": lambda _self, sem: _cond_cmp_indexed16_8616(_self, kind, sem),
            "cmp_reg_indexed_abs16": lambda _self, sem: _cond_cmp_indexed16_8616(_self, kind, sem),
            "sub_reg_reg16": lambda _self, sem: _cond_sub_reg_operands_8616(_self, kind, sem),
            "sub_reg_mem16": lambda _self, sem: _cond_sub_reg_operands_8616(_self, kind, sem),
            "sub_reg_imm16": lambda _self, sem: _cond_sub_reg_operands_8616(_self, kind, sem),
            "inc_reg16": lambda _self, sem: _cond_incdec_operands_8616(_self, kind, sem),
            "dec_reg16": lambda _self, sem: _cond_incdec_operands_8616(_self, kind, sem),
        }
        builder = builders.get(kind)
        return builder(self, semantics) if builder is not None else None

    def _condition_reg_affine_state_8616(
        self,
        reg_name: object,
        *,
        width_bits: cython.longlong = 16,
    ) -> object:
        base: object
        current: object
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
        reg_name: object,
        delta: cython.longlong,
        *,
        width_bits: cython.longlong = 16,
    ) -> None:
        current: object
        state = Instruction_ANY._inertia_condition_reg_affine_state_8616
        current = self._condition_reg_affine_state_8616(reg_name, width_bits=width_bits)
        if current is None or not isinstance(state, dict):
            return
        base, offset = current
        mask = (1 << int(width_bits)) - 1
        state[reg_name.lower()] = (base, (int(offset) + int(delta)) & mask)

    def _restore_condition_reg_affine_snapshot_8616(self) -> None:
        snapshot: object
        if not _affine_switch_conditions_enabled_8616():
            return
        snapshot = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616.get(int(self.addr))
        if isinstance(snapshot, dict):
            Instruction_ANY._inertia_condition_reg_affine_state_8616 = dict(snapshot)

    @staticmethod
    def _condition_target_addr_8616(target: object) -> int | None:
        args: object
        con: object
        con_value: object
        value: object
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
        target_addr: object
        if not _affine_switch_conditions_enabled_8616():
            return
        target_addr = Instruction_ANY._condition_target_addr_8616(target)
        if target_addr is None:
            return
        state = Instruction_ANY._inertia_condition_reg_affine_state_8616
        if isinstance(state, dict):
            Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616[target_addr] = dict(state)

    def _clear_condition_index_reg_state_8616(self, reg_name: object) -> None:
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if isinstance(state, dict):
            state.pop(str(reg_name).lower(), None)

    def _clear_condition_reg_value_state_8616(self, reg_name: object) -> None:
        """Forget transient exact-value provenance after a register write."""
        block_addr: object
        parent: object
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
        """Discard unproven prior-block value and index provenance on entry."""
        block_addr: object
        emu: object
        instruction_addr: object
        key: object
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
            or operator.ne(instruction_addr, int(block_addr))
        ):
            return
        Instruction_ANY._inertia_condition_index_reg_state_8616.clear()
        stale_keys = tuple(
            key
            for key in iter(state)
            if isinstance(key, tuple)
            and len(key) == 2
            and operator.eq(key[0], int(block_addr))
        )
        for key in stale_keys:
            state.pop(key, None)

    def _set_condition_reg_value_state_8616(
        self,
        reg_name: object,
        value: IRValue | IRBinaryValue,
    ) -> None:
        """Bind one exact value to a register in the current basic block."""
        block_addr: object
        parent: object
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
        dst_reg: object,
        src_reg: object,
    ) -> None:
        """Copy exact-value provenance between equal-width register views."""
        block_addr: object
        dst_key: object
        source: object
        src_key: object
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

    def _widen_condition_reg_value_state_8616(self, reg_name: object) -> None:
        """Preserve signed CBW/CWDE value conversion and original load width."""
        block_addr: object
        destination_size: object
        extended: object
        source: object
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
        source = state.get((int(block_addr), "ax"))
        destination_size = {"ax": 2, "eax": 4}.get(reg_name)
        if (
            not isinstance(source, _ConditionRegisterValueState8616)
            or source.next_addr > int(self.addr)
            or destination_size is None
        ):
            state.pop(key, None)
            return
        extended = sign_extend_condition_value_8616(source.value, destination_size)
        if extended is None:
            state.pop(key, None)
            return
        state[key] = _ConditionRegisterValueState8616(
            value=extended,
            next_addr=int(self.addr) + int(self.cs.size),
        )

    def _set_condition_reg_indexed_value_8616(
        self,
        reg_name: object,
        mem_spec: Any,
        *,
        width_bits: cython.longlong,
    ) -> None:
        """Record a load whose DS address is proven from stack index state."""
        block_addr: object
        parent: object
        value: object
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
        reg_name: object,
        offset: cython.longlong,
    ) -> None:
        """Record a byte load from one exact DS offset."""
        block_addr: object
        parent: object
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

    def _copy_condition_index_reg_state_8616(self, dst_reg: object, src_reg: object) -> None:
        src_state: object
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if not isinstance(state, dict):
            return
        src_state = state.get(str(src_reg).lower())
        if src_state is None:
            state.pop(str(dst_reg).lower(), None)
            return
        state[str(dst_reg).lower()] = src_state

    def _set_condition_index_reg_stack_state_8616(self, reg_name: object, mem_spec: Any) -> None:
        stack_value: object
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        stack_value = self._condition_stack_value_8616(mem_spec, width_bits=16)
        if not isinstance(state, dict) or stack_value is None:
            return
        state[str(reg_name).lower()] = (stack_value, 0)
        self._set_condition_reg_value_state_8616(reg_name, stack_value)

    def _set_condition_index_reg_direct_state_8616(self, reg_name: object, offset: cython.longlong) -> None:
        state = Instruction_ANY._inertia_condition_index_reg_state_8616
        if not isinstance(state, dict):
            return
        value = self._condition_direct_ds_value_8616(offset, width_bits=16)
        state[str(reg_name).lower()] = (value, 0)
        self._set_condition_reg_value_state_8616(reg_name, value)

    def _arithmetic_result_value_from_semantics_8616(
        self,
        semantics: object,
    ) -> object:
        """Build one exact register arithmetic value from block-local provenance."""
        lhs: object
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
        rhs = _arithmetic_rhs_value_8616(self, kind, semantics[2])
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
        result: object,
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
        reg_id: object
        try:
            _read_ids, write_ids = self.cs.regs_access()
        except Exception:
            return ()
        names: set[str] = set()
        for reg_id in write_ids:
            name = str(self.cs.reg_name(int(reg_id))).lower()
            names.add(self._LOW8_PARENT_REGS.get(name, name))
        return tuple(sorted(name for name in iter(names) if name in self._REG16_NAMES))

    def _transfer_full_lift_condition_value_semantics_8616(self) -> None:
        """Update typed value provenance after normal Instr16 machine lifting."""
        byte_copy: object
        result: object
        semantics: object
        reg_name: object
        semantics = self.condition_value_semantics
        byte_copy = None
        preserved_shift_reg: object = None
        if semantics is None:
            semantics, byte_copy, preserved_shift_reg = _infer_full_lift_semantics_from_operands_8616(self)
        result = self._arithmetic_result_value_from_semantics_8616(semantics) if semantics is not None else None
        logical_operation = str(semantics[0]).partition("_")[0] if semantics is not None else ""
        if semantics is not None and logical_operation in {"and", "or", "xor"}:
            self._record_logical_result_condition_source_8616(
                logical_operation,
                str(semantics[1]),
                object(),
            )
        if semantics is not None and str(semantics[0]).startswith("cmp_"):
            _transfer_cmp_semantics_8616(self, semantics)
        if semantics is not None and str(semantics[0]).startswith("test_"):
            _transfer_test_semantics_8616(self, semantics)
        written_registers = set(self._full_lift_written_condition_registers_8616())
        if result is not None:
            written_registers.add(result[0])
        for reg_name in written_registers:
            if reg_name != preserved_shift_reg:
                self._clear_condition_index_reg_state_8616(reg_name)
            self._clear_condition_reg_value_state_8616(reg_name)
        self._set_condition_arithmetic_result_state_8616(result)
        _transfer_mov_index_state_8616(self, semantics)
        if byte_copy is not None:
            self._copy_condition_reg_value_state_8616(*byte_copy)

    def _shift_condition_index_reg_state_8616(self, reg_name: object, shift: cython.longlong) -> cython.bint:
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
        reg_name: object,
        imm: cython.longlong,
        *,
        width_bits: cython.longlong = 16,
    ) -> object:
        current: object
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
        width_bits: cython.longlong = 16,
        normalized_lhs: Any | None = None,
        normalized_rhs: Any | None = None,
        producer_semantics: object = None,
    ) -> None:
        """Record CMP operands on the emulator for downstream JCC consumption."""
        base: object
        block_addr: object
        typed_operands: object
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
        width_bits: cython.longlong = 16,
        normalized_value: IRValue | IRBinaryValue | None = None,
        bind_operand_at_jcc: cython.bint = False,
        producer_semantics: object = None,
    ) -> None:
        """Record TEST/self-test operands for downstream JCC consumption."""
        block_addr: object
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
        op_name: object,
        dst_reg: object,
    ) -> IRBinaryValue | None:
        """Build the typed value computed by a logical register ALU instruction."""
        lhs: object
        rhs: object
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
        rhs = None
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
        op_name: object,
        dst_reg: object,
        result: Any,
    ) -> cython.bint:
        """Record a logical ALU result consumed immediately by a JCC."""
        result_value: object
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
        jcc_mnemonic: object,
        *,
        block_addr: int | None,
        taken_target: int | None,
        fallthrough_target: int | None,
    ) -> ConditionIR | ConditionFailure | None:
        producer_insn: object
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
        counter_name: object,
        counter_size: cython.longlong,
        displacement: cython.longlong,
        instruction_size: cython.longlong,
    ) -> None:
        """Record the exact post-decrement counter condition owned by plain LOOP."""
        block_addr: object
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
        block_addr: object
        # Before emitting, record the typed ConditionIR if source available
        Instruction_ANY._snapshot_condition_reg_affine_state_8616(target)
        target_addr = Instruction_ANY._condition_target_addr_8616(target)
        fallthrough_addr = _jcc_fallthrough_addr_8616(self)
        source = _jcc_condition_source_8616(self)
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
            lhs, rhs = _normalized_jcc_source_operands_8616(self, source)
            _propagate_jcc_condition_source_8616(self, 
                source, lhs, rhs, jcc_mnemonic, fallthrough_addr, target_addr
            )
            cond_ir = _build_jcc_cond_ir_8616(self, 
                source, lhs, jcc_mnemonic, block_addr, target_addr, fallthrough_addr, rhs
            )
            self._record_typed_condition_8616(cond_ir)
        else:
            _record_consumed_jcc_condition_8616(self, 
                jcc_mnemonic, block_addr, target_addr, fallthrough_addr
            )
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
        """Bind current conditional bytes, then retain one coherent fact in both caches."""
        block_addr: object
        log: object
        if isinstance(cond, ConditionIR) and operator.eq(cond.src_insn, self.addr):
            cond = attach_relative_condition_edge(cond, self.addr, bytes(self.cs.bytes))
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
                and operator.eq(condition_sort_key_8616(existing), condition_key)
                for existing in iter(block_conditions)
            ):
                block_conditions.append(cond)
        elif not any(
            isinstance(existing, ConditionFailure) and existing == cond
            for existing in iter(block_conditions)
        ):
            block_conditions.append(cond)

    def _lift_simple_incdec_reg16_8616(
        self,
        kind: object,
        semantics: object,
    ) -> cython.bint:
        """Lift one simple INC/DEC and retain exact evidence for a following JCC."""
        next_semantics: object
        normalized_operands: object
        proven_value: object
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
        one = self._const16(1)
        updated_value = value + one if is_increment else value - one
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
            next_semantics = self._future_instructions[0].simple_semantics
            use_current_result = (
                normalized_operands is None
                and next_semantics is not None
                and next_semantics[0] in {"je", "jz", "jne", "jnz"}
            )
            if use_current_result:
                # Without an independent input binding, a bare register denotes
                # its updated value at JCC, not the value consumed by INC/DEC.
                self._record_test_condition_source(
                    updated_value, normalized_value=self._condition_reg_value_8616(reg_name),
                    bind_operand_at_jcc=True, producer_semantics=(kind, reg_name, operation_count),
                )
            else:
                self._record_cmp_condition_source(
                    value,
                    self._const16(zero_boundary),
                    normalized_lhs=normalized_operands[0] if normalized_operands is not None else None,
                    normalized_rhs=normalized_operands[1] if normalized_operands is not None else None,
                    producer_semantics=(kind, reg_name, operation_count),
                )
        arithmetic_result = self._arithmetic_result_value_from_semantics_8616(
            (
                "add_reg_imm16" if is_increment else "sub_reg_imm16",
                reg_name,
                1,
            )
        )
        self.put(updated_value, reg_name)
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
        self._restore_condition_reg_affine_snapshot_8616()
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
        if _lift_simple_kind_8616(self, kind, semantics):
            return
        if _lift_simple_suffix_8616(self, kind, semantics):
            return
        raise NotImplementedError(f"unknown simple semantics: {kind}")

    def compute_result(self) -> None:
        """Execute the parsed instruction against the emulator-backed lifter facade."""
        _compute_result_8616(self)

    def disassemble(self) -> tuple[cython.longlong, str, list[str]]:
        """Return the pyvex disassembly tuple for the current instruction."""

        return self.start, self.cs.insn_name(), [str(i) for i in iter(self.cs.operands)]

    def ends_block(self) -> cython.bint:
        """Return whether this instruction terminates the current lifted block."""

        if self.cs.mnemonic == "int":
            return getattr(self.instr, "control_flow_class", "interrupt") == "interrupt"
        return self.cs.mnemonic in self._BLOCK_TERMINATORS


    def _match_simple_binary_semantics_8616(self, ops: Any) -> object:
        """Bound facade over the module-level binary-semantics matcher."""
        return _match_simple_binary_semantics_8616(self, ops)

    def _lift_simple_cmp_8616(self, kind: object) -> cython.bint:
        """Bound facade so tests may stub the CMP lift on instances."""
        return _lift_simple_cmp_8616(self, kind)

    def _lift_simple_jcc_8616(self, kind: object) -> cython.bint:
        """Bound facade so tests may stub the JCC lift on instances."""
        return _lift_simple_jcc_8616(self, kind)

# Dynamic pyvex/gymrat boundary: instruction metadata is discovered at runtime.
cast(Any, Instruction_ANY).bin_format = "xxxxxxxx"
cast(Any, Instruction_ANY).name = "nop"
update_abstractmethods(Instruction_ANY)





# ---------------------------------------------------------------------------
# Module-level lift helpers (self passed explicitly for namespace test fakes).
# ---------------------------------------------------------------------------

@cython.ccall
def _disasm_once_8616(self: Instruction_ANY, raw: object) -> list[Any]:
    """Disassemble one insn, translating capstone timeout into ParseError."""
    try:
        return list(self.arch.capstone.disasm(raw, self.addr, 1))
    except AnalysisTimeout as ex:
        raise ParseError("Instruction disassembly timed out") from ex

@cython.ccall
def _disasm_sanitized_pop_8616(self: Instruction_ANY, raw: object, prefix_index: cython.longlong) -> object:
    """Retry disassembly with the invalid 0x8F pop extension masked out."""
    sanitized = bytearray(raw)
    sanitized[prefix_index + 1] &= 0xC7
    return _disasm_once_8616(self, bytes(sanitized))

@cython.ccall
@cython.locals(strip_len=cython.int)
def _disasm_stripped_prefix_8616(self: Instruction_ANY, raw: object) -> tuple[list[Any], cython.longlong]:
    """Strip leading prefix bytes until capstone decodes the opcode."""
    # Capstone rejects several LOCK-prefixed forms that the real 286 still
    # executes, and also segment-override + LOCK combinations.
    # Decode the underlying opcode for mnemonic discovery, but let our
    # own parser consume the real prefix byte stream below.
    for strip_len in range(1, min(4, len(raw))):
        instr = _disasm_once_8616(self, raw[strip_len:])
        if instr:
            return instr, strip_len
    return [], 0

@cython.ccall
def _commit_simple_parse_8616(self: Instruction_ANY, bitstrm: Any, cs_prefix_len: cython.longlong) -> dict[str, str]:
    """Commit a simple-semantics parse and stop at the capstone insn size."""
    bitstrm.bytepos = self.start + cs_prefix_len + self.cs.size
    self.bitwidth = (cs_prefix_len + self.cs.size) * 8
    self.is_mode32 = self.emu.is_mode32()
    self.chsz_op = False
    return {"x": "00000000"}

@cython.ccall
def _parse_full_insn_8616(self: Instruction_ANY, bitstrm: Any, cs_prefix_len: cython.longlong) -> dict[str, str]:
    """Run the full 16/32-bit instruction parser and commit its size."""
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

@cython.locals(
    raw=bytes,
    prefix_bytes=set,
    prefix_index=cython.int,
    cs_prefix_len=cython.int,
    capstone_rejected_full=cython.bint,
    invalid_pop_extension=cython.bint,
    width_override=cython.bint,
    segment_override=cython.bint,
    wide_memory_operand=cython.bint,
    dead_flags_wide_register_semantics=cython.bint,
)
def _parse_insn_8616(self: Instruction_ANY, bitstrm: Any) -> object:
    """Decode one instruction and choose simple vs full semantics."""
    self.start = bitstrm.bytepos
    raw = bytes(bitstrm[self.start * 8 : self.start * 8 + 15 * 8])
    cs_prefix_len = 0
    instr = _disasm_once_8616(self, raw)
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
        instr = _disasm_sanitized_pop_8616(self, raw, prefix_index)
    if not instr:
        instr, cs_prefix_len = _disasm_stripped_prefix_8616(self, raw)
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
    wide_memory_operand = any(operand.type == 3 and operand.size > 1 for operand in iter(self.cs.operands))
    self.instr.invalid_lock = capstone_rejected_full and 0xF0 in raw[:prefix_index]
    self.instr.invalid_opcode_extension = invalid_pop_extension
    self.condition_value_semantics = _full_lift_semantics_8616(self, 
        matched_semantics, wide_memory_operand, segment_override, width_override
    )
    dead_flags_wide_register_semantics = bool(
        matched_semantics
        and matched_semantics[0] == "ror_reg_imm32_dead_flags"
    )
    self.simple_semantics = _drop_matched_semantics_8616(self, 
        matched_semantics,
        segment_override,
        wide_memory_operand,
        width_override,
        dead_flags_wide_register_semantics,
    )
    if self.simple_semantics is not None:
        return _commit_simple_parse_8616(self, bitstrm, cs_prefix_len)
    return _parse_full_insn_8616(self, bitstrm, cs_prefix_len)

@cython.ccall
def _match_ret_8616(self: Instruction_ANY, ops: Any) -> tuple[Any, ...]:
    """Match ``ret``/``ret imm16`` simple semantics."""
    if len(ops) == 1 and ops[0].type == 2:
        return ("ret_imm16", ops[0].imm & 0xFFFF)
    return ("ret",)

@cython.ccall
def _match_cbw_8616(self: Instruction_ANY, ops: Any) -> object:
    """Match ``cbw``/``cwde`` sign-extension semantics by prefix bytes."""
    if ops:
        return None
    instruction_bytes = bytes(self.cs.bytes)
    if 0x66 in instruction_bytes[:-1]:
        return ("sign_extend_ax_eax",)
    return ("sign_extend_al_ax",)

def _match_enter_8616(self: Instruction_ANY, ops: Any) -> object:
    """Match ``enter imm16, imm8`` simple semantics."""
    if len(ops) == 2 and all(op.type == 2 for op in iter(ops)):
        return ("enter", ops[0].imm & 0xFFFF, ops[1].imm & 0xFF)
    return None

@cython.ccall
def _match_push_pop_8616(self: Instruction_ANY, ops: Any) -> object:
    """Match ``push``/``pop`` reg16/imm16/mem16 simple semantics."""
    if len(ops) != 1:
        return None
    reg_name = self._reg16_name(ops[0])
    mem = self._bp_mem(ops[0])
    if reg_name:
        return (f"{self.cs.mnemonic}_reg16", reg_name)
    if self.cs.mnemonic == "push" and ops[0].type == 2:
        return ("push_imm16", ops[0].imm & 0xFFFF)
    if self.cs.mnemonic == "push" and mem:
        return ("push_mem16", mem)
    return None

@cython.ccall
def _match_call_8616(self: Instruction_ANY, ops: Any) -> object:
    """Match near ``call imm``/``call mem16`` simple semantics."""
    if len(ops) != 1:
        return None
    if ops[0].type == 2:
        return ("call", ops[0].imm)
    mem = self._bp_mem(ops[0])
    if mem:
        return ("call_mem16", mem)
    return None

@cython.ccall
def _match_incdec_8616(self: Instruction_ANY, ops: Any) -> object:
    """Match ``inc``/``dec reg16`` when a condition-forming pattern follows."""
    if len(ops) != 1:
        return None
    mnemonic = self.cs.mnemonic
    if mnemonic == "inc":
        enabled = _affine_switch_conditions_enabled_8616() or self._next_instruction_is_simple_jcc_from_bytes_8616()
    else:
        enabled = (
            _affine_switch_conditions_enabled_8616()
            or self._next_instruction_is_simple_jcc_from_bytes_8616()
            or self._next_instruction_is_incdec_reg16_from_bytes_8616()
        )
    if not enabled:
        return None
    reg_name = self._reg16_name(ops[0])
    if reg_name and reg_name not in {"sp", "bp"}:
        return (f"{mnemonic}_reg16", reg_name)
    return None

@cython.ccall
def _cmp_lift_operand_value_8616(self: Instruction_ANY, role: object, operand: Any) -> Any:
    """Materialize one CMP operand value by its operand-role tag."""
    if role == "mem16":
        return self._load_mem16(operand)
    if role == "abs16":
        return self._load_abs16(operand)
    if role == "abs8":
        return self._load_abs8(operand)
    if role == "idx8":
        return self._load_indexed_abs(operand, width_bytes=1)
    if role == "idx16":
        return self._load_indexed_abs(operand, width_bytes=2)
    if role == "reg16":
        return self._get_reg16(operand)
    if role == "reg8":
        return self.get(operand, Type.int_8)
    if role == "imm16":
        return self._const16(operand)
    return self.constant(operand, Type.int_8)

@cython.ccall
def _flag_jcc_conditions_8616(self: Instruction_ANY) -> object:
    """Build the flag-expression for every simple JCC mnemonic."""
    kind: object
    kinds: object
    value: object
    zf = self._flag_is_set(6)
    cf = self._flag_is_set(0)
    sf = self._flag_is_set(7)
    of = self._flag_is_set(11)
    nof = self._flag_is_clear(11)
    nzf = self._flag_is_clear(6)
    ncf = self._flag_is_clear(0)
    groups: tuple[tuple[Any, Any], ...] = (
        (JCC_EQ_MNEMONICS_8616, zf),
        (JCC_NE_MNEMONICS_8616, nzf),
        (JCC_SLE_MNEMONICS_8616, zf | (sf != of)),
        (JCC_SGT_MNEMONICS_8616, nzf & (sf == of)),
        (JCC_SLT_MNEMONICS_8616, sf != of),
        (JCC_SGE_MNEMONICS_8616, sf == of),
        (JCC_ULT_MNEMONICS_8616, cf),
        (JCC_UGE_MNEMONICS_8616, ncf),
        (JCC_ULE_MNEMONICS_8616, cf | zf),
        (JCC_UGT_MNEMONICS_8616, ncf & nzf),
    )
    conditions: dict[str, Any] = {
        "jo": of,
        "jno": nof,
        "js": sf,
        "jns": self._flag_is_clear(7),
        "jp": self._flag_is_set(2),
        "jpe": self._flag_is_set(2),
        "jnp": self._flag_is_clear(2),
        "jpo": self._flag_is_clear(2),
    }
    for kinds, value in groups:
        for kind in kinds:
            conditions[kind] = value
    return conditions

@cython.ccall
def _consume_last_condition_8616(self: Instruction_ANY, last_condition: Any, prev_emu: object, prev: Any) -> None:
    """Record that this JCC consumed the previous instruction's last condition."""
    if not (isinstance(last_condition, IRCondition) and prev_emu is not None):
        return
    cast(Any, self)._inertia_consumed_last_condition_8616 = last_condition
    cast(Any, self)._inertia_consumed_last_condition_addr_8616 = getattr(prev, "addr", None)
    if self._next_instruction_is_simple_jcc():
        with contextlib.suppress(Exception):
            self.emu.set_last_condition(last_condition)
    else:
        with contextlib.suppress(Exception):
            prev_emu.clear_last_condition()

@cython.ccall
def _prev_cmp_semantics_8616(self: Instruction_ANY, prev: object) -> object:
    """Read CMP semantics from the actual preceding instruction in this IRSB.

    Pending transfer evidence is keyed only by address and can belong to a
    different image or path. It cannot replace architectural FLAGS in emitted
    execution IR; a branch without an adjacent producer reads those flags.
    ``prev`` is the dynamic pyvex instruction boundary.
    """
    prev_semantics = getattr(prev, "simple_semantics", None) if prev is not None else None
    return cast(tuple[Any, ...] | None, prev_semantics)

def _cmp_result_jcc_condition_8616(self: Instruction_ANY, kind: object, lhs: Any, rhs: Any) -> Any | None:
    """Build the per-kind comparison expression over CMP operands."""
    build: object
    kinds: object
    groups: tuple[tuple[Any, Callable[[], Any]], ...] = (
        (JCC_EQ_MNEMONICS_8616, lambda: lhs == rhs),
        (JCC_NE_MNEMONICS_8616, lambda: lhs != rhs),
        (JCC_SLE_MNEMONICS_8616, lambda: lhs.signed <= rhs.signed),
        (JCC_SGT_MNEMONICS_8616, lambda: lhs.signed > rhs.signed),
        (JCC_SLT_MNEMONICS_8616, lambda: lhs.signed < rhs.signed),
        (JCC_SGE_MNEMONICS_8616, lambda: lhs.signed >= rhs.signed),
        (JCC_ULT_MNEMONICS_8616, lambda: lhs < rhs),
        (JCC_UGE_MNEMONICS_8616, lambda: lhs >= rhs),
        (JCC_ULE_MNEMONICS_8616, lambda: lhs <= rhs),
        (JCC_UGT_MNEMONICS_8616, lambda: lhs > rhs),
    )
    for kinds, build in groups:
        if kind in kinds:
            return build()
    return None

@cython.ccall
def _resolve_jcc_condition_8616(self: Instruction_ANY, kind: object, last_condition: Any, prev: Any) -> Any | None:
    """Resolve a direct JCC predicate from last-condition, result, or CMP evidence."""
    branch_cond: object
    operands: object
    prev_semantics: object
    result_condition: object
    if isinstance(last_condition, IRCondition):
        branch_cond = _direct_jcc_condition_from_last_condition_8616(cast(Any, self), kind, last_condition)
        if branch_cond is not None:
            return branch_cond
    result_condition = direct_register_result_zero_jcc_8616(
        cast(Any, self), kind, instruction_addr=int(self.addr), previous=prev,
    )
    if result_condition is not None:
        return result_condition
    prev_semantics = _prev_cmp_semantics_8616(self, prev)
    if prev_semantics is None:
        return None
    operands = self._cmp_operands_from_semantics(prev_semantics)
    if operands is None:
        return None
    lhs, rhs = operands
    return _cmp_result_jcc_condition_8616(self, kind, lhs, rhs)

@cython.ccall
def _record_sub_reg_imm_condition_8616(self: Instruction_ANY, dst: Any, src: Any, dst_reg: object, imm: Any) -> None:
    """Record CMP-style operands for ``sub reg16, imm`` when a JCC follows."""
    normalized_operands: object
    if not self._next_instruction_is_simple_jcc():
        return
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

@cython.ccall
def _cond_cmp_reg_reg16_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    rhs: object
    _, lhs_reg, rhs_reg = semantics
    lhs = _cond_reg_chain_8616(self, lhs_reg, width_bits=16, proven=True, unshifted=True)
    rhs = _cond_reg_chain_8616(self, rhs_reg, width_bits=16, proven=True, unshifted=True)
    return (lhs, rhs) if lhs is not None and rhs is not None else None

@cython.ccall
def _cond_cmp_reg_imm16_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    _, lhs_reg, imm = semantics
    lhs = _cond_reg_chain_8616(self, lhs_reg, width_bits=16, proven=True)
    rhs = self._condition_const_value_8616(imm, width_bits=16)
    return (lhs, rhs) if lhs is not None else None

@cython.ccall
def _cond_cmp_reg_mem16_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    rhs: object
    _, lhs_reg, mem_spec = semantics
    lhs = _cond_reg_chain_8616(self, lhs_reg, width_bits=16, proven=True)
    rhs = self._condition_stack_value_8616(mem_spec, width_bits=16, memory_access_insn=self.addr)
    return (lhs, rhs) if lhs is not None and rhs is not None else None

@cython.ccall
def _cond_cmp_reg_abs16_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    _, lhs_reg, offset = semantics
    lhs = self._condition_reg_value_8616(lhs_reg, width_bits=16)
    rhs = self._condition_direct_ds_value_8616(offset, width_bits=16)
    return (lhs, rhs) if lhs is not None else None

@cython.ccall
def _cond_cmp_mem_reg16_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    rhs: object
    _, mem_spec, rhs_reg = semantics
    lhs = self._condition_stack_value_8616(mem_spec, width_bits=16, memory_access_insn=self.addr)
    rhs = _cond_reg_chain_8616(self, rhs_reg, width_bits=16, unshifted=True)
    return (lhs, rhs) if lhs is not None and rhs is not None else None

@cython.ccall
def _cond_mem_imm_indexed_lhs_8616(self: Instruction_ANY, mem_spec: Any) -> Any:
    """Build the indexed DS lhs for ``cmp [bp+..], imm`` when stack lookup fails."""
    index_state: object
    lhs: object
    register_index: object
    if not (isinstance(mem_spec, tuple) and mem_spec):
        return None
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
        register_index = self._condition_reg_value_8616(base_reg, width_bits=16)
        if register_index is not None:
            lhs = self._condition_indexed_ds_value_8616(
                mem_spec,
                (register_index, 0),
                width_bits=16,
                memory_access_insn=self.addr,
            )
    return lhs

@cython.ccall
def _cond_cmp_mem_imm16_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    _, mem_spec, imm = semantics
    lhs = self._condition_stack_value_8616(mem_spec, width_bits=16, memory_access_insn=self.addr)
    if lhs is None:
        lhs = _cond_mem_imm_indexed_lhs_8616(self, mem_spec)
    rhs = self._condition_const_value_8616(imm, width_bits=16)
    return (lhs, rhs) if lhs is not None else None

@cython.ccall
def _cond_cmp_abs_reg16_8616(self: Instruction_ANY, semantics: object) -> object:
    rhs: object
    _, offset, rhs_reg = semantics
    lhs = self._condition_direct_ds_value_8616(offset, width_bits=16)
    rhs = _cond_reg_chain_8616(self, rhs_reg, width_bits=16, unshifted=True)
    return (lhs, rhs) if rhs is not None else None

@cython.ccall
def _cond_cmp_abs_imm16_8616(self: Instruction_ANY, semantics: object) -> object:
    _, offset, imm = semantics
    return (
        self._condition_direct_ds_value_8616(offset, width_bits=16),
        self._condition_const_value_8616(imm, width_bits=16),
    )

@cython.ccall
def _cond_cmp_reg_abs8_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    _, lhs_reg, offset = semantics
    lhs = self._condition_reg_value_8616(lhs_reg, width_bits=8)
    rhs = self._condition_direct_ds_value_8616(offset, width_bits=8)
    return (lhs, rhs) if lhs is not None else None

@cython.ccall
def _cond_cmp_reg_imm8_8616(self: Instruction_ANY, semantics: object) -> object:
    lhs: object
    _, lhs_reg, imm = semantics
    lhs = _cond_reg_chain_8616(self, lhs_reg, width_bits=8, proven=True)
    rhs = self._condition_const_value_8616(imm, width_bits=8)
    return (lhs, rhs) if lhs is not None else None

@cython.ccall
def _cond_cmp_abs_reg8_8616(self: Instruction_ANY, semantics: object) -> object:
    rhs: object
    _, offset, rhs_reg = semantics
    lhs = self._condition_direct_ds_value_8616(offset, width_bits=8)
    rhs = self._condition_reg_value_8616(rhs_reg, width_bits=8)
    return (lhs, rhs) if rhs is not None else None

@cython.ccall
def _cond_cmp_abs_imm8_8616(self: Instruction_ANY, semantics: object) -> object:
    _, offset, imm = semantics
    return (
        self._condition_direct_ds_value_8616(offset, width_bits=8),
        self._condition_const_value_8616(imm, width_bits=8),
    )

@cython.ccall
def _cond_indexed_ds_retry_8616(self: Instruction_ANY, mem_spec: Any, index_state: Any, width_bits: cython.longlong, addr: Any) -> Any:
    """Retry an indexed DS value with a fresh zero-shift register index."""
    indexed: object
    register_index: object
    indexed = Instruction_ANY._condition_indexed_ds_value_8616(
        mem_spec,
        index_state,
        width_bits=width_bits,
        memory_access_insn=addr,
    )
    if indexed is None:
        base_reg = str(mem_spec[0]).lower() if isinstance(mem_spec, tuple) and mem_spec else ""
        register_index = self._condition_reg_value_8616(base_reg, width_bits=16)
        if register_index is not None:
            indexed = Instruction_ANY._condition_indexed_ds_value_8616(
                mem_spec,
                (register_index, 0),
                width_bits=width_bits,
                memory_access_insn=self.addr,
            )
    return indexed

@cython.ccall
def _cond_cmp_indexed8_8616(self: Instruction_ANY, kind: object, semantics: object) -> object:
    index_state: object
    indexed: object
    register: object
    _, first, second = semantics
    mem_spec = first if kind == "cmp_indexed_abs_reg8" else second
    reg_name = second if kind == "cmp_indexed_abs_reg8" else first
    base_reg = str(mem_spec[0]).lower() if isinstance(mem_spec, tuple) and mem_spec else ""
    index_state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(base_reg)
    indexed = _cond_indexed_ds_retry_8616(self, 
        mem_spec,
        index_state,
        8,
        int(self.addr) if isinstance(getattr(self, "addr", None), int) else None,
    )
    register = _cond_reg_chain_8616(self, reg_name, width_bits=8, proven=True)
    if indexed is None or register is None:
        return None
    return (indexed, register) if kind == "cmp_indexed_abs_reg8" else (register, indexed)

@cython.ccall
def _cond_cmp_indexed16_8616(self: Instruction_ANY, kind: object, semantics: object) -> object:
    index_state: object
    indexed: object
    register: object
    _, first, second = semantics
    mem_spec = first if kind == "cmp_indexed_abs_reg16" else second
    reg_name = second if kind == "cmp_indexed_abs_reg16" else first
    base_reg = str(mem_spec[0]).lower()
    index_state = Instruction_ANY._inertia_condition_index_reg_state_8616.get(base_reg)
    indexed = _cond_indexed_ds_retry_8616(self, mem_spec, index_state, 16, self.addr)
    register = _cond_reg_chain_8616(self, reg_name, width_bits=16, proven=True)
    if indexed is None or register is None:
        return None
    return (indexed, register) if kind == "cmp_indexed_abs_reg16" else (register, indexed)

@cython.ccall
def _cond_sub_reg_operands_8616(self: Instruction_ANY, kind: object, semantics: object) -> object:
    lhs: object
    rhs: object
    _, lhs_reg, rhs_operand = semantics
    lhs = self._condition_reg_value_8616(lhs_reg, width_bits=16)
    if kind == "sub_reg_reg16":
        rhs = self._condition_reg_value_8616(rhs_operand, width_bits=16)
    elif kind == "sub_reg_mem16":
        rhs = self._condition_stack_value_8616(rhs_operand, width_bits=16)
    else:
        rhs = self._condition_const_value_8616(rhs_operand, width_bits=16)
    return (lhs, rhs) if lhs is not None and rhs is not None else None

@cython.ccall
def _cond_incdec_operands_8616(self: Instruction_ANY, kind: object, semantics: object) -> object:
    lhs: object
    _, lhs_reg, operation_count = semantics
    lhs = _cond_reg_chain_8616(self, lhs_reg, width_bits=16, proven=True)
    boundary = (
        (-int(operation_count)) & 0xFFFF
        if kind == "inc_reg16"
        else int(operation_count)
    )
    rhs = self._condition_const_value_8616(boundary, width_bits=16)
    return (lhs, rhs) if lhs is not None else None

@cython.ccall
def _arithmetic_rhs_value_8616(self: Instruction_ANY, kind: object, operand: Any) -> IRValue | IRBinaryValue | None:
    """Resolve the rhs typed value for one register arithmetic semantics."""
    if kind in {"add_reg_mem16", "sub_reg_mem16"}:
        return self._condition_stack_value_8616(operand, width_bits=16)
    if kind in {"add_reg_reg16", "sub_reg_reg16"}:
        rhs_reg = str(operand).lower()
        return self._condition_proven_reg_value_8616(
            rhs_reg,
            width_bits=16,
        ) or self._condition_unshifted_index_reg_value_8616(
            rhs_reg,
            width_bits=16,
        )
    if kind in {"add_reg_imm16", "sub_reg_imm16"} and isinstance(operand, int):
        return self._condition_const_value_8616(
            operand,
            width_bits=16,
        )
    return None

@cython.ccall
def _infer_full_lift_semantics_from_operands_8616(self: Instruction_ANY) -> tuple[tuple[Any, ...] | None, tuple[str, str] | None, str | None]:
    """Recover byte-copy/incdec/shift provenance when no value semantics matched."""
    dst_reg8: object
    reg_name: object
    shift: object
    src_reg8: object
    byte_copy: object = None
    preserved_shift_reg: object = None
    semantics: object = None
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
    return semantics, byte_copy, preserved_shift_reg

@cython.ccall
def _transfer_cmp_semantics_8616(self: Instruction_ANY, semantics: object) -> None:
    """Publish typed CMP operands as normalized condition evidence."""
    typed_operands: object
    typed_operands = self._condition_operands_from_cmp_semantics_8616(semantics)
    if typed_operands is not None:
        self._record_cmp_condition_source(
            *typed_operands,
            normalized_lhs=typed_operands[0],
            normalized_rhs=typed_operands[1],
            producer_semantics=semantics,
        )

@cython.ccall
def _transfer_test_semantics_8616(self: Instruction_ANY, semantics: object) -> None:
    """Publish typed TEST masked-value evidence for full-lift operands."""
    typed_value: object
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

@cython.ccall
def _transfer_mov_index_state_8616(self: Instruction_ANY, semantics: object) -> None:
    """Seed index-register state for full-lift mov load semantics."""
    if semantics is None:
        return
    kind = str(semantics[0])
    if kind == "mov_reg_mem16":
        self._set_condition_index_reg_stack_state_8616(
            str(semantics[1]),
            semantics[2],
        )
    elif kind == "mov_reg_abs16":
        self._set_condition_index_reg_direct_state_8616(
            str(semantics[1]),
            int(semantics[2]),
        )
    elif kind == "mov_reg_indexed_abs16":
        self._set_condition_reg_indexed_value_8616(
            str(semantics[1]),
            semantics[2],
            width_bits=16,
        )

@cython.ccall
def _jcc_fallthrough_addr_8616(self: Instruction_ANY) -> int | None:
    """Compute the not-taken fallthrough address for this JCC."""
    with contextlib.suppress(Exception):
        fallthrough_size = int(getattr(getattr(self, "cs", None), "size", 0) or 2)
        candidate_fallthrough = int(self.addr) + fallthrough_size
        if operator.ne(candidate_fallthrough, int(self.addr)):
            return candidate_fallthrough
    return None

@cython.ccall
def _jcc_condition_source_8616(self: Instruction_ANY) -> Any:
    """Recover the pending ConditionSource for this JCC."""
    prev_emu: object
    source: object
    source = getattr(self.emu, "_inertia_last_condition_source", None)
    if not isinstance(source, ConditionSource) and getattr(self, "_past_instructions", None):
        prev_emu = getattr(self._past_instructions[-1], "emu", None)
        source = getattr(prev_emu, "_inertia_last_condition_source", None)
    if not isinstance(source, ConditionSource):
        source = Instruction_ANY._inertia_pending_condition_sources_by_addr.pop(int(self.addr), None)
    return source

@cython.ccall
def _normalized_jcc_source_operands_8616(self: Instruction_ANY, source: ConditionSource) -> tuple[Any, Any]:
    """Prefer typed/normalized operands over the raw recorded source operands."""
    typed_cmp_operands: object
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
    return lhs, rhs

@cython.ccall
def _lift_sign_extend_al_ax_8616(self: Instruction_ANY) -> None:
    self.put(
        self.get("al", Type.int_8).widen_signed(Type.int_16),
        "ax",
    )
    self._widen_condition_reg_value_state_8616("ax")

@cython.ccall
def _lift_sign_extend_ax_eax_8616(self: Instruction_ANY) -> None:
    self.put(
        self.get("ax", Type.int_16).widen_signed(Type.int_32),
        "eax",
    )
    self._widen_condition_reg_value_state_8616("eax")

@cython.ccall
def _lift_ror_dead_flags_8616(self: Instruction_ANY, semantics: object) -> None:
    value: object
    _, reg_name, count = semantics
    value = self.get(reg_name, Type.int_32)
    if count:
        rotate_count = self.constant(count, Type.int_8)
        inverse_count = self.constant(32 - count, Type.int_8)
        value = (value >> rotate_count) | (value << inverse_count)
    self.put(value, reg_name)
    self._clear_condition_index_reg_state_8616(reg_name)
    self._clear_condition_reg_value_state_8616(reg_name)

@cython.ccall
def _lift_push_reg16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, reg_name = semantics
    value = self._get_reg16(reg_name)
    sp = self._get_reg16("sp") - self._const16(2)
    self.put(sp, "sp")
    if reg_name == "sp":
        value = sp + self._const16(2)
    self._stack_store16(sp, value, offset=-2)

@cython.ccall
def _lift_push_imm16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, imm = semantics
    sp = self._get_reg16("sp") - self._const16(2)
    self.put(sp, "sp")
    self._stack_store16(sp, self._const16(imm), offset=-2)

@cython.ccall
def _lift_push_mem16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, mem_spec = semantics
    sp = self._get_reg16("sp") - self._const16(2)
    self.put(sp, "sp")
    self._stack_store16(sp, self._load_mem16(mem_spec), offset=-2)

@cython.ccall
def _lift_pop_reg16_8616(self: Instruction_ANY, semantics: object) -> None:
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

@cython.ccall
def _saved_call_ip_8616(self: Instruction_ANY) -> VexValue:
    """Convert the decoded instruction's next address to an architectural IP."""
    # The typed arithmetic owner also supports concrete emulator values; this
    # adapter supplies PyVEX's expression and constant surfaces.
    return cast(VexValue, architectural_offset(
        self.addr + self.cs.size, cast(CoordinateValue, self._get_reg16("cs")),
        ControlWidth.WORD, cast(CoordinateConstant, self.constant),
        domain=self.arch.control_address_domain,
    ))


@cython.ccall
def _lift_call_8616(self: Instruction_ANY, semantics: object) -> None:
    """Retain the native near-call frame and selector-relative target.

    Recognizing a helper's bytes does not prove the selected runtime target,
    its normal-return path, or its memory/flag effects. Summaries belong to
    proof consumers; helper registration must never erase this native call.
    """
    _, target = semantics
    ret_addr = _saved_call_ip_8616(self)
    sp = self._get_reg16("sp") - self._const16(2)
    self.put(sp, "sp")
    self._stack_store16(sp, ret_addr, offset=-2)
    # Capstone's immediate is a decoded relative destination. Recover the
    # displacement modulo WORD, wrap architectural IP, then restore CS's
    # full loader coordinate rather than truncating the physical destination.
    next_address = self.addr + self.cs.size
    destination = relative_continuation(
        next_address, cast(CoordinateValue, self._get_reg16("cs")),
        int(target) - next_address, ControlWidth.WORD,
        cast(CoordinateConstant, self.constant),
        domain=self.arch.control_address_domain,
    )
    self.jump(None, cast(VexValue, destination), JumpKind.Call)

@cython.ccall
def _lift_call_mem16_8616(self: Instruction_ANY, semantics: object) -> None:
    """Preserve the architectural frame for an indirect near word call."""
    _, mem_spec = semantics
    target = self._load_mem16(mem_spec)
    ret_addr = _saved_call_ip_8616(self)
    sp = self._get_reg16("sp") - self._const16(2)
    self.put(sp, "sp")
    self._stack_store16(sp, ret_addr, offset=-2)
    self.jump(None, target, JumpKind.Call)

@cython.ccall
def _lift_enter_8616(self: Instruction_ANY, semantics: object) -> None:
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

@cython.ccall
def _lift_leave_8616(self: Instruction_ANY) -> None:
    bp = self._get_reg16("bp")
    self.put(bp, "sp")
    self.put(self._stack_load16(bp, offset=0, base="bp"), "bp")
    self.put(bp + self._const16(2), "sp")

@cython.ccall
def _lift_mov_reg_imm16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, reg_name, imm = semantics
    self.put(self._const16(imm), reg_name)
    self._clear_condition_index_reg_state_8616(reg_name)
    self._clear_condition_reg_value_state_8616(reg_name)
    self._set_condition_reg_value_state_8616(
        reg_name,
        self._condition_const_value_8616(int(imm), width_bits=16),
    )

@cython.ccall
def _mov_lift_value_8616(self: Instruction_ANY, role: object, operand: Any) -> Any:
    """Materialize one mov load value by its operand-role tag."""
    if role == "reg16":
        return self._get_reg16(operand)
    if role == "mem16":
        return self._load_mem16(operand)
    if role == "abs16":
        return self._load_abs16(operand)
    if role == "idx8":
        return self._load_indexed_abs(operand, width_bytes=1)
    if role == "idx16":
        return self._load_indexed_abs(operand, width_bytes=2)
    return self._load_abs8(operand)

@cython.ccall
def _mov_lift_state_8616(self: Instruction_ANY, role: object, dst_reg: Any, operand: Any) -> None:
    """Apply the mov destination's typed condition-state update."""
    if role == "copy":
        self._copy_condition_index_reg_state_8616(dst_reg, operand)
        self._copy_condition_reg_value_state_8616(dst_reg, operand)
    elif role == "set_stack":
        self._set_condition_index_reg_stack_state_8616(dst_reg, operand)
    elif role == "set_direct":
        self._set_condition_index_reg_direct_state_8616(dst_reg, operand)
    elif role == "set_indexed8":
        self._set_condition_reg_indexed_value_8616(dst_reg, operand, width_bits=8)
    elif role == "set_indexed16":
        self._set_condition_reg_indexed_value_8616(dst_reg, operand, width_bits=16)
    else:
        self._set_condition_reg_direct_byte_value_8616(dst_reg, operand)

@cython.ccall
def _lift_mov_load_8616(self: Instruction_ANY, kind: object, semantics: object) -> None:
    """Lift ``mov reg, <load>`` with its typed state update."""
    load_role, state_role = _MOV_LIFT_LOAD_ROLES_8616[kind]
    _, dst_reg, operand = semantics
    self.put(_mov_lift_value_8616(self, load_role, operand), dst_reg)
    _mov_lift_state_8616(self, state_role, dst_reg, operand)

@cython.ccall
def _lift_mov_mem_reg16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, mem_spec, src_reg = semantics
    self._store_mem16(mem_spec, self._get_reg16(src_reg))

@cython.ccall
def _lift_mov_mem_imm16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, mem_spec, imm = semantics
    self._store_mem16(mem_spec, self._const16(imm))

@cython.ccall
def _lift_lea_reg_bpdisp16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, dst_reg, mem_spec = semantics
    self.put(self._addr_from_bp_mem(mem_spec), dst_reg)
    self._clear_condition_index_reg_state_8616(dst_reg)
    self._clear_condition_reg_value_state_8616(dst_reg)

@cython.ccall
def _lift_xor_reg_mem8_8616(self: Instruction_ANY, semantics: object) -> None:
    _, dst_reg, mem_spec = semantics
    self._xor_reg_mem8(dst_reg, mem_spec)
    self._clear_condition_reg_value_state_8616(dst_reg)

@cython.ccall
def _lift_add_reg_imm16_8616(self: Instruction_ANY, semantics: object) -> None:
    _, reg_name, imm = semantics
    self._binop_reg_imm("add", reg_name, imm)
    self._clear_condition_index_reg_state_8616(reg_name)
    self._clear_condition_reg_value_state_8616(reg_name)

@cython.ccall
def _lift_binop_reg_abs16_8616(self: Instruction_ANY, semantics: object) -> None:
    op_name, dst_reg, offset = semantics
    self._binop_reg_abs(op_name[:-10], dst_reg, offset)
    self._clear_condition_index_reg_state_8616(dst_reg)
    self._clear_condition_reg_value_state_8616(dst_reg)

@cython.ccall
def _lift_binop_abs_dst_8616(self: Instruction_ANY, semantics: object, *, imm: cython.bint) -> None:
    op_name, offset, src_operand = semantics
    if imm:
        self._binop_abs_imm(op_name[:-10], offset, src_operand)
    else:
        self._binop_abs_reg(op_name[:-10], offset, src_operand)

@cython.ccall
def _lift_ret_8616(self: Instruction_ANY, imm: cython.longlong = 0) -> None:
    """Pop a word IP and retain the full loaded destination after adding CS."""
    sp = self._get_reg16("sp")
    ret_addr = self._stack_load16(sp, offset=0)
    self.put(sp + self._const16(2 + imm), "sp")
    # PyVEX values form a dynamic third-party arithmetic boundary.
    target = linear_continuation(
        cast(CoordinateValue, self._get_reg16("cs")), cast(CoordinateValue, ret_addr),
        ControlWidth.WORD, cast(CoordinateConstant, self.constant), control_width=ControlWidth.DWORD,
        domain=self.arch.control_address_domain,
    )
    self.jump(None, cast(VexValue, target), JumpKind.Ret)

@cython.ccall
def _lift_simple_suffix_8616(self: Instruction_ANY, kind: Any, semantics: object) -> cython.bint:
    """Dispatch the op-prefixed binop suffix semantics."""
    apply_binop: object
    suffix: object
    kind_str = str(kind)
    arith_suffixes: tuple[tuple[str, Callable[[str, Any, Any], None]], ...] = (
        ("_reg_reg16", self._binop_reg_reg),
        ("_reg_mem16", self._binop_reg_mem),
        ("_reg_imm16", self._binop_reg_imm),
    )
    for suffix, apply_binop in arith_suffixes:
        if kind_str.endswith(suffix):
            _lift_binop_with_arith_state_8616(self, semantics, apply_binop)
            return True
    if kind_str.endswith("_reg_abs16"):
        _lift_binop_reg_abs16_8616(self, semantics)
        return True
    if kind_str.endswith("_abs_imm16"):
        _lift_binop_abs_dst_8616(self, semantics, imm=True)
        return True
    if kind_str.endswith("_abs_reg16"):
        _lift_binop_abs_dst_8616(self, semantics, imm=False)
        return True
    return False

@cython.ccall
def _lift_simple_kind_8616(self: Instruction_ANY, kind: Any, semantics: object) -> cython.bint:
    """Dispatch exact-match simple semantics to their lift handlers."""
    handler: object
    sem_handler: object
    kind_str = str(kind)
    handlers: dict[str, Callable[[Instruction_ANY], None]] = {
        "sign_extend_al_ax": _lift_sign_extend_al_ax_8616,
        "sign_extend_ax_eax": _lift_sign_extend_ax_eax_8616,
        "leave": _lift_leave_8616,
    }
    handler = handlers.get(kind_str)
    if handler is not None:
        handler(self)
        return True
    sem_handlers: dict[str, Callable[[Instruction_ANY, tuple[Any, ...]], None]] = {
        "ror_reg_imm32_dead_flags": _lift_ror_dead_flags_8616,
        "push_reg16": _lift_push_reg16_8616,
        "push_imm16": _lift_push_imm16_8616,
        "push_mem16": _lift_push_mem16_8616,
        "pop_reg16": _lift_pop_reg16_8616,
        "call": _lift_call_8616,
        "call_mem16": _lift_call_mem16_8616,
        "enter": _lift_enter_8616,
        "mov_reg_imm16": _lift_mov_reg_imm16_8616,
        "mov_mem_reg16": _lift_mov_mem_reg16_8616,
        "mov_mem_imm16": _lift_mov_mem_imm16_8616,
        "lea_reg_bpdisp16": _lift_lea_reg_bpdisp16_8616,
        "xor_reg_mem8": _lift_xor_reg_mem8_8616,
        "add_reg_imm16": _lift_add_reg_imm16_8616,
    }
    sem_handler = sem_handlers.get(kind_str)
    if sem_handler is not None:
        sem_handler(self, semantics)
        return True
    if kind_str in _MOV_LIFT_LOAD_ROLES_8616:
        _lift_mov_load_8616(self, kind_str, semantics)
        return True
    if kind_str == "ret":
        _lift_ret_8616(self)
        return True
    if kind_str == "ret_imm16":
        _, imm = semantics
        _lift_ret_8616(self, int(imm))
        return True
    return False

@cython.ccall
def _dump_irsb_debug_8616(self: Instruction_ANY) -> None:
    """Emit the generated IRSB statement dump when DEBUG logging is on."""
    stmt: object
    if hasattr(self.emu, "irsb") and self.emu.irsb:
        logger.debug("IRSB at %04x: %s", self.addr, self.emu.irsb)
        irsb_dynamic = cast(Any, self.emu.irsb)
        irsb_obj = irsb_dynamic.irsb if hasattr(irsb_dynamic, "irsb") else irsb_dynamic
        if hasattr(irsb_obj, "statements"):
            for stmt in cast(Any, irsb_obj).statements:
                logger.debug("Statement: %s (type: %s)", type(stmt).__name__, type(stmt))
    logger.debug("IRSB generated successfully for %04x", self.addr)

@cython.ccall
def _exec_lifted_insn_8616(self: Instruction_ANY) -> None:
    """Execute the mode-matched instruction machine for this insn."""
    instr32: object
    instr32 = self.instr32
    if self.is_mode32 ^ bool(self.chsz_op):
        if instr32 is None:
            instr32 = self._ensure_instr32()
        instr32.exec()
    else:
        self.instr16.exec()

@cython.ccall
@cython.locals(debug_enabled=cython.bint)
def _compute_result_8616(self: Instruction_ANY) -> None:
    """Execute instruction effects and preserve explicit failure diagnostics."""
    try:
        debug_enabled = logger.isEnabledFor(logging.DEBUG)
        if debug_enabled:
            logger.debug("Lifting instruction at %04x: %s %s", self.addr, self.cs.mnemonic, self.cs.op_str)
        _exec_lifted_insn_8616(self)
        self._transfer_full_lift_condition_value_semantics_8616()
        if debug_enabled:
            _dump_irsb_debug_8616(self)
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

_CMP_LIFT_SHAPES_8616: Mapping[str, tuple[str, str, cython.longlong]] = {
    "cmp_mem_reg16": ("mem16", "reg16", 16),
    "cmp_mem_imm16": ("mem16", "imm16", 16),
    "cmp_abs_reg16": ("abs16", "reg16", 16),
    "cmp_abs_imm16": ("abs16", "imm16", 16),
    "cmp_reg_abs16": ("reg16", "abs16", 16),
    "cmp_reg_imm8": ("reg8", "imm8", 8),
    "cmp_reg_abs8": ("reg8", "abs8", 8),
    "cmp_abs_reg8": ("abs8", "reg8", 8),
    "cmp_abs_imm8": ("abs8", "imm8", 8),
    "cmp_indexed_abs_reg8": ("idx8", "reg8", 8),
    "cmp_reg_indexed_abs8": ("reg8", "idx8", 8),
    "cmp_indexed_abs_reg16": ("idx16", "reg16", 16),
    "cmp_reg_indexed_abs16": ("reg16", "idx16", 16),
}

_CMP_OPERAND_SHAPES_8616: Mapping[str, tuple[str, str, cython.longlong]] = {
    **{
        kind: shape
        for kind, shape in builtins.iter(_CMP_LIFT_SHAPES_8616.items())
        if kind != "cmp_reg_imm8"
    },
    "cmp_reg_reg16": ("reg16", "reg16", 16),
    "cmp_reg_imm16": ("reg16", "imm16", 16),
    "cmp_reg_mem16": ("reg16", "mem16", 16),
}

_MOV_LIFT_LOAD_ROLES_8616: Mapping[str, tuple[str, str]] = {
    "mov_reg_reg16": ("reg16", "copy"),
    "mov_reg_mem16": ("mem16", "set_stack"),
    "mov_reg_abs16": ("abs16", "set_direct"),
    "mov_reg_indexed_abs8": ("idx8", "set_indexed8"),
    "mov_reg_indexed_abs16": ("idx16", "set_indexed16"),
    "mov_reg_abs8": ("abs8", "set_byte"),
}


@cython.ccall
def _full_lift_semantics_8616(
    self: Instruction_ANY,
    matched_semantics: object,
    wide_memory_operand: cython.bint,
    segment_override: cython.bint,
    width_override: cython.bint,
) -> object:
    """Keep matched semantics as condition values only for clean wide-memory forms."""
    if not (
        wide_memory_operand
        and matched_semantics
        and str(matched_semantics[0]).startswith(
            ("add_reg_", "and_reg_", "cmp_", "mov_reg_", "or_reg_", "sub_reg_", "test_", "xor_reg_")
        )
    ):
        return None
    if segment_override or width_override or self.instr.invalid_lock or self.instr.invalid_opcode_extension:
        return None
    return matched_semantics

@cython.ccall
def _drop_matched_semantics_8616(
    self: Instruction_ANY,
    matched_semantics: object,
    segment_override: cython.bint,
    wide_memory_operand: cython.bint,
    width_override: cython.bint,
    dead_flags_wide_register_semantics: cython.bint,
) -> object:
    """Drop the simple-semantics match when overrides force the full parser."""
    if wide_memory_operand and not (
        matched_semantics is not None and str(matched_semantics[0]).startswith("cmp_")
    ):
        return None
    if (
        segment_override
        or (width_override and not dead_flags_wide_register_semantics)
        or self.instr.invalid_lock
        or self.instr.invalid_opcode_extension
    ):
        return None
    return matched_semantics

@cython.ccall
def _match_early_binary_semantics_8616(
    self: Instruction_ANY,
    mnemonic: object,
    dst_reg8: Any,
    src_indexed_mem8: object,
    src_abs_mem8: object,
    dst_reg: Any,
    src_indexed_mem16: object,
    dst_reg32: Any,
    src_imm8: object,
) -> object:
    """Match the ror/mov-load arms that precede mov/lea classification."""
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
    return None

@cython.ccall
def _match_test_semantics_8616(
    self: Instruction_ANY,
    dst_mem8: object,
    src_imm8: object,
    dst_mem: object,
    src_imm: object,
    dst_abs_mem8: object,
    dst_abs_mem: object,
) -> object:
    """Match ``test mem, imm`` shapes once a simple JCC is known to follow."""
    if dst_mem8 is not None and src_imm8 is not None:
        return ("test_mem_imm8", dst_mem8, src_imm8)
    if dst_mem is not None and src_imm is not None:
        return ("test_mem_imm16", dst_mem, src_imm)
    if dst_abs_mem8 is not None and src_imm8 is not None:
        return ("test_abs_imm8", dst_abs_mem8, src_imm8)
    if dst_abs_mem is not None and src_imm is not None:
        return ("test_abs_imm16", dst_abs_mem, src_imm)
    return None

@cython.ccall
def _match_arith_dst_reg_8616(
    self: Instruction_ANY,
    mnemonic: object,
    dst_reg: Any,
    src_reg: Any,
    src_mem: Any,
    src_abs_mem: object,
    src_imm: object,
) -> object:
    """Match ``op reg16, src`` once the destination register is proven."""
    if src_reg:
        return (f"{mnemonic}_reg_reg16", dst_reg, src_reg)
    if src_mem:
        return (f"{mnemonic}_reg_mem16", dst_reg, src_mem)
    if src_abs_mem is not None:
        return (f"{mnemonic}_reg_abs16", dst_reg, src_abs_mem)
    if src_imm is not None:
        return (f"{mnemonic}_reg_imm16", dst_reg, src_imm)
    return None

@cython.ccall
def _match_arith_binary_semantics_8616(
    self: Instruction_ANY,
    mnemonic: object,
    dst_reg: Any,
    src_reg: Any,
    src_mem: Any,
    src_abs_mem: Any,
    src_imm: object,
    dst_abs_mem: object,
) -> object:
    """Match add/sub/xor/and/or destination-source operand shapes."""
    if mnemonic not in {"add", "sub", "xor", "and", "or"}:
        return None
    if dst_reg and dst_reg not in {"sp", "bp"} and mnemonic in {"add", "sub"}:
        return _match_arith_dst_reg_8616(self, 
            mnemonic, dst_reg, src_reg, src_mem, src_abs_mem, src_imm
        )
    if (
        dst_reg
        and dst_reg not in {"sp", "bp"}
        and self._next_instruction_is_simple_jcc_from_bytes_8616()
    ):
        return _match_arith_dst_reg_8616(self, 
            mnemonic, dst_reg, src_reg, src_mem, src_abs_mem, src_imm
        )
    if dst_abs_mem is not None and src_imm is not None:
        return (f"{mnemonic}_abs_imm16", dst_abs_mem, src_imm)
    if dst_abs_mem is not None and src_reg:
        return (f"{mnemonic}_abs_reg16", dst_abs_mem, src_reg)
    return None

@cython.ccall
def _match_cmp_dst_reg_semantics_8616(
    self: Instruction_ANY,
    dst_reg: Any,
    src_reg: Any,
    src_mem: Any,
    src_imm: object,
    src_abs_mem: object,
) -> object:
    """Classify ``cmp reg16, src`` operand shapes."""
    if not dst_reg:
        return None
    if src_reg:
        return ("cmp_reg_reg16", dst_reg, src_reg)
    if src_mem:
        return ("cmp_reg_mem16", dst_reg, src_mem)
    if src_imm is not None:
        return ("cmp_reg_imm16", dst_reg, src_imm)
    if src_abs_mem is not None:
        return ("cmp_reg_abs16", dst_reg, src_abs_mem)
    return None

@cython.ccall
def _match_cmp_mem_semantics_8616(
    self: Instruction_ANY,
    dst_mem: Any,
    src_reg: Any,
    src_imm: object,
    dst_abs_mem: object,
    dst_abs_mem8: object,
    src_imm8: object,
    src_reg8: Any,
) -> object:
    """Classify ``cmp mem/absmem, src`` operand shapes."""
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
    return None

@cython.ccall
def _match_cmp_byte_indexed_semantics_8616(
    self: Instruction_ANY,
    dst_reg8: Any,
    src_imm8: object,
    dst_indexed_mem8: object,
    src_reg8: Any,
    src_indexed_mem8: object,
    dst_indexed_mem16: object,
    src_imm: object,
    src_reg: Any,
    dst_reg: Any,
    src_indexed_mem16: object,
    src: Any,
) -> object:
    """Classify the 8-bit and indexed CMP operand shapes."""
    src_abs_mem8: object
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

@cython.ccall
def _cond_reg_chain_8616(
    self: Instruction_ANY,
    reg_name: Any,
    *,
    width_bits: cython.longlong,
    proven: cython.bint = False,
    unshifted: cython.bint = False,
) -> Any:
    """Resolve a condition register value through the available evidence chain."""
    value: object
    value = self._condition_proven_reg_value_8616(reg_name, width_bits=width_bits) if proven else None
    if value is None and unshifted:
        value = self._condition_unshifted_index_reg_value_8616(reg_name, width_bits=width_bits)
    if value is None:
        value = self._condition_reg_value_8616(reg_name, width_bits=width_bits)
    return value

@cython.ccall
def _propagate_jcc_condition_source_8616(
    self: Instruction_ANY,
    source: ConditionSource,
    lhs: Any,
    rhs: Any,
    jcc_mnemonic: Any,
    fallthrough_addr: object,
    target_addr: Any,
) -> None:
    """Re-seed pending condition evidence at the JCC's taken/fallthrough targets."""
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

@cython.ccall
def _build_jcc_cond_ir_8616(
    self: Instruction_ANY,
    source: ConditionSource,
    lhs: Any,
    jcc_mnemonic: Any,
    block_addr: Any,
    target_addr: Any,
    fallthrough_addr: int | None,
    rhs: Any,
) -> Any:
    """Build the typed condition/failure for one consumed JCC source."""
    if source.kind == "cmp":
        return build_condition_from_cmp_8616(
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
    if source.kind == "test":
        return build_condition_from_test_8616(
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
    return ConditionFailure(
        "unknown_condition_source_kind",
        source=("jcc", jcc_mnemonic),
        detail=f"kind={source.kind}",
    )

@cython.ccall
def _record_consumed_jcc_condition_8616(
    self: Instruction_ANY,
    jcc_mnemonic: Any,
    block_addr: Any,
    target_addr: Any,
    fallthrough_addr: int | None,
) -> None:
    """Record a typed condition rebuilt from the consumed IRCondition evidence."""
    consumed_cond_ir: object
    consumed_condition: object
    consumed_condition = getattr(self, "_inertia_consumed_last_condition_8616", None)
    if not isinstance(consumed_condition, IRCondition):
        return
    consumed_cond_ir = self._typed_condition_from_consumed_ir_condition_8616(
        consumed_condition,
        jcc_mnemonic,
        block_addr=block_addr if isinstance(block_addr, int) else None,
        taken_target=target_addr,
        fallthrough_target=fallthrough_addr,
    )
    if consumed_cond_ir is not None:
        self._record_typed_condition_8616(consumed_cond_ir)

@cython.ccall
def _lift_binop_with_arith_state_8616(
    self: Instruction_ANY,
    semantics: object,
    apply_binop: Callable[[str, Any, Any], None],
) -> None:
    """Lift a reg-dst binop and retain its exact arithmetic condition value."""
    op_name, dst_reg, operand = semantics
    arithmetic_result = self._arithmetic_result_value_from_semantics_8616(
        semantics,
    )
    apply_binop(op_name[:-10], dst_reg, operand)
    self._clear_condition_index_reg_state_8616(dst_reg)
    self._clear_condition_reg_value_state_8616(dst_reg)
    self._set_condition_arithmetic_result_state_8616(arithmetic_result)


@cython.ccall
def _match_simple_binary_semantics_8616(self: Instruction_ANY, ops: Any) -> object:
    """Classify one two-operand instruction into typed frontend semantics."""
    cmp_sem: object
    early_sem: object
    mov_sem: object
    src_mem8: object
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

    early_sem = _match_early_binary_semantics_8616(self, 
        mnemonic, dst_reg8, src_indexed_mem8, src_abs_mem8, dst_reg, src_indexed_mem16, dst_reg32, src_imm8
    )
    if early_sem is not None:
        return early_sem
    mov_sem = _match_mov_lea_binary_semantics_8616(self, dst_reg, src_imm, src_reg, src_mem, src_abs_mem, dst_mem)
    if mov_sem is not None:
        return mov_sem
    cmp_sem = _match_cmp_binary_semantics_8616(self, 
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
        return _match_test_semantics_8616(self, 
            dst_mem8, src_imm8, dst_mem, src_imm, dst_abs_mem8, dst_abs_mem
        )
    if mnemonic == "xor" and dst_reg8 and src_mem8 is not None:
        return ("xor_reg_mem8", dst_reg8, src_mem8)
    return _match_arith_binary_semantics_8616(self, 
        mnemonic, dst_reg, src_reg, src_mem, src_abs_mem, src_imm, dst_abs_mem
    )

def _match_mov_lea_binary_semantics_8616(
    self: Instruction_ANY,
    dst_reg: Any,
    src_imm: Any,
    src_reg: Any,
    src_mem: Any,
    src_abs_mem: Any,
    dst_mem: Any,
) -> object:
    def _impl() -> object:
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

@cython.ccall
def _match_cmp_binary_semantics_8616(
    self: Instruction_ANY,
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
) -> object:
    """Classify CMP operands while preserving exact memory-address shape."""
    mem_sem: object
    reg_sem: object
    if self.cs.mnemonic != "cmp":
        return None
    reg_sem = _match_cmp_dst_reg_semantics_8616(self, 
        dst_reg, src_reg, src_mem, src_imm, src_abs_mem
    )
    if reg_sem is not None:
        return reg_sem
    mem_sem = _match_cmp_mem_semantics_8616(self, 
        dst_mem, src_reg, src_imm, dst_abs_mem, dst_abs_mem8, src_imm8, src_reg8
    )
    if mem_sem is not None:
        return mem_sem
    return _match_cmp_byte_indexed_semantics_8616(self, 
        dst_reg8,
        src_imm8,
        dst_indexed_mem8,
        src_reg8,
        src_indexed_mem8,
        dst_indexed_mem16,
        src_imm,
        src_reg,
        dst_reg,
        src_indexed_mem16,
        src,
    )

@cython.ccall
def _lift_simple_cmp_8616(self: Instruction_ANY, kind: object) -> cython.bint:
    """Lift CMP's architectural flag effect and its typed condition operands.

    A direct predicate for the following Jcc does not kill FLAGS: successors
    still observe the updated status bits at the block cutpoint.
    """
    shape: object
    shape = _CMP_LIFT_SHAPES_8616.get(kind)
    if shape is None:
        return False
    lhs_role, rhs_role, width_bits = shape
    _, lhs_operand, rhs_operand = cast(tuple[Any, Any, Any], self.simple_semantics)
    lhs_val = _cmp_lift_operand_value_8616(self, lhs_role, lhs_operand)
    rhs_val = _cmp_lift_operand_value_8616(self, rhs_role, rhs_operand)
    self._record_cmp_condition_source(lhs_val, rhs_val, width_bits=width_bits)
    self._update_binop_flags16("sub", lhs_val, rhs_val)
    return True

@cython.ccall
def _lift_simple_jcc_8616(self: Instruction_ANY, kind: object) -> cython.bint:
    """Emit direct control without discarding a word JMP's selector coordinate."""
    cond: object
    if kind not in (self._SIMPLE_JCC_8616 | {"jmp"}):
        return False
    semantics = cast(tuple[Any, ...], self.simple_semantics)
    _, abs_target = semantics
    if kind == "jmp" and self.cs.operands[0].size == 2:
        next_address = self.addr + self.cs.size
        destination = relative_continuation(
            next_address, cast(CoordinateValue, self._get_reg16("cs")),
            int(abs_target) - next_address, ControlWidth.WORD,
            cast(CoordinateConstant, self.constant),
            domain=self.arch.control_address_domain,
        )
        self.jump(None, cast(VexValue, destination), JumpKind.Boring)
        return True
    linear_target = self._linear_near_target_8616(int(abs_target))
    target = self._code_address_constant_8616(linear_target)
    if kind == "jmp":
        if operator.eq(linear_target, self.addr + self.cs.size):
            return True
        self.jump(None, target, JumpKind.Boring)
        return True
    cond = self._direct_jcc_condition(kind)
    if cond is None:
        conditions = _flag_jcc_conditions_8616(self)
        if kind not in conditions:
            raise NotImplementedError(kind)
        cond = conditions[kind]
    self._emit_simple_jcc(cond, target)
    return True


class Lifter86_16(GymratLifter):  # type: ignore[misc]  # dynamic pyvex base
    """Gymrat lifter entry point for the 16-bit x86 frontend."""

    instrs: ClassVar[list[type[Instruction_ANY]]] = [Instruction_ANY]

    @cython.locals(instructions=list)
    def decode(self) -> object:
        """Decode only the requested instruction window for lifting and lookahead.

        Gymrat passes the entire decoded suffix to each instruction even when
        lifting is bounded by ``max_inst``. Keep that suffix inside the same
        window so outside instructions cannot authorize flag-write deletion.
        """

        try:
            self.create_bitstrm()
            instructions = []
            addr = self.irsb.addr
            bitstrm = cast(bitstring.ConstBitStream, self.bitstrm)
            decode_next = self._decode_next_instruction
            bytepos = bitstrm.bytepos

            while not _bitstream_is_empty(bitstrm):
                if self.max_inst is not None and len(instructions) >= self.max_inst:
                    break
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


@cython.ccall
def main() -> None:
    """Run a local manual smoke test for the 16-bit lifter."""
    num: object
    test: object

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
