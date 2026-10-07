"""Layer: Helper boundary.

Responsibility: execute memory access while recording segmented IR facts for alias/type consumers.
Forbidden: treating linear execution addresses as semantic storage identity.
"""

from __future__ import annotations

from typing import Protocol, cast

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import Type

from inertia.frontend.x86_16.hardware import Hardware
from inertia.frontend.x86_16.segment_offset_execution import advance_segment_offset_8616

from .addressing_helpers import ResolvedMemoryOperand, linear_address, resolve_memory_operand_8616
from .regs import reg16_t, sgreg_t
from .stack_helpers import StackEmulator, pop16, pop32, push16, push32, push_far_return_frame16

ITY_I8: object = Type.int_8
ITY_I16: object = Type.int_16
ITY_I32: object = Type.int_32

# Constants for access modes
MODE_READ: int = 0
MODE_WRITE: int = 1
MODE_EXEC: int = 2

# Module-level fact cache — bridges ephemeral emulator → persistent pipeline.
# Key = function address (int), value = list of AliasStorageFacts/AliasFailure.
# Populated by _record_semantic_memory_access() during VEX lifting.
# Consumed by collect_semantic_alias_facts_from_project_8616().
_inertia_module_alias_fact_cache: dict[int, list[object]] = {}


class _AddableValue(Protocol):
    """VEX value subset that can be added after address arithmetic."""

    def __add__(self, _other: object) -> object:
        """Return this value plus another VEX helper expression."""
        ...


class _CastableValue(Protocol):
    """VEX value subset that can be cast and shifted by access helpers."""

    def cast_to(self, _ty: object) -> _CastableValue:
        """Return this value cast to the requested VEX type."""
        ...

    def __lshift__(self, _other: int) -> _AddableValue:
        """Return this value shifted left by a constant bit count."""
        ...


class _JumpEmitter(Protocol):
    """Active lifter instruction jump API used by far control transfers."""

    def jump(
        self,
        _condition: object,
        _target: object,
        _jumpkind: object | None = None,
        **_kwargs: object,
    ) -> None:
        """Emit a VEX control-flow edge for the active instruction."""
        ...


class _InstructionAddressWidth8616(Protocol):
    """Decoded instruction API used for effective address-size resolution."""

    def effective_address_bits(self) -> int:
        """Return address width after applying decoded size overrides."""
        ...


class _InstructionSite8616(Protocol):
    """Active third-party lifter instruction site used for evidence identity."""

    addr: int


class DataAccess(Hardware):  # type: ignore[misc, unused-ignore]  # dynamic frontend base contract
    """Frontend access surface that keeps execution and semantic addresses separate."""

    active_instruction: object | None

    def __init__(self, size: int = 0) -> None:
        """Initialize TLB state and owned semantic access logs."""
        super().__init__(size)
        self.tlb: list[object | None] = []  # Translation Lookaside Buffer
        self._inertia_last_resolved_operand: ResolvedMemoryOperand | None = None
        self._inertia_resolved_operands: list[tuple[int, ResolvedMemoryOperand]] = []
        self._inertia_semantic_access_log: list[tuple[int, object]] = []
        self._inertia_current_block_addr: int | None = None
        self._inertia_uncollected_accesses: int = 0

    def set_segment(self, reg: sgreg_t, sel: object) -> None:
        """Write a segment selector through the frontend register surface."""
        self.set_sgreg(reg, sel)

    def get_segment(self, reg: sgreg_t | VexValue) -> object:
        """Read a segment selector through the frontend register surface."""
        return self.get_sgreg(reg)

    def convert_ss_vaddr(self, vaddr: object) -> object:
        """Return the execution-linear address for an SS-relative offset."""
        _, off = self.convert_segoff2vexv(sgreg_t.SS, vaddr)
        ss = cast(_CastableValue, self.get_sgreg(sgreg_t.SS)).cast_to(ITY_I32)
        return (ss << 4) + off

    def v2p(self, seg: object, off: object) -> object:
        """Return the execution-linear address for a segment:offset pair."""
        sg, vaddr = self.convert_segoff2vexv(seg, off)
        return (sg << 4) + vaddr

    def convert_segoff2vexv(self, seg: object, vaddr: object) -> tuple[_CastableValue, object]:
        """Normalize a segment and offset into VEX-width execution values."""
        if isinstance(seg, sgreg_t):
            sg = self.get_sgreg(seg)
        elif isinstance(seg, int):
            sg = self.constant(seg, ITY_I16)
        else:
            sg = seg
        if isinstance(vaddr, int):
            vaddr = self.constant(vaddr, ITY_I32)
        else:
            vaddr = cast(_CastableValue, vaddr).cast_to(ITY_I32)
        return cast(_CastableValue, sg).cast_to(ITY_I32), vaddr

    def _record_resolved_operand(self, operand: ResolvedMemoryOperand, mode: int) -> ResolvedMemoryOperand:
        """Remember the last decoded operand and record semantic evidence."""
        self._inertia_last_resolved_operand = operand
        self._inertia_resolved_operands.append((mode, operand))
        DataAccess._record_semantic_memory_access(self, operand, mode)
        return operand

    def _record_semantic_memory_access(self, operand: ResolvedMemoryOperand, mode: int) -> None:
        """Record typed IR address for alias/type consumption.

        The execution path still uses operand.exec_linear (linear) for the actual
        read/write.  This log is consumed by the alias and type recovery layers.

        AGENTS rule #3: exec_linear is execution-only; assert_semantic_safe()
        blocks accidental leakage of linear IR into semantic layers.
        """
        from inertia.ir.core import IRAddress

        # Hard block: no linear addresses in semantic logs
        operand.assert_semantic_safe()

        addr = operand.ir_address()

        # Do NOT create alias facts here.
        # Lifting may only record semantic IR addresses.
        # Alias facts are produced after stack-frame normalization
        # in collect_normalized_semantic_alias_facts_from_project_8616().

        if isinstance(addr, IRAddress):
            self._inertia_semantic_access_log.append((mode, addr))
            # Write to canonical evidence_cache.
            #
            # CFG-time lifting has no function owner and must not publish evidence.
            # Normalized collection re-lifts known blocks inside an explicit,
            # context-local function collection.
            from inertia.semantics.evidence_cache import (
                get_current_function_addr,
                record_access,
            )

            func_addr = get_current_function_addr()
            if isinstance(func_addr, int):
                active_instruction = self.lifter_instruction
                insn_addr = (
                    None
                    if active_instruction is None
                    else cast(_InstructionSite8616, active_instruction).addr
                )
                record_access(
                    function_addr=func_addr,
                    mode=mode,
                    addr=addr,
                    block_addr=self._inertia_current_block_addr,
                    insn_addr=insn_addr,
                    address_bits=operand.address_bits,
                )

    def _resolve_memory_operand(
        self, seg: object, addr: object, width_bits: int, mode: int, *, address_bits: int | None = None
    ) -> ResolvedMemoryOperand:
        """Decode an operand and record its semantic segmented address."""
        operand = self._resolved_segment_operand(seg, addr, width_bits, address_bits=address_bits)
        self._record_resolved_operand(operand, mode)
        return operand

    def _resolved_segment_operand(
        self, seg: object, addr: object, width_bits: int, *, address_bits: int | None = None
    ) -> ResolvedMemoryOperand:
        """Resolve an operand; explicit stack addressing overrides instruction prefixes."""
        if address_bits is not None:
            return resolve_memory_operand_8616(self, seg, addr, width_bits, address_bits=address_bits)
        address_bits = 16
        try:
            active_instruction = self.active_instruction
            active_address_bits = (
                0
                if active_instruction is None
                else cast(_InstructionAddressWidth8616, active_instruction).effective_address_bits()
            )
        except AttributeError:
            active_address_bits = 0
        if isinstance(active_address_bits, int) and active_address_bits > 0:
            address_bits = active_address_bits
        return resolve_memory_operand_8616(self, seg, addr, width_bits, address_bits=address_bits)

    def search_tlb(self, vpn: int) -> object | None:
        """Return a cached TLB entry when present."""
        if vpn + 1 > len(self.tlb) or self.tlb[vpn] is None:
            return None
        return self.tlb[vpn]

    def cache_tlb(self, vpn: int, pte: object) -> None:
        """Cache a TLB entry for frontend execution."""
        if vpn + 1 > len(self.tlb):
            self.tlb.extend([None] * (vpn + 1 - len(self.tlb)))
        self.tlb[vpn] = pte

    def push32(self, value: object) -> None:
        """Push a 32-bit value through the stack helper surface."""
        push32(cast(StackEmulator, self), value)

    def pop32(self) -> object:
        """Pop a 32-bit value through the stack helper surface."""
        return pop32(cast(StackEmulator, self))

    def push16(self, value: object) -> None:
        """Push a 16-bit value through the stack helper surface."""
        push16(cast(StackEmulator, self), value)

    def pop16(self) -> object:
        """Pop a 16-bit value through the stack helper surface."""
        return pop16(cast(StackEmulator, self))

    def read_mem32_seg(self, seg: object, addr: object, *, address_bits: int | None = None) -> object:
        """Read 32 bits from segmented memory while recording semantic evidence."""
        addresses = self._segment_byte_addresses(seg, addr, 32, MODE_READ, address_bits=address_bits)
        # PyVEX's vvifyresults decorator returns VexValue, not the wrapped RdTmp.
        result = cast(VexValue, cast(VexValue, self.read_mem8(cast(int | VexValue, addresses[0]))).cast_to(Type.int_32))
        for index, address in enumerate(addresses[1:], start=1):
            byte = cast(VexValue, cast(VexValue, self.read_mem8(cast(int | VexValue, address))).cast_to(Type.int_32))
            result = result | (byte << (index * 8))
        return result

    def read_mem16_seg(self, seg: object, addr: object, *, address_bits: int | None = None) -> object:
        """Read one typed word as independently wrapped segmented bytes."""
        low_address, high_address = self._segment_byte_addresses(seg, addr, 16, MODE_READ, address_bits=address_bits)
        low = cast(VexValue, self.read_mem8(cast(int | VexValue, low_address))).cast_to(Type.int_16)
        high = cast(VexValue, cast(VexValue, self.read_mem8(cast(int | VexValue, high_address))).cast_to(Type.int_16))
        return low | (high << 8)

    def read_mem8_seg(self, seg: object, addr: object) -> object:
        """Read 8 bits from segmented memory while recording semantic evidence."""
        operand = self._resolve_memory_operand(seg, addr, 8, MODE_READ)
        return self.read_mem8(cast(int | VexValue, operand.exec_linear))

    def write_mem32_seg(
        self, seg: object, addr: object, value: object, *, address_bits: int | None = None
    ) -> None:
        """Write 32 bits to segmented memory while recording semantic evidence."""
        addresses = self._segment_byte_addresses(seg, addr, 32, MODE_WRITE, address_bits=address_bits)
        value32 = self.constant(value, Type.int_32) if isinstance(value, int) else cast(VexValue, value)
        for index, address in enumerate(addresses):
            byte = cast(VexValue, cast(VexValue, value32 >> (index * 8)).cast_to(Type.int_8))
            self.write_mem8(cast(int | VexValue, address), byte)

    def write_mem16_seg(
        self, seg: object, addr: object, value: object, *, address_bits: int | None = None
    ) -> None:
        """Write one typed word as independently wrapped segmented bytes."""
        low_address, high_address = self._segment_byte_addresses(seg, addr, 16, MODE_WRITE, address_bits=address_bits)
        value16 = cast(VexValue, self.constant(value, Type.int_16) if isinstance(value, int) else value)
        low = cast(VexValue, value16.cast_to(Type.int_8))
        high = cast(VexValue, cast(VexValue, value16 >> 8).cast_to(Type.int_8))
        self.write_mem8(cast(int | VexValue, low_address), low)
        self.write_mem8(cast(int | VexValue, high_address), high)

    def write_mem8_seg(self, seg: object, addr: object, value: object) -> None:
        """Write 8 bits to segmented memory while recording semantic evidence."""
        operand = self._resolve_memory_operand(seg, addr, 8, MODE_WRITE)
        self.write_mem8(cast(int | VexValue, operand.exec_linear), cast(int | VexValue, value))

    def get_code8(self, offset: int) -> int:
        """Read an 8-bit immediate from the instruction bitstream."""
        assert offset == 0
        return cast(int, self.bitstream.read("uint:8"))

    def get_code16(self, offset: int) -> int:
        """Read a 16-bit immediate from the instruction bitstream."""
        assert offset == 0
        return cast(int, self.bitstream.read("uintle:16"))

    def get_code32(self, offset: int) -> int:
        """Read a 32-bit immediate from the instruction bitstream."""
        assert offset == 0
        return cast(int, self.bitstream.read("uintle:32"))

    def get_data16(self, seg: object, addr: object) -> object:
        """Read 16-bit segmented data for instruction helpers."""
        return self.read_mem16_seg(seg, addr)

    def get_data32(self, seg: object, addr: object) -> object:
        """Read 32-bit segmented data for instruction helpers."""
        return self.read_mem32_seg(seg, addr)

    def get_data8(self, seg: object, addr: object) -> object:
        """Read 8-bit segmented data for instruction helpers."""
        return self.read_mem8_seg(seg, addr)

    def put_data8(self, seg: object, addr: object, value: object) -> None:
        """Write 8-bit segmented data for instruction helpers."""
        self.write_mem8_seg(seg, addr, value)

    def put_data16(self, seg: object, addr: object, value: object) -> None:
        """Write 16-bit segmented data for instruction helpers."""
        self.write_mem16_seg(seg, addr, value)

    def put_data32(self, seg: object, addr: object, value: object) -> None:
        """Write 32-bit segmented data for instruction helpers."""
        self.write_mem32_seg(seg, addr, value)

    def callf(self, seg: object, ip: object, return_ip: object | None = None) -> None:
        """Emit a far call using execution-linear control flow."""
        push_far_return_frame16(cast(StackEmulator, self), return_ip)
        self.set_sgreg(sgreg_t.CS, seg)
        self.set_gpreg(reg16_t.IP, ip)
        laddr = linear_address(self, seg, ip)
        cast(_JumpEmitter, self.lifter_instruction).jump(None, laddr, jumpkind=JumpKind.Call)

    def jmpf(self, seg: object, ip: object) -> None:
        """Emit a far jump using execution-linear control flow."""
        self.set_sgreg(sgreg_t.CS, seg)
        self.set_gpreg(reg16_t.IP, ip)
        laddr = linear_address(self, seg, ip)
        cast(_JumpEmitter, self.lifter_instruction).jump(None, laddr, jumpkind=JumpKind.Boring)
    def _segment_byte_addresses(
        self,
        seg: object,
        addr: object,
        width_bits: int,
        mode: int,
        *,
        address_bits: int | None = None,
    ) -> tuple[object, ...]:
        """Record one typed operation and independently resolve wrapped bytes."""
        first = self._resolve_memory_operand(seg, addr, width_bits, mode, address_bits=address_bits)
        stepped_addr = (
            addr
            if isinstance(addr, int) or first.address_bits == 16
            else cast(VexValue, addr).cast_to(Type.int_32)
        )
        return tuple(
            first.exec_linear
            if delta == 0
            else self._resolved_segment_operand(
                seg,
                advance_segment_offset_8616(
                    stepped_addr,
                    delta,
                    first.address_bits,
                    self.constant(delta, Type.int_32 if first.address_bits == 32 else Type.int_16),
                ),
                8,
                address_bits=first.address_bits,
            ).exec_linear
            for delta in range(width_bits // 8)
        )
