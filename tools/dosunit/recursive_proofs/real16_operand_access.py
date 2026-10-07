"""Layer: dosunit binary operand-coordinate evidence (staging).

Responsibility: retain the decoded logical segment and original operand width
for every raw native byte access. Logical offsets remain distinct from physical
addresses; candidates require an independent native binding and scope proof.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import StrEnum

import angr
import capstone
import pyvex
from capstone.x86 import X86OpMem
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_AND,
    X86_INS_CALL,
    X86_INS_CMP,
    X86_INS_DEC,
    X86_INS_INC,
    X86_INS_MOV,
    X86_INS_MOVSX,
    X86_INS_MOVZX,
    X86_INS_OR,
    X86_INS_RET,
    X86_INS_SUB,
    X86_INS_TEST,
    X86_INS_XOR,
    X86_OP_IMM,
    X86_OP_MEM,
)

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.capstone_memory_segment import effective_capstone_memory_segment_8616
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.contracts.proof_contracts import FactCounters
from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch
from tools.dosunit.recursive_proofs.real16_native_memory_access import (
    NativeAccessFact,
    NativeAccessKind,
    NativeAccessLimits,
    NativeAccessReason,
    NativeAccessReport,
    _AccessStop,
    collect_native_memory_accesses,
)


class OperandScopeReason(StrEnum):
    """Explicit raw-coordinate intake result, granting no architectural proof."""

    COLLECTED = "native_operand_coordinates_collected"
    DECODE = "native_operand_decode_incomplete"
    RAW = "native_operand_raw_ledger_incomplete"
    FORM = "native_operand_address_form_unsupported"
    MATCH = "native_operand_access_manifest_differs"
    LOWERING = "native_operand_prefix_lowering_refused"
    DEADLINE = "native_operand_original_deadline_exhausted"
    RESOURCE = "native_operand_intake_budget_exhausted"


class OperandSegment(StrEnum):
    """The encoded/defaulted architectural space, never a disjointness theorem."""

    CS = "cs"
    DS = "ds"
    ES = "es"
    SS = "ss"
    FS = "fs"
    GS = "gs"


@dataclass(frozen=True, slots=True)
class NativeOperand:
    """Binary-decoded width and logical offset at this instruction's entry."""

    instruction: int
    kind: NativeAccessKind
    segment: OperandSegment
    selector: S.SsaExpr
    offset: S.SsaExpr
    size: int


@dataclass(frozen=True, slots=True)
class OperandAccessFact:
    """One raw occurrence paired with its proposed original operand byte lane."""

    access: NativeAccessFact
    operand: NativeOperand
    byte_lane: int


@dataclass(frozen=True, slots=True)
class NativeOperandReport:
    """Complete decoded occurrence accounting; coordinates still require SMT proof."""

    reason: OperandScopeReason
    byte_hash: str
    raw: NativeAccessReport
    facts: tuple[OperandAccessFact, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def complete(self) -> bool:
        """A decoder proposal must retain the exact independent raw denominator."""
        ids = tuple(row.access.id for row in self.facts)
        return (self.reason is OperandScopeReason.COLLECTED and self.raw.complete
                and len(ids) == len(set(ids)) and set(ids) == set(self.raw.required)
                and self.counters.failure_count == 0)

    @property
    def binary_equivalence_proved(self) -> bool:
        """Neither guessed correspondence nor collected coordinates establish equality."""
        return False


class _OperandStop(Exception):
    """Retain an exact decoded-form or denominator refusal."""

    def __init__(self, reason: OperandScopeReason, detail: str) -> None:
        """Carry the owned reason with the underlying boundary description."""
        self.reason = reason
        super().__init__(detail)


def _constant(width: int, value: int) -> S.SsaExpr:
    """Use exact modular bitvectors for encoded displacement and stack arithmetic."""
    return S.SsaExpr("const", width, value=value & ((1 << width) - 1))


def _register(name: str, width: int, versions: dict[str, S.SsaExpr]) -> S.SsaExpr:
    """Read the actual native SSA storage view at the architecture boundary."""
    location = Arch86_16().registers.get(name)
    if location is None:
        raise _OperandStop(OperandScopeReason.FORM, f"decoded register has no native view: {name}")
    value = S._read_register(versions, location[0], width, source="decoded_operand_coordinate")
    if isinstance(value, S.LowerFailure):
        raise value
    return value


def _offset(instruction: capstone.CsInsn, memory: X86OpMem, width: int,
             versions: dict[str, S.SsaExpr]) -> S.SsaExpr:
    """Apply only the decoded base/index/scale/displacement with native bit widths."""
    offset = _constant(width, memory.disp)
    for register_id, scale in ((memory.base, 1), (memory.index, memory.scale)):
        if register_id:
            register_name = instruction.reg_name(register_id)
            if not isinstance(register_name, str) or not register_name:
                raise _OperandStop(OperandScopeReason.FORM, "decoded register has no architectural name")
            value = _register(register_name, width, versions)
            term = S.SsaExpr("mul", width, (value, _constant(width, scale)))
            offset = S.SsaExpr("add", width, (offset, term))
    return offset


def _explicit(instruction: capstone.CsInsn, versions: dict[str, S.SsaExpr]) -> tuple[NativeOperand, ...]:
    """Propose decoded integer-memory offsets without inspecting rendered assembly."""
    supported = {X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_ADD, X86_INS_SUB,
                 X86_INS_INC, X86_INS_DEC, X86_INS_AND, X86_INS_OR, X86_INS_XOR, X86_INS_TEST, X86_INS_CMP}
    if instruction.id not in supported:
        raise _OperandStop(OperandScopeReason.FORM, "implicit or unmodeled memory operand needs its own contract")
    width = instruction.addr_size * 8
    if width not in {16, 32}:
        raise _OperandStop(OperandScopeReason.FORM, "native effective address width is unsupported")
    result: list[NativeOperand] = []
    for operand in instruction.operands:
        if operand.type != X86_OP_MEM:
            continue
        segment_id = effective_capstone_memory_segment_8616(operand.mem.segment, operand.mem.base)
        name = instruction.reg_name(segment_id) if segment_id is not None else ""
        if name not in {item.value for item in OperandSegment}:
            raise _OperandStop(OperandScopeReason.FORM, "decoded memory segment is not architectural")
        offset = _offset(instruction, operand.mem, width, versions)
        if operand.size not in {1, 2, 4} or not operand.access:
            raise _OperandStop(OperandScopeReason.FORM, "decoded access width or read/write role is absent")
        segment = OperandSegment(name)
        selector = _register(name, 16, versions)
        for mask, kind in ((capstone.CS_AC_READ, NativeAccessKind.READ), (capstone.CS_AC_WRITE, NativeAccessKind.WRITE)):
            if operand.access & mask:
                result.append(NativeOperand(instruction.address, kind, segment, selector, offset, operand.size))
    return tuple(result)


def _operands(instruction: capstone.CsInsn, versions: dict[str, S.SsaExpr]) -> tuple[NativeOperand, ...]:
    """Near CALL/RET implicit stack accesses use encoded operand width and SP16."""
    if instruction.id not in {X86_INS_CALL, X86_INS_RET}:
        return _explicit(instruction, versions)
    if instruction.id == X86_INS_CALL and (len(instruction.operands) != 1 or instruction.operands[0].type != X86_OP_IMM):
        raise _OperandStop(OperandScopeReason.FORM, "indirect CALL requires separate target and stack operands")
    size = 4 if instruction.prefix[2] == 0x66 else 2
    offset = _register("sp", 16, versions)
    kind = NativeAccessKind.READ
    if instruction.id == X86_INS_CALL:
        kind = NativeAccessKind.WRITE
        offset = S.SsaExpr("sub", 16, (offset, _constant(16, size)))
    return (NativeOperand(instruction.address, kind, OperandSegment.SS,
                          _register("ss", 16, versions), offset, size),)


def _match(instruction: capstone.CsInsn, versions: dict[str, S.SsaExpr], accesses: tuple[NativeAccessFact, ...],
           facts: list[OperandAccessFact]) -> None:
    """Account each byte lane exactly once; ambiguous same-kind operands refuse."""
    operands = _operands(instruction, versions)
    for kind in (NativeAccessKind.READ, NativeAccessKind.WRITE):
        selected = tuple(row for row in operands if row.kind is kind)
        rows = tuple(row for row in accesses if row.kind is kind)
        if not rows and not selected:
            continue
        if len(selected) != 1 or sum(row.width for row in rows) != 8 * selected[0].size:
            raise _OperandStop(OperandScopeReason.MATCH, "raw byte widths differ from one decoded operand")
        lane = 0
        for row in rows:
            if row.width <= 0 or row.width % 8:
                raise _OperandStop(OperandScopeReason.MATCH, "raw access lacks a complete byte width")
            facts.append(OperandAccessFact(row, selected[0], lane))
            lane += row.width // 8


def _gather(irsb: pyvex.IRSB, instructions: tuple[capstone.CsInsn, ...], raw: NativeAccessReport,
            limits: NativeAccessLimits, facts: list[OperandAccessFact]) -> None:
    """Consume actual instruction-entry register versions before lowering their effects."""
    decoded = {row.address: row for row in instructions}
    state = S._IrsbLowerState(S._initial_reg_versions(), S.SsaExpr("mem_input", 0, name="mem"),
                             S.SsaExpr("mem_input", 0, name="io"))
    last_access = max((row.statement for row in raw.required), default=-1)
    for index, statement in enumerate(irsb.statements):
        # Later pure register/control effects belong to the full-state owner.
        # All earlier prefix effects and every raw memory occurrence remain.
        if index > last_access:
            break
        limits.check()
        if isinstance(statement, pyvex.stmt.IMark):
            accesses = tuple(row for row in raw.facts if row.instruction == statement.addr)
            if accesses:
                instruction = decoded.get(statement.addr)
                if instruction is None:
                    raise _OperandStop(OperandScopeReason.DECODE, "raw instruction has no decoded source")
                _match(instruction, state.reg_versions, accesses, facts)
        else:
            failure = S._lower_irsb_statement(statement, state, tyenv=irsb.tyenv,
                                              output_regs=tuple(S.INTERNAL_STATE_REGS))
            if failure is not None:
                raise failure


def _remaining(deadline: float) -> int:
    """Check the single absolute budget before entering the foreign lift boundary."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise _OperandStop(OperandScopeReason.DEADLINE, "original operand deadline exhausted")
    return remaining


def _fresh_lift(data: bytes, address: int) -> pyvex.IRSB:
    """Require the selected native engine to supply real unoptimized VEX."""
    project = angr.load_shellcode(data, arch=real16_loader_arch(), load_address=address)
    irsb = project.factory.block(address, byte_string=data, size=len(data), opt_level=0).vex
    if not isinstance(irsb, pyvex.IRSB):
        raise _OperandStop(OperandScopeReason.DECODE, "native operand intake requires the VEX backend")
    return irsb


def collect_native_operand_accesses(data: bytes, address: int, *, deadline: float) -> NativeOperandReport:
    """Freshly decode/lift one bounded byte block and preserve original operand widths.

    File/loader/domain binding is a separate prerequisite. A complete result is
    a proposal: every logical coordinate must still match its raw native address
    and every original wide operand must satisfy architectural segment scope.
    """
    limits = NativeAccessLimits(deadline)
    if type(data) is not bytes or not 0 < len(data) <= 4096 or type(address) is not int or not 0 <= address < 0x100000:
        raise ValueError("native operand intake requires bounded immutable real16 bytes")
    raw = NativeAccessReport(NativeAccessReason.MANIFEST, (), (), FactCounters(0, 0, 0, 0, 1), False)
    facts: list[OperandAccessFact] = []
    reason, detail = OperandScopeReason.COLLECTED, ""
    try:
        limits.check()
        with S._timeout_alarm(_remaining(deadline), message="native operand intake deadline"):
            irsb = _fresh_lift(data, address)
            raw = collect_native_memory_accesses(irsb, limits)
            if not raw.complete:
                raise _OperandStop(OperandScopeReason.RAW, raw.detail)
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
            decoder.detail = True
            instructions = tuple(decoder.disasm(data, address))
            if irsb.size != len(data) or sum(row.size for row in instructions) != len(data):
                raise _OperandStop(OperandScopeReason.DECODE, "complete bytes are not covered by native decode")
            _gather(irsb, instructions, raw, limits, facts)
        limits.check()
    except _OperandStop as refusal:
        reason, detail = refusal.reason, str(refusal)
    except S.LowerFailure as refusal:
        reason, detail = OperandScopeReason.LOWERING, f"{refusal.reason}: {refusal.message}"
    except _AccessStop as refusal:
        reason = OperandScopeReason.DEADLINE if refusal.reason is NativeAccessReason.DEADLINE else OperandScopeReason.RESOURCE
        detail = str(refusal)
    except TimeoutError as refusal:
        reason, detail = OperandScopeReason.DEADLINE, str(refusal)
    except RecursionError as refusal:
        reason, detail = OperandScopeReason.RESOURCE, str(refusal)
    except (angr.errors.SimEngineError, pyvex.errors.PyVEXError) as refusal:
        reason, detail = OperandScopeReason.DECODE, str(refusal)
    count = len(raw.required)
    ids = tuple(row.access.id for row in facts)
    failed = len(set(raw.required) - set(ids)) + len(ids) - len(set(ids)) + int(reason is not OperandScopeReason.COLLECTED)
    return NativeOperandReport(reason, hashlib.sha256(data).hexdigest(), raw, tuple(facts),
                               FactCounters(count, count, count, len(facts), failed), detail)
