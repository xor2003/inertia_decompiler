"""Layer: Frontend/angr compatibility.

Responsibility: patch angr calling-convention behavior needed for 16-bit x86.
Forbidden: source/COD/text-backed signature recovery or rewrite-stage call repair.
Dynamic boundary: this module patches third-party angr calling-convention
analysis, project, function, IRSB, and capstone objects. Owned Inertia
contracts must use typed fields and dot access.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable, Iterator
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.calling_convention import calling_convention as _cc_analysis
from angr.analyses.calling_convention import fact_collector as _cc_fact_collector
from angr.analyses.calling_convention import utils as _cc_utils
from angr.errors import SimTranslationError
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimType, SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from capstone.x86_const import X86_OP_MEM, X86_REG_INVALID, X86_REG_SS
from pyvex.expr import Get
from pyvex.stmt import Put

from .capstone_memory_segment import effective_capstone_memory_segment_8616
from .semantics.terminal_register_returns import collect_terminal_ax_return_evidence_8616
from .semantics.terminal_return_storage import TerminalReturnStorage8616, terminal_return_storage_8616
from .simos_86_16 import SimCC8616MSCsmall
from .widening.stack_argument_widths import (
    StackWordArithmeticFact8616,
    StackWordRegisterRole8616,
    WideStackArgumentWidthEvidence8616,
    analyze_wide_stack_argument_widths_8616,
)

__all__ = [
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_stack_byte_prototype_evidence",
    "apply_x86_16_wide_stack_prototype_evidence",
    "apply_x86_16_wide_stack_prototype_evidence_at_address",
    "collect_bp_word_stack_access_offsets_8616",
    "collect_wide_stack_argument_width_evidence_8616",
]


class _WideReturnEvidence8616(Enum):
    NONE = "none"
    DX_AX_TERMINAL_ARITH = "dx_ax_terminal_arith"


_ABI_WORD_BYTES_8616: int = 2
_FIRST_STACK_ARGUMENT_8616: int = 4
_OFFSET_SIGN_BIT_8616: int = 0x8000
_OFFSET_MASK_8616: int = 0xFFFF
_OFFSET_MODULUS_8616: int = 0x10000


class _CapstoneMemory8616(Protocol):
    """Typed view of the capstone x86 memory operand fields used here."""

    base: int
    disp: int


class _CapstoneOperand8616(Protocol):
    """Typed view of the capstone operand fields used by ABI evidence."""

    type: int
    size: int
    reg: int
    mem: _CapstoneMemory8616


class _CapstoneInstruction8616(Protocol):
    """Typed view of a capstone instruction after wrapper normalization."""

    mnemonic: str
    operands: tuple[_CapstoneOperand8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return capstone's canonical register name."""
        ...


def _has_explicit_arg_names_8616(prototype: object) -> bool:
    arg_names = getattr(prototype, "arg_names", None) or ()
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return True
    return False


def _irsb_reads_word_bp_8616(irsb: object, arch: object) -> bool:
    arch_dynamic = cast(Any, arch)
    irsb_dynamic = cast(Any, irsb)
    bp_offset = arch_dynamic.registers["bp"][0]
    for stmt in irsb_dynamic.statements:
        for expr in stmt.expressions:
            if isinstance(expr, Get) and expr.offset == bp_offset and expr.ty == "Ity_I16":
                return True
    return False


def _count_ax_dx_puts_8616(irsb: object, arch: object) -> int:
    arch_dynamic = cast(Any, arch)
    irsb_dynamic = cast(Any, irsb)
    count = 0
    for stmt in irsb_dynamic.statements:
        if not isinstance(stmt, Put):
            continue
        reg_name = arch_dynamic.translate_register_name(stmt.offset, size=arch_dynamic.bytes)
        if reg_name in {"ax", "dx"}:
            count += 1
    return count


def _iter_function_blocks_8616(project: object, function: object) -> Iterator[object]:
    project_dynamic = cast(Any, project)
    # Dynamic angr function compatibility boundary.
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            yield project_dynamic.factory.block(int(block_addr), opt_level=0)
        except SimTranslationError:
            continue


def _capstone_reg_name_8616(insn: object, reg_id: int) -> str:
    """Return a lower-case register name from a capstone or angr capstone wrapper."""
    try:
        return str(cast(Any, _capstone_instruction_8616(insn)).reg_name(reg_id)).lower()
    except Exception:
        return ""


def _capstone_instruction_8616(insn: object) -> object:
    """Return the underlying capstone instruction from an angr wrapper."""
    # Dynamic angr/capstone compatibility boundary.
    return getattr(insn, "insn", insn)


def _typed_capstone_instruction_8616(insn: object) -> _CapstoneInstruction8616:
    """Return a typed view over a normalized third-party instruction."""
    return cast(_CapstoneInstruction8616, _capstone_instruction_8616(insn))


def _bp_word_memory_offset_8616(insn: object, operand: _CapstoneOperand8616) -> int | None:
    """Return an exact positive SS:BP word offset, refusing indexed addresses."""
    if operand.type != X86_OP_MEM or operand.size != _ABI_WORD_BYTES_8616 or operand.mem.base == X86_REG_INVALID:
        return None
    if _capstone_reg_name_8616(insn, operand.mem.base) != "bp":
        return None
    # Partial third-party adapters can omit optional addressing fields.
    index = getattr(operand.mem, "index", X86_REG_INVALID)
    segment = effective_capstone_memory_segment_8616(
        getattr(operand.mem, "segment", X86_REG_INVALID), operand.mem.base,
    )
    if index != X86_REG_INVALID or segment != X86_REG_SS:
        return None
    displacement = operand.mem.disp
    if _OFFSET_SIGN_BIT_8616 <= displacement <= _OFFSET_MASK_8616:
        displacement -= _OFFSET_MODULUS_8616
    return displacement if displacement >= _FIRST_STACK_ARGUMENT_8616 else None


def _binary_stack_operand_offset_8616(insn: object) -> int | None:
    """Return the sole BP word offset used by a two-operand instruction."""
    operands = _typed_capstone_instruction_8616(insn).operands
    if len(operands) != 2:
        return None
    offsets = tuple(
        offset
        for operand in operands
        if (offset := _bp_word_memory_offset_8616(insn, operand)) is not None
    )
    return offsets[0] if len(offsets) == 1 else None


def _compared_register_id_8616(insn: object) -> int | None:
    """Return the register compared with one exact BP word operand."""
    instruction = _typed_capstone_instruction_8616(insn)
    operands = instruction.operands
    if instruction.mnemonic.lower() != "cmp" or len(operands) != 2:
        return None
    for index, operand in enumerate(operands):
        if _bp_word_memory_offset_8616(insn, operand) is None:
            continue
        peer = operands[1 - index]
        return peer.reg if peer.type == 1 else None
    return None


def _written_register_id_8616(insn: object) -> int | None:
    """Return the destination register id for a register-writing instruction."""
    operands = _typed_capstone_instruction_8616(insn).operands
    if not operands or operands[0].type != 1:
        return None
    return operands[0].reg


def _written_register_role_8616(insn: object) -> StackWordRegisterRole8616:
    """Classify the ABI return role of an instruction destination register."""
    register_id = _written_register_id_8616(insn)
    if register_id is None:
        return StackWordRegisterRole8616.OTHER
    register_name = _capstone_reg_name_8616(insn, register_id)
    if register_name == "ax":
        return StackWordRegisterRole8616.AX_LOW_RETURN
    if register_name == "dx":
        return StackWordRegisterRole8616.DX_HIGH_RETURN
    return StackWordRegisterRole8616.OTHER


def _wide_stack_argument_evidence_from_insns_8616(
    instruction_groups: Iterator[tuple[object, ...]],
) -> WideStackArgumentWidthEvidence8616:
    """Normalize Capstone instructions before the Widening proof."""
    return analyze_wide_stack_argument_widths_8616(
        tuple(
            StackWordArithmeticFact8616(
                mnemonic=_typed_capstone_instruction_8616(insn).mnemonic,
                destination_register=_written_register_id_8616(insn),
                source_bp_offset=_binary_stack_operand_offset_8616(insn),
                compared_register=_compared_register_id_8616(insn),
                destination_role=_written_register_role_8616(insn),
            )
            for insn in instruction_group
        )
        for instruction_group in instruction_groups
    )


def _function_instruction_groups_8616(project: object, function: object) -> Iterator[tuple[object, ...]]:
    """Yield capstone instruction groups for each known function block."""
    for block in _iter_function_blocks_8616(project, function):
        # Dynamic angr block compatibility boundary.
        yield tuple(cast(Any, block).capstone.insns or ())


def _wide_stack_argument_evidence_8616(
    project: object,
    function: object,
) -> WideStackArgumentWidthEvidence8616:
    """Classify carry-linked arithmetic over adjacent BP words as one value."""
    return _wide_stack_argument_evidence_from_insns_8616(_function_instruction_groups_8616(project, function))


def collect_wide_stack_argument_width_evidence_8616(
    project: object,
    function: object,
) -> WideStackArgumentWidthEvidence8616:
    """Collect binary-backed logical stack-argument widths for lowering."""
    return _wide_stack_argument_evidence_8616(project, function)


def _instruction_writes_reg_8616(insn: object, reg_name: str) -> bool:
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if not operands:
        return False
    first = operands[0]
    # Dynamic capstone compatibility boundary.
    if int(getattr(first, "type", -1)) != 1:
        return False
    # Dynamic capstone compatibility boundary.
    return _capstone_reg_name_8616(insn, int(getattr(first, "reg", 0) or 0)) == reg_name


def _instruction_reads_reg_8616(insn: object, reg_names: set[str]) -> bool:
    """Return whether an instruction reads one of the requested registers."""
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    for operand in operands[1:]:
        # Dynamic capstone compatibility boundary.
        if int(getattr(operand, "type", -1)) != 1:
            continue
        # Dynamic capstone compatibility boundary.
        if _capstone_reg_name_8616(insn, int(getattr(operand, "reg", 0) or 0)) in reg_names:
            return True
    # Dynamic capstone compatibility boundary.
    mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
    if mnemonic in {"cmp", "test"} and operands:
        first = operands[0]
        # Dynamic capstone compatibility boundary.
        return int(getattr(first, "type", -1)) == 1 and _capstone_reg_name_8616(
            # Dynamic capstone compatibility boundary.
            insn, int(getattr(first, "reg", 0) or 0)
        ) in reg_names
    return False


def _bp_byte_load_offsets_from_instructions_8616(project: object, function: object) -> tuple[int, ...]:
    """Return positive BP stack offsets read through byte memory operands."""
    offsets: set[int] = set()
    for block in _iter_function_blocks_8616(project, function):
        # Dynamic angr/capstone compatibility boundary.
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            # Dynamic capstone compatibility boundary.
            for operand in tuple(getattr(insn, "operands", ()) or ()):
                # Dynamic capstone compatibility boundary.
                if int(getattr(operand, "type", -1)) != 3 or int(getattr(operand, "size", 0) or 0) != 1:
                    continue
                # Dynamic capstone compatibility boundary.
                mem = getattr(operand, "mem", None)
                # Dynamic capstone compatibility boundary.
                if mem is None or not getattr(mem, "base", None):
                    continue
                if _capstone_reg_name_8616(insn, int(mem.base)) != "bp":
                    continue
                # Dynamic capstone compatibility boundary.
                disp = int(getattr(mem, "disp", 0) or 0)
                if 0x8000 <= disp <= 0xFFFF:
                    disp -= 0x10000
                if disp >= 4:
                    offsets.add(disp)
    return tuple(sorted(offsets))


def _terminal_byte_return_evidence_8616(project: object, function: object) -> bool:
    """Detect terminal low-byte-only return production without source declarations."""
    return terminal_return_storage_8616(project, function) is TerminalReturnStorage8616.AL


def _terminal_word_return_evidence_8616(project: object, function: object) -> bool:
    """Return whether a terminal path leaves a word result in AX."""
    return terminal_return_storage_8616(project, function) is TerminalReturnStorage8616.AX


def _function_target_addrs_8616(function: object) -> set[int]:
    """Return address aliases that may identify a function in exact slices."""
    # Dynamic angr function compatibility boundary.
    target_addr = getattr(function, "addr", None)
    if not isinstance(target_addr, int):
        return set()
    targets = {target_addr}
    # Dynamic angr function compatibility boundary.
    original_delta = getattr(getattr(function, "project", None), "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        targets.add(target_addr + original_delta)
    return targets


def _caller_sign_extends_byte_return_8616(project: object, function: object) -> bool | None:
    """Return whether callers prove signed or non-signed AL consumption."""
    try:
        from .analysis_helpers import collect_neighbor_call_targets
    except Exception:
        return None
    target_addrs = _function_target_addrs_8616(function)
    if not target_addrs:
        return None
    # Dynamic angr project compatibility boundary.
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None:
        return None
    saw_matching_call = False
    try:
        callers = tuple(functions.values())
    except Exception:
        return False
    for caller in callers:
        try:
            seeds = tuple(collect_neighbor_call_targets(caller))
        except Exception:
            continue
        for seed in seeds:
            # CallTargetSeed is owned evidence, not part of the angr boundary.
            if seed.target_addr not in target_addrs:
                continue
            saw_matching_call = True
            if _callsite_cbw_verdict_8616(caller, seed.callsite_addr) is True:
                return True
    return False if saw_matching_call else None


def _callsite_cbw_verdict_8616(caller: object, callsite_addr: int) -> bool | None:
    """Return True when the instructions after this callsite prove CBW."""
    try:
        from .callsite_summary import _block_insns_for_callsite, _find_call_index
    except Exception:
        return None
    insns = _block_insns_for_callsite(caller, callsite_addr)
    call_idx = _find_call_index(insns, callsite_addr) if insns else None
    if call_idx is None:
        return None
    for follow in insns[call_idx + 1 : call_idx + 5]:
        # Dynamic capstone compatibility boundary.
        mnemonic = str(getattr(follow, "mnemonic", "") or "").lower()
        if mnemonic == "cbw":
            return True
        if _instruction_reads_reg_8616(follow, {"al"}) or _instruction_writes_reg_8616(follow, "ax"):
            break
    return False


def _terminal_wide_return_evidence_from_instructions_8616(
    project: object,
    function: object,
    insns: tuple[object, ...],
) -> _WideReturnEvidence8616:
    """Detect a terminal DX:AX producer in one bounded instruction sequence."""
    terminal_dx_ops = {"adc", "sbb", "mov"}
    last_ax_idx = None
    last_dx_idx = None
    last_dx_mnemonic = None
    for idx, insn in enumerate(insns):
        if _instruction_writes_reg_8616(insn, "ax"):
            last_ax_idx = idx
        if _instruction_writes_reg_8616(insn, "dx"):
            last_dx_idx = idx
            last_dx_mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
    if last_ax_idx is None or last_dx_idx is None or last_dx_idx <= last_ax_idx:
        return _WideReturnEvidence8616.NONE
    if last_dx_mnemonic in terminal_dx_ops and _wide_return_suffix_is_terminal_8616(
        project, function, insns, last_dx_idx
    ):
        return _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH
    return _WideReturnEvidence8616.NONE


def _terminal_wide_return_evidence_8616(project: object, function: object) -> _WideReturnEvidence8616:
    """Detect a DX:AX result only from a complete terminal-path census."""
    evidence = collect_terminal_ax_return_evidence_8616(project, function)
    return (
        _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH
        if evidence.proves_wide_return
        else _WideReturnEvidence8616.NONE
    )


def _wide_return_suffix_is_terminal_8616(
    project: object, function: object, insns: tuple[object, ...], producer_idx: int
) -> bool:
    """Return whether a DX:AX producer is followed only by epilogue instructions."""
    for insn in insns[producer_idx + 1 :]:
        # Dynamic capstone compatibility boundary.
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if mnemonic in {"nop", "pop", "leave"}:
            continue
        if mnemonic in {"jmp", "ljmp"}:
            target = _direct_jump_target_8616(insn)
            return target is not None and _target_block_is_epilogue_only_8616(project, function, target)
        return mnemonic in {"ret", "retf", "iret"}
    return False


def _direct_jump_target_8616(insn: object) -> int | None:
    """Return a direct jump target from a capstone instruction, if present."""
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if len(operands) != 1:
        return None
    operand = operands[0]
    # Dynamic capstone compatibility boundary.
    if int(getattr(operand, "type", -1)) != 2:
        return None
    # Dynamic capstone compatibility boundary.
    target = getattr(operand, "imm", None)
    return target if isinstance(target, int) else None


def _target_block_is_epilogue_only_8616(project: object, function: object, target_addr: int) -> bool:
    """Return whether a direct target block contains only stack teardown and return."""
    project_dynamic = cast(Any, project)
    # Dynamic angr function compatibility boundary.
    block_addrs = set(getattr(function, "block_addrs_set", ()) or ())
    if block_addrs and target_addr not in block_addrs:
        return False
    try:
        block = project_dynamic.factory.block(target_addr, opt_level=0)
    except SimTranslationError:
        return False
    # Dynamic angr/capstone compatibility boundary.
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    if not insns:
        return False
    for idx, insn in enumerate(insns):
        # Dynamic capstone compatibility boundary.
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if mnemonic in {"nop", "pop", "leave"} or _instruction_is_mov_sp_bp_8616(insn):
            continue
        return idx == len(insns) - 1 and mnemonic in {"ret", "retf", "iret"}
    return False


def _instruction_is_mov_sp_bp_8616(insn: object) -> bool:
    """Return whether an instruction is the 16-bit epilogue form `mov sp, bp`."""
    # Dynamic capstone compatibility boundary.
    if str(getattr(insn, "mnemonic", "") or "").lower() != "mov":
        return False
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if len(operands) != 2:
        return False
    lhs = operands[0]
    rhs = operands[1]
    # Dynamic capstone compatibility boundary.
    if int(getattr(lhs, "type", -1)) != 1 or int(getattr(rhs, "type", -1)) != 1:
        return False
    # Dynamic capstone compatibility boundary.
    lhs_reg = int(getattr(lhs, "reg", 0) or 0)
    # Dynamic capstone compatibility boundary.
    rhs_reg = int(getattr(rhs, "reg", 0) or 0)
    return _capstone_reg_name_8616(insn, lhs_reg) == "sp" and _capstone_reg_name_8616(insn, rhs_reg) == "bp"


def _bp_word_load_offsets_from_insns_8616(instruction_groups: Iterator[tuple[object, ...]]) -> tuple[int, ...]:
    """Return positive SS:BP word operand offsets for ABI evidence."""
    offsets: set[int] = set()
    for insns in instruction_groups:
        for insn in insns:
            for operand in _typed_capstone_instruction_8616(insn).operands:
                offset = _bp_word_memory_offset_8616(insn, operand)
                if offset is not None:
                    offsets.add(offset)
    return tuple(sorted(offsets))


def collect_bp_word_stack_access_offsets_8616(project: object, function: object) -> tuple[int, ...]:
    """Return positive BP stack offsets accessed through word memory operands."""
    return _bp_word_load_offsets_from_insns_8616(_function_instruction_groups_8616(project, function))


def _wide_stack_arg_count_from_offsets_8616(offsets: tuple[int, ...]) -> int:
    remaining = set(offsets)
    count = 0
    offset = 4
    while offset in remaining and offset + 2 in remaining:
        count += 1
        offset += 4
    return count


def _sim_type_stack_width_8616(sim_type: object) -> int:
    """Return a 16-bit ABI stack width for an angr type."""
    try:
        bit_width = int(cast(Any, sim_type).size)
    except (AttributeError, TypeError, ValueError):
        return 2
    return max(2, (bit_width + 7) // 8)


def _existing_prototype_parts_8616(
    project: object, function: object
) -> tuple[list[SimType], SimType, bool]:
    """Read the current function prototype's args/return/variadic shape."""
    project_dynamic = cast(Any, project)
    existing = cast(Any, function).prototype
    if isinstance(existing, SimTypeFunction):
        return (
            list(cast(Iterable[SimType], existing.args or ())),
            existing.returnty,
            existing.variadic,
        )
    return [], SimTypeBottom(label="void").with_arch(project_dynamic.arch), False


def _merge_wide_stack_args_8616(
    physical_args: list[SimType],
    wide_offsets: set[int],
    arch: object,
    *,
    signed: bool,
) -> tuple[list[SimType], set[int]]:
    """Merge carry-linked adjacent stack words into logical wide arguments."""
    logical_args: list[SimType] = []
    materialized_offsets: set[int] = set()
    physical_index = 0
    stack_offset = 4
    while physical_index < len(physical_args):
        arg_type = physical_args[physical_index]
        arg_width = _sim_type_stack_width_8616(arg_type)
        if stack_offset in wide_offsets:
            if arg_width >= 4:
                logical_args.append(arg_type)
                materialized_offsets.add(stack_offset)
                stack_offset += arg_width
                physical_index += 1
                continue
            if physical_index + 1 < len(physical_args):
                high_type = physical_args[physical_index + 1]
                if arg_width == 2 and _sim_type_stack_width_8616(high_type) == 2:
                    logical_args.append(SimTypeLong(signed=signed).with_arch(cast(Any, arch)))
                    materialized_offsets.add(stack_offset)
                    stack_offset += 4
                    physical_index += 2
                    continue
        logical_args.append(arg_type)
        stack_offset += arg_width
        physical_index += 1
    return logical_args, materialized_offsets


def _wide_stack_arithmetic_prototype_from_evidence_8616(
    project: object,
    function: object,
    *,
    evidence: WideStackArgumentWidthEvidence8616,
    loaded_offsets: tuple[int, ...],
    signed: bool,
    terminal_wide_return: bool = False,
) -> tuple[object, object, WideStackArgumentWidthEvidence8616] | None:
    """Build a logical prototype from carry-linked adjacent stack words."""
    if evidence.classified_fact_count == 0:
        return None

    project_dynamic = cast(Any, project)
    physical_args, return_type, variadic = _existing_prototype_parts_8616(project, function)
    if terminal_wide_return and not isinstance(return_type, SimTypeLong):
        # Width evidence cannot override an already established wide signedness.
        return_type = SimTypeLong(signed=signed).with_arch(project_dynamic.arch)

    required_word_count = 0
    if loaded_offsets:
        required_word_count = ((max(loaded_offsets) - 4) // 2) + 1
    while len(physical_args) < required_word_count:
        physical_args.append(SimTypeShort(False).with_arch(project_dynamic.arch))

    logical_args, materialized_offsets = _merge_wide_stack_args_8616(
        physical_args, set(evidence.classified_offsets), project_dynamic.arch, signed=signed
    )

    materialized_evidence = evidence.with_materialized_count(len(materialized_offsets))
    if materialized_evidence.materialized_count != materialized_evidence.classified_fact_count:
        return None
    prototype = SimTypeFunction(logical_args, return_type, variadic=variadic).with_arch(project_dynamic.arch)
    return SimCC8616MSCsmall(project_dynamic.arch), prototype, materialized_evidence


def _wide_stack_arithmetic_prototype_from_function_8616(
    project: object, function: object, *, signed: bool
) -> tuple[object, object, WideStackArgumentWidthEvidence8616] | None:
    """Build a logical prototype from one discovered function body."""
    return _wide_stack_arithmetic_prototype_from_evidence_8616(
        project,
        function,
        evidence=_wide_stack_argument_evidence_8616(project, function),
        loaded_offsets=collect_bp_word_stack_access_offsets_8616(project, function),
        signed=signed,
        terminal_wide_return=_terminal_wide_return_evidence_8616(project, function)
        is not _WideReturnEvidence8616.NONE,
    )


def _wide_stack_arg_prototype_from_function_8616(
    project: object, function: object, *, signed: bool = True
) -> tuple[object, object] | None:
    project_dynamic = cast(Any, project)
    arithmetic_inference = _wide_stack_arithmetic_prototype_from_function_8616(
        project,
        function,
        signed=signed,
    )
    if arithmetic_inference is not None:
        cc, prototype, _evidence = arithmetic_inference
        return cc, prototype
    evidence = _terminal_wide_return_evidence_8616(project, function)
    if evidence is _WideReturnEvidence8616.NONE:
        return None
    arg_count = _wide_stack_arg_count_from_offsets_8616(collect_bp_word_stack_access_offsets_8616(project, function))
    if arg_count <= 0:
        return None
    wide_ty = SimTypeLong(signed=signed).with_arch(project_dynamic.arch)
    return SimCC8616MSCsmall(project_dynamic.arch), SimTypeFunction([wide_ty] * arg_count, wide_ty).with_arch(
        project_dynamic.arch
    )


def _stack_byte_prototype_from_function_8616(project: object, function: object) -> tuple[object, object] | None:
    """Infer a byte stack prototype from terminal AL and byte BP-load evidence."""
    project_dynamic = cast(Any, project)
    if not _terminal_byte_return_evidence_8616(project, function):
        return None
    arg_offsets = _bp_byte_load_offsets_from_instructions_8616(project, function)
    if not arg_offsets:
        return None
    signed_evidence = _caller_sign_extends_byte_return_8616(project, function)
    signed = True if signed_evidence is None else signed_evidence
    byte_ty = SimTypeChar(signed=signed).with_arch(project_dynamic.arch)
    return SimCC8616MSCsmall(project_dynamic.arch), SimTypeFunction([byte_ty] * len(arg_offsets), byte_ty).with_arch(
        project_dynamic.arch
    )


def _guess_retval_type_8616(self: object, cc: object, ret_val_size: object) -> object:
    """Refine angr's guessed return type using terminal register evidence."""
    self_dynamic = cast(Any, self)

    def _impl() -> object:
        ret_type = cast(Any, _guess_retval_type_8616)._orig(self, cc, ret_val_size)
        if getattr(self_dynamic.project.arch, "name", None) != "86_16" or ret_type is None:
            return ret_type
        if not isinstance(ret_type, SimTypeShort):
            return ret_type
        cc_dynamic = cast(Any, cc)
        if not getattr(cc_dynamic, "OVERFLOW_RETURN_VAL", None) or getattr(cc_dynamic, "RETURN_VAL", None) is None:
            return ret_type
        evidence = _terminal_wide_return_evidence_8616(self_dynamic.project, self_dynamic._function)
        if evidence is not _WideReturnEvidence8616.NONE:
            return SimTypeLong().with_arch(self_dynamic.project.arch)
        return ret_type

    return _impl()


def _promote_wide_return_and_stack_args_8616(
    self: object,
    prototype: object,
    *,
    promote_return: bool,
) -> object:
    """Apply proven wide stack arguments and an optional terminal DX:AX return."""
    self_dynamic = cast(Any, self)

    def _impl() -> object:
        if getattr(self_dynamic.project.arch, "name", None) != "86_16" or prototype is None:
            return prototype
        wide_stack_proto = _wide_stack_arg_prototype_from_function_8616(self_dynamic.project, self_dynamic._function)
        if wide_stack_proto is not None:
            _cc, promoted = wide_stack_proto
            return promoted
        if (
            promote_return
            and isinstance(prototype, SimTypeFunction)
            and _terminal_wide_return_evidence_8616(self_dynamic.project, self_dynamic._function)
            is not _WideReturnEvidence8616.NONE
        ):
            wide_type = SimTypeLong(signed=True).with_arch(self_dynamic.project.arch)
            return SimTypeFunction(
                list(prototype.args),
                wide_type,
                arg_names=prototype.arg_names,
                variadic=prototype.variadic,
            ).with_arch(self_dynamic.project.arch)
        return prototype

    return _impl()


def _fallback_wide_stack_return_prototype_8616(self: object) -> tuple[object, object] | None:
    """Return only a prototype backed by typed terminal wide-stack evidence."""
    self_dynamic = cast(Any, self)
    return _wide_stack_arg_prototype_from_function_8616(
        self_dynamic.project,
        self_dynamic._function,
    )


def _set_function_prototype_8616(
    function: object,
    cc: object,
    prototype: object,
    *,
    allow_binary_refinement: bool = False,
) -> tuple[object, object]:
    """Set one inferred prototype without replacing stronger named evidence."""
    function_dynamic = cast(Any, function)
    # Dynamic angr function compatibility boundary.
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        # Dynamic angr function compatibility boundary.
        _has_explicit_arg_names_8616(existing)
        or (
            not allow_binary_refinement
            and not bool(getattr(function, "is_prototype_guessed", True))
        )
    ):
        return cc, existing
    # Dynamic angr SimType compatibility boundary.
    if prototype is not None and getattr(prototype, "_arch", None) is None:
        with contextlib.suppress(Exception):
            prototype = cast(Any, prototype).with_arch(function_dynamic.project.arch)
    function_dynamic.prototype = prototype
    function_dynamic.prototype_source = PrototypeSource.CCA_DECOMPILER
    if cc is not None:
        with contextlib.suppress(Exception):
            function_dynamic.calling_convention = _far_aware_cc_8616(function, cc)
    return cc, prototype


def _far_aware_cc_8616(function: object, cc: object) -> object:
    """Substitute the proven far-frame convention over a seeded near MSC CC.

    Evidence passes build a near ``SimCC8616MSCsmall`` as the default caller-
    cleanup ABI. When the callee's own terminal ``retf`` proves a four-byte
    return frame, the far convention must win so arguments resolve at ``BP+6``.
    """
    from .lowering.argument_frame_base import msc_calling_convention_for_function_8616
    from .simos_86_16 import SimCC8616MSCmedium, SimCC8616MSCsmall

    if not isinstance(cc, (SimCC8616MSCsmall, SimCC8616MSCmedium)):
        return cc
    project = getattr(function, "project", None)
    if project is None:
        return cc
    return msc_calling_convention_for_function_8616(project, function)


def apply_x86_16_wide_stack_prototype_evidence(project: object, function: object) -> bool:
    """Promote guessed prototypes when binary evidence proves a wide stack ABI."""
    # Dynamic angr project compatibility boundary.
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    # Dynamic angr function compatibility boundary.
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        # Dynamic angr function compatibility boundary.
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return False
    inferred = _wide_stack_arg_prototype_from_function_8616(project, function)
    if inferred is None:
        return False
    cc, prototype = inferred
    _set_function_prototype_8616(function, cc, prototype)
    return True


def apply_x86_16_wide_stack_prototype_evidence_at_address(
    project: object,
    function: object,
    address: int,
    *,
    scan_size: int = 512,
) -> bool:
    """Promote a bodyless function stub from bounded binary instruction facts.

    Exact-region projects keep direct callees as bodyless stubs. This entrypoint
    reads a bounded window from the original project and refuses evidence unless
    a decoded return terminates the window.
    """
    project_dynamic = cast(Any, project)
    function_dynamic = cast(Any, function)
    if project_dynamic.arch.name != "86_16" or address < 0 or not 16 <= scan_size <= 4096:
        return False
    existing = function_dynamic.prototype
    if existing is not None and _has_explicit_arg_names_8616(existing):
        return False
    try:
        block = project_dynamic.factory.block(address, size=scan_size, opt_level=0)
    except (KeyError, SimTranslationError, ValueError):
        return False
    instructions: list[object] = []
    for insn in tuple(cast(Any, block).capstone.insns or ()):
        instructions.append(insn)
        if _typed_capstone_instruction_8616(insn).mnemonic.lower() in {"ret", "retf", "iret"}:
            break
    if not instructions or _typed_capstone_instruction_8616(instructions[-1]).mnemonic.lower() not in {
        "ret",
        "retf",
        "iret",
    }:
        return False
    instruction_group = (tuple(instructions),)
    inferred = _wide_stack_arithmetic_prototype_from_evidence_8616(
        project,
        function,
        evidence=_wide_stack_argument_evidence_from_insns_8616(iter(instruction_group)),
        loaded_offsets=_bp_word_load_offsets_from_insns_8616(iter(instruction_group)),
        signed=True,
        terminal_wide_return=_terminal_wide_return_evidence_from_instructions_8616(
            project, function, tuple(instructions)
        )
        is not _WideReturnEvidence8616.NONE,
    )
    if inferred is None:
        return False
    cc, prototype, evidence = inferred
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise RuntimeError("wide stack argument evidence was classified but not materialized")
    _set_function_prototype_8616(
        function,
        cc,
        prototype,
        allow_binary_refinement=True,
    )
    return True


def apply_x86_16_stack_byte_prototype_evidence(project: object, function: object) -> bool:
    """Promote guessed prototypes when binary evidence proves byte stack values."""
    # Dynamic angr project compatibility boundary.
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    # Dynamic angr function compatibility boundary.
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        # Dynamic angr function compatibility boundary.
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return False
    inferred = _stack_byte_prototype_from_function_8616(project, function)
    if inferred is None:
        return False
    cc, prototype = inferred
    _set_function_prototype_8616(function, cc, prototype)
    return True


def apply_x86_16_calling_convention_compatibility() -> None:
    """Install x86-16 calling-convention compatibility patches once per process."""
    _patch_sane_register_variable_8616()
    _patch_cca_analyze_function_8616()
    if getattr(_cc_analysis.CallingConventionAnalysis._guess_retval_type, "__name__", "") != "_guess_retval_type_8616":
        cast(Any, _guess_retval_type_8616)._orig = _cc_analysis.CallingConventionAnalysis._guess_retval_type
        cast(Any, _cc_analysis.CallingConventionAnalysis)._guess_retval_type = _guess_retval_type_8616


def _patch_sane_register_variable_8616() -> None:
    """Accept every register variable on the 16-bit architecture."""
    if getattr(_cc_utils.is_sane_register_variable, "__name__", "") == "_is_sane_register_variable_8616":
        return
    _orig_is_sane_register_variable = _cc_utils.is_sane_register_variable

    def _is_sane_register_variable_8616(
        arch: object, reg_offset: object, reg_size: object, def_cc: object = None
    ) -> bool:
        arch_dynamic = cast(Any, arch)
        if arch_dynamic.name == "86_16":
            return True
        return bool(cast(Any, _orig_is_sane_register_variable)(arch, reg_offset, reg_size, def_cc=def_cc))

    cast(Any, _cc_utils).is_sane_register_variable = _is_sane_register_variable_8616
    cast(Any, _cc_analysis).is_sane_register_variable = _is_sane_register_variable_8616
    cast(Any, _cc_fact_collector).is_sane_register_variable = _is_sane_register_variable_8616


def _patch_cca_analyze_function_8616() -> None:
    """Install the wide-return prototype fallback into CallingConventionAnalysis."""
    if getattr(_cc_analysis.CallingConventionAnalysis._analyze_function, "__name__", "") == "_analyze_function_8616":
        return
    cast(Any, _guess_retval_type_8616)._orig = _cc_analysis.CallingConventionAnalysis._guess_retval_type
    _analyze_function_orig = _cc_analysis.CallingConventionAnalysis._analyze_function

    def _analyze_function_8616(self: object) -> object:
        self_dynamic = cast(Any, self)
        existing_prototype = getattr(self_dynamic._function, "prototype", None)
        had_explicit_prototype = existing_prototype is not None and not bool(
            getattr(self_dynamic._function, "is_prototype_guessed", True)
        )
        result = cast(Any, _analyze_function_orig)(self)
        if result is None:
            fallback = _fallback_wide_stack_return_prototype_8616(self)
            if fallback is None:
                return result
            return _set_function_prototype_8616(self_dynamic._function, *fallback)
        cc, prototype = result
        if prototype is None:
            fallback = _fallback_wide_stack_return_prototype_8616(self)
            if fallback is not None:
                return _set_function_prototype_8616(self_dynamic._function, *fallback)
        promoted = _promote_wide_return_and_stack_args_8616(
            self,
            prototype,
            promote_return=not had_explicit_prototype,
        )
        if (
            promoted is not prototype
            and not had_explicit_prototype
            and not _has_explicit_arg_names_8616(promoted)
        ):
            return _set_function_prototype_8616(self_dynamic._function, cc, promoted)
        return cc, promoted

    cast(Any, _cc_analysis.CallingConventionAnalysis)._analyze_function = _analyze_function_8616
