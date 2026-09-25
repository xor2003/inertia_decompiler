"""Recover conservative simple loop evidence from decoded instructions.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ..decoded_memory_width import decoded_memory_operand_width_8616
from ..function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)


@dataclass(frozen=True, slots=True)
class InsnSummary8616:
    """Decoded instruction summary used by the counted-loop recognizer."""

    mnemonic: str
    op0_kind: str | None = None
    op0_value: int | str | None = None
    op1_kind: str | None = None
    op1_value: int | str | None = None
    op0_size: int | None = None
    op1_size: int | None = None
    address: int | None = None


@dataclass(frozen=True, slots=True)
class CountedStackLoop8616:
    """Evidence for a conservative counted stack-local loop."""

    induction_disp: int
    accumulator_disp: int
    limit_disp: int
    parity_mask: int


class _CapstoneInsnLike8616(Protocol):
    """Structural view of dynamic Capstone instruction APIs used by this recognizer."""

    def reg_name(self, reg_id: int) -> str | None:
        """Return a register name for a Capstone register id."""
        ...


class _CapstoneEngineLike8616(Protocol):
    """Structural view of Capstone engine APIs used by this recognizer."""

    detail: bool

    def disasm(self, code: bytes, addr: int) -> object:
        """Disassemble bytes at an address."""
        ...


class _MemoryLike8616(Protocol):
    """Structural view of project loader memory needed for byte reads."""

    def load(self, addr: int, size: int) -> bytes:
        """Read bytes from loader memory."""
        ...


class _LoaderLike8616(Protocol):
    """Structural view of a project loader with memory."""

    memory: _MemoryLike8616


class _ProjectLoaderLike8616(Protocol):
    """Structural view of project state needed for linear instruction decoding."""

    loader: _LoaderLike8616


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Dynamic third-party boundary: read optional Capstone/project/function attributes."""
    return getattr(obj, name, default)


def _dynamic_sequence_8616(obj: object) -> tuple[object, ...]:
    """Return a tuple from a dynamic Capstone sequence-like object."""
    if isinstance(obj, tuple):
        return obj
    if isinstance(obj, list):
        return tuple(obj)
    if isinstance(obj, Iterable) and not isinstance(obj, (bytes, str)):
        return tuple(obj)
    return ()


def _dynamic_int_8616(obj: object, default: int = 0) -> int:
    """Return an integer from a dynamic Capstone/project value."""
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, str):
        try:
            return int(obj, 0)
        except ValueError:
            return default
    return default


def _summary_int_8616(value: int | str | None, default: int = 0) -> int:
    """Return an integer from an owned instruction summary operand value."""
    return _dynamic_int_8616(value, default)


def _capstone_reg_name_8616(insn: object, reg_id: int) -> str:
    """Return a lowercase register name from the dynamic Capstone boundary."""
    typed_insn = cast(_CapstoneInsnLike8616, insn)
    return str(typed_insn.reg_name(reg_id) or "").lower()


def _capstone_engine_8616(project: object) -> _CapstoneEngineLike8616 | None:
    """Return the dynamic project Capstone engine when present."""
    arch = _dynamic_attr_8616(project, "arch", None)
    capstone = _dynamic_attr_8616(arch, "capstone", None)
    return cast(_CapstoneEngineLike8616, capstone) if capstone is not None else None


def _sanitize_c_identifier_8616(name: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in str(name or ""))
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"sub_{cleaned}" if cleaned else "sub_func"
    return cleaned


def _local_name_8616(disp: int) -> str:
    if disp < 0:
        return f"local_{abs(disp):x}"
    return f"arg_{disp:x}"


def recover_counted_stack_loop_from_summaries_8616(
    summaries: list[InsnSummary8616],
) -> CountedStackLoop8616 | None:
    """Recover a simple MS C counted stack-local loop from binary operands.

    This is intentionally conservative: every emitted variable must be tied to
    repeated BP-relative instruction evidence. Unknown or partial patterns are
    refused rather than guessed.
    """
    census = _LoopCensus8616()
    for insn in summaries:
        census.collect(insn)
    return _match_counted_loop_8616(census)


@dataclass(slots=True)
class _LoopCensus8616:
    """Mutable per-instruction census for the counted-stack-loop recognizer."""

    zero_inits: set[int] = field(default_factory=set)
    inc_slots: set[int] = field(default_factory=set)
    cmp_pairs: list[tuple[int, int]] = field(default_factory=list)
    test_pairs: list[tuple[int, int]] = field(default_factory=list)
    add_pairs: list[tuple[int, int]] = field(default_factory=list)
    dec_slots: set[int] = field(default_factory=set)
    ax_loads: list[int] = field(default_factory=list)
    previous_ax_load: int | None = None

    def collect(self, insn: InsnSummary8616) -> None:
        """Fold one instruction summary into the census."""
        mnemonic = insn.mnemonic.lower()
        if self._zero_init(insn, mnemonic):
            return
        if self._inc_slot(insn, mnemonic):
            return
        if self._ax_load(insn, mnemonic):
            return
        if self._cmp_pair(insn, mnemonic):
            return
        if self._test_pair(insn, mnemonic):
            return
        if self._add_pair(insn, mnemonic):
            return
        if self._dec_slot(insn, mnemonic):
            return
        if mnemonic not in {"mov", "cmp", "test", "add"}:
            self.previous_ax_load = None

    def _zero_init(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record a `mov word [bp+disp], 0` slot initialization."""
        if (
            mnemonic == "mov"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "imm"
            and _summary_int_8616(insn.op1_value) == 0
            and (insn.op0_size in {None, 2})
        ):
            self.zero_inits.add(_summary_int_8616(insn.op0_value))
            return True
        return False

    def _inc_slot(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record an `inc word [bp+disp]` induction step."""
        if mnemonic == "inc" and insn.op0_kind == "bp_mem" and (insn.op0_size in {None, 2}):
            self.inc_slots.add(_summary_int_8616(insn.op0_value))
            return True
        return False

    def _ax_load(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record a `mov ax, [bp+disp]` induction-source load."""
        if mnemonic == "mov" and insn.op0_kind == "reg" and insn.op0_value == "ax" and insn.op1_kind == "bp_mem":
            self.previous_ax_load = _summary_int_8616(insn.op1_value)
            self.ax_loads.append(self.previous_ax_load)
            return True
        return False

    def _cmp_pair(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record a `cmp [bp+disp], ax` induction-limit comparison."""
        if (
            mnemonic == "cmp"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "reg"
            and insn.op1_value == "ax"
            and self.previous_ax_load is not None
        ):
            self.cmp_pairs.append((_summary_int_8616(insn.op0_value), self.previous_ax_load))
            return True
        return False

    def _test_pair(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record a `test [bp+disp], mask` parity check."""
        if mnemonic == "test" and insn.op0_kind == "bp_mem" and insn.op1_kind == "imm":
            self.test_pairs.append((_summary_int_8616(insn.op0_value), _summary_int_8616(insn.op1_value)))
            return True
        return False

    def _add_pair(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record an `add [bp+disp], ax` accumulator step."""
        if (
            mnemonic == "add"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "reg"
            and insn.op1_value == "ax"
            and self.previous_ax_load is not None
        ):
            self.add_pairs.append((_summary_int_8616(insn.op0_value), self.previous_ax_load))
            return True
        return False

    def _dec_slot(self, insn: InsnSummary8616, mnemonic: str) -> bool:
        """Record a `dec word [bp+disp]` accumulator drain."""
        if mnemonic == "dec" and insn.op0_kind == "bp_mem" and (insn.op0_size in {None, 2}):
            self.dec_slots.add(_summary_int_8616(insn.op0_value))
            return True
        return False


def _match_counted_loop_8616(census: _LoopCensus8616) -> CountedStackLoop8616 | None:
    """Match the census against the counted-loop shape."""
    for induction_disp, limit_disp in census.cmp_pairs:
        if induction_disp >= 0 or limit_disp <= 0:
            continue
        if induction_disp not in census.zero_inits or induction_disp not in census.inc_slots:
            continue
        parity_masks = [
            mask
            for disp, mask in census.test_pairs
            if disp == induction_disp and mask > 0
        ]
        if not parity_masks:
            continue
        loop = _match_accumulator_8616(census, induction_disp, limit_disp, parity_masks)
        if loop is not None:
            return loop
    return None


def _match_accumulator_8616(
    census: _LoopCensus8616,
    induction_disp: int,
    limit_disp: int,
    parity_masks: list[int],
) -> CountedStackLoop8616 | None:
    """Match the accumulator step for one induction/limit candidate."""
    for accumulator_disp, add_source_disp in census.add_pairs:
        if accumulator_disp >= 0 or add_source_disp != induction_disp:
            continue
        if accumulator_disp not in census.zero_inits or accumulator_disp not in census.dec_slots:
            continue
        if accumulator_disp not in census.ax_loads:
            continue
        return CountedStackLoop8616(
            induction_disp=induction_disp,
            accumulator_disp=accumulator_disp,
            limit_disp=limit_disp,
            parity_mask=int(parity_masks[0]),
        )
    return None


def _summarize_capstone_insn_8616(insn: object) -> InsnSummary8616:
    """Project decoded operands with frontend-normalized memory extents."""
    operands = _dynamic_sequence_8616(_dynamic_attr_8616(insn, "operands", ()))

    def _operand(index: int) -> tuple[str | None, int | str | None, int | None]:
        """Project one operand without confusing offset width with memory extent."""
        if index >= len(operands):
            return None, None, None
        operand = operands[index]
        op_type = _dynamic_int_8616(_dynamic_attr_8616(operand, "type", -1), -1)
        raw_size = _dynamic_attr_8616(operand, "size", None)
        size = raw_size if isinstance(raw_size, int) else None
        if op_type == X86_OP_REG:
            return "reg", _capstone_reg_name_8616(insn, _dynamic_int_8616(_dynamic_attr_8616(operand, "reg", 0))), size
        if op_type == X86_OP_IMM:
            return "imm", _dynamic_int_8616(_dynamic_attr_8616(operand, "imm", 0)), size
        if op_type == X86_OP_MEM:
            destination_width = _dynamic_attr_8616(operands[0], "size", None)
            size = decoded_memory_operand_width_8616(
                _dynamic_int_8616(_dynamic_attr_8616(insn, "id", 0)), index, size,
                destination_width if isinstance(destination_width, int) else None,
            )
            mem = _dynamic_attr_8616(operand, "mem", None)
            if mem is not None:
                base = _dynamic_int_8616(_dynamic_attr_8616(mem, "base", 0))
                mem_index = _dynamic_int_8616(_dynamic_attr_8616(mem, "index", 0))
                base_name = _capstone_reg_name_8616(insn, base)
                if base_name == "bp":
                    return "bp_mem", _dynamic_int_8616(_dynamic_attr_8616(mem, "disp", 0)), size
                if base == 0 and mem_index == 0:
                    return "direct_mem", _dynamic_int_8616(_dynamic_attr_8616(mem, "disp", 0)), size
                return "indexed_mem", _dynamic_int_8616(_dynamic_attr_8616(mem, "disp", 0)), size
            return "mem", None, size
        return None, None, size

    op0_kind, op0_value, op0_size = _operand(0)
    op1_kind, op1_value, op1_size = _operand(1)
    raw_address = _dynamic_attr_8616(insn, "address", None)
    return InsnSummary8616(
        mnemonic=str(_dynamic_attr_8616(insn, "mnemonic", "")).lower(),
        op0_kind=op0_kind,
        op0_value=op0_value,
        op1_kind=op1_kind,
        op1_value=op1_value,
        op0_size=op0_size,
        op1_size=op1_size,
        address=raw_address if isinstance(raw_address, int) else None,
    )


def _function_instruction_summaries_8616(project: object, function: object) -> list[InsnSummary8616]:
    # This recognizer only needs Capstone operands. Using project.factory.block()
    # here invokes the full x86-16 lifter for every block and can dominate
    # decompilation time for functions that do not match this narrow pattern.
    return list(
        collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
            builder=lambda evidence_project, evidence_function: _linear_instruction_summaries_8616(
                evidence_project,
                evidence_function,
                max_size=0x300,
            ),
        )
    )


def _capstone_instruction_summaries_from_bytes_8616(
    project: object, addr: int, code: bytes
) -> list[InsnSummary8616]:
    if not code:
        return []
    capstone = _capstone_engine_8616(project)
    if capstone is None:
        return []
    with contextlib.suppress(Exception):
        capstone.detail = True
    try:
        insns = _dynamic_sequence_8616(capstone.disasm(code, addr))
    except Exception:
        return []
    return [_summarize_capstone_insn_8616(insn) for insn in insns]


def _linear_instruction_summaries_8616(
    project: object, function: object, *, max_size: int = 0x180
) -> list[InsnSummary8616]:
    addr = _dynamic_attr_8616(function, "addr", None)
    if not isinstance(addr, int):
        return []
    size = _dynamic_attr_8616(function, "size", None)
    if not isinstance(size, int) or size <= 0:
        size = max_size
    size = max(1, min(int(size), max_size))
    try:
        typed_project = cast(_ProjectLoaderLike8616, project)
        code = bytes(typed_project.loader.memory.load(addr, size))
    except Exception:
        return []
    return _capstone_instruction_summaries_from_bytes_8616(project, addr, code)


def recover_counted_stack_loop_c_8616(project: object, function: object) -> str | None:
    """Recover a source-shaped counted stack loop from a project function."""
    summaries = _function_instruction_summaries_8616(project, function)
    evidence = recover_counted_stack_loop_from_summaries_8616(summaries)
    if evidence is None:
        return None
    raw_name = _dynamic_attr_8616(function, "name", None)
    raw_addr = _dynamic_int_8616(_dynamic_attr_8616(function, "addr", 0))
    func_name = _sanitize_c_identifier_8616(str(raw_name or f"sub_{raw_addr:x}"))
    induction = _local_name_8616(evidence.induction_disp)
    accumulator = _local_name_8616(evidence.accumulator_disp)
    limit = "arg"
    mask = evidence.parity_mask
    return (
        f"int {func_name}(int {limit})\n"
        "{\n"
        f"    int {induction};\n"
        f"    int {accumulator};\n"
        f"    {accumulator} = 0;\n"
        f"    for ({induction} = 0; {induction} < {limit}; ++{induction}) {{\n"
        f"        if (({induction} & {mask}) == 0) {{\n"
        f"            {accumulator} += {induction};\n"
        "        } else {\n"
        f"            {accumulator} -= 1;\n"
        "        }\n"
        "    }\n"
        f"    return {accumulator};\n"
        "}\n"
    )


__all__ = [
    "CountedStackLoop8616",
    "InsnSummary8616",
    "recover_counted_stack_loop_c_8616",
    "recover_counted_stack_loop_from_summaries_8616",
]
