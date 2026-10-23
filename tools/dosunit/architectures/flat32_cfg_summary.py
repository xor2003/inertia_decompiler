"""Layer: dosunit native CFG instruction admission.

Responsibility: carry byte-verified isolated REP semantics across every flat32
CFG consumer, preserving full state while tokenizing only its continuation.
"""
from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any

import pyvex

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_control import finish_flat32_control
from tools.dosunit.architectures.flat32_control_word import (
    NativeX87Instruction,
    decode_native_x87,
    native_x87_body,
)
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.contracts.repeat_string_contracts import RepeatArchitecture, decode_repeat_summary
from tools.dosunit.ssa.materialization import input_items

if TYPE_CHECKING:
    import angr


def cfg_control_word_instruction(project: angr.Project, irsb: pyvex.IRSB) -> NativeX87Instruction | None:
    """Bind an isolated native x87 instruction to its loaded bytes before SSA admission."""
    marks = [stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.IMark)]
    if len(marks) != 1 or irsb.jumpkind != "Ijk_Boring":
        return None
    mark = marks[0]
    if mark.addr != irsb.addr or mark.len != irsb.size or mark.delta != 0:
        return None
    return decode_native_x87(bytes(project.loader.memory.load(irsb.addr, irsb.size)))


def cfg_repeat_instruction(project: angr.Project, irsb: pyvex.IRSB) -> list[dict[str, Any]] | None:
    """Admit one complete modeled REP backed by the loaded native bytes."""
    marks = [statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.IMark)]
    if len(marks) != 1 or marks[0].addr != irsb.addr or marks[0].len != irsb.size or marks[0].delta != 0:
        return None
    if not 0 < irsb.size <= 15 or irsb.jumpkind != "Ijk_Boring":
        return None
    raw = bytes(project.loader.memory.load(irsb.addr, irsb.size))
    record = {"address": {"linear": hex(irsb.addr)}, "size": irsb.size, "bytes": raw.hex()}
    instructions = [record]
    if decode_repeat_summary(instructions, architecture=RepeatArchitecture.FLAT32) is None:
        return None
    return instructions


def lower_cfg_block(
    irsb: pyvex.IRSB, *, output_regs: tuple[str, ...], control_targets: dict[int, int],
    repeat_instructions: list[dict[str, Any]] | None = None,
    control_word_instruction: NativeX87Instruction | None = None,
) -> dict[str, Any] | S.LowerFailure:
    """Lower ordinary VEX or an admitted REP with the same full-state boundary."""
    if control_word_instruction is not None:
        fallthrough = irsb.addr + irsb.size
        if fallthrough not in control_targets:
            return S.LowerFailure("flat32_indirect_control", "native x87 continuation is outside the closed CFG")
        widths = dict(flat32_register_architecture().registers)
        if any(name not in widths and name not in {"ip", "memory", "io"} for name in output_regs):
            return S.LowerFailure("unsupported_ir", "unknown native x87 output register")
        registers = {name: widths[name] for name in output_regs if name in widths}
        return native_x87_body(control_word_instruction, continuation=control_targets[fallthrough],
                                       registers=registers, address=irsb.addr)
    if repeat_instructions is None:
        return S._lower_irsb(
            irsb, output_regs=output_regs, max_assignments_per_function=4096,
            architecture=flat32_register_architecture(),
            block_finisher=partial(finish_flat32_control, control_targets=control_targets),
        )
    fallthrough = irsb.addr + irsb.size
    if fallthrough not in control_targets:
        return S.LowerFailure("flat32_indirect_control", "REP continuation is outside the closed CFG")
    body = S._lower_repeat_string_summary(
        repeat_instructions, output_regs=output_regs, max_assignments_per_function=4096,
        architecture=flat32_register_architecture(),
    )
    if body is None:
        return S.LowerFailure("flat32_repeat_summary_unavailable", "byte-admitted REP could not be lowered")
    # The instruction summary proves that control continues immediately after
    # the complete REP. Only that native destination becomes a CFG token.
    expected = {"op": "const", "width": 32, "value": hex(fallthrough)}
    if body["outputs"].get("eip") != expected:
        return S.LowerFailure("flat32_repeat_control_mismatch", "summary continuation differs from native extent")
    body["outputs"]["eip"] = {"op": "const", "width": 32, "value": hex(control_targets[fallthrough])}
    body["outputs"].setdefault("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    body["inputs"] = input_items(body["outputs"].values(), body["assignments"])
    return body
