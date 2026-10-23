"""Layer: validation instruction-summary admission.

Responsibility: isolate byte-derived default REP instructions and consume the
existing complete repeat-string SSA contract during flat32 call composition.
No instruction effects, flags, memory or counter state are discarded.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pyvex

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal, _LiftedBlock
from tools.dosunit.contracts.repeat_string_contracts import RepeatArchitecture, decode_repeat_summary

if TYPE_CHECKING:
    import angr

    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession


def _instruction_bytes(read: Callable[[int, int], bytes], mark: pyvex.stmt.IMark) -> dict[str, Any]:
    """Bind a native instruction marker to exact bytes in the loaded image."""
    if mark.delta != 0 or mark.len <= 0:
        raise CallCompositionRefusal("invalid_repeat_instruction_marker")
    return {"address": {"linear": hex(mark.addr)}, "size": mark.len,
            "bytes": read(mark.addr, mark.len).hex()}


def repeat_boundary_count_from_bytes(irsb: pyvex.IRSB, read: Callable[[int, int], bytes]) -> int | None:
    """End before REP, or isolate it when it is the first decoded instruction.

    The existing summary admits only a single default-form instruction. A
    preceding instruction therefore becomes a separate native block; the
    summary consumes the live state produced by that prefix during composition.
    """
    count = 0
    marks = [statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.IMark)]
    for index, statement in enumerate(marks):
        # libVEX can leave its failed-decode marker before a fallback lifter's
        # successful marker. It consumes no bytes, but PyVEX counts it against
        # num_inst on re-lift. Retain that count and all intervening SSA effects,
        # and require the successful replacement marker at the same address.
        if statement.len == 0 and statement.delta == 0 and index + 1 < len(marks):
            following = marks[index + 1]
            if following.addr == statement.addr and following.len > 0 and following.delta == 0:
                count += 1
                continue
        record = _instruction_bytes(read, statement)
        if decode_repeat_summary([record], architecture=RepeatArchitecture.FLAT32) is not None:
            return count or 1
        count += 1
    return None

def _instruction(project: angr.Project, mark: pyvex.stmt.IMark) -> dict[str, Any]:
    """Bind a native marker to the loaded image through the shared byte reader."""
    return _instruction_bytes(lambda address, size: bytes(project.loader.memory.load(address, size)), mark)


def repeat_boundary_count(project: angr.Project, irsb: pyvex.IRSB) -> int | None:
    """Use the same REP boundary rules for loaded projects and native byte windows."""
    return repeat_boundary_count_from_bytes(
        irsb, lambda address, size: bytes(project.loader.memory.load(address, size)),
    )


def lower_repeat_block(
    session: _ComposeSession, function_entry: int, address: int, irsb: pyvex.IRSB,
) -> _LiftedBlock | None:
    """Replace only an isolated, byte-admitted REP with its authoritative SSA.

    Abstract summary terms over complete input state conservatively model the
    same architectural instruction on each side. Different summary inputs do
    not become equal by admission; solver and helper-interpretation checks stay
    with the existing comparison owners.
    """
    marks = [statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.IMark)]
    if len(marks) != 1 or marks[0].addr != address or marks[0].len != irsb.size:
        return None
    instructions = [_instruction(session.project, marks[0])]
    architecture = flat32_register_architecture()
    lowered = S._lower_repeat_string_summary(
        instructions, output_regs=(*session.reg_widths, "ip"),
        max_assignments_per_function=session.limits.max_assignments_per_block,
        architecture=architecture,
    )
    if lowered is None:
        return None
    fallthrough = address + irsb.size
    part = {
        "entry": {"linear": hex(address)},
        "function_entry": {"linear": hex(function_entry)},
        "source": {"ir": "vex", "jumpkind": "Ijk_Boring",
                   "machine_code_size": irsb.size, "conditional_exit_count": 0,
                   "transfer": {"kind": "direct_successors", "summary": "repeat_string",
                                "successors": [{"linear": hex(fallthrough)}]}},
        **lowered,
    }
    return _LiftedBlock(address=address, irsb=irsb, part=part, jumpkind="Ijk_Boring",
                        successors=(fallthrough,), call_target=None, fallthrough=None,
                        tail_targets=frozenset())
