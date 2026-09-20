"""Import terminal VEX control flow into typed x86-16 IR instructions.

Layer: IR.
Responsibility: preserve explicit calls, returns, and instruction addresses from
the third-party VEX block boundary. This module does not classify call
semantics or materialize C.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Protocol, cast

from .core import IRInstr, IRValue, MemSpace

__all__ = ["terminal_control_flow_instr_8616", "terminal_ret_instruction_addrs_8616"]


class _VexConstant8616(Protocol):
    """Minimal third-party VEX constant contract."""

    value: object


class _VexConstantExpression8616(Protocol):
    """Minimal third-party VEX constant-expression contract."""

    con: _VexConstant8616


class _VexBlock8616(Protocol):
    """Minimal third-party VEX block terminal control-flow contract."""

    jumpkind: object
    next: object


class _IRArtifactBlocks8616(Protocol):
    """Third-party typed IR artifact surface holding ordered blocks."""

    blocks: Iterable[_IRArtifactBlock8616]


class _IRArtifactBlock8616(Protocol):
    """Third-party typed IR block surface holding ordered instructions."""

    instrs: Iterable[_IRArtifactInstruction8616]


class _IRArtifactInstruction8616(Protocol):
    """Typed IR instruction fields read for terminal return classification."""

    op: str
    addr: int | None


def _constant_target_8616(expr: object) -> int | None:
    """Return an exact integer target from a VEX constant expression."""
    try:
        value = cast(_VexConstantExpression8616, expr).con.value
        return int(cast(Any, value))
    except (AttributeError, TypeError, ValueError):
        return None


def terminal_control_flow_instr_8616(
    vex: object,
    instruction_addr: int | None,
    *,
    resolve_target: Callable[[object], IRValue] | None = None,
) -> IRInstr | None:
    """Preserve calls and returns independently of resolving their destinations.

    RET is control-flow evidence only. Its target is generally a runtime stack
    load, while register and stack effects remain in the preceding typed IR.
    Dropping an indirect CALL would leave its return-address push without the
    call boundary needed by stack-state consumers. Unknown targets stay explicit.
    """
    try:
        boundary = cast(_VexBlock8616, vex)
        jumpkind = str(boundary.jumpkind)
        if jumpkind == "Ijk_Ret":
            return IRInstr(op="RET", dst=None, args=(), addr=instruction_addr)
        target = _constant_target_8616(boundary.next)
    except AttributeError:
        return None
    if jumpkind != "Ijk_Call":
        return None
    if target is not None:
        target_value = IRValue(MemSpace.CONST, const=target, size=4)
    elif resolve_target is not None:
        target_value = resolve_target(boundary.next)
    else:
        target_value = IRValue(MemSpace.UNKNOWN)
    return IRInstr(
        op="CALL",
        dst=None,
        args=(target_value,),
        addr=instruction_addr,
    )


def terminal_ret_instruction_addrs_8616(artifact: object) -> frozenset[int]:
    """Return addresses of block-terminal RET instructions in one IR artifact.

    A block-terminal RET instruction is the control-flow owner of that block's
    return-frame pops. Artifacts without typed blocks, without instructions, or
    without integer instruction addresses contribute no addresses; callers must
    treat that absence as absence of proof, never as an empty machine return.
    """
    try:
        blocks = tuple(cast(_IRArtifactBlocks8616, artifact).blocks)
    except AttributeError:
        return frozenset()
    addresses: set[int] = set()
    for block in blocks:
        try:
            instructions = tuple(block.instrs)
        except AttributeError:
            continue
        if not instructions:
            continue
        terminal = instructions[-1]
        if terminal.op != "RET":
            continue
        if isinstance(terminal.addr, int):
            addresses.add(terminal.addr)
    return frozenset(addresses)
