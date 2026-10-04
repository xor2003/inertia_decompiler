"""Import terminal VEX control flow into typed x86-16 IR instructions.

Layer: IR.
Responsibility: preserve explicit calls, returns, jumps, and instruction addresses from
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
from .instruction_origin import vex_block_next_origin_8616

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
    retain_boring_transfer: bool = False,
    proven_target: int | None = None,
    block_addr: int | None = None,
    statement_count: int | None = None,
) -> IRInstr | None:
    """Preserve calls and returns independently of resolving their destinations.

    RET is control-flow evidence only. Its target is generally a runtime stack
    load, while register and stack effects remain in the preceding typed IR.
    Dropping an indirect CALL would leave its return-address push without the
    call boundary needed by stack-state consumers. Unknown targets stay explicit.
    The block importer opts into Boring transfer retention only when decoded
    native bytes prove the final machine instruction is a real unconditional
    near jump; coordinate arithmetic it emits is an instruction effect, never
    a reason to drop the transfer. ``proven_target`` carries a loader-linear
    destination proven by the importer's terminal-jump evidence for a
    symbolic ``next``; it is used only on the retained-jump path and never
    overrides a literal VEX constant.

    When ``block_addr`` and ``statement_count`` are supplied, the retained
    terminal instruction is stamped with block-``next`` source provenance so
    consumers can bind a symbolic control operand to this exact block's
    imported ``next`` expression.
    """
    try:
        boundary = cast(_VexBlock8616, vex)
        jumpkind = str(boundary.jumpkind)
        origin = (
            vex_block_next_origin_8616(
                boundary.next,
                block_addr=block_addr,
                statement_count=statement_count,
            )
            if block_addr is not None and statement_count is not None
            else None
        )
        if jumpkind == "Ijk_Ret":
            return IRInstr(op="RET", dst=None, args=(), addr=instruction_addr, origin=origin)
        target = _constant_target_8616(boundary.next)
    except AttributeError:
        return None
    retain_jump = retain_boring_transfer and jumpkind == "Ijk_Boring"
    if jumpkind != "Ijk_Call" and not retain_jump:
        return None
    if target is not None:
        target_value = IRValue(MemSpace.CONST, const=target, size=4)
    elif retain_jump and proven_target is not None:
        target_value = IRValue(MemSpace.CONST, const=proven_target, size=4)
    elif resolve_target is not None:
        target_value = resolve_target(boundary.next)
    else:
        target_value = IRValue(MemSpace.UNKNOWN)
    return IRInstr(
        op="JMP" if retain_jump else "CALL",
        dst=None,
        args=(target_value,),
        addr=instruction_addr,
        origin=origin,
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
