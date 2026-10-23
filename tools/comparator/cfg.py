"""Layer: validation CFG lowering.

Responsibility: discover closed native CFGs, pair their edges and lower full-state blocks.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

import angr
import archinfo
import pyvex

from tools.dosunit.architectures.flat32 import _FLAT32_REGS, flat32_register_architecture
from tools.dosunit.architectures.flat32_cfg_lifting import CfgLiftingRefusal, lift_cfg_block
from tools.dosunit.architectures.flat32_cfg_summary import (
    cfg_control_word_instruction,
    cfg_repeat_instruction,
    lower_cfg_block,
)
from tools.dosunit.architectures.flat32_control_word import NativeX87Instruction
from tools.dosunit.compare import straightline_ssa as S

ARCH: archinfo.ArchX86 = archinfo.ArchX86()
REG32: dict[int, tuple[str, int]] = _FLAT32_REGS


@dataclass(frozen=True)
class Block:
    """Byte-backed VEX block and its ordered direct successor addresses."""

    address: int
    irsb: pyvex.IRSB
    successors: tuple[int, ...]
    repeat_instructions: list[dict[str, Any]] | None = None
    control_word_instruction: NativeX87Instruction | None = None


class CfgRefusal(ValueError):
    """A named unsupported proof boundary, never interpreted as equality."""


def static_next(irsb: pyvex.IRSB) -> int | None:
    """Resolve only constant copies through VEX temps/registers on fallthrough."""
    temps: dict[int, int | None] = {}
    registers: dict[int, int | None] = {}

    def value(expr: pyvex.expr.IRExpr) -> int | None:
        """Follow typed const/Get/RdTmp copies; arithmetic needs another proof."""
        if isinstance(expr, pyvex.expr.Const):
            raw = expr.con.value
            if isinstance(raw, int):
                return raw
            if isinstance(raw, float):
                return None  # F32/F64 immediates (incl. NaN) are not addresses
            return int(raw)
        if isinstance(expr, pyvex.expr.RdTmp):
            return temps.get(expr.tmp)
        if isinstance(expr, pyvex.expr.Get):
            return registers.get(expr.offset)
        return None

    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.WrTmp):
            temps[statement.tmp] = value(statement.data)
        elif isinstance(statement, pyvex.stmt.Put):
            registers[statement.offset] = value(statement.data)
    return value(irsb.next)


def direct_successors(irsb: pyvex.IRSB) -> tuple[int, ...]:
    """Read typed VEX edges, refusing exception exits and indirect transfers."""
    if irsb.jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
        raise CfgRefusal("call_or_exception_boundary")
    exits = [statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.Exit)]
    if any(statement.jumpkind != "Ijk_Boring" for statement in exits):
        raise CfgRefusal("exception_edge")
    seen_exit = False
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.Exit):
            seen_exit = True
        elif (
            seen_exit
            and statement.tag not in {"Ist_IMark", "Ist_WrTmp", "Ist_NoOp"}
            and (not isinstance(statement, pyvex.stmt.Put) or statement.offset != ARCH.ip_offset)
        ):
            raise CfgRefusal("effect_after_conditional_exit")
    if irsb.jumpkind == "Ijk_Ret":
        if exits:
            raise CfgRefusal("conditional_return_block")
        return ()
    fallthrough = static_next(irsb)
    if fallthrough is None:
        raise CfgRefusal("indirect_jump")
    return tuple([int(statement.dst.value) for statement in exits] + [fallthrough])


def discover(project: angr.Project, start: int, size: int, max_blocks: int) -> dict[int, Block]:
    """Close the reachable CFG inside declared bounds without following callees."""
    pending = deque([start])
    blocks: dict[int, Block] = {}
    while pending:
        address = pending.popleft()
        if address in blocks:
            continue
        if not start <= address < start + size:
            raise CfgRefusal("edge_outside_declared_function")
        if len(blocks) >= max_blocks:
            raise CfgRefusal("block_limit")
        try:
            irsb = lift_cfg_block(project, address, start + size - address)
        except CfgLiftingRefusal as error:
            raise CfgRefusal(error.reason.value) from error
        from tools.dosunit.contracts.binary_environment import requires_environment_contract

        control_word = cfg_control_word_instruction(project, irsb)
        if control_word is None and requires_environment_contract(irsb):
            raise CfgRefusal("external_environment_contract_required")
        if not isinstance(irsb, pyvex.IRSB):
            raise CfgRefusal("non_vex_lifter")
        repeated = cfg_repeat_instruction(project, irsb)
        # A native x87 or REP summary replaces the whole VEX block: its own
        # fallthrough is the only successor, and VEX EmWarn/exit edges of the
        # erased projection are not architectural edges.
        successors = (address + irsb.size,) if (repeated is not None or control_word is not None) \
            else direct_successors(irsb)
        blocks[address] = Block(address, irsb, successors, repeated, control_word)
        pending.extend(successors)
    return blocks


def pair_graphs(
    oracle: dict[int, Block], candidate: dict[int, Block], oracle_start: int, candidate_start: int
) -> list[tuple[int, int]]:
    """Construct and validate a successor-order-preserving graph bijection."""
    pending = deque([(oracle_start, candidate_start)])
    forward: dict[int, int] = {}
    backward: dict[int, int] = {}
    pairs: list[tuple[int, int]] = []
    while pending:
        left, right = pending.popleft()
        if left in forward:
            if forward[left] != right:
                raise CfgRefusal("cfg_not_bijective")
            continue
        if right in backward:
            raise CfgRefusal("cfg_not_bijective")
        oblock, cblock = oracle[left], candidate[right]
        if oblock.irsb.jumpkind != cblock.irsb.jumpkind or len(oblock.successors) != len(cblock.successors):
            raise CfgRefusal("cfg_shape_mismatch")
        forward[left], backward[right] = right, left
        pairs.append((left, right))
        pending.extend(zip(oblock.successors, cblock.successors, strict=True))
    if len(pairs) != len(oracle) or len(pairs) != len(candidate):
        raise CfgRefusal("cfg_not_closed")
    return pairs


def lower_blocks(
    blocks: dict[int, Block], addresses: list[int], module: str, outputs: tuple[str, ...]
) -> dict[str, Any]:
    """Keep full state on internal edges and stable canonical 32-bit edge tokens."""
    targets = {address: index for index, address in enumerate(addresses)}
    functions: list[dict[str, Any]] = []
    for index, address in enumerate(addresses):
        block = blocks[address]
        observed = outputs if block.irsb.jumpkind == "Ijk_Ret" else tuple(name for name, _ in flat32_register_architecture().registers)
        body = lower_cfg_block(
            block.irsb, output_regs=observed, control_targets=targets,
            repeat_instructions=block.repeat_instructions,
            control_word_instruction=block.control_word_instruction,
        )
        if isinstance(body, S.LowerFailure):
            raise CfgRefusal(f"{body.reason}: {body.message}")
        name = f"block_{index}"
        functions.append(
            {
                "id": f"{module}:{name}",
                "function": {"id": f"{module}:{name}", "name": name},
                "part": {"kind": "block", "index": 0, "entry_delta": "0x0"},
                "entry": {"linear": hex(address)},
                "function_entry": {"linear": hex(address)},
                "source": {"jumpkind": block.irsb.jumpkind, "machine_code_size": block.irsb.size},
                **body,
            }
        )
    return {"functions": functions}
