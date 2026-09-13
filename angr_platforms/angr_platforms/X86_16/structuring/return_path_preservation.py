"""Prove bounded return-register preservation through decoded CFG tails.

Layer: Structuring.
Responsibility: require a complete jump path to return whose instruction effects
preserve AX/DX according to Semantics. Missing blocks and cycles are refusals.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM

from ..semantics.branch_target_return import (
    BranchTargetReturnEffectKind8616,
    branch_target_return_effect_8616,
)
from ..semantics.return_register_preservation import instruction_preserves_return_registers_8616


class _Operand8616(Protocol):
    """Third-party Capstone fields needed to identify a direct branch."""

    type: int
    imm: object


class _Instruction8616(Protocol):
    """Third-party Capstone operand sequence."""

    operands: Sequence[_Operand8616]


class _CapstoneBlock8616(Protocol):
    """Third-party decoded instruction sequence."""

    insns: Iterable[object]


class _Block8616(Protocol):
    """Third-party angr block view used by the path proof."""

    capstone: _CapstoneBlock8616


def branch_target_imm_8616(insn: object) -> int | None:
    """Read an exact direct target at the third-party Capstone boundary."""
    try:
        operands = tuple(cast(_Instruction8616, insn).operands or ())
        if len(operands) != 1 or operands[0].type != X86_OP_IMM:
            return None
        value = operands[0].imm
    except (AttributeError, TypeError):
        return None
    return value if isinstance(value, int) else None


def return_path_preserves_return_registers_8616(
    target_addr: int,
    load_block: Callable[[int], object | None],
    *,
    max_depth: int = 4,
) -> bool:
    """Prove a complete bounded jump tail without changing AX or DX."""
    target = target_addr
    seen: set[int] = set()
    for _ in range(max_depth + 1):
        if target in seen:
            return False
        seen.add(target)
        try:
            block = cast(_Block8616, load_block(target))
            insns = tuple(block.capstone.insns)
        except Exception:
            return False
        if not insns:
            return False
        for index, insn in enumerate(insns):
            if instruction_preserves_return_registers_8616(insn):
                continue
            effect = branch_target_return_effect_8616(insn, branch_target_imm_8616)
            terminal = index == len(insns) - 1
            if effect.kind is BranchTargetReturnEffectKind8616.RETURN:
                return terminal
            if (
                effect.kind is BranchTargetReturnEffectKind8616.JUMP
                and terminal
                and isinstance(effect.jump_target, int)
            ):
                target = effect.jump_target
                break
            return False
        else:
            return False
    return False
