# cython: language_level=3, infer_types=True
"""Publish immutable direct Capstone instruction and block views.

Layer: Frontend.
Responsibility: expose direct byte decoding through the read-only angr block
surface consumed by frontend CFG and discovery owners.
"""

from __future__ import annotations
import dataclasses
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, Self, cast


class _DetailedInstructionBoundary8616(Protocol):
    """Capstone detail fields consumed by downstream semantic recovery."""

    operands: Sequence[object]
    bytes: object

    def reg_name(self, register_id: cython.longlong) -> object:
        """Return Capstone's canonical name for one register id."""
        ...


@dataclasses.dataclass(frozen=True, )
class DirectCapstoneInstruction8616:
    """angr-compatible immutable view of one raw Capstone instruction."""

    address: cython.longlong
    size: cython.longlong
    mnemonic: object
    op_str: object
    insn: object

    @property
    def bytes(self) -> bytes:
        """Expose immutable encoded bytes from the raw decoder boundary."""
        return bytes(cast(_DetailedInstructionBoundary8616, self.insn).bytes)

    @property
    def operands(self) -> Sequence[object]:
        """Expose immutable operand evidence from the raw decoder boundary."""
        return cast(_DetailedInstructionBoundary8616, self.insn).operands

    def reg_name(self, register_id: cython.longlong) -> object:
        """Resolve a register id through the raw decoder boundary."""
        return cast(_DetailedInstructionBoundary8616, self.insn).reg_name(register_id)


@dataclasses.dataclass(frozen=True, )
class DirectCapstoneBlock8616:
    """One contiguous block decoded directly from loaded bytes."""

    addr: cython.longlong
    size: cython.longlong
    code: object
    instructions: object

    @property
    def bytes(self) -> object:
        """Expose the exact owned bytes through angr's block field name."""
        return self.code

    @property
    def capstone(self) -> Self:
        """Expose this immutable instruction projection as a Capstone view."""
        return self

    @property
    def insns(self) -> object:
        """Expose instructions through angr's ``block.capstone.insns`` shape."""
        return self.instructions


__all__ = ["DirectCapstoneBlock8616", "DirectCapstoneInstruction8616"]
