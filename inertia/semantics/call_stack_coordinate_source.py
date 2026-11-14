# cython: language_level=3, infer_types=True
"""Retain and recheck the source of projected call-stack coordinates.

Layer: Semantics.
Responsibility: bind immutable coordinate projections to their admitted caller
IR and original evidence inputs. Counters or copied integers cannot replace
this source binding, including when downstream Alias consumes a partial proof.
Owns instruction effects, flags, branch meaning, and expression interpretation
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING
import dataclasses
import operator
CallsiteSummary8616 = typing.TypeVar("CallsiteSummary8616")
IRBlock = typing.TypeVar("IRBlock")
IRCallStackCoordinates8616 = typing.TypeVar("IRCallStackCoordinates8616")
IRInstr = typing.TypeVar("IRInstr")
ReturnSegmentFrame8616 = typing.TypeVar("ReturnSegmentFrame8616")

if TYPE_CHECKING:
    from inertia.ir.call_stack_coordinates import IRCallStackCoordinates8616
    from inertia.ir.core import IRBlock, IRInstr

    from .call_return_segment import ReturnSegmentFrame8616
    from .callsite_summary import CallsiteSummary8616


@dataclasses.dataclass(frozen=True, )
class CallStackCoordinateSource8616:
    """Exact producer inputs used to authorize a coordinate projection."""

    project: object | None = field(compare=False, repr=False)
    summary: CallsiteSummary8616
    instruction: IRInstr | None
    block: IRBlock | None
    return_frame: ReturnSegmentFrame8616 | None

    def matches_call(self, instruction: IRInstr) -> cython.bint:
        """Require the same typed transfer before attaching its retained effect."""
        original: object
        original = self.instruction
        return bool(
            original is not None
            and instruction.op == original.op == "CALL"
            and operator.eq(instruction.addr, original.addr)
            and operator.eq(instruction.args, original.args)
            and operator.eq(instruction.size, original.size)
            and operator.eq(instruction.origin, original.origin)
        )

    def matches(self, coordinates: IRCallStackCoordinates8616) -> cython.bint:
        """Reproduce source facts without trusting the offered scalar fields."""
        from .call_stack_coordinates import prove_call_stack_coordinates_8616

        fresh = prove_call_stack_coordinates_8616(
            self.project, self.summary, instruction=self.instruction,
            block=self.block, return_frame=self.return_frame,
            _retained_body_sp_proof=coordinates.callee_sp_proof,
            _recheck_retained_body=True,
        )
        projected = replace(coordinates, source=None, callee_sp_proof=None)
        expected = replace(fresh, source=None, callee_sp_proof=None)
        if projected != expected:
            return False
        return coordinates.callee_sp_proof is fresh.callee_sp_proof
