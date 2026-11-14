# cython: language_level=3, infer_types=True
"""Typed deferred return pass-through trial contracts.

Layer: Types/Lowering.
Responsibility: retain exact CALL and terminal-return identities for a proven
call-result pass-through until an SCC contract supplies its output storage and
type class. These contracts do not infer storage, types, or codegen changes.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
import dataclasses
import operator

__all__ = [
    "ReturnPassThroughTrial8616",
    "ReturnPassThroughTrialFailure8616",
]


class ReturnPassThroughTrialFailure8616(StrEnum):
    """Stable reasons why a pass-through relation remains unresolved."""

    CALLER_FUNCTION_UNAVAILABLE = "caller_function_unavailable"
    SEMANTIC_EVIDENCE_REFUSED = "semantic_evidence_refused"
    SEMANTIC_FACT_CONFLICT = "semantic_fact_conflict"
    CALLER_SSA_UNAVAILABLE = "caller_ssa_unavailable"
    FUNCTION_IDENTITY_CONFLICT = "function_identity_conflict"
    RETURN_FACT_NOT_PASSTHROUGH = "return_fact_not_passthrough"
    RETURN_WITNESS_CONFLICT = "return_witness_conflict"
    CALLSITE_NOT_FOUND = "callsite_not_found"
    CALLSITE_CONFLICT = "callsite_conflict"
    CALL_TARGET_UNKNOWN = "call_target_unknown"
    CALL_TARGET_CONFLICT = "call_target_conflict"


@dataclasses.dataclass(frozen=True, )
class ReturnPassThroughTrial8616:
    """One storage- and type-deferred call-result-to-function-return relation."""

    callee_addr: cython.longlong
    caller_addr: cython.longlong
    callsite_addr: cython.longlong
    target_addr: cython.longlong
    return_instruction_addr: cython.longlong
    path_block_addrs: object
    call_block_addr: cython.longlong
    call_instr_index: cython.longlong

    @property
    def is_complete(self) -> cython.bint:
        """Return whether every pre-SCC identity is exact and deterministic."""
        return (
            self.callee_addr >= 0
            and self.caller_addr >= 0
            and self.callsite_addr >= 0
            and self.target_addr >= 0
            and self.return_instruction_addr >= 0
            and bool(self.path_block_addrs)
            and operator.eq(len(set(self.path_block_addrs)), len(self.path_block_addrs))
            and operator.eq(self.call_block_addr, self.path_block_addrs[0])
            and self.call_instr_index >= 0
        )

    def belongs_to(self, callee_addr: cython.longlong, caller_addr: cython.longlong, callsite_addr: cython.longlong) -> cython.bint:
        """Return whether this trial belongs to one exact containing callsite."""
        return (
            self.is_complete
            and operator.eq(self.callee_addr, callee_addr)
            and operator.eq(self.caller_addr, caller_addr)
            and operator.eq(self.callsite_addr, callsite_addr)
        )
