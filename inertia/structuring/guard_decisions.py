"""Typed decisions for evidence-backed structured control-flow guards.

Layer: Structuring.
Responsibility: own stable decision values shared by control-flow guard
materialization and validation consumers.
Forbidden: inspect rendered C/assembly, recover semantic facts, or mutate ASTs.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["VoidTailCallGuardDecision8616"]


class VoidTailCallGuardDecision8616(Enum):
    """Classify a void tail-call guard materialization decision."""

    MATERIALIZE = "materialize"
    MATERIALIZE_SUFFIX_DIAMOND = "materialize_suffix_diamond"
    KEEP_NOT_VOID = "keep_not_void"
    KEEP_NO_CFG_PROOF = "keep_no_cfg_proof"
    KEEP_NO_TAIL_CALL = "keep_no_tail_call"
    KEEP_NO_BRANCH_MATCH = "keep_no_branch_match"
    KEEP_AMBIGUOUS_BRANCH_MATCH = "keep_ambiguous_branch_match"
