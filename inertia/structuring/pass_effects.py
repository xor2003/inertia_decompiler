"""Describe which Lowering consumers a Structuring mutation can invalidate.

Layer: Structuring.
Responsibility: provide typed mutation-impact values for scheduling Lowering
replays after structured-C passes.
Forbidden: inspect or mutate ASTs, recover semantic facts, or infer impact from
rendered C text.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = [
    "StructuringLoweringReplayImpact8616",
    "structuring_lowering_replay_impact_after_changes_8616",
    "structuring_return_closure_requires_segment_replay_8616",
]


class StructuringLoweringReplayImpact8616(IntEnum):
    """Rank the Lowering replay required after one Structuring mutation."""

    NONE = 0
    RETURN_LIVENESS_ONLY = 1
    FULL_AST = 2

    def merged(self, other: StructuringLoweringReplayImpact8616) -> StructuringLoweringReplayImpact8616:
        """Return the stronger replay requirement."""
        return max(self, other)


def structuring_lowering_replay_impact_after_changes_8616(
    current: StructuringLoweringReplayImpact8616,
    *,
    return_liveness_changed: bool,
    full_ast_changes: tuple[bool, ...],
) -> StructuringLoweringReplayImpact8616:
    """Upgrade replay when a post-prime Structuring pass invalidates Lowering.

    Validation priming runs every Lowering owner before the baseline and is not
    itself a post-prime invalidation. Any later full-AST owner must report its
    mutation through ``current`` or ``full_ast_changes``.
    """
    if return_liveness_changed:
        current = current.merged(
            StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY
        )
    if any(full_ast_changes):
        return current.merged(StructuringLoweringReplayImpact8616.FULL_AST)
    return current


def structuring_return_closure_requires_segment_replay_8616(
    *,
    switch_exit_changed: bool,
    terminal_call_return_changed: bool,
    terminal_return_shape_changed: bool,
) -> bool:
    """Return whether return closure rebuilt a segment/global consumer."""
    return bool(
        switch_exit_changed
        or terminal_call_return_changed
        or terminal_return_shape_changed
    )
