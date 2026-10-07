"""Typed condition-call effect evidence shared across decompiler stages.

Layer: Traits/summaries/confidence.
Responsibility: classify semantic calls and transparent runtime access helpers
inside structured conditions without changing CFG shape or emitted C.

Unknown calls remain semantic because no effect-free proof exists. Runtime
segment/pointer access helpers are expression projections rather than machine
calls. The owning Structuring pass decides whether classified evidence blocks
condition rematerialization; this module does not rewrite conditions.

Package ownership contract (canonical inertia/structuring package):
Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

__all__ = [
    "ConditionCallEffectEvidence8616",
    "ConditionCallEffectKind8616",
    "classify_condition_call_effects_8616",
]

_TRANSPARENT_RUNTIME_CONDITION_HELPERS_8616: frozenset[str] = frozenset(
    {
        "MEM_U8",
        "MEM_U16",
        "MEM_U32",
        "MK_FP",
        "SEG_PTR",
        "SEG_U8",
        "SEG_U16",
        "SEG_U32",
    }
)


class ConditionCallEffectKind8616(Enum):
    """Effect class for calls nested in one structured condition."""

    NO_CALL = "no_call"
    TRANSPARENT_RUNTIME_ACCESS = "transparent_runtime_access"
    SEMANTIC_CALL = "semantic_call"


@dataclass(frozen=True, slots=True)
class ConditionCallEffectEvidence8616:
    """Closed evidence for call effects found in one condition expression."""

    kind: ConditionCallEffectKind8616
    raw_call_count: int
    transparent_call_count: int
    semantic_call_count: int

    @property
    def has_semantic_call(self) -> bool:
        """Return whether at least one call lacks transparent-helper proof."""
        return self.kind is ConditionCallEffectKind8616.SEMANTIC_CALL


def classify_condition_call_effects_8616(
    condition: object,
) -> ConditionCallEffectEvidence8616:
    """Classify every call nested in a structured condition without guessing."""
    raw_call_count = 0
    transparent_call_count = 0
    semantic_call_count = 0
    for node in _iter_c_nodes_deep_8616(condition):
        if not isinstance(node, CFunctionCall):
            continue
        raw_call_count += 1
        callee_target = node.callee_target
        if (
            isinstance(callee_target, str)
            and callee_target in _TRANSPARENT_RUNTIME_CONDITION_HELPERS_8616
        ):
            transparent_call_count += 1
        else:
            semantic_call_count += 1
    if semantic_call_count:
        kind = ConditionCallEffectKind8616.SEMANTIC_CALL
    elif transparent_call_count:
        kind = ConditionCallEffectKind8616.TRANSPARENT_RUNTIME_ACCESS
    else:
        kind = ConditionCallEffectKind8616.NO_CALL
    return ConditionCallEffectEvidence8616(
        kind=kind,
        raw_call_count=raw_call_count,
        transparent_call_count=transparent_call_count,
        semantic_call_count=semantic_call_count,
    )
