"""Preserve native stack address provenance when introducing SSA references.

Layer: Frontend/IR adapter.
Responsibility: publish the exact native StackBaseOffset coordinate on its
direct reference replacement. No BP conversion, alias inference, or rendered
C recovery belongs here. Adjusted or ambiguous replacements remain untagged.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, cast

from angr.ailment.expression import Expression, StackBaseOffset, UnaryOp, VirtualVariable
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting

from .ir.native_stack_anchor import NATIVE_ENTRY_SP_ANCHOR_TAG8616, NativeStackAnchorStats8616


class _AnchorEvidenceBoundary8616(Protocol):
    """Owned publication census attached to a native SSA engine."""

    _inertia_native_anchor_stats_8616: NativeStackAnchorStats8616


def publish_native_stack_anchor_8616(source: StackBaseOffset, result: Expression | None) -> bool:
    """Tag only exact direct SSA replacements, without changing either value."""
    if result is None:
        return False
    if (
        not isinstance(result, UnaryOp) or result.op != "Reference"
        or not isinstance(result.operand, VirtualVariable)
        or not result.operand.was_stack
        or type(source.offset) is not int
        or result.operand.stack_offset != source.offset
    ):
        return False
    result.tags[NATIVE_ENTRY_SP_ANCHOR_TAG8616] = source.offset
    return True


def apply_native_stack_anchor_compatibility_8616() -> None:
    """Install an idempotent architecture-scoped native SSA provenance hook."""
    current = cast(
        Callable[[SimEngineSSARewriting, StackBaseOffset], Expression | None],
        SimEngineSSARewriting._handle_expr_StackBaseOffset,
    )
    # Dynamic boundary: angr's third-party method may not carry our install marker.
    if getattr(current, "_inertia_native_stack_anchor_8616", False):
        return

    def rewrite(engine: SimEngineSSARewriting, source: StackBaseOffset) -> Expression | None:
        """Carry source coordinates only for this architecture's exact reference."""
        result = current(engine, source)
        if engine.project.arch.name == "86_16":
            evidence = cast(_AnchorEvidenceBoundary8616, engine)
            try:
                stats = evidence._inertia_native_anchor_stats_8616
            except AttributeError:
                stats = NativeStackAnchorStats8616()
                evidence._inertia_native_anchor_stats_8616 = stats
            stats.record(publish_native_stack_anchor_8616(source, result))
        return result

    boundary = cast(Any, rewrite)
    boundary._inertia_native_stack_anchor_8616 = True
    SimEngineSSARewriting._handle_expr_StackBaseOffset = boundary
