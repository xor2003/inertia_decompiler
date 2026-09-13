"""Schedule argument-only lowering when arity conceals unresolved values.

Layer: Types/Lowering.
Responsibility: visit summarized calls in every expression context and consult
the existing source classifier. This is scheduling, not equivalence proof or
permission to remove setup statements. Argument mutation retains its own vetoes.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CTypeCast, CVariable
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsitePushSourceKind8616, CallsiteSummary8616

_LITERAL_SOURCE_FIELDS = 2


def _stack_value_argument(expression: object) -> bool:
    """Identify a direct stack-value carrier without trusting its display name."""
    seen: set[int] = set()
    while isinstance(expression, CTypeCast):
        if id(expression) in seen:
            return False
        seen.add(id(expression))
        expression = expression.expr
    return isinstance(expression, CVariable) and isinstance(expression.variable, SimStackVariable)


def has_literal_push_stack_carrier_8616(
    call: CFunctionCall, push_arg_sources: tuple[object, ...],
) -> bool:
    """Require literal-source lowering instead of accepting a named stack read.

    A source proven by the callsite contract to be immediate does not become a
    stack-value source because the existing C argument has a pleasant name.
    This requests materialization only; the existing consumer must still bind
    the exact callsite, construct the typed value and preserve call effects.
    Physical/logical arity mismatches remain the arity owner's responsibility.
    """
    if not push_arg_sources or len(call.args) != len(push_arg_sources):
        return False
    for argument, source in zip(call.args, reversed(push_arg_sources), strict=True):
        if not isinstance(source, tuple) or len(source) != _LITERAL_SOURCE_FIELDS:
            continue
        kind, value = source
        literal_source = (
            kind == CallsitePushSourceKind8616.IMMEDIATE.value
            and isinstance(value, int) and not isinstance(value, bool)
        )
        if literal_source and _stack_value_argument(argument):
            return True
    return False


class CallArgumentGapClassifier8616(Protocol):
    """Existing semantic classifier consumed without a competing value model."""

    def __call__(
        self, call: CFunctionCall, *, push_arg_sources: tuple[object, ...],
    ) -> bool:
        """Return whether the call needs evidence-backed argument lowering."""
        ...


def has_call_argument_semantic_gap_8616(
    root: object,
    summaries: Mapping[int, CallsiteSummary8616],
    classifier: CallArgumentGapClassifier8616,
) -> bool:
    """Find unresolved values even when the existing argument count is correct.

    Calls inside casts, masks and return expressions are not standalone
    statements. Visit them without flattening or changing their evaluation
    context; the argument-only consumer remains responsible for any mutation.
    Missing evidence and stack-probe contracts do not authorize this replay.
    """
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summaries.get(id(node))
        if summary is None or summary.stack_probe_helper or not summary.push_arg_sources:
            continue
        if classifier(node, push_arg_sources=summary.push_arg_sources):
            return True
    return False
