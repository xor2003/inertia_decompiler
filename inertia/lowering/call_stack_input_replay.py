"""Reconsume typed call arguments without invalidating architectural contexts.

Layer: Types/Lowering.
Responsibility: expose authenticated original arguments to a source-backed
Lowering consumer, then bind its actual arguments before any validation.
Unknown or corrupted contexts refuse before invoking that consumer.
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""
from __future__ import annotations

from collections.abc import Callable
from copy import copy
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c

from inertia.alias.scoped_call_stack_context import ScopedCallStackContext8616
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.pipeline.call_stack_input_outcome import CallStackInputStatus8616
from inertia.pipeline.errors import PipelineHardError

from .c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from .call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
    CallStackContextLayout8616,
    call_stack_context_layout_8616,
)
from .call_stack_inputs import apply_call_stack_input_lowering_8616
from .entry_stack_pointer_capture import StackPointerCaptureFunction8616


class _ReplayCodegen8616(Protocol):
    """Native codegen boundary needed by a call-input replay transaction."""

    cfunc: StackPointerCaptureFunction8616 | None


def _require_context_status_8616(
    codegen: object, status: CallStackInputStatus8616, message: str,
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> None:
    """Authenticate the actual tree and retain every refusal counter in the error."""
    observed = apply_call_stack_input_lowering_8616(
        codegen, scoped_context=scoped_context, scoped_caller_scope=scoped_caller_scope)
    if observed is None or observed.status is not status:
        raise PipelineHardError(layer="types:call_stack_inputs", message=message,
            details=observed.to_dict() if observed is not None else {})


def _context_layouts_8616(wrappers: list[c.CMultiStatementExpression]) -> list[CallStackContextLayout8616]:
    """Retain every authenticated layout, refusing any intervening inconsistency."""
    layouts: list[CallStackContextLayout8616] = []
    for wrapper in wrappers:
        layout = call_stack_context_layout_8616(wrapper)
        if layout is None:
            raise PipelineHardError(layer="types:call_stack_inputs", message="Authenticated call context lost its layout")
        layouts.append(layout)
    return layouts


def _project_original_calls_8616(root: object, replacements: dict[int, c.CFunctionCall]) -> object:
    """Copy ancestors of reopened contexts while retaining actual call identities."""
    copies: dict[int, object] = {}

    def project(node: object) -> object:
        """Share unaffected nodes and preserve native DAG identity relationships."""
        if id(node) in replacements:
            return replacements[id(node)]
        if id(node) in copies:
            return copies[id(node)]
        candidate = copy(node)
        copies[id(node)] = candidate
        changed = _replace_c_children_8616(candidate, project,
            should_process_child=lambda current, _field: current is candidate)
        result = candidate if changed else node
        copies[id(node)] = result
        return result

    return project(root)


def run_call_stack_input_aware_lowering_8616(
    codegen: object, consume: Callable[[], bool],
    *,
    scoped_context: ScopedCallStackContext8616 | None = None,
    scoped_caller_scope: Real16InvocationDomain8616 | None = None,
) -> bool:
    """Replay a source-backed consumer through fully authenticated call contexts.

    The consumer sees the original argument expressions, not their capture
    temporaries. A changed tree receives fresh ordered contexts. An unchanged
    consumption retains its original tree, local IDs and call identities.
    Consumer exceptions propagate; this owner restores only its own projection.
    Scoped evidence replays only under the offered context and caller
    domain — without them the status check refuses before the consumer runs.
    """
    function = cast(_ReplayCodegen8616, codegen).cfunc
    if function is None:
        return consume()
    original_root = function.statements
    wrappers = [node for node in _iter_c_nodes_deep_8616(original_root)
                if isinstance(node, c.CMultiStatementExpression) and CALL_STACK_INPUT_BINDING_TAG_8616 in node.tags]
    if not wrappers:
        return consume()
    _require_context_status_8616(
        codegen, CallStackInputStatus8616.STABLE,
        "Cannot reopen unproved call contexts",
        scoped_context=scoped_context, scoped_caller_scope=scoped_caller_scope)
    layouts = _context_layouts_8616(wrappers)
    saved_arguments = [(layout.call, layout.call.args) for layout in layouts]
    replacements = {id(wrapper): layout.call for wrapper, layout in zip(wrappers, layouts, strict=True)}
    retained = False
    try:
        for layout in layouts:
            layout.call.args = list(layout.original_arguments)
        function.statements = _project_original_calls_8616(original_root, replacements)
        changed = consume()
        if not changed and any(tuple(layout.call.args or []) != layout.original_arguments for layout in layouts):
            raise PipelineHardError(layer="types:call_stack_inputs", message="Consumer changed arguments without recording a mutation")
        if changed:
            _require_context_status_8616(
                codegen, CallStackInputStatus8616.MATERIALIZED,
                "Replayed arguments lack call contexts",
                scoped_context=scoped_context, scoped_caller_scope=scoped_caller_scope)
            retained = True
    finally:
        if not retained:
            for call, arguments in saved_arguments:
                call.args = arguments
            function.statements = original_root
    if not changed:
        _require_context_status_8616(
            codegen, CallStackInputStatus8616.STABLE,
            "Unchanged replay invalidated call contexts",
            scoped_context=scoped_context, scoped_caller_scope=scoped_caller_scope)
    return changed
