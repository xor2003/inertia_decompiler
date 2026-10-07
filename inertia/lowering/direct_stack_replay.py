"""Schedule direct-stack lowering from exact typed replay requests.

Layer: Types/Lowering.
Responsibility: suppress only confirmed-stable direct-stack materialization
requests whose structured AST, consumed typed facts, callsite projection,
function, and execution options are unchanged.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic boundary: codegen, function, and project are third-party angr objects.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol, cast

from inertia.semantics.callsite_summary import CallsiteSummary8616, callsite_summary_inventory_8616
from inertia.pipeline.contracts import SemanticLaneState
from inertia.pipeline.structured_ast_generation import structured_ast_generation_8616

from .consumed_call_push_evidence import (
    normalize_consumed_call_push_evidence_8616,
)
from .direct_stack_consumer_generation import (
    advance_direct_stack_consumer_generation_8616,
    begin_direct_stack_consumer_generation_scope_8616,
    current_direct_stack_consumer_generation_8616,
    end_direct_stack_consumer_generation_scope_8616,
)
from .direct_stack_replay_contracts import (
    DirectStackCallsiteProjection8616,
    DirectStackConsumerGeneration8616,
    DirectStackConsumerGenerationScope8616,
    DirectStackMaterializationResult8616,
    DirectStackReplayGeneration8616,
    DirectStackReplayOptions8616,
    DirectStackReplayRequest8616,
    DirectStackReplayState8616,
    DirectStackReplayStats8616,
)

__all__ = [
    "DirectStackCallsiteProjection8616",
    "DirectStackConsumerGeneration8616",
    "DirectStackConsumerGenerationScope8616",
    "DirectStackMaterializationResult8616",
    "DirectStackReplayGeneration8616",
    "DirectStackReplayOptions8616",
    "DirectStackReplayRequest8616",
    "DirectStackReplayState8616",
    "DirectStackReplayStats8616",
    "advance_direct_stack_consumer_generation_8616",
    "begin_direct_stack_consumer_generation_scope_8616",
    "direct_stack_callsite_projection_8616",
    "direct_stack_replay_generation_8616",
    "direct_stack_replay_scheduling_generation_8616",
    "end_direct_stack_consumer_generation_scope_8616",
    "execute_direct_stack_replay_8616",
]


class _CodegenReplayBoundary8616(Protocol):
    """Third-party codegen facts and scheduler state consumed by replay."""

    cfunc: object
    project: object
    _inertia_direct_stack_move_facts_8616: tuple[object, ...]
    _inertia_direct_stack_mov_lane_8616: SemanticLaneState
    _inertia_direct_stack_replay_state_8616: DirectStackReplayState8616


class _CFunctionReplayBoundary8616(Protocol):
    """Third-party CFunction statement root consumed by replay generation."""

    statements: object


@dataclass(frozen=True, slots=True)
class _StructuredRootCodegen8616:
    """Adapt one structured statement root to the generation boundary."""

    cfunc: object


class _FunctionReplayBoundary8616(Protocol):
    """Third-party function facts consumed by direct-stack replay."""

    addr: int
    _inertia_direct_stack_move_instruction_facts_8616: tuple[object, ...]


def direct_stack_callsite_projection_8616(
    inventory_addr: int,
    summary: CallsiteSummary8616,
) -> DirectStackCallsiteProjection8616:
    """Project one summary to every fact read by direct-stack replay."""
    return DirectStackCallsiteProjection8616(
        inventory_addr=inventory_addr,
        callsite_addr=summary.callsite_addr,
        target_addr=summary.target_addr,
        return_addr=summary.return_addr,
        arg_count=summary.arg_count,
        arg_widths=summary.arg_widths,
        stack_cleanup=summary.stack_cleanup,
        stack_cleanup_instruction_addr=summary.stack_cleanup_instruction_addr,
        consumed_push_evidence=normalize_consumed_call_push_evidence_8616(summary),
    )


def _direct_stack_replay_generation_8616(
    codegen: object,
    function: object | None,
    consumer_generation: DirectStackConsumerGeneration8616 | None,
) -> DirectStackReplayGeneration8616:
    """Return value-based replay inputs under one structured-surface owner."""
    callsites = callsite_summary_inventory_8616(codegen)
    try:
        attached_facts = tuple(
            cast(_CodegenReplayBoundary8616, codegen)._inertia_direct_stack_move_facts_8616
            or ()
        )
    except AttributeError:
        attached_facts = ()
    try:
        typed_function = cast(_FunctionReplayBoundary8616, function)
        function_facts = tuple(
            typed_function._inertia_direct_stack_move_instruction_facts_8616 or ()
        )
        function_addr = typed_function.addr
    except AttributeError:
        function_facts = ()
        function_addr = None
    cfunc: object | None = None
    try:
        cfunc = cast(_CodegenReplayBoundary8616, codegen).cfunc
        statement_root = cast(_CFunctionReplayBoundary8616, cfunc).statements
    except AttributeError:
        statement_root = cfunc
    return DirectStackReplayGeneration8616(
        ast=(
            structured_ast_generation_8616(_StructuredRootCodegen8616(statement_root))
            if consumer_generation is None
            else None
        ),
        callsites=tuple(
            direct_stack_callsite_projection_8616(addr, summary)
            for addr, summary in sorted(callsites.items())
        ),
        attached_facts=attached_facts,
        function_facts=function_facts,
        function_addr=function_addr if isinstance(function_addr, int) else None,
        consumer_generation=consumer_generation,
    )


def direct_stack_replay_generation_8616(
    codegen: object,
    function: object | None,
) -> DirectStackReplayGeneration8616:
    """Return exact value-based AST and fact inputs consumed by replay."""
    return _direct_stack_replay_generation_8616(codegen, function, None)


def direct_stack_replay_scheduling_generation_8616(
    codegen: object,
    function: object | None,
) -> DirectStackReplayGeneration8616:
    """Use a covered consumer generation, otherwise retain the exact AST."""
    return _direct_stack_replay_generation_8616(
        codegen,
        function,
        current_direct_stack_consumer_generation_8616(codegen),
    )


def _replay_state_8616(codegen: object) -> DirectStackReplayState8616:
    """Read the owned scheduler state from a third-party codegen boundary."""
    try:
        state = cast(_CodegenReplayBoundary8616, codegen)._inertia_direct_stack_replay_state_8616
    except AttributeError:
        return DirectStackReplayState8616()
    return state if isinstance(state, DirectStackReplayState8616) else DirectStackReplayState8616()


def _publish_replay_state_8616(
    codegen: object,
    state: DirectStackReplayState8616,
) -> None:
    """Publish closed replay state at the dynamic codegen boundary."""
    if not state.stats.closed:
        raise ValueError("direct-stack replay accounting is not closed")
    cast(_CodegenReplayBoundary8616, codegen)._inertia_direct_stack_replay_state_8616 = state


def _direct_stack_replay_failed_8616(codegen: object) -> bool:
    """Return whether the current typed materialization lane failed closure."""
    try:
        lane = cast(_CodegenReplayBoundary8616, codegen)._inertia_direct_stack_mov_lane_8616
    except AttributeError:
        return False
    if not isinstance(lane, SemanticLaneState):
        return True
    return bool(
        lane.failures > 0
        or (lane.raw > 0
        and lane.normalized == 0)
        or (lane.bound > 0
        and lane.materialized == 0)
        or (lane.classified > 0
        and lane.materialized == 0)
    )


def _request_8616(
    codegen: object,
    function: object,
    options: DirectStackReplayOptions8616,
) -> DirectStackReplayRequest8616:
    """Build one request from exact AST or covered consumer generation."""
    return DirectStackReplayRequest8616(
        generation=direct_stack_replay_scheduling_generation_8616(codegen, function),
        options=options,
    )


def _resolve_replay_function_8616(
    codegen: object,
    project: object | None,
    function: object | None,
) -> object | None:
    """Resolve the active third-party angr function for one replay request."""
    if function is not None:
        return function
    try:
        boundary = cast(_CodegenReplayBoundary8616, codegen)
        active_project = project if project is not None else boundary.project
        func_addr = getattr(boundary.cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return None
        resolved: object | None = cast(Any, active_project).kb.functions.function(
            addr=func_addr,
            create=False,
        )
        return resolved
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def execute_direct_stack_replay_8616(
    codegen: object,
    project: object | None,
    function: object | None,
    options: DirectStackReplayOptions8616,
    operation: Callable[[object | None], bool | DirectStackMaterializationResult8616],
) -> bool:
    """Execute or skip one complete direct-stack materialization transaction.

    A reported mutation invalidates stability immediately, so it does not pay
    for a second whole-AST generation. A reportedly stable pass still compares
    pre/post requests; only that confirmed stable post-state can be skipped.
    """
    function = _resolve_replay_function_8616(codegen, project, function)
    if function is None:
        unavailable_result = operation(None)
        return (
            unavailable_result.changed
            if isinstance(unavailable_result, DirectStackMaterializationResult8616)
            else bool(unavailable_result)
        )
    request_before = _request_8616(codegen, function, options)
    state = _replay_state_8616(codegen)
    if state.stable_request == request_before:
        _publish_replay_state_8616(
            codegen,
            replace(
                state,
                stats=replace(
                    state.stats,
                    skipped_count=state.stats.skipped_count + 1,
                ),
            ),
        )
        return False
    try:
        operation_result = operation(function)
        if isinstance(operation_result, DirectStackMaterializationResult8616):
            if not operation_result.evidence_closed:
                raise ValueError("direct-stack materialization evidence is not closed")
            reported_changed = operation_result.changed
        else:
            if request_before.generation.consumer_generation is not None:
                raise TypeError(
                    "covered direct-stack generation requires a typed owner result"
                )
            reported_changed = bool(operation_result)
        request_after = (
            None
            if reported_changed
            else _request_8616(codegen, function, options)
        )
    except Exception:
        _publish_replay_state_8616(
            codegen,
            DirectStackReplayState8616(
                stable_request=None,
                stats=replace(
                    state.stats,
                    attempt_count=state.stats.attempt_count + 1,
                    failure_count=state.stats.failure_count + 1,
                ),
            ),
        )
        raise
    exact_witness_changed = bool(
        request_after is not None
        and request_before.generation.ast is not None
        and request_after.generation.ast != request_before.generation.ast
    )
    effective_changed = reported_changed or exact_witness_changed
    replay_failed = _direct_stack_replay_failed_8616(codegen)
    replay_stable = not effective_changed and not replay_failed
    _publish_replay_state_8616(
        codegen,
        DirectStackReplayState8616(
            stable_request=request_after if replay_stable else None,
            stats=replace(
                state.stats,
                attempt_count=state.stats.attempt_count + 1,
                changed_count=state.stats.changed_count
                + int(effective_changed and not replay_failed),
                stable_count=state.stats.stable_count + int(replay_stable),
                failure_count=state.stats.failure_count + int(replay_failed),
            ),
        ),
    )
    return effective_changed
