"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import logging
import os
import typing
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.pipeline.errors import PipelineHardError

from inertia_decompiler.cli_linear_recurrence_state import LinearRecurrenceState

log: logging.Logger = logging.getLogger(__name__)

type CNode = object
type LinearDeltaMatch = tuple[CNode | None, int]
type CarryCandidate = tuple[CNode | None, int | None, structured_c.CAssignment | bool | None]
type LoopParts = tuple[CNode | None, str, CNode | None, CNode | None]


class _LinearRecurrenceRules(Protocol):
    """Rule helper surface consumed by CLI recurrence cleanup."""

    def _carry_base_rewrite_plan(
        self,
        carry_base: object,
        *,
        expr_contains_dereference: Callable[[object], bool],
        extract_linear_delta: Callable[[object], tuple[object | None, int]],
    ) -> dict[str, object] | None:
        """Return a replacement plan for a carry-base expression."""
        ...

    def _should_commit_linear_rewrite(
        self,
        original_expr: object,
        rewritten_expr: object,
        *,
        expr_contains_dereference: Callable[[object], bool],
        same_c_expression: Callable[[object, object], bool],
    ) -> bool:
        """Return whether a linear rewrite is evidence-backed enough to commit."""
        ...


def _dynamic_codegen_attr(obj: object, name: str, default: Any = None) -> Any:  # noqa: ANN401
    """Read a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    return getattr(obj, name, default)


def _dynamic_codegen_setattr(obj: object, name: str, value: object) -> None:
    """Write a dynamic angr structured-codegen attribute at the CLI boundary."""
    # Dynamic codegen boundary: angr C-AST nodes expose version-dependent fields.
    setattr(obj, name, value)


def _linear_recurrence_debug_enabled() -> bool:
    return bool(os.environ.get("INERTIA_DEBUG_LINEAR_RECURRENCE"))


def _node_summary_8616(node: object) -> str:
    if node is None:
        return "None"
    try:
        c_repr = _dynamic_codegen_attr(node, "c_repr", None)
        text = str(c_repr(indent=0)) if callable(c_repr) else repr(node)
    except Exception as ex:
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] failed c_repr for %s: %s", type(node).__name__, ex)
        text = repr(node)
    text = text.replace("\n", " ")
    if len(text) > 220:
        text = text[:217] + "..."
    return f"{type(node).__name__}: {text}"


def _iter_nested_statement_summaries_8616(node: object) -> Iterable[str]:
    if node is None:
        return
    if isinstance(node, structured_c.CStatements):
        for stmt in _dynamic_codegen_attr(node, "statements", ()) or ():
            yield _node_summary_8616(stmt)
            yield from _iter_nested_statement_summaries_8616(stmt)
        return
    for attr in ("body", "else_node"):
        child = _dynamic_codegen_attr(node, attr, None)
        if child is not None:
            yield from _iter_nested_statement_summaries_8616(child)


def _debug_loop_structure_8616(loop: object) -> None:
    if not _linear_recurrence_debug_enabled():
        return
    body = _dynamic_codegen_attr(loop, "body", None)
    body_statements = tuple(_dynamic_codegen_attr(body, "statements", ()) or ()) if isinstance(body, structured_c.CStatements) else ()
    log.warning("[linear-recurrence] loop type=%s", type(loop).__name__)
    log.warning("[linear-recurrence] initializer=%s", _node_summary_8616(_dynamic_codegen_attr(loop, "initializer", None)))
    log.warning("[linear-recurrence] init=%s", _node_summary_8616(_dynamic_codegen_attr(loop, "init", None)))
    log.warning("[linear-recurrence] condition=%s", _node_summary_8616(_dynamic_codegen_attr(loop, "condition", None)))
    log.warning("[linear-recurrence] iteration=%s", _node_summary_8616(_dynamic_codegen_attr(loop, "iteration", None)))
    log.warning("[linear-recurrence] iterator=%s", _node_summary_8616(_dynamic_codegen_attr(loop, "iterator", None)))
    log.warning("[linear-recurrence] body_count=%d", len(body_statements))
    for idx, summary in enumerate(_iter_nested_statement_summaries_8616(body)):
        log.warning("[linear-recurrence] body[%d]=%s", idx, summary)


def _rewrite_linear_condition(
    node: object,
    state: LinearRecurrenceState,
    *,
    structured_codegen_node: Callable[[object], bool],
    same_c_expression: Callable[[object, object], bool],
    rules: _LinearRecurrenceRules,
) -> None:
    candidate = None
    current = _dynamic_codegen_attr(node, "condition", None)
    if structured_codegen_node(current):
        candidate = state.resolve_known_copy_alias_expr(current)
        candidate = state.inline_known_linear_defs(candidate)
        if candidate is not current and rules._should_commit_linear_rewrite(
            current,
            candidate,
            expr_contains_dereference=state.expr_contains_dereference,
            same_c_expression=same_c_expression,
        ):
            typing.cast(typing.Any, node).condition = candidate
            state.changed = True


def _self_delta_assignment_parts(
    stmt: object, state: LinearRecurrenceState
) -> tuple[object, object, object, int | None] | None:
    if not isinstance(stmt, structured_c.CAssignment) or not isinstance(stmt.lhs, structured_c.CVariable):
        if _linear_recurrence_debug_enabled():
            log.warning("[linear-recurrence] low-delta reject: stmt=%s", _node_summary_8616(stmt))
        return None
    lhs = stmt.lhs
    rhs = state.resolve_known_copy_alias_expr(stmt.rhs)
    base_expr, delta = state.extract_linear_delta(rhs)
    if base_expr is None:
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] low-delta reject: no linear delta lhs=%s rhs=%s",
                _node_summary_8616(lhs),
                _node_summary_8616(rhs),
            )
        return None
    return lhs, rhs, base_expr, delta


def _match_self_delta_assignment(stmt: object, state: LinearRecurrenceState) -> int | None:
    def _impl() -> int | None:
        parts = _self_delta_assignment_parts(stmt, state)
        if parts is None:
            return None
        lhs, rhs, base_expr, delta = parts
        if not state.same_c_expression(state.unwrap_c_casts(base_expr), state.unwrap_c_casts(lhs)):
            if _linear_recurrence_debug_enabled():
                log.warning(
                    "[linear-recurrence] low-delta reject: base mismatch lhs=%s base=%s delta=%r",
                    _node_summary_8616(lhs),
                    _node_summary_8616(base_expr),
                    delta,
                )
            return None
        if delta not in {1, -1}:
            if _linear_recurrence_debug_enabled():
                log.warning(
                    "[linear-recurrence] low-delta reject: unsupported delta lhs=%s delta=%r rhs=%s",
                    _node_summary_8616(lhs),
                    delta,
                    _node_summary_8616(rhs),
                )
            return None
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] low-delta match lhs=%s base=%s delta=%r",
                _node_summary_8616(lhs),
                _node_summary_8616(base_expr),
                delta,
            )
        return delta

    return _impl()


def _match_byte_carrier_high_update(expr: object, state: LinearRecurrenceState) -> tuple[object, int] | None:
    def _impl() -> tuple[object, int] | None:
        nonlocal expr
        expr = state.unwrap_c_casts(expr)
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Shr":
            if _linear_recurrence_debug_enabled():
                log.warning("[linear-recurrence] high-carry reject: expr=%s", _node_summary_8616(expr))
            return None
        shift = state.c_constant_value(state.unwrap_c_casts(expr.rhs))
        if shift != 8:
            if _linear_recurrence_debug_enabled():
                log.warning("[linear-recurrence] high-carry reject: shift=%r expr=%s", shift, _node_summary_8616(expr))
            return None
        inner = state.unwrap_c_casts(expr.lhs)
        if not isinstance(inner, structured_c.CBinaryOp) or inner.op not in {"Add", "Sub"}:
            if _linear_recurrence_debug_enabled():
                log.warning("[linear-recurrence] high-carry reject: inner=%s", _node_summary_8616(inner))
            return None
        matched = _match_carry_low_side(inner, expr, state)
        if matched is not None:
            return matched
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] high-carry reject: no variable low expr inner=%s", _node_summary_8616(inner)
            )
        return None

    return _impl()


def _match_carry_low_side(
    inner: structured_c.CBinaryOp,
    expr: object,
    state: LinearRecurrenceState,
) -> tuple[object, int] | None:
    for maybe_low, maybe_const in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
        const = state.c_constant_value(state.unwrap_c_casts(maybe_const))
        if const != 1:
            continue
        low_expr = state.unwrap_c_casts(maybe_low)
        duplicate_word_base = state.match_duplicate_word_base_expr(
            state.resolve_known_copy_alias_expr(low_expr),
            state.resolve_known_copy_alias_expr,
        )
        if duplicate_word_base is not None:
            low_expr = state.unwrap_c_casts(duplicate_word_base)
        if isinstance(low_expr, structured_c.CVariable):
            if _linear_recurrence_debug_enabled():
                log.warning(
                    "[linear-recurrence] high-carry match low=%s delta=%r expr=%s",
                    _node_summary_8616(low_expr),
                    (1 if inner.op == "Add" else -1),
                    _node_summary_8616(expr),
                )
            return low_expr, (1 if inner.op == "Add" else -1)
    return None


def _collect_body_assignments_8616(node: object) -> list[structured_c.CAssignment]:
    assignments: list[structured_c.CAssignment] = []
    if node is None:
        return assignments
    if isinstance(node, structured_c.CStatements):
        for stmt in _dynamic_codegen_attr(node, "statements", ()) or ():
            assignments.extend(_collect_body_assignments_8616(stmt))
        return assignments
    if isinstance(node, structured_c.CAssignment):
        assignments.append(node)
        return assignments
    for attr in ("body", "else_node"):
        child = _dynamic_codegen_attr(node, attr, None)
        if child is not None:
            assignments.extend(_collect_body_assignments_8616(child))
    return assignments


def _find_low_delta_stmt_8616(
    assignments: Sequence[structured_c.CAssignment],
    state: LinearRecurrenceState,
    low_carrier: object,
    candidate_delta: object,
) -> structured_c.CAssignment | None:
    for stmt in reversed(assignments):
        if not isinstance(stmt, structured_c.CAssignment):
            continue
        tail_delta = _match_self_delta_assignment(stmt, state)
        if tail_delta != candidate_delta:
            continue
        if state.same_c_expression(
            state.unwrap_c_casts(stmt.lhs),
            state.unwrap_c_casts(low_carrier),
        ):
            return stmt
    return None


def _remove_statement_from_tree_8616(node: object, target_stmt: object) -> bool:
    def _impl() -> bool:
        if node is None or target_stmt is None:
            return False
        removed = False
        if isinstance(node, structured_c.CStatements):
            new_statements = []
            for stmt in _dynamic_codegen_attr(node, "statements", ()) or ():
                if stmt is target_stmt:
                    removed = True
                    continue
                child_removed = _remove_statement_from_tree_8616(stmt, target_stmt)
                removed = removed or child_removed
                new_statements.append(stmt)
            if removed:
                node.statements = new_statements
            return removed
        for attr in ("body", "else_node"):
            child = _dynamic_codegen_attr(node, attr, None)
            if child is None:
                continue
            child_removed = _remove_statement_from_tree_8616(child, target_stmt)
            removed = removed or child_removed
        return removed

    return _impl()


def _rebind_for_loop_byte_carrier_recurrence(
    loop: object, state: LinearRecurrenceState, *, rules: _LinearRecurrenceRules
) -> bool:
    def _impl() -> bool:
        _debug_loop_structure_8616(loop)
        init, iteration_attr, iteration, body = _initial_loop_parts_8616(loop)
        if not _valid_loop_inputs_8616(state, init, iteration, iteration_attr, body):
            return False

        if not isinstance(init, structured_c.CAssignment):
            return False
        iterator_local = init.lhs
        body_assignments = _collect_body_assignments_8616(body)
        if _linear_recurrence_debug_enabled():
            _debug_body_assignments_8616(body_assignments)
        low_carrier, candidate_delta, low_stmt = _resolve_loop_carry_candidate_8616(
            state, rules, iteration, iterator_local, body_assignments
        )
        if low_stmt is False:
            return False
        return _apply_loop_byte_carrier_rebind(
            loop, state, iteration_attr, iterator_local, low_carrier, candidate_delta, low_stmt, body
        )

    return _impl()


def _loop_rebind_debug_reject(reason: str, *args: object) -> None:
    if _linear_recurrence_debug_enabled():
        log.warning(f"[linear-recurrence] reject loop: {reason}", *args)


def _initial_loop_parts_8616(loop: object) -> LoopParts:
    init_local = _dynamic_codegen_attr(loop, "initializer", None) or _dynamic_codegen_attr(loop, "init", None)
    iteration_attr_local = "iteration" if _dynamic_codegen_attr(loop, "iteration", None) is not None else "iterator"
    iteration_local = _dynamic_codegen_attr(loop, iteration_attr_local, None)
    body_local = _dynamic_codegen_attr(loop, "body", None)
    return init_local, iteration_attr_local, iteration_local, body_local


def _valid_loop_inputs_8616(
    state: LinearRecurrenceState,
    init_local: object,
    iteration_local: object,
    iteration_attr_local: str,
    body_local: object,
) -> bool:
    if not isinstance(init_local, structured_c.CAssignment):
        _loop_rebind_debug_reject("init not assignment")
        return False
    if not isinstance(init_local.lhs, structured_c.CVariable):
        _loop_rebind_debug_reject("init lhs not CVariable")
        return False
    if not state.is_materialized_stack_local(init_local.lhs):
        _loop_rebind_debug_reject("init lhs not materialized local: %r", init_local.lhs)
        return False
    if not isinstance(iteration_local, structured_c.CAssignment):  # noqa: SIM102
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] reject loop: iteration attr=%s value=%r",
                iteration_attr_local,
                iteration_local,
            )
    if not isinstance(body_local, structured_c.CStatements) or not _dynamic_codegen_attr(body_local, "statements", None):
        _loop_rebind_debug_reject("body=%r", body_local)
        return False
    return True


def _candidate_from_iteration_8616(
    state: LinearRecurrenceState,
    rules: _LinearRecurrenceRules,
    iteration_local: object,
    iterator_local: object,
    body_assignments: Sequence[structured_c.CAssignment],
) -> CarryCandidate:
    if not isinstance(iteration_local, structured_c.CAssignment):
        return None, None, None
    carry_base = state.match_duplicate_word_increment_shift_expr(
        iteration_local.rhs,
        state.resolve_known_copy_alias_expr,
        state.codegen,
    )
    carry_rewrite = rules._carry_base_rewrite_plan(
        carry_base,
        expr_contains_dereference=state.expr_contains_dereference,
        extract_linear_delta=state.extract_linear_delta,
    )
    if carry_rewrite is not None:
        candidate_expr = state.resolve_known_copy_alias_expr(carry_rewrite["replacement"])
        candidate_base, candidate_delta_local = state.extract_linear_delta(candidate_expr)
        if candidate_base is None or candidate_delta_local not in {1, -1}:
            state._record_recurrence_reason("ambiguous_delta")
            return None, None, False
        if not state.same_c_expression(
            state.unwrap_c_casts(candidate_base), state.unwrap_c_casts(iterator_local)
        ):
            if _linear_recurrence_debug_enabled():
                log.warning(
                    "[linear-recurrence] iterator candidate rejected: base=%s iterator=%s delta=%r",
                    _node_summary_8616(candidate_base),
                    _node_summary_8616(iterator_local),
                    candidate_delta_local,
                )
            state._record_recurrence_reason("not_materialized_local")
            return None, None, False
        return (
            iterator_local,
            candidate_delta_local,
            _find_low_delta_stmt_8616(body_assignments, state, iterator_local, candidate_delta_local),
        )
    reduced = _match_byte_carrier_high_update(iteration_local.rhs, state)
    if reduced is None:
        return None, None, None
    low_carrier_local, candidate_delta_local = reduced
    return (
        low_carrier_local,
        candidate_delta_local,
        _find_low_delta_stmt_8616(body_assignments, state, low_carrier_local, candidate_delta_local),
    )


def _candidate_from_body_scan_8616(
    state: LinearRecurrenceState,
    body_assignments: Sequence[structured_c.CAssignment],
) -> CarryCandidate:
    for idx, stmt in enumerate(body_assignments[:-1]):
        reduced = _match_byte_carrier_high_update(stmt.rhs, state)
        if reduced is None:
            continue
        maybe_low_carrier, maybe_delta = reduced
        if _linear_recurrence_debug_enabled():
            log.warning(
                "[linear-recurrence] high-carry candidate[%d] lhs=%s low=%s delta=%r",
                idx,
                _node_summary_8616(stmt.lhs),
                _node_summary_8616(maybe_low_carrier),
                maybe_delta,
            )
        maybe_low_stmt = _find_low_delta_stmt_8616(
            body_assignments[idx + 1 :], state, maybe_low_carrier, maybe_delta
        )
        if maybe_low_stmt is None:
            if _linear_recurrence_debug_enabled():
                log.warning("[linear-recurrence] candidate[%d] rejected: no matching low-delta stmt", idx)
            continue
        return maybe_low_carrier, maybe_delta, maybe_low_stmt
    return None, None, None


def _coalesce_linear_recurrence_statements(
    project: object,
    codegen: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    structured_codegen_node: Callable[[object], bool],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    same_c_expression: Callable[[object, object], bool],
    c_constant_value: Callable[[object], object | None],
    canonicalize_stack_cvar_expr: Callable[..., object],
    seed_adjacent_byte_pair_aliases: Callable[..., dict[object, object]],
    describe_alias_storage: Callable[[object], object | None],
    analyze_widening_expr: Callable[..., object | None],
    match_high_byte_projection_base: Callable[..., object | None],
    match_duplicate_word_base_expr: Callable[..., object | None],
    match_duplicate_word_increment_shift_expr: Callable[..., object | None],
    same_stack_slot_identity_var: Callable[..., bool],
    rules: _LinearRecurrenceRules,
) -> bool:
    cfunc = _dynamic_codegen_attr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    state = LinearRecurrenceState(
        project=project,
        codegen=cast(Any, codegen),
        unwrap_c_casts=unwrap_c_casts,
        structured_codegen_node=structured_codegen_node,
        iter_c_nodes_deep=iter_c_nodes_deep,
        same_c_expression=same_c_expression,
        c_constant_value=c_constant_value,
        canonicalize_stack_cvar_expr=canonicalize_stack_cvar_expr,
        seed_adjacent_byte_pair_aliases=seed_adjacent_byte_pair_aliases,
        describe_alias_storage=cast(Any, describe_alias_storage),
        analyze_widening_expr=cast(Any, analyze_widening_expr),
        match_high_byte_projection_base=match_high_byte_projection_base,
        match_duplicate_word_base_expr=match_duplicate_word_base_expr,
        match_duplicate_word_increment_shift_expr=match_duplicate_word_increment_shift_expr,
        same_stack_slot_identity_var=same_stack_slot_identity_var,
    )
    state.prepare()

    _visit_linear_recurrence(_dynamic_codegen_attr(cfunc, "statements", None), state, codegen, rules=rules)
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[linear-recurrence] function=%#x candidates=%d bound=%d failed=%d reasons=%r",
            _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "addr", -1) or -1,
            state.recurrence_candidates,
            state.recurrence_bound_to_materialized_local,
            state.recurrence_failed_to_bind,
            state.recurrence_reasons,
        )
    if state.recurrence_candidates > 0 and state.recurrence_bound_to_materialized_local == 0:
        raise PipelineHardError(
            "byte-carrier recurrence not rebound to materialized local",
            layer="stack_lowering",
        )
    typing.cast(typing.Any, codegen)._inertia_recurrence_state = state
    return bool(state.changed)


def _debug_body_assignments_8616(body_assignments: Sequence[structured_c.CAssignment]) -> None:
    log.warning("[linear-recurrence] body_assignment_count=%d", len(body_assignments))
    for idx, stmt in enumerate(body_assignments):
        log.warning("[linear-recurrence] assignment[%d]=%s", idx, _node_summary_8616(stmt))


def _resolve_loop_carry_candidate_8616(
    state: LinearRecurrenceState,
    rules: _LinearRecurrenceRules,
    iteration: object,
    iterator_local: object,
    body_assignments: Sequence[structured_c.CAssignment],
) -> CarryCandidate:
    low_carrier, candidate_delta, low_stmt = _candidate_from_iteration_8616(
        state, rules, iteration, iterator_local, body_assignments
    )
    if low_stmt is False or low_stmt is not None:
        return low_carrier, candidate_delta, low_stmt
    return _candidate_from_body_scan_8616(state, body_assignments)


def _apply_loop_byte_carrier_rebind(
    loop: object,
    state: LinearRecurrenceState,
    iteration_attr: str,
    iterator_local: object,
    low_carrier: object,
    candidate_delta: object,
    low_stmt: object,
    body: object,
) -> bool:
    if candidate_delta not in {1, -1} or low_stmt is None:
        state._record_recurrence_reason("no_carry_pattern")
        return False
    if not isinstance(low_stmt, structured_c.CAssignment):
        return False

    state._record_recurrence_candidate()

    if low_carrier is not None and not state.same_c_expression(
        state.unwrap_c_casts(low_stmt.lhs),
        state.unwrap_c_casts(low_carrier),
    ):
        state._record_recurrence_reason("carrier_pair_mismatch")
        return False

    _dynamic_codegen_setattr(
        loop,
        iteration_attr,
        structured_c.CAssignment(
            iterator_local,
            state.build_linear_expr(iterator_local, candidate_delta),
            codegen=state.codegen,
        ),
    )
    removed_low_stmt = _remove_statement_from_tree_8616(body, low_stmt)
    if _linear_recurrence_debug_enabled():
        log.warning("[linear-recurrence] removed_low_stmt=%s", removed_low_stmt)
    state.changed = True
    state._record_recurrence_success()
    return True


def _visit_linear_recurrence(
    node: object,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> None:
    if isinstance(node, structured_c.CStatements):
        _visit_statements_8616(node, state, codegen, rules=rules)
    elif isinstance(node, structured_c.CIfElse):
        _visit_ifelse_8616(node, state, codegen, rules=rules)
    elif isinstance(node, structured_c.CWhileLoop) or (
        hasattr(structured_c, "CDoWhileLoop")
        and isinstance(node, _dynamic_codegen_attr(structured_c, "CDoWhileLoop"))
    ):
        _visit_conditional_loop_8616(node, state, codegen, rules=rules)
    elif hasattr(structured_c, "CForLoop") and isinstance(node, _dynamic_codegen_attr(structured_c, "CForLoop")):
        _visit_forloop_8616(node, state, codegen, rules=rules)


def _visit_statements_8616(
    node: structured_c.CStatements,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> None:
    new_statements = []
    i = 0
    while i < len(node.statements):
        stmt = node.statements[i]
        next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None
        if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
            stmt_var = _dynamic_codegen_attr(stmt.lhs, "variable", None)
            if stmt_var is not None and id(stmt_var) in state.dereferenced_variable_ids:
                _visit_linear_recurrence(stmt, state, codegen, rules=rules)
                new_statements.append(stmt)
                i += 1
                continue
            carry_replacement = _record_or_rewrite_carry_assignment(stmt, stmt_var, state, codegen, rules)
            if carry_replacement is not None:
                new_statements.append(carry_replacement)
                i += 1
                continue
        if (
            isinstance(stmt, structured_c.CAssignment)
            and isinstance(stmt.lhs, structured_c.CVariable)
            and isinstance(next_stmt, structured_c.CAssignment)
            and isinstance(next_stmt.lhs, structured_c.CVariable)
        ):
            handled = _coalesce_assignment_pair_8616(
                stmt, next_stmt, state, codegen, rules=rules
            )
            if handled is not None:
                new_stmts, advance = handled
                new_statements.extend(new_stmts)
                i += advance
                continue
        _visit_linear_recurrence(stmt, state, codegen, rules=rules)
        new_statements.append(stmt)
        i += 1
    if state.changed or new_statements != node.statements:
        node.statements = new_statements


def _record_or_rewrite_carry_assignment(
    stmt: structured_c.CAssignment,
    stmt_var: object,
    state: LinearRecurrenceState,
    codegen: object,
    rules: _LinearRecurrenceRules,
) -> object | None:
    carry_base = state.match_duplicate_word_increment_shift_expr(
        stmt.rhs, state.resolve_known_copy_alias_expr, codegen
    )
    carry_rewrite = rules._carry_base_rewrite_plan(
        carry_base,
        expr_contains_dereference=state.expr_contains_dereference,
        extract_linear_delta=state.extract_linear_delta,
    )
    if carry_rewrite is None:
        return None
    linear_rewrite = carry_rewrite["linear"]
    if (
        stmt_var is not None
        and isinstance(linear_rewrite, tuple)
        and len(linear_rewrite) == 2
        and isinstance(linear_rewrite[1], int)
    ):
        state.linear_defs[id(stmt_var)] = linear_rewrite
    state.changed = True
    return cast(object, structured_c.CAssignment(stmt.lhs, carry_rewrite["replacement"], codegen=codegen))


def _coalesce_assignment_pair_8616(
    stmt: structured_c.CAssignment,
    next_stmt: structured_c.CAssignment,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> tuple[list[object], int] | None:
    temp_var = _dynamic_codegen_attr(stmt.lhs, "variable", None)
    next_var = _dynamic_codegen_attr(next_stmt.lhs, "variable", None)
    temp_use_count = state.variable_use_counts.get(id(temp_var), 0) if temp_var is not None else 0
    if _pair_var_is_protected_8616(temp_var, state) or _pair_var_is_protected_8616(next_var, state):
        _visit_linear_recurrence(stmt, state, codegen, rules=rules)
        return [stmt], 1
    combined = _match_pair_linear_combine(stmt, next_stmt, temp_use_count, state, codegen)
    if combined is not None:
        state.changed = True
        return [combined], 2
    shift_combined = _match_pair_shift_combine(stmt, next_stmt, temp_use_count, state, codegen)
    if shift_combined is not None:
        state.changed = True
        return [shift_combined], 2
    if state.is_linear_register_temp(stmt.lhs):
        stmt = _process_linear_temp_assignment(stmt, temp_var, state, codegen)
        _record_copy_aliases_8616(stmt, temp_var, state)
        return _finish_pair_lane(stmt, state, codegen, rules=rules)
    return _finish_pair_lane(stmt, state, codegen, rules=rules)


def _finish_pair_lane(
    stmt: structured_c.CAssignment,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> tuple[list[object], int]:
    _visit_linear_recurrence(stmt, state, codegen, rules=rules)
    return [stmt], 1


def _pair_var_is_protected_8616(var: object, state: LinearRecurrenceState) -> bool:
    return var is not None and (
        id(var) in state.dereferenced_variable_ids or id(var) in state.protected_linear_alias_ids
    )


def _match_pair_linear_combine(
    stmt: structured_c.CAssignment,
    next_stmt: structured_c.CAssignment,
    temp_use_count: int,
    state: LinearRecurrenceState,
    codegen: object,
) -> object | None:
    if not (
        temp_use_count >= 2
        and state.is_linear_register_temp(stmt.lhs)
        and state.is_linear_register_temp(next_stmt.lhs)
    ):
        return None
    stmt_base, stmt_delta = state.extract_linear_delta(stmt.rhs)
    next_rhs = state.unwrap_c_casts(next_stmt.rhs)
    if not isinstance(next_rhs, structured_c.CBinaryOp) or next_rhs.op not in {"Add", "Sub"}:
        return None
    next_base, next_delta = _pair_combine_parts(next_rhs, stmt, stmt_base, state)
    if next_base is None or not isinstance(next_delta, int):
        return None
    combined = stmt_delta + next_delta if next_rhs.op == "Add" else stmt_delta - next_delta
    return cast(
        object,
        structured_c.CAssignment(
            next_stmt.lhs, state.build_linear_expr(next_base, combined), codegen=codegen
        ),
    )


def _pair_combine_parts(
    next_rhs: structured_c.CBinaryOp,
    stmt: structured_c.CAssignment,
    stmt_base: object,
    state: LinearRecurrenceState,
) -> tuple[object, object | None]:
    if state.same_c_expression(state.unwrap_c_casts(next_rhs.lhs), stmt.lhs):
        return stmt_base, state.c_constant_value(state.unwrap_c_casts(next_rhs.rhs))
    if state.same_c_expression(state.unwrap_c_casts(next_rhs.rhs), stmt.lhs):
        return stmt_base, state.c_constant_value(state.unwrap_c_casts(next_rhs.lhs))
    return None, None


def _match_pair_shift_combine(
    stmt: structured_c.CAssignment,
    next_stmt: structured_c.CAssignment,
    temp_use_count: int,
    state: LinearRecurrenceState,
    codegen: object,
) -> object | None:
    if not (
        temp_use_count >= 2
        and state.is_linear_register_temp(stmt.lhs)
        and state.is_linear_register_temp(next_stmt.lhs)
    ):
        return None
    stmt_shift_base, stmt_shift_count = state.extract_shift_delta(stmt.rhs)
    next_shift_rhs = state.unwrap_c_casts(next_stmt.rhs)
    if not isinstance(next_shift_rhs, structured_c.CBinaryOp) or next_shift_rhs.op != "Shr":
        return None
    if not state.same_c_expression(state.unwrap_c_casts(next_shift_rhs.lhs), stmt.lhs):
        return None
    next_shift_count = state.c_constant_value(state.unwrap_c_casts(next_shift_rhs.rhs))
    if not isinstance(next_shift_count, int) or stmt_shift_count < 0:
        return None
    combined_shift = stmt_shift_count + next_shift_count
    shift_repl = structured_c.CAssignment(
        next_stmt.lhs,
        state.build_shift_expr(stmt_shift_base, combined_shift),
        codegen=codegen,
    )
    shift_var = _dynamic_codegen_attr(next_stmt.lhs, "variable", None)
    if shift_var is not None:
        state.shift_defs[id(shift_var)] = (stmt_shift_base, combined_shift)
    return cast(object, shift_repl)


def _process_linear_temp_assignment(
    stmt: structured_c.CAssignment,
    temp_var: object,
    state: LinearRecurrenceState,
    codegen: object,
) -> object:
    stmt_base, stmt_delta = state.extract_linear_delta(stmt.rhs)
    if stmt_base is not None:
        resolved_stmt_base = state.resolve_known_copy_alias_expr(stmt_base)
        if state.expr_contains_dereference(stmt_base) or state.expr_contains_dereference(
            resolved_stmt_base
        ):
            return stmt
        base_var = (
            _dynamic_codegen_attr(stmt_base, "variable", None)
            if isinstance(stmt_base, structured_c.CVariable)
            else None
        )
        if base_var is not None and (
            id(base_var) in state.dereferenced_variable_ids
            or id(base_var) in state.protected_linear_alias_ids
        ):
            return stmt
        state.linear_defs[id(temp_var)] = (stmt_base, stmt_delta)
        resolved_base = state.resolve_known_copy_alias_expr(stmt_base)
        if isinstance(resolved_base, structured_c.CVariable) and isinstance(
            _dynamic_codegen_attr(resolved_base, "variable", None), SimStackVariable
        ):
            state.protected_linear_defs.add(id(temp_var))
        canonical_rhs = state.build_linear_expr(stmt_base, stmt_delta)
        if not state.same_c_expression(stmt.rhs, canonical_rhs):
            stmt = structured_c.CAssignment(stmt.lhs, canonical_rhs, codegen=codegen)
            state.changed = True
    rhs = state.inline_known_linear_defs(stmt.rhs)
    inlined_base, inlined_delta = state.extract_linear_delta(rhs)
    if inlined_base is not None and not state.same_c_expression(rhs, stmt.rhs):
        stmt = structured_c.CAssignment(
            stmt.lhs, state.build_linear_expr(inlined_base, inlined_delta), codegen=codegen
        )
        rhs = stmt.rhs
        state.changed = True
    return _apply_self_linear_combine(stmt, temp_var, rhs, state, codegen)


def _apply_self_linear_combine(
    stmt: structured_c.CAssignment,
    temp_var: object,
    rhs: object,
    state: LinearRecurrenceState,
    codegen: object,
) -> object:
    current_linear = state.linear_defs.get(id(temp_var)) if temp_var is not None else None
    if not _is_self_linear_update(rhs, stmt, current_linear, state):
        return stmt
    assert isinstance(rhs, structured_c.CBinaryOp)
    assert current_linear is not None
    current_delta = state.c_constant_value(state.unwrap_c_casts(rhs.lhs))
    if current_delta is None:
        current_delta = state.c_constant_value(state.unwrap_c_casts(rhs.rhs))
    if not isinstance(current_delta, int):
        return stmt
    base_expr, base_delta = current_linear
    resolved_base = state.resolve_known_copy_alias_expr(base_expr)
    if isinstance(resolved_base, structured_c.CVariable) and isinstance(
        _dynamic_codegen_attr(resolved_base, "variable", None), SimStackVariable
    ):
        state.protected_linear_defs.add(id(temp_var))
    combined = (
        base_delta + current_delta if rhs.op == "Add" else base_delta - current_delta
    )
    state.changed = True
    return structured_c.CAssignment(
        stmt.lhs, state.build_linear_expr(base_expr, combined), codegen=codegen
    )


def _is_self_linear_update(
    rhs: object,
    stmt: structured_c.CAssignment,
    current_linear: tuple[object, int] | None,
    state: LinearRecurrenceState,
) -> bool:
    return (
        current_linear is not None
        and isinstance(rhs, structured_c.CBinaryOp)
        and rhs.op in {"Add", "Sub"}
    ) and (
        state.same_c_expression(state.unwrap_c_casts(rhs.lhs), stmt.lhs)
        or state.same_c_expression(state.unwrap_c_casts(rhs.rhs), stmt.lhs)
    )


def _record_copy_aliases_8616(stmt: structured_c.CAssignment, temp_var: object, state: LinearRecurrenceState) -> None:
    if temp_var is not None and state.is_copy_alias_candidate(stmt.rhs):
        alias = state.unwrap_c_casts(stmt.rhs)
        alias_var = _dynamic_codegen_attr(alias, "variable", None)
        if alias_var is not None and alias_var is not temp_var:
            state.expr_aliases[id(temp_var)] = alias
            storage_key = state.alias_storage_key(stmt.lhs)
            if storage_key is not None:
                state.expr_aliases[storage_key] = alias
    if isinstance(temp_var, SimStackVariable) and state.is_copy_alias_candidate(stmt.rhs):
        alias = state.unwrap_c_casts(stmt.rhs)
        alias_var = _dynamic_codegen_attr(alias, "variable", None)
        if (
            isinstance(alias_var, SimStackVariable)
            and alias_var is not temp_var
            and state.same_stack_slot_identity_var(temp_var, alias_var)
        ):
            state.expr_aliases[id(temp_var)] = alias
            storage_key = state.alias_storage_key(stmt.lhs)
            if storage_key is not None:
                state.expr_aliases[storage_key] = alias


def _visit_ifelse_8616(
    node: structured_c.CIfElse,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> None:
    new_pairs = []
    pair_changed = False
    for cond, body in node.condition_and_nodes:
        new_cond = cond
        if state.structured_codegen_node(cond):
            candidate_cond = state.resolve_known_copy_alias_expr(new_cond)
            candidate_cond = state.inline_known_linear_defs(candidate_cond)
            if rules._should_commit_linear_rewrite(
                cond,
                candidate_cond,
                expr_contains_dereference=state.expr_contains_dereference,
                same_c_expression=state.same_c_expression,
            ):
                new_cond = cast(structured_c.CExpression, candidate_cond)
        if new_cond is not cond:
            pair_changed = True
        _visit_linear_recurrence(body, state, codegen, rules=rules)
        new_pairs.append((new_cond, body))
    if pair_changed:
        node.condition_and_nodes = new_pairs
        state.changed = True
    if node.else_node is not None:
        _visit_linear_recurrence(node.else_node, state, codegen, rules=rules)


def _visit_conditional_loop_8616(
    node: object,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> None:
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        loop_kind = (
            "do-while-loop"
            if hasattr(structured_c, "CDoWhileLoop")
            and isinstance(node, _dynamic_codegen_attr(structured_c, "CDoWhileLoop"))
            else "while-loop"
        )
        log.warning(
            "[linear-recurrence] saw %s function=%#x",
            loop_kind,
            _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "addr", -1) or -1,
        )
    _rewrite_linear_condition(
        node,
        state,
        structured_codegen_node=state.structured_codegen_node,
        same_c_expression=state.same_c_expression,
        rules=rules,
    )
    _visit_linear_recurrence(_dynamic_codegen_attr(node, "condition", None), state, codegen, rules=rules)
    _visit_linear_recurrence(_dynamic_codegen_attr(node, "body", None), state, codegen, rules=rules)


def _visit_forloop_8616(
    node: object,
    state: LinearRecurrenceState,
    codegen: object,
    *,
    rules: _LinearRecurrenceRules,
) -> None:
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[linear-recurrence] saw for-loop function=%#x",
            _dynamic_codegen_attr(_dynamic_codegen_attr(codegen, "cfunc", None), "addr", -1) or -1,
        )
    for attr in ("initializer", "init", "condition", "iteration", "iterator"):
        current = _dynamic_codegen_attr(node, attr, None)
        if state.structured_codegen_node(current):
            candidate = state.resolve_known_copy_alias_expr(current)
            candidate = state.inline_known_linear_defs(candidate)
            if candidate is not current and rules._should_commit_linear_rewrite(
                current,
                candidate,
                expr_contains_dereference=state.expr_contains_dereference,
                same_c_expression=state.same_c_expression,
            ):
                _dynamic_codegen_setattr(node, attr, candidate)
                state.changed = True
    for attr in ("initializer", "init", "condition", "iteration", "iterator", "body"):
        _visit_linear_recurrence(_dynamic_codegen_attr(node, attr, None), state, codegen, rules=rules)
    _rebind_for_loop_byte_carrier_recurrence(node, state, rules=rules)
