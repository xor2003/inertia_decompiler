"""Layer: Rewrite/Postprocess cleanup.

Responsibility: execute one evidence-backed backward-liveness DCE block walk.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures,
control flow, or facts from rendered text, COD, source, or CLI/reporting
evidence here.
"""

from __future__ import annotations

import builtins
import sys
import typing
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CUnaryOp,
    CVariable,
)

from ...decompiler_postprocess_utils import _same_c_expression_8616
from ...lowering.stack_storage_evidence import alias_proves_private_stack_write_8616

_DceKey8616 = tuple[str, int | str]
_DceNameKey8616 = tuple[str, str]


def _dynamic_dce_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic third-party angr/codegen boundary."""
    return builtins.getattr(obj, name, default)


def _dynamic_dce_setattr_8616(obj: object, name: str, value: object) -> None:
    """Write an attribute across the dynamic third-party angr/codegen boundary."""
    builtins.setattr(obj, name, value)


class DceValuePurity8616(Enum):
    """Purity classification used by conservative DCE decisions."""

    LOCAL_VALUE = "local_value"
    GLOBAL_MEMORY_READ = "global_memory_read"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class _DceWalkContext8616:
    """Typed state and classifiers consumed by one DCE statement-block walk."""

    codegen: object
    debug_optimization: bool
    protected: set[_DceKey8616]
    pruned_decl_keys: set[_DceKey8616]
    pruned_decl_names: set[str]
    changed: bool
    bump_codegen_counter: Callable[[str], None]
    call_name: Callable[[CFunctionCall], str | None]
    callsite_materialization_complete_or_no_calls: Callable[[], bool]
    callsite_materialization_proven_complete: Callable[[], bool]
    collect_nested_stmt_reads: Callable[[object], set[_DceKey8616]]
    collect_stmt_reads: Callable[[object], set[_DceKey8616]]
    debug_node_shape: Callable[[object], str]
    dirty_is_storage_free_temp: Callable[[object], bool]
    dirty_key: Callable[[object], _DceKey8616 | None]
    dirty_lhs_delete_proven: Callable[[object, object], bool]
    dirty_temp_cleanup_mode: Callable[[object], bool]
    expr_contains_memory_read_shape: Callable[[object], bool]
    expr_is_discardable_dead_value: Callable[[object], bool]
    expr_is_discardable_value: Callable[[object], bool]
    expr_is_pure_local_value: Callable[[object], bool]
    expr_value_purity: Callable[[object], DceValuePurity8616]
    has_direct_stack_write_evidence_for_offset: Callable[[int | None], bool]
    is_dead_argument_overwrite_artifact: Callable[
        [object, object, object, _DceKey8616, _DceNameKey8616 | None, set[_DceKey8616]],
        bool,
    ]
    is_frame_anchor_stack_lvalue: Callable[[object], bool]
    is_function_argument_lvalue: Callable[[object, _DceKey8616, _DceNameKey8616 | None], bool]
    is_observable_lvalue: Callable[[object], bool]
    is_plain_local_lvalue: Callable[[object], bool]
    is_pure_generated_helper_call: Callable[[CFunctionCall], bool]
    is_structured_or_control_statement: Callable[[object], bool]
    iter_with_root: Callable[[object], Iterator[object]]
    lhs_key_and_name: Callable[
        [object],
        tuple[_DceKey8616 | None, _DceNameKey8616 | None, bool],
    ]
    lhs_variable: Callable[[object], CVariable | None]
    node_has_instruction_evidence: Callable[[object], bool]
    prune_adjacent_duplicate_assignments: Callable[[object], bool]
    rhs_evaluation_is_proven_unobservable: Callable[[object], bool]
    rhs_has_side_effects: Callable[[object], bool]
    rhs_is_pure_stack_base_carrier: Callable[[object], bool]
    rhs_is_unproven_dirty_register_carrier: Callable[[object, set[_DceKey8616]], bool]
    stack_offset_from_plain_lvalue: Callable[[object], int | None]
    standalone_expression_is_definitely_dead: Callable[[object], bool]
    standalone_expression_payload: Callable[[object], object]
    stmt_is_consumed_boolean_carrier: Callable[[object], bool]
    stmt_is_consumed_call_cleanup_carrier: Callable[[object], bool]
    stmt_is_direct_stack_move_evidence: Callable[[object, object], bool]
    stmt_is_direct_stack_update_evidence: Callable[[object, object], bool]


def _delete_proven_non_temp_statement_8616(
    context: _DceWalkContext8616,
    *,
    stmt_index: int,
    stmt: object,
    stmts: Sequence[object],
    lhs: object,
    rhs: object,
    key: _DceKey8616,
    name_key: _DceNameKey8616 | None,
    live: set[_DceKey8616],
    outside_reads: int,
    total_reads: dict[_DceKey8616, int],
    dirty_carrier_reads: dict[_DceKey8616, int],
) -> bool:
    """Delete one non-temp assignment only when an existing proof applies."""
    protected = context.protected
    if (
        context.is_plain_local_lvalue(lhs)
        and not context.node_has_instruction_evidence(stmt)
        and not any(context.rhs_has_side_effects(prefix_stmt) for prefix_stmt in stmts[:stmt_index])
        and (context.expr_is_discardable_value(rhs) or context.expr_is_pure_local_value(rhs))
        and (key not in live or int(total_reads.get(key, 0)) <= int(dirty_carrier_reads.get(key, 0)))
        and outside_reads <= 0
        and key not in protected
        and (name_key is None or name_key not in protected)
        and not context.is_function_argument_lvalue(lhs, key, name_key)
    ):
        if context.debug_optimization:
            print(
                "[optimization] dce_decision "
                f"reason=delete_untagged_local_artifact key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        context.bump_codegen_counter("dce_candidates")
        context.bump_codegen_counter("dce_deleted")
        if context.expr_value_purity(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
            context.bump_codegen_counter("dce_dead_memory_read_candidates")
            context.bump_codegen_counter("dce_dead_memory_read_deleted")
        return True
    if (
        context.is_plain_local_lvalue(lhs)
        and context.expr_is_discardable_value(rhs)
        and key not in live
        and outside_reads <= 0
        and key not in protected
        and (name_key is None or name_key not in protected)
        and context.callsite_materialization_complete_or_no_calls()
    ):
        if context.debug_optimization:
            print(
                "[optimization] dce_decision "
                f"reason=delete_non_temp_discardable key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        context.bump_codegen_counter("dce_candidates")
        context.bump_codegen_counter("dce_deleted")
        if context.expr_value_purity(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
            context.bump_codegen_counter("dce_dead_memory_read_candidates")
            context.bump_codegen_counter("dce_dead_memory_read_deleted")
        return True
    if (
        context.is_plain_local_lvalue(lhs)
        and context.expr_is_pure_local_value(rhs)
        and key not in live
        and outside_reads <= 0
        and key not in protected
        and (name_key is None or name_key not in protected)
        and (
            _same_c_expression_8616(lhs, rhs)
            or context.callsite_materialization_proven_complete()
        )
    ):
        if context.debug_optimization:
            print(
                "[optimization] dce_decision "
                f"reason=delete_non_temp_pure key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        context.bump_codegen_counter("dce_candidates")
        context.bump_codegen_counter("dce_deleted")
        return True
    if (
        key[0].startswith("dirty")
        and context.rhs_is_pure_stack_base_carrier(rhs)
        and key not in live
        and outside_reads <= 0
        and key not in protected
        and (name_key is None or name_key not in protected)
        and context.callsite_materialization_complete_or_no_calls()
    ):
        if context.debug_optimization:
            print(
                "[optimization] dce_decision "
                f"reason=delete_stack_base key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        context.bump_codegen_counter("dce_candidates")
        context.bump_codegen_counter("dce_deleted")
        return True
    return False


def _walk_statements_8616(
    context: _DceWalkContext8616,
    statements: object,
    total_reads: dict[_DceKey8616, int],
    block_reads: dict[int, dict[_DceKey8616, int]],
    loop_backedge_reads: dict[int, frozenset[_DceKey8616]],
    defined_keys: set[_DceKey8616],
    observable_reads: dict[_DceKey8616, int],
    dirty_carrier_reads: dict[_DceKey8616, int],
    all_dirty_carrier_reads: dict[_DceKey8616, int],
) -> bool:
    """Walk one structured statement block and remove only proven dead values."""
    codegen = context.codegen
    debug_optimization = context.debug_optimization
    protected = context.protected
    pruned_decl_keys = context.pruned_decl_keys
    pruned_decl_names = context.pruned_decl_names
    changed = context.changed
    _bump_codegen_counter_8616 = context.bump_codegen_counter
    _call_name_8616 = context.call_name
    _collect_nested_stmt_reads = context.collect_nested_stmt_reads
    _collect_stmt_reads = context.collect_stmt_reads
    _debug_node_shape_8616 = context.debug_node_shape
    _dirty_is_storage_free_temp_8616 = context.dirty_is_storage_free_temp
    _dirty_key = context.dirty_key
    _dirty_lhs_delete_proven_8616 = context.dirty_lhs_delete_proven
    _dirty_temp_cleanup_mode_8616 = context.dirty_temp_cleanup_mode
    _expr_contains_memory_read_shape_8616 = context.expr_contains_memory_read_shape
    _expr_is_discardable_dead_value_8616 = context.expr_is_discardable_dead_value
    _expr_is_discardable_value_8616 = context.expr_is_discardable_value
    _expr_value_purity_8616 = context.expr_value_purity
    _has_direct_stack_write_evidence_for_offset_8616 = context.has_direct_stack_write_evidence_for_offset
    _is_dead_argument_overwrite_artifact_8616 = context.is_dead_argument_overwrite_artifact
    _is_frame_anchor_stack_lvalue_8616 = context.is_frame_anchor_stack_lvalue
    _is_function_argument_lvalue_8616 = context.is_function_argument_lvalue
    _is_observable_lvalue = context.is_observable_lvalue
    _is_plain_local_lvalue_8616 = context.is_plain_local_lvalue
    _is_pure_generated_helper_call_8616 = context.is_pure_generated_helper_call
    _is_structured_or_control_statement_8616 = context.is_structured_or_control_statement
    _iter_with_root = context.iter_with_root
    _lhs_key_and_name_8616 = context.lhs_key_and_name
    _lhs_variable_8616 = context.lhs_variable
    _node_has_instruction_evidence_8616 = context.node_has_instruction_evidence
    _prune_adjacent_duplicate_assignments_8616 = context.prune_adjacent_duplicate_assignments
    _rhs_evaluation_is_proven_unobservable_8616 = context.rhs_evaluation_is_proven_unobservable
    _rhs_has_side_effects = context.rhs_has_side_effects
    _rhs_is_unproven_dirty_register_carrier_8616 = context.rhs_is_unproven_dirty_register_carrier
    _stack_offset_from_plain_lvalue_8616 = context.stack_offset_from_plain_lvalue
    _standalone_expression_is_definitely_dead_8616 = context.standalone_expression_is_definitely_dead
    _standalone_expression_payload_8616 = context.standalone_expression_payload
    _stmt_is_consumed_boolean_carrier_8616 = context.stmt_is_consumed_boolean_carrier
    _stmt_is_consumed_call_cleanup_carrier_8616 = context.stmt_is_consumed_call_cleanup_carrier
    _stmt_is_direct_stack_move_evidence_8616 = context.stmt_is_direct_stack_move_evidence
    _stmt_is_direct_stack_update_evidence_8616 = context.stmt_is_direct_stack_update_evidence

    duplicate_changed = _prune_adjacent_duplicate_assignments_8616(statements)
    stmts = list(_dynamic_dce_getattr_8616(statements, "statements", ()) or ())
    if not stmts:
        context.changed = changed or duplicate_changed
        return duplicate_changed
    local_reads = block_reads.get(id(statements), {})
    block_loop_backedge_reads = loop_backedge_reads.get(id(statements), frozenset())
    live = set(block_loop_backedge_reads)
    later_local_defs: set[_DceKey8616] = set()
    new_rev: list[object] = []
    block_changed = duplicate_changed

    for stmt_index, stmt in reversed(list(enumerate(stmts))):
        if not isinstance(stmt, CAssignment):
            if _is_structured_or_control_statement_8616(stmt):
                live.update(_collect_nested_stmt_reads(stmt))
                new_rev.append(stmt)
                continue
            expr_stmt = _standalone_expression_payload_8616(stmt)
            if debug_optimization and any(
                isinstance(node, CFunctionCall) and _is_pure_generated_helper_call_8616(node)
                for node in _iter_with_root(expr_stmt)
            ):
                print(
                    "[optimization] dce_non_assignment_helper "
                    f"stmt_type={type(stmt).__name__} payload_type={type(expr_stmt).__name__} "
                    f"shape={_debug_node_shape_8616(stmt)}",
                    file=sys.stderr,
                    flush=True,
                )
            if isinstance(expr_stmt, CUnaryOp) and expr_stmt.op == "Dereference":
                _bump_codegen_counter_8616("dce_pure_expression_candidates")
                if _standalone_expression_is_definitely_dead_8616(expr_stmt):
                    _bump_codegen_counter_8616("dce_candidates")
                    _bump_codegen_counter_8616("dce_deleted")
                    _bump_codegen_counter_8616("dce_pure_expression_deleted")
                    changed = True
                    block_changed = True
                    continue
                _bump_codegen_counter_8616("dce_pure_expression_refused")
            elif _expr_is_discardable_dead_value_8616(expr_stmt):
                _bump_codegen_counter_8616("dce_pure_expression_candidates")
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                _bump_codegen_counter_8616("dce_pure_expression_deleted")
                changed = True
                block_changed = True
                continue
            live.update(_collect_nested_stmt_reads(stmt))
            new_rev.append(stmt)
            continue
        lhs = _dynamic_dce_getattr_8616(stmt, "lhs", None)
        rhs = _dynamic_dce_getattr_8616(stmt, "rhs", None)
        key, name_key, is_temp_like = _lhs_key_and_name_8616(lhs)
        if key is None:
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
            continue
        is_exact_direct_stack_evidence = _stmt_is_direct_stack_move_evidence_8616(
            stmt,
            lhs,
        ) or _stmt_is_direct_stack_update_evidence_8616(stmt, lhs)
        is_ambiguous_direct_stack_evidence = (
            not _node_has_instruction_evidence_8616(stmt)
            and not _is_function_argument_lvalue_8616(lhs, key, name_key)
            and _has_direct_stack_write_evidence_for_offset_8616(
                _stack_offset_from_plain_lvalue_8616(lhs)
            )
        )
        private_write_proven = (
            is_exact_direct_stack_evidence
            and alias_proves_private_stack_write_8616(codegen, stmt)
            and context.expr_is_pure_local_value(rhs)
        )
        if (is_exact_direct_stack_evidence and not private_write_proven) or is_ambiguous_direct_stack_evidence:
            _bump_codegen_counter_8616(
                "dce_keep_unknown" if is_ambiguous_direct_stack_evidence else "dce_keep_protected"
            )
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
            later_local_defs.add(key)
            continue
        if is_temp_like and key in block_loop_backedge_reads and _node_has_instruction_evidence_8616(stmt):
            _bump_codegen_counter_8616("dce_keep_protected")
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
            later_local_defs.add(key)
            continue
        if (
            _same_c_expression_8616(lhs, rhs)
            and (_dirty_key(lhs) is None or _dirty_is_storage_free_temp_8616(lhs))
            and not _is_observable_lvalue(lhs)
            and not _rhs_has_side_effects(rhs)
        ):
            if debug_optimization:
                print(
                    "[optimization] dce_decision "
                    f"reason=delete_self key={key!r} name_key={name_key!r} "
                    f"stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            typing.cast(typing.Any, codegen).dce_candidates = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_candidates", 0)) + 1
            )
            typing.cast(typing.Any, codegen).dce_deleted = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_deleted", 0)) + 1
            )
            changed = True
            block_changed = True
            continue
        outside_reads = (
            0
            if _dirty_is_storage_free_temp_8616(lhs)
            else int(total_reads.get(key, 0)) - int(local_reads.get(key, 0))
        )
        if key[0].startswith("dirty") and _stmt_is_consumed_boolean_carrier_8616(stmt):
            _bump_codegen_counter_8616("dce_boolean_carrier_candidates")
            rhs_has_call = any(isinstance(node, CFunctionCall) for node in _iter_with_root(rhs))
            if (
                key not in live
                and outside_reads <= 0
                and key not in protected
                and (name_key is None or name_key not in protected)
                and not _is_observable_lvalue(lhs)
                and not rhs_has_call
            ):
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                _bump_codegen_counter_8616("dce_boolean_carrier_deleted")
                pruned_decl_keys.add(key)
                if name_key is not None:
                    pruned_decl_names.add(name_key[1])
                changed = True
                block_changed = True
                continue
            _bump_codegen_counter_8616("dce_boolean_carrier_refused")
        if (
            (is_temp_like or key[0].startswith("dirty"))
            and _stmt_is_consumed_call_cleanup_carrier_8616(stmt)
        ):
            _bump_codegen_counter_8616("dce_call_cleanup_carrier_candidates")
            rhs_unobservable = _rhs_evaluation_is_proven_unobservable_8616(rhs)
            if debug_optimization and (
                key in live
                or outside_reads > 0
                or key in protected
                or (name_key is not None and name_key in protected)
                or _is_observable_lvalue(lhs)
                or not rhs_unobservable
            ):
                rhs_node_types = tuple(sorted({type(node).__name__ for node in _iter_with_root(rhs)}))
                rhs_ops = tuple(
                    sorted(
                        {
                            str(op)
                            for node in _iter_with_root(rhs)
                            if (op := _dynamic_dce_getattr_8616(node, "op", None)) is not None
                        }
                    )
                )
                print(
                    "[optimization] dce_call_cleanup_refusal "
                    f"key={key!r} name_key={name_key!r} "
                    f"is_temp_like={is_temp_like} "
                    f"outside_reads={outside_reads} "
                    f"live={key in live} protected={key in protected} "
                    f"observable={_is_observable_lvalue(lhs)} "
                    f"rhs_unobservable={rhs_unobservable} "
                    f"rhs_node_types={rhs_node_types!r} "
                    f"rhs_ops={rhs_ops!r}",
                    file=sys.stderr,
                    flush=True,
                )
            if (
                key not in live
                and outside_reads <= 0
                and key not in protected
                and (name_key is None or name_key not in protected)
                and not _is_observable_lvalue(lhs)
                and rhs_unobservable
            ):
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                _bump_codegen_counter_8616("dce_call_cleanup_carrier_deleted")
                pruned_decl_keys.add(key)
                if name_key is not None:
                    pruned_decl_names.add(name_key[1])
                changed = True
                block_changed = True
                continue
            _bump_codegen_counter_8616("dce_call_cleanup_carrier_refused")
        if _is_frame_anchor_stack_lvalue_8616(lhs):
            # BP+0 is a frame artifact. Delete it only with unobservable RHS
            # evidence and no non-dirty read.
            _bump_codegen_counter_8616("dce_frame_anchor_candidates")
            if (
                int(total_reads.get(key, 0)) <= int(all_dirty_carrier_reads.get(key, 0))
                and key not in protected
                and (name_key is None or name_key not in protected)
                and _rhs_evaluation_is_proven_unobservable_8616(rhs)
            ):
                if debug_optimization:
                    print(
                        "[optimization] dce_decision "
                        f"reason=delete_frame_anchor key={key!r} name_key={name_key!r} "
                        f"stmt={stmt!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                _bump_codegen_counter_8616("dce_frame_anchor_deleted")
                pruned_decl_keys.add(key)
                changed = True
                block_changed = True
                continue
            _bump_codegen_counter_8616("dce_frame_anchor_refused")
            if debug_optimization:
                print(
                    "[optimization] dce_frame_anchor_refused "
                    f"key={key!r} name_key={name_key!r} outside_reads={outside_reads} "
                    f"total_reads={int(total_reads.get(key, 0))} "
                    f"dirty_carrier_reads={int(all_dirty_carrier_reads.get(key, 0))} "
                    f"protected={key in protected or (name_key is not None and name_key in protected)} "
                    f"rhs_unobservable={_rhs_evaluation_is_proven_unobservable_8616(rhs)}",
                    file=sys.stderr,
                    flush=True,
                )
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
            later_local_defs.add(key)
            continue
        if _is_function_argument_lvalue_8616(lhs, key, name_key):
            typing.cast(typing.Any, codegen).dce_arg_overwrite_artifact_candidates = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_arg_overwrite_artifact_candidates", 0))
                + 1
            )
            if debug_optimization:
                print(
                    "[optimization] dce_arg_overwrite_probe "
                    f"key={key!r} name_key={name_key!r} "
                    f"tagged={_node_has_instruction_evidence_8616(stmt)} "
                    f"stack_offset={_stack_offset_from_plain_lvalue_8616(lhs)!r} "
                    f"direct_stack_evidence="
                    f"{_has_direct_stack_write_evidence_for_offset_8616(_stack_offset_from_plain_lvalue_8616(lhs))} "
                    f"rhs_dirty={_rhs_is_unproven_dirty_register_carrier_8616(rhs, defined_keys)}",
                    file=sys.stderr,
                    flush=True,
                )
            if _is_dead_argument_overwrite_artifact_8616(stmt, lhs, rhs, key, name_key, defined_keys):
                if debug_optimization:
                    print(
                        "[optimization] dce_decision "
                        f"reason=delete_arg_overwrite key={key!r} name_key={name_key!r} "
                        f"stmt={stmt!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                typing.cast(typing.Any, codegen).dce_arg_overwrite_artifact_deleted = (
                    int(_dynamic_dce_getattr_8616(codegen, "dce_arg_overwrite_artifact_deleted", 0))
                    + 1
                )
                changed = True
                block_changed = True
                continue
            typing.cast(typing.Any, codegen).dce_arg_overwrite_artifact_refused = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_arg_overwrite_artifact_refused", 0)) + 1
            )
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
            later_local_defs.add(key)
            continue
        if (
            _is_plain_local_lvalue_8616(lhs)
            and later_local_defs
            and key in later_local_defs
            and key not in live
            and outside_reads <= 0
            and key not in protected
            and (name_key is None or name_key not in protected)
            and not _is_function_argument_lvalue_8616(lhs, key, name_key)
        ):
            _bump_codegen_counter_8616("dce_overwritten_local_candidates")
            if _rhs_evaluation_is_proven_unobservable_8616(rhs):
                if debug_optimization:
                    print(
                        "[optimization] dce_decision "
                        f"reason=delete_overwritten_local key={key!r} name_key={name_key!r} "
                        f"stmt={stmt!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                _bump_codegen_counter_8616("dce_overwritten_local_deleted")
                changed = True
                block_changed = True
                continue
            _bump_codegen_counter_8616("dce_overwritten_local_refused")
        if (
            isinstance(rhs, CFunctionCall)
            and _call_name_8616(rhs) not in {None, "unknown_addr"}
            and not _is_pure_generated_helper_call_8616(rhs)
            and (is_temp_like or key[0].startswith("dirty"))
            and key not in live
            and outside_reads <= 0
            and key not in protected
            and (name_key is None or name_key not in protected)
            and key not in block_loop_backedge_reads
            and not _is_observable_lvalue(lhs)
        ):
            if debug_optimization:
                print(
                    "[optimization] dce_decision "
                    f"reason=preserve_call_drop_result key={key!r} name_key={name_key!r} "
                    f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            expression_statement = CExpressionStatement(
                rhs,
                codegen=_dynamic_dce_getattr_8616(stmt, "codegen", codegen),
            )
            _bump_codegen_counter_8616("dce_candidates")
            _bump_codegen_counter_8616("dce_deleted")
            pruned_decl_keys.add(key)
            if name_key is not None:
                pruned_decl_names.add(name_key[1])
            live.update(_collect_stmt_reads(expression_statement))
            new_rev.append(expression_statement)
            changed = True
            block_changed = True
            continue
        if key[0].startswith("dirty"):
            typing.cast(typing.Any, codegen).dce_dirty_value_candidates = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_dirty_value_candidates", 0)) + 1
            )
            if (
                key not in live
                and outside_reads <= 0
                and key not in protected
                and (name_key is None or name_key not in protected)
                and _dirty_lhs_delete_proven_8616(lhs, rhs)
            ) or (
                _dirty_temp_cleanup_mode_8616(lhs)
                and key not in live
                and outside_reads <= 0
                and int(observable_reads.get(key, 0)) <= 0
                and key not in protected
                and (name_key is None or name_key not in protected)
                and _rhs_evaluation_is_proven_unobservable_8616(rhs)
            ):
                if debug_optimization:
                    print(
                        "[optimization] dce_decision "
                        f"reason=delete_dirty key={key!r} name_key={name_key!r} "
                        f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                _bump_codegen_counter_8616("dce_candidates")
                _bump_codegen_counter_8616("dce_deleted")
                typing.cast(typing.Any, codegen).dce_dirty_value_deleted = (
                    int(_dynamic_dce_getattr_8616(codegen, "dce_dirty_value_deleted", 0)) + 1
                )
                changed = True
                block_changed = True
                continue
            typing.cast(typing.Any, codegen).dce_dirty_value_refused = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_dirty_value_refused", 0)) + 1
            )
        if not is_temp_like:
            if key in protected or (name_key is not None and name_key in protected):
                typing.cast(typing.Any, codegen).dce_keep_protected = (
                    int(_dynamic_dce_getattr_8616(codegen, "dce_keep_protected", 0)) + 1
                )
                live.discard(key)
                live.update(_collect_stmt_reads(stmt))
                new_rev.append(stmt)
                later_local_defs.add(key)
                continue
            if _delete_proven_non_temp_statement_8616(
                context,
                stmt_index=stmt_index,
                stmt=stmt,
                stmts=stmts,
                lhs=lhs,
                rhs=rhs,
                key=key,
                name_key=name_key,
                live=live,
                outside_reads=outside_reads,
                total_reads=total_reads,
                dirty_carrier_reads=dirty_carrier_reads,
            ):
                pruned_decl_keys.add(key)
                changed = True
                block_changed = True
                continue
            typing.cast(typing.Any, codegen).dce_keep_unknown = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_keep_unknown", 0)) + 1
            )
            live.discard(key)
            live.update(_collect_stmt_reads(stmt))
            new_rev.append(stmt)
            later_local_defs.add(key)
            continue
        typing.cast(typing.Any, codegen).dce_candidates = (
            int(_dynamic_dce_getattr_8616(codegen, "dce_candidates", 0)) + 1
        )
        removable = False
        lhs_var_for_observable = _lhs_variable_8616(lhs)
        if _is_observable_lvalue(lhs) or (
            lhs_var_for_observable is not None and _is_observable_lvalue(lhs_var_for_observable)
        ):
            typing.cast(typing.Any, codegen).dce_keep_observable = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_keep_observable", 0)) + 1
            )
        elif _rhs_has_side_effects(rhs):
            typing.cast(typing.Any, codegen).dce_keep_side_effect = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_keep_side_effect", 0)) + 1
            )
        elif key in protected or (name_key is not None and name_key in protected):
            typing.cast(typing.Any, codegen).dce_keep_protected = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_keep_protected", 0)) + 1
            )
        elif key in live or outside_reads > 0:
            typing.cast(typing.Any, codegen).dce_keep_live_use = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_keep_live_use", 0)) + 1
            )
            if debug_optimization and key[0] in {"dirty", "dirty_expr"}:
                print(
                    "[optimization] dce_keep_live "
                    f"key={key!r} live={key in live} outside_reads={outside_reads} stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
        elif not _expr_is_discardable_value_8616(rhs):
            if _expr_contains_memory_read_shape_8616(rhs):
                typing.cast(typing.Any, codegen).dce_dead_memory_read_refused = (
                    int(_dynamic_dce_getattr_8616(codegen, "dce_dead_memory_read_refused", 0)) + 1
                )
            typing.cast(typing.Any, codegen).dce_keep_unknown = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_keep_unknown", 0)) + 1
            )
        else:
            if _expr_value_purity_8616(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
                typing.cast(typing.Any, codegen).dce_dead_memory_read_candidates = (
                    int(_dynamic_dce_getattr_8616(codegen, "dce_dead_memory_read_candidates", 0)) + 1
                )
                typing.cast(typing.Any, codegen).dce_dead_memory_read_deleted = (
                    int(_dynamic_dce_getattr_8616(codegen, "dce_dead_memory_read_deleted", 0)) + 1
                )
            removable = True
        if debug_optimization:
            reason = (
                "delete"
                if removable
                else "keep_observable"
                if _is_observable_lvalue(lhs)
                or (lhs_var_for_observable is not None and _is_observable_lvalue(lhs_var_for_observable))
                else "keep_side_effect"
                if _rhs_has_side_effects(rhs)
                else "keep_protected"
                if key in protected or (name_key is not None and name_key in protected)
                else "keep_live_use"
                if key in live or outside_reads > 0
                else "keep_unknown"
            )
            print(
                "[optimization] dce_decision "
                f"reason={reason} key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in live} "
                f"instruction_evidence={_node_has_instruction_evidence_8616(stmt)} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        if removable:
            pruned_decl_keys.add(key)
            typing.cast(typing.Any, codegen).dce_deleted = (
                int(_dynamic_dce_getattr_8616(codegen, "dce_deleted", 0)) + 1
            )
            changed = True
            block_changed = True
            continue
        live.discard(key)
        live.update(_collect_stmt_reads(stmt))
        new_rev.append(stmt)
        later_local_defs.add(key)
    new_stmts = list(reversed(new_rev))
    if new_stmts != stmts:
        typing.cast(typing.Any, statements).statements = new_stmts
        block_changed = True
    context.changed = changed or block_changed
    return block_changed
