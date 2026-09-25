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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CUnaryOp,
    CVariable,
)

from ...lowering.stack_storage_evidence import alias_proves_private_stack_write_8616
from .dce_value_identity import same_local_value_expression_8616

_DceKey8616 = tuple[str, int | str]
_DceNameKey8616 = tuple[str, str]


def _dynamic_dce_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic third-party angr/codegen boundary."""
    return builtins.getattr(obj, name, default)


def _dynamic_dce_setattr_8616(obj: object, name: str, value: object) -> None:
    """Write an attribute across the dynamic third-party angr/codegen boundary."""
    builtins.setattr(obj, name, value)


def _bump_codegen_attr_8616(codegen: object, name: str) -> None:
    """Increment a dynamic angr/codegen boundary diagnostic counter attribute."""
    _dynamic_dce_setattr_8616(codegen, name, int(_dynamic_dce_getattr_8616(codegen, name, 0)) + 1)


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


def _unprotected_dead_key_8616(
    context: _DceWalkContext8616,
    key: _DceKey8616,
    name_key: _DceNameKey8616 | None,
    outside_reads: int,
) -> bool:
    """Return whether a key is unprotected and has no reads outside the block."""
    protected = context.protected
    return (
        outside_reads <= 0
        and key not in protected
        and (name_key is None or name_key not in protected)
    )


def _key_free_to_delete_8616(
    context: _DceWalkContext8616,
    key: _DceKey8616,
    name_key: _DceNameKey8616 | None,
    live: set[_DceKey8616],
    outside_reads: int,
) -> bool:
    """Return the shared liveness/protection gate for deleting one key."""
    return key not in live and _unprotected_dead_key_8616(context, key, name_key, outside_reads)


def _untagged_local_artifact_gate_8616(
    context: _DceWalkContext8616,
    stmt: object,
    stmts: Sequence[object],
    stmt_index: int,
    lhs: object,
    rhs: object,
) -> bool:
    """Return whether an untagged plain-local assignment carries a removable value."""
    return (
        context.is_plain_local_lvalue(lhs)
        and not context.node_has_instruction_evidence(stmt)
        and not any(context.rhs_has_side_effects(prefix_stmt) for prefix_stmt in stmts[:stmt_index])
        and (context.expr_is_discardable_value(rhs) or context.expr_is_pure_local_value(rhs))
    )


def _key_not_live_or_dirty_only_8616(
    key: _DceKey8616,
    live: set[_DceKey8616],
    total_reads: dict[_DceKey8616, int],
    dirty_carrier_reads: dict[_DceKey8616, int],
) -> bool:
    """Return whether a key is dead or only read by dirty carrier statements."""
    return key not in live or int(total_reads.get(key, 0)) <= int(dirty_carrier_reads.get(key, 0))


def _record_non_temp_delete_8616(
    context: _DceWalkContext8616,
    *,
    reason: str,
    key: _DceKey8616,
    name_key: _DceNameKey8616 | None,
    outside_reads: int,
    live: set[_DceKey8616],
    stmt: object,
    rhs: object,
    track_memory_read: bool,
) -> bool:
    """Emit shared debug/counter bookkeeping for a proven non-temp delete."""
    if context.debug_optimization:
        print(
            "[optimization] dce_decision "
            f"reason={reason} key={key!r} name_key={name_key!r} "
            f"outside_reads={outside_reads} live={key in live} stmt={stmt!r}",
            file=sys.stderr,
            flush=True,
        )
    context.bump_codegen_counter("dce_candidates")
    context.bump_codegen_counter("dce_deleted")
    if track_memory_read and context.expr_value_purity(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
        context.bump_codegen_counter("dce_dead_memory_read_candidates")
        context.bump_codegen_counter("dce_dead_memory_read_deleted")
    return True


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
    if (
        _untagged_local_artifact_gate_8616(context, stmt, stmts, stmt_index, lhs, rhs)
        and _key_not_live_or_dirty_only_8616(key, live, total_reads, dirty_carrier_reads)
        and _unprotected_dead_key_8616(context, key, name_key, outside_reads)
        and not context.is_function_argument_lvalue(lhs, key, name_key)
    ):
        return _record_non_temp_delete_8616(
            context,
            reason="delete_untagged_local_artifact",
            key=key,
            name_key=name_key,
            outside_reads=outside_reads,
            live=live,
            stmt=stmt,
            rhs=rhs,
            track_memory_read=True,
        )
    if (
        context.is_plain_local_lvalue(lhs)
        and context.expr_is_discardable_value(rhs)
        and _key_free_to_delete_8616(context, key, name_key, live, outside_reads)
        and context.callsite_materialization_complete_or_no_calls()
    ):
        return _record_non_temp_delete_8616(
            context,
            reason="delete_non_temp_discardable",
            key=key,
            name_key=name_key,
            outside_reads=outside_reads,
            live=live,
            stmt=stmt,
            rhs=rhs,
            track_memory_read=True,
        )
    if (
        context.is_plain_local_lvalue(lhs)
        and context.expr_is_pure_local_value(rhs)
        and _key_free_to_delete_8616(context, key, name_key, live, outside_reads)
        and (
            same_local_value_expression_8616(lhs, rhs)
            or context.callsite_materialization_proven_complete()
        )
    ):
        return _record_non_temp_delete_8616(
            context,
            reason="delete_non_temp_pure",
            key=key,
            name_key=name_key,
            outside_reads=outside_reads,
            live=live,
            stmt=stmt,
            rhs=rhs,
            track_memory_read=False,
        )
    if (
        key[0].startswith("dirty")
        and context.rhs_is_pure_stack_base_carrier(rhs)
        and _key_free_to_delete_8616(context, key, name_key, live, outside_reads)
        and context.callsite_materialization_complete_or_no_calls()
    ):
        return _record_non_temp_delete_8616(
            context,
            reason="delete_stack_base",
            key=key,
            name_key=name_key,
            outside_reads=outside_reads,
            live=live,
            stmt=stmt,
            rhs=rhs,
            track_memory_read=False,
        )
    return False


@dataclass
class _DceStatementWalk8616:
    """Mutable backward-liveness walk state for one DCE statement block."""

    context: _DceWalkContext8616
    stmts: list[object]
    total_reads: dict[_DceKey8616, int]
    local_reads: dict[_DceKey8616, int]
    block_loop_backedge_reads: frozenset[_DceKey8616]
    defined_keys: set[_DceKey8616]
    observable_reads: dict[_DceKey8616, int]
    dirty_carrier_reads: dict[_DceKey8616, int]
    all_dirty_carrier_reads: dict[_DceKey8616, int]
    block_changed: bool = False
    changed: bool = False
    live: set[_DceKey8616] = field(default_factory=set)
    later_local_defs: set[_DceKey8616] = field(default_factory=set)
    new_rev: list[object] = field(default_factory=list)

    def _bump(self, name: str) -> None:
        """Increment a codegen-boundary counter through the walk context."""
        self.context.bump_codegen_counter(name)

    def _key_free(self, key: _DceKey8616, name_key: _DceNameKey8616 | None, outside_reads: int) -> bool:
        """Return the shared liveness/protection gate for deleting one key."""
        return _key_free_to_delete_8616(self.context, key, name_key, self.live, outside_reads)

    def _prune_decl(self, key: _DceKey8616, name_key: _DceNameKey8616 | None) -> None:
        """Record one deleted definition for later declaration pruning."""
        self.context.pruned_decl_keys.add(key)
        if name_key is not None:
            self.context.pruned_decl_names.add(name_key[1])

    def _delete(self, key: _DceKey8616, name_key: _DceNameKey8616 | None = None, *, decl: bool = False) -> None:
        """Record a proven delete for the current statement."""
        if decl:
            self._prune_decl(key, name_key)
        self.changed = True
        self.block_changed = True

    def _keep(self, stmt: object, key: _DceKey8616) -> None:
        """Record one surviving statement into the backward-liveness walk."""
        self.live.discard(key)
        self.live.update(self.context.collect_stmt_reads(stmt))
        self.new_rev.append(stmt)
        self.later_local_defs.add(key)

    def run(self, statements: object) -> bool:
        """Walk the statement list backward and write the survivors back."""
        self.live = set(self.block_loop_backedge_reads)
        for stmt_index, stmt in reversed(list(enumerate(self.stmts))):
            if not isinstance(stmt, CAssignment):
                self._non_assignment(stmt)
                continue
            self._assignment(stmt_index, stmt)
        new_stmts = list(reversed(self.new_rev))
        if new_stmts != self.stmts:
            typing.cast(typing.Any, statements).statements = new_stmts
            self.block_changed = True
        self.context.changed = self.context.changed or self.changed or self.block_changed
        return self.block_changed

    def _non_assignment(self, stmt: object) -> None:
        """Handle one non-assignment statement in the backward walk."""
        context = self.context
        if context.is_structured_or_control_statement(stmt):
            self.live.update(context.collect_nested_stmt_reads(stmt))
            self.new_rev.append(stmt)
            return
        expr_stmt = context.standalone_expression_payload(stmt)
        if context.debug_optimization and any(
            isinstance(node, CFunctionCall) and context.is_pure_generated_helper_call(node)
            for node in context.iter_with_root(expr_stmt)
        ):
            print(
                "[optimization] dce_non_assignment_helper "
                f"stmt_type={type(stmt).__name__} payload_type={type(expr_stmt).__name__} "
                f"shape={context.debug_node_shape(stmt)}",
                file=sys.stderr,
                flush=True,
            )
        if isinstance(expr_stmt, CUnaryOp) and expr_stmt.op == "Dereference":
            self._bump("dce_pure_expression_candidates")
            if context.standalone_expression_is_definitely_dead(expr_stmt):
                self._bump("dce_candidates")
                self._bump("dce_deleted")
                self._bump("dce_pure_expression_deleted")
                self.changed = True
                self.block_changed = True
                return
            self._bump("dce_pure_expression_refused")
        elif context.expr_is_discardable_dead_value(expr_stmt):
            self._bump("dce_pure_expression_candidates")
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            self._bump("dce_pure_expression_deleted")
            self.changed = True
            self.block_changed = True
            return
        self.live.update(context.collect_nested_stmt_reads(stmt))
        self.new_rev.append(stmt)

    def _assignment(self, stmt_index: int, stmt: object) -> None:
        """Dispatch one assignment through the ordered evidence arm ladder."""
        context = self.context
        lhs = _dynamic_dce_getattr_8616(stmt, "lhs", None)
        rhs = _dynamic_dce_getattr_8616(stmt, "rhs", None)
        key, name_key, is_temp_like = context.lhs_key_and_name(lhs)
        if key is None:
            self.live.update(context.collect_stmt_reads(stmt))
            self.new_rev.append(stmt)
            return
        if self._early_arms(stmt, lhs, rhs, key, name_key, is_temp_like):
            return
        outside_reads = (
            0
            if context.dirty_is_storage_free_temp(lhs)
            else int(self.total_reads.get(key, 0)) - int(self.local_reads.get(key, 0))
        )
        if self._read_dependent_arms(stmt, lhs, rhs, key, name_key, is_temp_like, outside_reads):
            return
        if not is_temp_like:
            self._non_temp(stmt_index, stmt, lhs, rhs, key, name_key, outside_reads)
            return
        self._temp_fallthrough(stmt, lhs, rhs, key, name_key, outside_reads)

    def _early_arms(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, is_temp_like: bool,
    ) -> bool:
        """Run the arms that do not depend on outside-read accounting."""
        if self._guard_direct_stack_evidence(stmt, lhs, rhs, key, name_key):
            return True
        if self._guard_temp_backedge(stmt, key, is_temp_like):
            return True
        return self._self_assignment(stmt, lhs, rhs, key, name_key)

    def _read_dependent_arms(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, is_temp_like: bool, outside_reads: int,
    ) -> bool:
        """Run the arms gated on liveness and outside-read accounting."""
        if self._boolean_carrier(stmt, lhs, rhs, key, name_key, outside_reads):
            return True
        if self._call_cleanup_carrier(stmt, lhs, rhs, key, name_key, is_temp_like, outside_reads):
            return True
        if self._frame_anchor(stmt, lhs, rhs, key, name_key, outside_reads):
            return True
        if self._arg_overwrite(stmt, lhs, rhs, key, name_key):
            return True
        if self._overwritten_local(stmt, lhs, rhs, key, name_key, outside_reads):
            return True
        if self._call_result_drop(stmt, lhs, rhs, key, name_key, is_temp_like, outside_reads):
            return True
        return self._dirty_value(stmt, lhs, rhs, key, name_key, outside_reads)

    def _guard_direct_stack_evidence(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616, name_key: _DceNameKey8616 | None
    ) -> bool:
        """Keep stack-evidence statements that are not proven private writes."""
        context = self.context
        is_exact_direct_stack_evidence = context.stmt_is_direct_stack_move_evidence(
            stmt, lhs
        ) or context.stmt_is_direct_stack_update_evidence(stmt, lhs)
        is_ambiguous_direct_stack_evidence = (
            not context.node_has_instruction_evidence(stmt)
            and not context.is_function_argument_lvalue(lhs, key, name_key)
            and context.has_direct_stack_write_evidence_for_offset(
                context.stack_offset_from_plain_lvalue(lhs)
            )
        )
        private_write_proven = (
            is_exact_direct_stack_evidence
            and alias_proves_private_stack_write_8616(context.codegen, stmt)
            and context.expr_is_pure_local_value(rhs)
        )
        if (is_exact_direct_stack_evidence and not private_write_proven) or is_ambiguous_direct_stack_evidence:
            self._bump("dce_keep_unknown" if is_ambiguous_direct_stack_evidence else "dce_keep_protected")
            self._keep(stmt, key)
            return True
        return False

    def _guard_temp_backedge(self, stmt: object, key: _DceKey8616, is_temp_like: bool) -> bool:
        """Keep tagged temp statements that feed loop backedge reads."""
        if is_temp_like and key in self.block_loop_backedge_reads and self.context.node_has_instruction_evidence(stmt):
            self._bump("dce_keep_protected")
            self._keep(stmt, key)
            return True
        return False

    def _self_assignment(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616, name_key: _DceNameKey8616 | None
    ) -> bool:
        """Delete a self-assignment when the value is non-observable and pure."""
        context = self.context
        if not (
            same_local_value_expression_8616(lhs, rhs)
            and (context.dirty_key(lhs) is None or context.dirty_is_storage_free_temp(lhs))
            and not context.is_observable_lvalue(lhs)
            and not context.rhs_has_side_effects(rhs)
        ):
            return False
        if context.debug_optimization:
            print(
                "[optimization] dce_decision "
                f"reason=delete_self key={key!r} name_key={name_key!r} "
                f"stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        _bump_codegen_attr_8616(context.codegen, "dce_candidates")
        _bump_codegen_attr_8616(context.codegen, "dce_deleted")
        self._delete(key)
        return True

    def _boolean_carrier(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> bool:
        """Delete a consumed boolean carrier when its RHS carries no call."""
        context = self.context
        if not (key[0].startswith("dirty") and context.stmt_is_consumed_boolean_carrier(stmt)):
            return False
        self._bump("dce_boolean_carrier_candidates")
        rhs_has_call = any(isinstance(node, CFunctionCall) for node in context.iter_with_root(rhs))
        if self._key_free(key, name_key, outside_reads) and not context.is_observable_lvalue(lhs) and not rhs_has_call:
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            self._bump("dce_boolean_carrier_deleted")
            self._delete(key, name_key, decl=True)
            return True
        self._bump("dce_boolean_carrier_refused")
        return False

    def _debug_cleanup_refusal_8616(
        self, rhs: object, key: _DceKey8616, name_key: _DceNameKey8616 | None,
        is_temp_like: bool, outside_reads: int, rhs_unobservable: bool, lhs: object,
    ) -> None:
        """Emit the detailed call-cleanup refusal debug record."""
        context = self.context
        rhs_node_types = tuple(sorted({type(node).__name__ for node in context.iter_with_root(rhs)}))
        rhs_ops = tuple(
            sorted(
                {
                    str(op)
                    for node in context.iter_with_root(rhs)
                    if (op := _dynamic_dce_getattr_8616(node, "op", None)) is not None
                }
            )
        )
        print(
            "[optimization] dce_call_cleanup_refusal "
            f"key={key!r} name_key={name_key!r} "
            f"is_temp_like={is_temp_like} "
            f"outside_reads={outside_reads} "
            f"live={key in self.live} protected={key in context.protected} "
            f"observable={context.is_observable_lvalue(lhs)} "
            f"rhs_unobservable={rhs_unobservable} "
            f"rhs_node_types={rhs_node_types!r} "
            f"rhs_ops={rhs_ops!r}",
            file=sys.stderr,
            flush=True,
        )

    def _call_cleanup_carrier(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, is_temp_like: bool, outside_reads: int,
    ) -> bool:
        """Delete a consumed call-cleanup carrier when its RHS is unobservable."""
        context = self.context
        if not (is_temp_like or key[0].startswith("dirty")) or not context.stmt_is_consumed_call_cleanup_carrier(stmt):
            return False
        self._bump("dce_call_cleanup_carrier_candidates")
        rhs_unobservable = context.rhs_evaluation_is_proven_unobservable(rhs)
        deletable = (
            self._key_free(key, name_key, outside_reads)
            and not context.is_observable_lvalue(lhs)
            and rhs_unobservable
        )
        if context.debug_optimization and not deletable:
            self._debug_cleanup_refusal_8616(rhs, key, name_key, is_temp_like, outside_reads, rhs_unobservable, lhs)
        if deletable:
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            self._bump("dce_call_cleanup_carrier_deleted")
            self._delete(key, name_key, decl=True)
            return True
        self._bump("dce_call_cleanup_carrier_refused")
        return False

    def _frame_anchor(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> bool:
        """Handle the frame-anchor stack lvalue arm; always consumes the statement."""
        context = self.context
        if not context.is_frame_anchor_stack_lvalue(lhs):
            return False
        # BP+0 is a frame artifact. Delete it only with unobservable RHS
        # evidence and no non-dirty read.
        self._bump("dce_frame_anchor_candidates")
        if (
            int(self.total_reads.get(key, 0)) <= int(self.all_dirty_carrier_reads.get(key, 0))
            and key not in context.protected
            and (name_key is None or name_key not in context.protected)
            and context.rhs_evaluation_is_proven_unobservable(rhs)
        ):
            if context.debug_optimization:
                print(
                    "[optimization] dce_decision "
                    f"reason=delete_frame_anchor key={key!r} name_key={name_key!r} "
                    f"stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            self._bump("dce_frame_anchor_deleted")
            self._delete(key, decl=True)
            return True
        self._bump("dce_frame_anchor_refused")
        if context.debug_optimization:
            print(
                "[optimization] dce_frame_anchor_refused "
                f"key={key!r} name_key={name_key!r} outside_reads={outside_reads} "
                f"total_reads={int(self.total_reads.get(key, 0))} "
                f"dirty_carrier_reads={int(self.all_dirty_carrier_reads.get(key, 0))} "
                f"protected={key in context.protected or (name_key is not None and name_key in context.protected)} "
                f"rhs_unobservable={context.rhs_evaluation_is_proven_unobservable(rhs)}",
                file=sys.stderr,
                flush=True,
            )
        self._keep(stmt, key)
        return True

    def _arg_overwrite(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616, name_key: _DceNameKey8616 | None
    ) -> bool:
        """Handle the function-argument overwrite arm; always consumes the statement."""
        context = self.context
        if not context.is_function_argument_lvalue(lhs, key, name_key):
            return False
        codegen = context.codegen
        _bump_codegen_attr_8616(codegen, "dce_arg_overwrite_artifact_candidates")
        if context.debug_optimization:
            print(
                "[optimization] dce_arg_overwrite_probe "
                f"key={key!r} name_key={name_key!r} "
                f"tagged={context.node_has_instruction_evidence(stmt)} "
                f"stack_offset={context.stack_offset_from_plain_lvalue(lhs)!r} "
                f"direct_stack_evidence="
                f"{context.has_direct_stack_write_evidence_for_offset(context.stack_offset_from_plain_lvalue(lhs))} "
                f"rhs_dirty={context.rhs_is_unproven_dirty_register_carrier(rhs, self.defined_keys)}",
                file=sys.stderr,
                flush=True,
            )
        if context.is_dead_argument_overwrite_artifact(stmt, lhs, rhs, key, name_key, self.defined_keys):
            if context.debug_optimization:
                print(
                    "[optimization] dce_decision "
                    f"reason=delete_arg_overwrite key={key!r} name_key={name_key!r} "
                    f"stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            _bump_codegen_attr_8616(codegen, "dce_arg_overwrite_artifact_deleted")
            self._delete(key)
            return True
        _bump_codegen_attr_8616(codegen, "dce_arg_overwrite_artifact_refused")
        self._keep(stmt, key)
        return True

    def _overwritten_local(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> bool:
        """Delete a plain local overwritten by a later definition in the block."""
        context = self.context
        if not (
            context.is_plain_local_lvalue(lhs)
            and self.later_local_defs
            and key in self.later_local_defs
            and self._key_free(key, name_key, outside_reads)
            and not context.is_function_argument_lvalue(lhs, key, name_key)
        ):
            return False
        self._bump("dce_overwritten_local_candidates")
        if context.rhs_evaluation_is_proven_unobservable(rhs):
            if context.debug_optimization:
                print(
                    "[optimization] dce_decision "
                    f"reason=delete_overwritten_local key={key!r} name_key={name_key!r} "
                    f"stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            self._bump("dce_overwritten_local_deleted")
            self._delete(key)
            return True
        self._bump("dce_overwritten_local_refused")
        return False

    def _droppable_call_result_8616(self, rhs: object) -> bool:
        """Return whether the RHS is a named non-helper call whose result may drop."""
        context = self.context
        return (
            isinstance(rhs, CFunctionCall)
            and context.call_name(rhs) not in {None, "unknown_addr"}
            and not context.is_pure_generated_helper_call(rhs)
        )

    def _call_result_drop(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, is_temp_like: bool, outside_reads: int,
    ) -> bool:
        """Replace a dead call-result assignment with the call expression itself."""
        context = self.context
        if not (
            self._droppable_call_result_8616(rhs)
            and (is_temp_like or key[0].startswith("dirty"))
            and self._key_free(key, name_key, outside_reads)
            and key not in self.block_loop_backedge_reads
            and not context.is_observable_lvalue(lhs)
        ):
            return False
        if context.debug_optimization:
            print(
                "[optimization] dce_decision "
                f"reason=preserve_call_drop_result key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in self.live} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        expression_statement = CExpressionStatement(
            rhs,
            codegen=_dynamic_dce_getattr_8616(stmt, "codegen", context.codegen),
        )
        self._bump("dce_candidates")
        self._bump("dce_deleted")
        self._prune_decl(key, name_key)
        self.live.update(context.collect_stmt_reads(expression_statement))
        self.new_rev.append(expression_statement)
        self.changed = True
        self.block_changed = True
        return True

    def _dirty_cleanup_gate_8616(
        self, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> bool:
        """Return the cleanup-mode gate for a dirty temp value."""
        context = self.context
        return (
            context.dirty_temp_cleanup_mode(lhs)
            and key not in self.live
            and outside_reads <= 0
            and int(self.observable_reads.get(key, 0)) <= 0
            and _unprotected_dead_key_8616(context, key, name_key, outside_reads)
            and context.rhs_evaluation_is_proven_unobservable(rhs)
        )

    def _dirty_value(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> bool:
        """Delete a dirty-keyed value when proven dead or under cleanup mode."""
        context = self.context
        if not key[0].startswith("dirty"):
            return False
        codegen = context.codegen
        _bump_codegen_attr_8616(codegen, "dce_dirty_value_candidates")
        proven_delete = self._key_free(
            key, name_key, outside_reads
        ) and context.dirty_lhs_delete_proven(lhs, rhs)
        if proven_delete or self._dirty_cleanup_gate_8616(lhs, rhs, key, name_key, outside_reads):
            if context.debug_optimization:
                print(
                    "[optimization] dce_decision "
                    f"reason=delete_dirty key={key!r} name_key={name_key!r} "
                    f"outside_reads={outside_reads} live={key in self.live} stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            self._bump("dce_candidates")
            self._bump("dce_deleted")
            _bump_codegen_attr_8616(codegen, "dce_dirty_value_deleted")
            self._delete(key)
            return True
        _bump_codegen_attr_8616(codegen, "dce_dirty_value_refused")
        return False

    def _non_temp(
        self, stmt_index: int, stmt: object, lhs: object, rhs: object,
        key: _DceKey8616, name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> None:
        """Handle a non-temp assignment via protection or proven-delete gates."""
        context = self.context
        codegen = context.codegen
        if key in context.protected or (name_key is not None and name_key in context.protected):
            _bump_codegen_attr_8616(codegen, "dce_keep_protected")
            self._keep(stmt, key)
            return
        if _delete_proven_non_temp_statement_8616(
            context,
            stmt_index=stmt_index,
            stmt=stmt,
            stmts=self.stmts,
            lhs=lhs,
            rhs=rhs,
            key=key,
            name_key=name_key,
            live=self.live,
            outside_reads=outside_reads,
            total_reads=self.total_reads,
            dirty_carrier_reads=self.dirty_carrier_reads,
        ):
            self.context.pruned_decl_keys.add(key)
            self.changed = True
            self.block_changed = True
            return
        _bump_codegen_attr_8616(codegen, "dce_keep_unknown")
        self._keep(stmt, key)

    def _temp_fallthrough_keep_reason_8616(
        self, lhs: object, rhs: object, lhs_var: CVariable | None,
        key: _DceKey8616, name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> str:
        """Return the keep-reason label for the final temp fallthrough debug line."""
        context = self.context
        if context.is_observable_lvalue(lhs) or (lhs_var is not None and context.is_observable_lvalue(lhs_var)):
            return "keep_observable"
        if context.rhs_has_side_effects(rhs):
            return "keep_side_effect"
        if key in context.protected or (name_key is not None and name_key in context.protected):
            return "keep_protected"
        if key in self.live or outside_reads > 0:
            return "keep_live_use"
        return "keep_unknown"

    def _temp_keep_ladder_8616(
        self, stmt: object, lhs: object, rhs: object, lhs_var: CVariable | None,
        key: _DceKey8616, name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> bool:
        """Record the keep-reason counter; return whether the value is removable."""
        context = self.context
        codegen = context.codegen
        if context.is_observable_lvalue(lhs) or (
            lhs_var is not None and context.is_observable_lvalue(lhs_var)
        ):
            _bump_codegen_attr_8616(codegen, "dce_keep_observable")
            return False
        if context.rhs_has_side_effects(rhs):
            _bump_codegen_attr_8616(codegen, "dce_keep_side_effect")
            return False
        if key in context.protected or (name_key is not None and name_key in context.protected):
            _bump_codegen_attr_8616(codegen, "dce_keep_protected")
            return False
        if key in self.live or outside_reads > 0:
            _bump_codegen_attr_8616(codegen, "dce_keep_live_use")
            if context.debug_optimization and key[0] in {"dirty", "dirty_expr"}:
                print(
                    "[optimization] dce_keep_live "
                    f"key={key!r} live={key in self.live} outside_reads={outside_reads} stmt={stmt!r}",
                    file=sys.stderr,
                    flush=True,
                )
            return False
        if not context.expr_is_discardable_value(rhs):
            if context.expr_contains_memory_read_shape(rhs):
                _bump_codegen_attr_8616(codegen, "dce_dead_memory_read_refused")
            _bump_codegen_attr_8616(codegen, "dce_keep_unknown")
            return False
        if context.expr_value_purity(rhs) is DceValuePurity8616.GLOBAL_MEMORY_READ:
            _bump_codegen_attr_8616(codegen, "dce_dead_memory_read_candidates")
            _bump_codegen_attr_8616(codegen, "dce_dead_memory_read_deleted")
        return True

    def _temp_fallthrough(
        self, stmt: object, lhs: object, rhs: object, key: _DceKey8616,
        name_key: _DceNameKey8616 | None, outside_reads: int,
    ) -> None:
        """Classify a temp-like assignment through the final keep/remove ladder."""
        context = self.context
        codegen = context.codegen
        _bump_codegen_attr_8616(codegen, "dce_candidates")
        lhs_var_for_observable = context.lhs_variable(lhs)
        removable = self._temp_keep_ladder_8616(
            stmt, lhs, rhs, lhs_var_for_observable, key, name_key, outside_reads
        )
        if context.debug_optimization:
            reason = (
                "delete"
                if removable
                else self._temp_fallthrough_keep_reason_8616(
                    lhs, rhs, lhs_var_for_observable, key, name_key, outside_reads
                )
            )
            print(
                "[optimization] dce_decision "
                f"reason={reason} key={key!r} name_key={name_key!r} "
                f"outside_reads={outside_reads} live={key in self.live} "
                f"instruction_evidence={context.node_has_instruction_evidence(stmt)} stmt={stmt!r}",
                file=sys.stderr,
                flush=True,
            )
        if removable:
            self._prune_decl(key, None)
            _bump_codegen_attr_8616(codegen, "dce_deleted")
            self.changed = True
            self.block_changed = True
            return
        self._keep(stmt, key)


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
    duplicate_changed = context.prune_adjacent_duplicate_assignments(statements)
    stmts = list(_dynamic_dce_getattr_8616(statements, "statements", ()) or ())
    if not stmts:
        context.changed = context.changed or duplicate_changed
        return duplicate_changed
    walk = _DceStatementWalk8616(
        context=context,
        stmts=stmts,
        total_reads=total_reads,
        local_reads=block_reads.get(id(statements), {}),
        block_loop_backedge_reads=loop_backedge_reads.get(id(statements), frozenset()),
        defined_keys=defined_keys,
        observable_reads=observable_reads,
        dirty_carrier_reads=dirty_carrier_reads,
        all_dirty_carrier_reads=all_dirty_carrier_reads,
        block_changed=duplicate_changed,
    )
    return walk.run(statements)
