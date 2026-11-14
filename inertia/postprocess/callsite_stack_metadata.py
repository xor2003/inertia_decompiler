# cython: language_level=3, infer_types=True
"""Layer: Recovery metadata.

Responsibility: prune and report already-materialized callsite stack/segment metadata.
Forbidden: source/COD-backed argument recovery, alias ownership, or emitted-C repair.

Package ownership contract (canonical inertia/postprocess package):
Layer: Rewrite/Postprocess cleanup.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from
rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations
import typing
import cython

import builtins
import enum
import logging
import os
import re
from collections.abc import Callable
from typing import Any, Protocol, cast, runtime_checkable

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall, CTypeCast, CUnaryOp
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.stack_c_ast_matching import _match_real_mode_linear_expr_8616, _segment_reg_name_8616
from inertia.lowering.stack_probe_return_facts import TypedStackProbeReturnFact8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
import operator

__all__ = ["prune_materialized_callsite_segment_metadata_8616"]

logger: logging.Logger = logging.getLogger(__name__)
_PHYSICAL_REGISTER_VERSION_RE_8616 = re.compile(r"^(?:[abcd][xhl]|[sb]p|[sd]i|[cdefgs]s)(?:_\d+)?$")
_DynamicCodegenValue8616 = typing.TypeAliasType("_DynamicCodegenValue8616", Any)


@cython.ccall
def _dynamic_codegen_getattr_8616(
    obj: object,
    name: object,
    default: object = None,
) -> _DynamicCodegenValue8616:
    """Read an attribute across the dynamic angr codegen/C AST boundary."""
    return builtins.getattr(obj, name, default)


@cython.ccall
def _dynamic_codegen_setattr_8616(obj: object, name: object, value: object) -> None:
    """Set an attribute across the dynamic angr codegen/C AST boundary."""
    builtins.setattr(obj, name, value)


@cython.ccall
def _is_plain_statement_block_8616(node: object) -> cython.bint:
    return node.__class__.__name__ == "CStatements"


@cython.ccall
def _call_from_statement_8616(stmt: object) -> CFunctionCall | None:
    if isinstance(stmt, CFunctionCall):
        return stmt
    expr = _dynamic_codegen_getattr_8616(stmt, "expr", None)
    if isinstance(expr, CFunctionCall):
        return expr
    return None


@cython.ccall
def _assignment_lhs_rhs_8616(node: object) -> tuple[object, object]:
    lhs: object
    lhs = _dynamic_codegen_getattr_8616(node, "lhs", None)
    rhs = _dynamic_codegen_getattr_8616(node, "rhs", None)
    if lhs is None and hasattr(node, "dst"):
        lhs = _dynamic_codegen_getattr_8616(node, "dst", None)
        rhs = _dynamic_codegen_getattr_8616(node, "src", None)
    return lhs, rhs


@cython.ccall
def _is_assignment_node_8616(node: object) -> cython.bint:
    class_name = node.__class__.__name__
    return (
        class_name == "CAssignment"
        or class_name.endswith("Assignment")
        or (hasattr(node, "dst") and hasattr(node, "src"))
    )


@cython.ccall
def _assignment_nodes_8616(stmt: object) -> tuple[object, ...]:
    node: object
    candidates: list[object] = []
    if _is_assignment_node_8616(stmt):
        candidates.append(stmt)
    for node in _iter_c_nodes_deep_8616(stmt):
        if _is_assignment_node_8616(node):
            candidates.append(node)
    return tuple(candidates)


@cython.ccall
def _lhs_writes_memory_8616(lhs: object) -> cython.bint:
    raw_node: object
    if lhs is None:
        return False
    nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
    for raw_node in nodes:
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            return True
        if isinstance(_dynamic_codegen_getattr_8616(node, "variable", None), SimMemoryVariable):
            return True
    return False


@cython.ccall
def _segment_register_value_expr_8616(expr: object, project: object) -> cython.bint:
    node = expr
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CBinaryOp) and node.op in {"Shr", "Shl", "And", "Or"}:
        return _segment_register_value_expr_8616(node.lhs, project)
    variable = _dynamic_codegen_getattr_8616(node, "variable", None)
    name = _dynamic_codegen_getattr_8616(variable, "name", None) or _dynamic_codegen_getattr_8616(node, "name", None)
    if isinstance(name, str) and name.lower() in {"cs", "ds", "es", "ss"}:
        return True
    if project is None:
        return False
    return _segment_reg_name_8616(node, cast(Any, project)) in {"cs", "ds", "es", "ss"}


@cython.ccall
def _lhs_has_ss_address_evidence_8616(lhs: object, project: object) -> cython.bint:
    raw_node: object
    nodes = (lhs, *_iter_c_nodes_deep_8616(lhs))
    for raw_node in nodes:
        node = raw_node
        while isinstance(node, CTypeCast):
            node = node.expr
        seg_name, _linear = _match_real_mode_linear_expr_8616(node, cast(Any, project))
        if seg_name == "ss":
            return True
    return False


@cython.ccall
def _segment_metadata_store_8616(stmt: object, project: object, *, allow_carried_high_byte: cython.bint) -> cython.bint:
    assignments = _assignment_nodes_8616(stmt)
    if not assignments:
        return False
    lhs, rhs = _assignment_lhs_rhs_8616(assignments[-1])
    if not _lhs_writes_memory_8616(lhs):
        return False
    if not _segment_register_value_expr_8616(rhs, project):
        return False
    return allow_carried_high_byte or _lhs_has_ss_address_evidence_8616(lhs, project)


@cython.ccall
def _typed_callsite_summary_map_8616(codegen: object) -> dict[cython.longlong, CallsiteSummary8616]:
    """Return typed callsite summaries across the dynamic angr codegen boundary."""
    summary_map = _dynamic_codegen_getattr_8616(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return {}
    return {
        key: value
        for key, value in builtins.iter(summary_map.items())
        if isinstance(key, int) and isinstance(value, CallsiteSummary8616)
    }


CarrierKey8616 = typing.TypeAliasType("CarrierKey8616", tuple[str, str | int])


@runtime_checkable
class _CallsiteMaterializationStatsLike8616(Protocol):
    """Structural view of the owned callsite materialization stats contract."""

    call_target_fact_count: cython.longlong
    call_target_materialized_count: cython.longlong
    call_arg_fact_count: cython.longlong
    call_arg_materialized_count: cython.longlong


class _StatementBlockLike8616(Protocol):
    """Structural view of dynamic angr C statement blocks."""

    statements: object


class StackCarrierPruneDecision8616(enum.Enum):
    """Evidence verdict for whether a stack carrier assignment can be pruned."""

    DEFINITELY_DEAD = "definitely_dead"
    LIVE_CALL_ARG_SETUP = "live_call_arg_setup"
    LIVE_MEMORY_WRITE = "live_memory_write"
    LIVE_STACK_CARRIER = "live_stack_carrier"
    LIVE_WIDENING_CARRIER = "live_widening_carrier"
    LIVE_CONDITION_SOURCE = "live_condition_source"
    UNKNOWN_REFUSE = "unknown_refuse"


class SafeDeadCarrierPruneMode8616(enum.Enum):
    """Runtime mode for safe dead carrier pruning."""

    DISABLED = "disabled"
    DIAGNOSTIC = "diagnostic"
    PRODUCTION = "production"


def _safe_dead_carrier_prune_mode_8616(codegen: object | None) -> SafeDeadCarrierPruneMode8616:
    def _impl() -> SafeDeadCarrierPruneMode8616:
        resolved: object
        resolved = _env_dead_carrier_prune_mode_8616() or _codegen_dead_carrier_prune_mode_8616(codegen)
        # Conservative default keeps proof and avoids semantic regression.
        return resolved if resolved is not None else SafeDeadCarrierPruneMode8616.DIAGNOSTIC

    return _impl()


@cython.ccall
def _env_dead_carrier_prune_mode_8616() -> SafeDeadCarrierPruneMode8616 | None:
    mode = os.environ.get("INERTIA_SAFE_DEAD_CARRIER_PRUNE_MODE", "").strip().lower()
    if mode in {"disabled", "off", "0", "false", "no"}:
        return SafeDeadCarrierPruneMode8616.DISABLED
    if mode in {"diagnostic", "diag"}:
        return SafeDeadCarrierPruneMode8616.DIAGNOSTIC
    if mode in {"production", "prod", "on", "1", "true", "yes"}:
        return SafeDeadCarrierPruneMode8616.PRODUCTION
    flag = os.environ.get("INERTIA_ENABLE_SAFE_DEAD_CARRIER_PRUNE", "").strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return SafeDeadCarrierPruneMode8616.PRODUCTION
    if flag in {"0", "false", "off", "no"}:
        return SafeDeadCarrierPruneMode8616.DISABLED
    legacy_disable = os.environ.get("INERTIA_DISABLE_SAFE_DEAD_CARRIER_PRUNE", "").strip().lower()
    if legacy_disable in {"1", "true", "yes", "on"}:
        return SafeDeadCarrierPruneMode8616.DISABLED
    if legacy_disable in {"0", "false", "off", "no"}:
        return SafeDeadCarrierPruneMode8616.DIAGNOSTIC
    return None


@cython.ccall
def _codegen_dead_carrier_prune_mode_8616(codegen: object) -> SafeDeadCarrierPruneMode8616 | None:
    if codegen is None:
        return None
    explicit_mode = _dynamic_codegen_getattr_8616(codegen, "_inertia_safe_dead_carrier_prune_mode", None)
    if isinstance(explicit_mode, SafeDeadCarrierPruneMode8616):
        return explicit_mode
    if isinstance(explicit_mode, str):
        explicit = explicit_mode.strip().lower()
        if explicit in {"disabled", "off", "0", "false", "no"}:
            return SafeDeadCarrierPruneMode8616.DISABLED
        if explicit in {"diagnostic", "diag"}:
            return SafeDeadCarrierPruneMode8616.DIAGNOSTIC
        if explicit in {"production", "prod", "on", "1", "true", "yes"}:
            return SafeDeadCarrierPruneMode8616.PRODUCTION
    attr = _dynamic_codegen_getattr_8616(codegen, "_inertia_enable_safe_dead_carrier_prune", None)
    if isinstance(attr, bool):
        return SafeDeadCarrierPruneMode8616.PRODUCTION if attr else SafeDeadCarrierPruneMode8616.DISABLED
    return None


@cython.ccall
def _safe_dead_carrier_prune_enabled_8616(codegen: object | None) -> cython.bint:
    # Emergency kill switch.
    mode = _safe_dead_carrier_prune_mode_8616(codegen)
    return operator.eq(mode, SafeDeadCarrierPruneMode8616.PRODUCTION)


@cython.ccall
def _callsite_materialization_complete_8616(codegen: object) -> cython.bint:
    if codegen is None:
        return False
    stats = _dynamic_codegen_getattr_8616(codegen, "_inertia_callsite_materialization_stats", None)
    if not isinstance(stats, _CallsiteMaterializationStatsLike8616):
        return False
    target_fact = int(stats.call_target_fact_count or 0)
    target_mat = int(stats.call_target_materialized_count or 0)
    arg_fact = int(stats.call_arg_fact_count or 0)
    arg_mat = int(stats.call_arg_materialized_count or 0)
    return target_mat >= target_fact and arg_mat >= arg_fact


@cython.ccall
def _bump_dead_setup_counter_8616(codegen: object, name: object, inc: cython.longlong = 1) -> None:
    if codegen is None:
        return
    _dynamic_codegen_setattr_8616(codegen, name, int(_dynamic_codegen_getattr_8616(codegen, name, 0)) + int(inc))


@cython.ccall
def _generic_stack_carrier_name_8616(node: object) -> object:
    name: object
    while isinstance(node, CTypeCast):
        node = node.expr
    variable = _dynamic_codegen_getattr_8616(node, "variable", None)
    for name in (_dynamic_codegen_getattr_8616(node, "name", None), _dynamic_codegen_getattr_8616(variable, "name", None)):
        if isinstance(name, str) and name.startswith(("vvar_", "ir_", "tmp_")):
            return name
    return None


@cython.ccall
def _stack_carrier_key_8616(node: object) -> CarrierKey8616 | None:
    """Return a stable AST-local key for a stack-address carrier variable."""
    name: object
    name = _generic_stack_carrier_name_8616(node)
    if name is not None:
        return ("name", name)
    while isinstance(node, CTypeCast):
        node = node.expr
    variable = _dynamic_codegen_getattr_8616(node, "variable", None)
    if isinstance(variable, SimRegisterVariable):
        stable_name = _dynamic_codegen_getattr_8616(variable, "name", None) or _dynamic_codegen_getattr_8616(node, "name", None)
        if isinstance(stable_name, str) and _PHYSICAL_REGISTER_VERSION_RE_8616.fullmatch(stable_name.lower()):
            return None
        return ("var", id(variable))
    return None


@cython.ccall
def _generic_stack_carrier_keys_8616(node: object) -> object:
    key: object
    raw_node: object
    names: set[CarrierKey8616] = set()
    for raw_node in (node, ) + tuple(_iter_c_nodes_deep_8616(node)):
        key = _stack_carrier_key_8616(raw_node)
        if key is not None:
            names.add(key)
    return names


def _stmt_has_call_8616(stmt: object) -> cython.bint:
    if stmt is None:
        return False
    if _call_from_statement_8616(stmt) is not None:
        return True
    return any(isinstance(node, CFunctionCall) for node in builtins.iter(_iter_c_nodes_deep_8616(stmt)))


@cython.ccall
def _stmt_has_memory_write_8616(stmt: object) -> cython.bint:
    assign: object
    for assign in _assignment_nodes_8616(stmt):
        lhs, _rhs = _assignment_lhs_rhs_8616(assign)
        if _lhs_writes_memory_8616(lhs):
            return True
    return False


@cython.ccall
def _stmt_uses_carrier_key_8616(stmt: object, key: CarrierKey8616) -> cython.bint:
    return key in _generic_stack_carrier_keys_8616(stmt)


@cython.ccall
def _carrier_key_protected_8616(lhs_key: CarrierKey8616, codegen: object) -> cython.bint:
    value: object
    attr: object
    if codegen is None:
        return False
    for attr in (
        "_inertia_callsite_arg_sources",
        "_inertia_stack_variable_bindings",
        "_inertia_stack_canonicalization_bridges",
        "_inertia_tail_validation_widened_carriers",
        "_inertia_linear_recurrence_state",
    ):
        value = _dynamic_codegen_getattr_8616(codegen, attr, None)
        if value is None:
            continue
        text = repr(value)
        if lhs_key[0] == "name" and isinstance(lhs_key[1], str) and lhs_key[1] in text:
            return True
    return False


def _classify_dead_carrier_candidate_8616(
    stmt: object,
    lhs_key: CarrierKey8616,
    rhs: object,
    *,
    live: object,
    known_carriers: object,
    call_indices: object,
    stmt_index: cython.longlong,
    statements: object,
    codegen: object | None,
) -> StackCarrierPruneDecision8616:
    def _impl() -> StackCarrierPruneDecision8616:
        near: object
        if _stmt_has_memory_write_8616(stmt):
            return StackCarrierPruneDecision8616.LIVE_MEMORY_WRITE
        if lhs_key in live:
            return StackCarrierPruneDecision8616.LIVE_STACK_CARRIER
        if _carrier_key_protected_8616(lhs_key, codegen):
            return StackCarrierPruneDecision8616.LIVE_WIDENING_CARRIER
        if _stmt_has_call_8616(stmt):
            return StackCarrierPruneDecision8616.LIVE_CALL_ARG_SETUP
        # Keep setup around call boundaries only when the call actually references
        # this carrier key.
        for near in (stmt_index - 1, stmt_index + 1):
            if (
                near in call_indices
                and 0 <= near < len(statements)
                and _stmt_uses_carrier_key_8616(statements[near], lhs_key)
            ):
                return StackCarrierPruneDecision8616.LIVE_CALL_ARG_SETUP
        if _generic_stack_carrier_keys_8616(rhs).intersection(known_carriers):
            # If RHS references other carrier keys, preserve unless we can prove the
            # entire chain is dead; conservative by default.
            referenced_carriers = _generic_stack_carrier_keys_8616(rhs).intersection(known_carriers)
            if referenced_carriers.intersection(live):
                return StackCarrierPruneDecision8616.LIVE_STACK_CARRIER
            return StackCarrierPruneDecision8616.DEFINITELY_DEAD
        return StackCarrierPruneDecision8616.DEFINITELY_DEAD

    return _impl()


def _expr_is_pure_stack_address_carrier_8616(
    expr: object,
    known_carriers: object = None,
) -> cython.bint:
    def _impl() -> cython.bint:
        """Return true for side-effect-free stack-address shuttle expressions."""
        key: object
        node = expr
        while isinstance(node, CTypeCast):
            node = node.expr
        if isinstance(node, CFunctionCall):
            return False
        if isinstance(node, CUnaryOp):
            if node.op == "Dereference":
                return False
            if node.op == "Reference":
                return True
            return _expr_is_pure_stack_address_carrier_8616(_dynamic_codegen_getattr_8616(node, "operand", None), known_carriers)
        if isinstance(node, CBinaryOp):
            if node.op not in {"Add", "Sub", "Mul", "Shl", "Shr", "And", "Or", "Xor"}:
                return False
            return _expr_is_pure_stack_address_carrier_8616(
                node.lhs, known_carriers
            ) or _expr_is_pure_stack_address_carrier_8616(node.rhs, known_carriers)
        key = _stack_carrier_key_8616(node)
        return key is not None and (
            _generic_stack_carrier_name_8616(node) is not None or key in (known_carriers or set())
        )

    return _impl()


@cython.ccall
def _dead_stack_carrier_assignment_8616(
    stmt: object,
    known_carriers: object,
) -> object:
    lhs_key: object
    if not _is_assignment_node_8616(stmt):
        return None
    lhs, rhs = _assignment_lhs_rhs_8616(stmt)
    if _lhs_writes_memory_8616(lhs):
        return None
    lhs_key = _stack_carrier_key_8616(lhs)
    if lhs_key is None or lhs_key not in known_carriers:
        return None
    if not _expr_is_pure_stack_address_carrier_8616(rhs, known_carriers):
        return None
    return lhs_key, rhs


@cython.ccall
def _collect_stack_carrier_assignments_8616(block: object) -> object:
    """Collect variables proven to carry stack addresses within this block."""
    lhs_key: object
    stmt: object
    known: set[CarrierKey8616] = set()
    if not _is_plain_statement_block_8616(block):
        return known
    statements = _dynamic_codegen_getattr_8616(block, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return known
    for stmt in statements:
        if not _is_assignment_node_8616(stmt):
            continue
        lhs, rhs = _assignment_lhs_rhs_8616(stmt)
        if _lhs_writes_memory_8616(lhs):
            continue
        lhs_key = _stack_carrier_key_8616(lhs)
        if lhs_key is not None and _expr_is_pure_stack_address_carrier_8616(rhs, known):
            known.add(lhs_key)
    return known


def _prune_dead_stack_carrier_assignments_8616(block: object, codegen: object | None = None) -> cython.bint:
    def _impl() -> cython.bint:
        """Remove dead generic address carriers left after call arguments are materialized."""
        carrier: object
        stmt: object
        stmt_index: object
        if not _dead_carrier_prune_gate_8616(codegen):
            return False
        changed = False
        if not _is_plain_statement_block_8616(block):
            return False
        statements = _dynamic_codegen_getattr_8616(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return False

        changed |= _prune_dead_carriers_in_child_blocks_8616(statements, codegen)

        # Dynamic angr codegen boundary: CStatements exposes statements structurally.
        statement_list: list[object] = list(_dynamic_codegen_getattr_8616(block, "statements", ()) or ())
        known_carriers = _collect_stack_carrier_assignments_8616(block)
        call_indices = {idx for idx, stmt in builtins.iter(enumerate(statement_list)) if _stmt_has_call_8616(stmt)}
        live: set[CarrierKey8616] = set()
        kept_reversed: list[object] = []
        removed = 0
        reversed_pairs = list(enumerate(statement_list))
        reversed_pairs.reverse()
        for stmt_index, stmt in reversed_pairs:
            carrier = _dead_stack_carrier_assignment_8616(stmt, known_carriers)
            if carrier is not None:
                if _prune_dead_carrier_candidate_8616(
                    stmt,
                    stmt_index,
                    carrier,
                    live,
                    kept_reversed,
                    known_carriers,
                    call_indices,
                    statement_list,
                    codegen,
                ):
                    changed = True
                    removed += 1
                continue
            live.update(_generic_stack_carrier_keys_8616(stmt).intersection(known_carriers))
            kept_reversed.append(stmt)

        if changed:
            logger.debug(
                "Pruned %d dead stack-address carrier assignment(s) from callsite metadata block with %d carrier key(s)",
                removed,
                len(known_carriers),
            )
            kept_reversed.reverse()
            cast(_StatementBlockLike8616, block).statements = (
                kept_reversed if isinstance(statements, list) else tuple(kept_reversed)
            )
        return changed

    return _impl()


@cython.ccall
def _dead_carrier_prune_gate_8616(codegen: object | None) -> cython.bint:
    """Gate dead-carrier pruning on mode and callsite materialization completeness."""
    prune_mode = _safe_dead_carrier_prune_mode_8616(codegen)
    if prune_mode in {SafeDeadCarrierPruneMode8616.DISABLED, SafeDeadCarrierPruneMode8616.DIAGNOSTIC}:
        _bump_dead_setup_counter_8616(codegen, "dead_setup_refused")
        _bump_dead_setup_counter_8616(codegen, "dead_setup_unknown_refuse")
        return False
    if not _callsite_materialization_complete_8616(codegen):
        # Evidence gate: do not prune carrier setup until callsite argument facts
        # are fully materialized.
        _bump_dead_setup_counter_8616(codegen, "dead_setup_refused")
        _bump_dead_setup_counter_8616(codegen, "dead_setup_live_call_arg")
        return False
    return True


_DEAD_CARRIER_DECISION_COUNTERS_8616: dict[StackCarrierPruneDecision8616, str] = {
    StackCarrierPruneDecision8616.LIVE_CALL_ARG_SETUP: "dead_setup_live_call_arg",
    StackCarrierPruneDecision8616.LIVE_STACK_CARRIER: "dead_setup_live_stack_carrier",
    StackCarrierPruneDecision8616.LIVE_WIDENING_CARRIER: "dead_setup_live_widening_carrier",
    StackCarrierPruneDecision8616.LIVE_CONDITION_SOURCE: "dead_setup_live_condition_source",
}


@cython.ccall
def _prune_dead_carriers_in_child_blocks_8616(
    statements: object, codegen: object | None
) -> cython.bint:
    child: object
    pair: object
    stmt: object
    changed = False
    for stmt in list(statements):
        for child in (
            _dynamic_codegen_getattr_8616(stmt, "body", None),
            _dynamic_codegen_getattr_8616(stmt, "else_node", None),
        ):
            if _is_plain_statement_block_8616(child):
                changed |= _prune_dead_stack_carrier_assignments_8616(child, codegen=codegen)
        if _is_plain_statement_block_8616(stmt):
            changed |= _prune_dead_stack_carrier_assignments_8616(stmt, codegen=codegen)
        for pair in _dynamic_codegen_getattr_8616(stmt, "condition_and_nodes", ()) or ():
            if isinstance(pair, tuple) and len(pair) == 2 and _is_plain_statement_block_8616(pair[1]):
                changed |= _prune_dead_stack_carrier_assignments_8616(pair[1], codegen=codegen)
    return changed


@cython.ccall
def _prune_dead_carrier_candidate_8616(
    stmt: object,
    stmt_index: cython.longlong,
    carrier: object,
    live: object,
    kept_reversed: object,
    known_carriers: object,
    call_indices: object,
    statement_list: object,
    codegen: object | None,
) -> cython.bint:
    """Classify one dead-carrier candidate; return True when the statement is pruned."""
    counter: object
    lhs_key, rhs = carrier
    _bump_dead_setup_counter_8616(codegen, "dead_setup_candidates")
    _bump_dead_setup_counter_8616(codegen, "dead_setup_raw_fact_count")
    _bump_dead_setup_counter_8616(codegen, "dead_setup_normalized_fact_count")
    _bump_dead_setup_counter_8616(codegen, "dead_setup_classified_fact_count")
    decision = _classify_dead_carrier_candidate_8616(
        stmt,
        lhs_key,
        rhs,
        live=live,
        known_carriers=known_carriers,
        call_indices=call_indices,
        stmt_index=stmt_index,
        statements=statement_list,
        codegen=codegen,
    )
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        logger.warning(
            "[stack-carrier-prune] index=%d lhs=%r rhs=%s tags=%r decision=%s",
            stmt_index,
            lhs_key,
            type(rhs).__name__,
            _dynamic_codegen_getattr_8616(stmt, "tags", None),
            decision.name,
        )
    if operator.eq(decision, StackCarrierPruneDecision8616.DEFINITELY_DEAD):
        _bump_dead_setup_counter_8616(codegen, "dead_setup_pruned")
        _bump_dead_setup_counter_8616(codegen, "dead_setup_materialized_count")
        return True
    counter = _DEAD_CARRIER_DECISION_COUNTERS_8616.get(decision, "dead_setup_unknown_refuse")
    _bump_dead_setup_counter_8616(codegen, counter)
    _bump_dead_setup_counter_8616(codegen, "dead_setup_refused")
    live.discard(lhs_key)
    live.update(_generic_stack_carrier_keys_8616(rhs).intersection(known_carriers))
    kept_reversed.append(stmt)
    return False


@cython.ccall
def _prune_trailing_segment_metadata_8616(statements: object, project: object) -> cython.bint:
    changed = False
    removed_store = False
    while statements:
        if _segment_metadata_store_8616(statements[-1], project, allow_carried_high_byte=removed_store):
            statements.pop()
            removed_store = True
            changed = True
            continue
        if (
            not removed_store
            and len(statements) >= 2
            and _segment_metadata_store_8616(statements[-1], project, allow_carried_high_byte=True)
            and _segment_metadata_store_8616(statements[-2], project, allow_carried_high_byte=False)
        ):
            statements.pop()
            removed_store = True
            changed = True
            continue
        break
    return changed


def prune_materialized_callsite_segment_metadata_8616(project: object, codegen: object) -> cython.bint:
    """Drop stack-probe segment metadata stores after their call args are materialized."""
    cfunc = _dynamic_codegen_getattr_8616(codegen, "cfunc", None)
    root = _dynamic_codegen_getattr_8616(cfunc, "statements", None) or _dynamic_codegen_getattr_8616(cfunc, "body", None)
    if not _is_plain_statement_block_8616(root):
        return False

    summary_map = _typed_callsite_summary_map_8616(codegen)
    typed_fact_map = _normalized_typed_probe_facts_8616(codegen)
    materialized_metadata_ids = _normalized_materialized_metadata_ids_8616(codegen)
    use_typed_facts = bool(typed_fact_map)

    changed = False

    def rewrite_block(block: object, inherited_stack_probe_address_seen: cython.bint = False) -> cython.bint:
        call: object
        stmt: object
        nonlocal changed
        if not _is_plain_statement_block_8616(block):
            return inherited_stack_probe_address_seen
        statements = _dynamic_codegen_getattr_8616(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            return inherited_stack_probe_address_seen

        stack_probe_address_seen = _stack_probe_address_seen_8616(
            inherited_stack_probe_address_seen, use_typed_facts, typed_fact_map, summary_map
        )
        new_statements: list[object] = []
        for stmt in list(statements):
            call = _call_from_statement_8616(stmt)
            summary = summary_map.get(id(call)) if call is not None else None
            stack_probe_address_seen = _refresh_probe_seen_for_call_8616(
                call, summary, use_typed_facts, typed_fact_map, stack_probe_address_seen
            )
            # Allow pruning for any call that has recorded segment-metadata store IDs.
            # Far calls (opcode 0x9A / CALL FAR) push CS as part of their call frame;
            # those stores are segment metadata and should be pruned even without a
            # preceding stack-probe helper call.
            if _prune_recorded_metadata_statements_8616(
                call, summary, stack_probe_address_seen, materialized_metadata_ids, project, new_statements
            ):
                changed = True
            # Ownership boundary:
            # This pass may prune call-frame metadata stores and their dead generic
            # carrier feeders after call arguments / metadata have already been
            # materialized. It must not recover new stack-slot semantics here.
            # If a vvar_/ir_/tmp_ carrier chain still needs to become a stack local,
            # that belongs in stack lowering / AST stack-alias rewrites, not in this
            # cleanup pass.
            if _prune_call_frame_metadata_stores_8616(
                call, materialized_metadata_ids, project, new_statements
            ):
                changed = True
            new_statements.append(stmt)

        if operator.ne(new_statements, list(statements)):
            cast(_StatementBlockLike8616, block).statements = (
                new_statements if isinstance(statements, list) else tuple(new_statements)
            )

        _rewrite_nested_blocks_8616(block, stack_probe_address_seen, rewrite_block)
        return stack_probe_address_seen

    rewrite_block(root)
    if _prune_dead_stack_carrier_assignments_8616(root, codegen=codegen):
        changed = True
    return changed 


def _stack_probe_address_seen_8616(
    inherited_stack_probe_address_seen: cython.bint,
    use_typed_facts: cython.bint,
    typed_fact_map: object,
    summary_map: object,
) -> cython.bint:
    if inherited_stack_probe_address_seen:
        return True
    if use_typed_facts:
        return bool(typed_fact_map)
    return any(
        item.stack_probe_helper
        and item.helper_return_state == "stack_address"
        and item.helper_return_space in {None, "ss"}
        for item in builtins.iter(summary_map.values())
    )


@cython.ccall
def _refresh_probe_seen_for_call_8616(
    call: object,
    summary: object,
    use_typed_facts: cython.bint,
    typed_fact_map: object,
    stack_probe_address_seen: cython.bint,
) -> cython.bint:
    if call is None or summary is None or not summary.stack_probe_helper:
        return stack_probe_address_seen
    if use_typed_facts:
        return id(call) in typed_fact_map
    if summary.helper_return_state == "stack_address":
        return summary.helper_return_space in {None, "ss"}
    return stack_probe_address_seen


def _prune_recorded_metadata_statements_8616(
    call: object,
    summary: object,
    stack_probe_address_seen: cython.bint,
    materialized_metadata_ids: object,
    project: object,
    new_statements: object,
) -> cython.bint:
    has_materialized_metadata = call is not None and bool(materialized_metadata_ids.get(id(call), ()))
    if not (
        call is not None
        and (stack_probe_address_seen or has_materialized_metadata)
        and (summary is None or not summary.stack_probe_helper)
    ):
        return False
    # Dynamic angr codegen boundary: CFunctionCall exposes args structurally.
    args: tuple[object, ...] = tuple(_dynamic_codegen_getattr_8616(call, "args", ()) or ())
    if not (args and all(not _segment_register_value_expr_8616(arg, project) for arg in iter(args))):
        return False
    prunable_ids = set(materialized_metadata_ids.get(id(call), ()))
    if not prunable_ids:
        return False
    kept_statements = [old_stmt for old_stmt in iter(new_statements) if id(old_stmt) not in prunable_ids]
    if operator.eq(len(kept_statements), len(new_statements)):
        return False
    new_statements[:] = kept_statements
    return True


def _prune_call_frame_metadata_stores_8616(
    call: object,
    materialized_metadata_ids: object,
    project: object,
    new_statements: object,
) -> cython.bint:
    # Far calls push CS + IP as a far return frame BEFORE the call.
    # The stores look like: *(vvar_N + 1) = cs >> 8;
    # Detect any preceding memory store whose rhs is a segment register
    # value, then prune it and its carrier-temp feeders.
    # Only prune stores recorded in materialized_metadata_ids for this call.
    # Dynamic angr codegen boundary: CFunctionCall exposes args structurally.
    _call_args: object = tuple(_dynamic_codegen_getattr_8616(call, "args", ()) or ()) if call is not None else ()
    if not (
        call is not None
        and _call_args
        and all(not _segment_register_value_expr_8616(arg, project) for arg in iter(_call_args))
    ):
        return False
    call_metadata_ids = set(materialized_metadata_ids.get(id(call), ())) if call is not None else set()
    if not call_metadata_ids:
        return False
    removed = _count_prunable_metadata_stores_8616(new_statements, call_metadata_ids, project)
    if removed <= 0:
        return False
    del new_statements[len(new_statements) - removed:]
    return True


@cython.ccall
def _normalized_typed_probe_facts_8616(codegen: object) -> dict[cython.longlong, object]:
    typed_fact_map = _dynamic_codegen_getattr_8616(codegen, "_inertia_typed_stack_probe_return_facts", None)
    if not isinstance(typed_fact_map, dict):
        return {}
    return {
        key: value
        for key, value in builtins.iter(typed_fact_map.items())
        if isinstance(key, int) and isinstance(value, TypedStackProbeReturnFact8616)
    }


def _normalized_materialized_metadata_ids_8616(codegen: object) -> object:
    key: object
    value: object
    # Dynamic angr codegen boundary: metadata IDs are attached by earlier materialization.
    raw_materialized_metadata_ids = _dynamic_codegen_getattr_8616(codegen, "_inertia_materialized_callsite_metadata_ids", None)
    materialized_metadata_ids: dict[cython.longlong, tuple[cython.longlong, ...]] = {}
    if isinstance(raw_materialized_metadata_ids, dict):
        for key, value in raw_materialized_metadata_ids.items():
            if isinstance(key, int) and isinstance(value, (list, tuple, set, frozenset)):
                materialized_metadata_ids[key] = tuple(item for item in iter(value) if isinstance(item, int))
    return materialized_metadata_ids


@cython.ccall
def _count_prunable_metadata_stores_8616(
    new_statements: object, call_metadata_ids: object, project: object
) -> cython.longlong:
    lhs: object
    removed = 0
    scan = len(new_statements) - 1
    while scan >= 0:
        candidate = new_statements[scan]
        if id(candidate) in call_metadata_ids:
            removed += 1
            scan -= 1
            continue
        assignments = _assignment_nodes_8616(candidate)
        if not assignments:
            break
        lhs, rhs = _assignment_lhs_rhs_8616(assignments[-1])
        if not _lhs_writes_memory_8616(lhs) or not _segment_register_value_expr_8616(rhs, project):
            break
        removed += 1
        scan -= 1
    # Also prune carrier-temp assignments (vvar_*) that feed the stores
    while scan >= 0:
        candidate = new_statements[scan]
        lhs, _rhs = _assignment_lhs_rhs_8616(candidate)
        if _lhs_writes_memory_8616(lhs):
            break
        if _generic_stack_carrier_name_8616(lhs if lhs is not None else candidate) is None:
            break
        removed += 1
        scan -= 1
    return removed


@cython.ccall
def _rewrite_nested_blocks_8616(
    block: object,
    stack_probe_address_seen: cython.bint,
    rewrite_block: Callable[[object, bool], cython.bint],
) -> None:
    child: object
    pair: object
    stmt: object
    for stmt in _dynamic_codegen_getattr_8616(block, "statements", ()) or ():
        for child in (
            _dynamic_codegen_getattr_8616(stmt, "body", None),
            _dynamic_codegen_getattr_8616(stmt, "else_node", None),
        ):
            if _is_plain_statement_block_8616(child):
                rewrite_block(child, stack_probe_address_seen)
        if _is_plain_statement_block_8616(stmt):
            rewrite_block(stmt, stack_probe_address_seen)
        for pair in _dynamic_codegen_getattr_8616(stmt, "condition_and_nodes", ()) or ():
            if isinstance(pair, tuple) and len(pair) == 2 and _is_plain_statement_block_8616(pair[1]):
                rewrite_block(pair[1], stack_probe_address_seen)
