"""Layer: Recovery metadata.

Responsibility: record optional condition traces for diagnostics of recovered conditions.
Forbidden: condition recovery, postprocess repair, or validation acceptance from traces.
"""

from __future__ import annotations

import logging
import os
import typing
from collections.abc import Iterable
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import CForLoop, CIfBreak, CIfElse

from .c_ast_utils import _iter_c_nodes_deep_8616
from .ir.condition_ir import ConditionIR
from .structuring.condition_rendering import render_condition_ir_8616, render_condition_ir_native_8616
from .tail_validation_fingerprint import _expr_fingerprint

log: logging.Logger = logging.getLogger(__name__)


def _current_original_func_addr_8616(project: object, codegen: object) -> int | None:
    """Resolve the current function address through the dynamic third-party angr metadata boundary."""
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if not isinstance(func_addr, int):
        return None
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        return func_addr + delta
    return func_addr


def _condition_trace_enabled_8616(project: object, codegen: object) -> bool:
    """Return whether optional condition tracing is enabled for this dynamic codegen boundary."""
    if not os.environ.get("INERTIA_DEBUG_CONDITION_TRACE"):
        return False
    target_text = os.environ.get("INERTIA_DEBUG_CONDITION_TRACE_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    current_addr = _current_original_func_addr_8616(project, codegen)
    return not isinstance(target_addr, int) or current_addr == target_addr


def _condition_trace_store_8616(codegen: object) -> dict[tuple[int, int], dict[str, object]]:
    """Return the mutable condition trace store attached at the dynamic codegen boundary."""
    store = getattr(codegen, "_inertia_condition_trace", None)
    if not isinstance(store, dict):
        store = {}
        # Dynamic codegen boundary: condition traces are optional diagnostic metadata on angr codegen.
        typing.cast(typing.Any, codegen)._inertia_condition_trace = store
    return store


def _condition_trace_key_8616(ins_addr: int, block_addr: int) -> tuple[int, int]:
    return (int(ins_addr), int(block_addr))


def _condition_id_for_key_8616(codegen: object, key: tuple[int, int]) -> int:
    """Return a stable diagnostic condition id for a trace key."""
    store = _condition_trace_store_8616(codegen)
    if key not in store:
        store[key] = {
            "condition_id": len(store) + 1,
            "origin_insn": key[0],
            "origin_block": key[1],
        }
    condition_id = store[key].get("condition_id")
    return int(condition_id) if isinstance(condition_id, int) else 0


def _render_c_expr_8616(expr: object) -> str | None:
    """Render a C expression for diagnostics without changing recovered semantics."""
    if expr is None:
        return None
    try:
        return cast(str, cast(Any, expr).c_repr(indent=0))
    except Exception:
        return str(expr)


def _node_condition_key_8616(node: object) -> tuple[int, int] | None:
    """Read condition origin tags from the dynamic third-party angr C-AST boundary."""
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return None
    ins_addr = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    if not isinstance(ins_addr, int) or not isinstance(block_addr, int):
        return None
    return _condition_trace_key_8616(ins_addr, block_addr)


def _condition_rows_for_node_8616(
    node: object,
) -> list[tuple[tuple[int, int], object, str]]:
    """Return the tagged condition rows contributed by one C-AST node."""
    rows: list[tuple[tuple[int, int], object, str]] = []
    if isinstance(node, CIfElse):
        condition_pairs = cast(
            tuple[tuple[object, object], ...],
            # Dynamic angr boundary: CIfElse condition pairs are stored in a variant-specific C-AST field.
            tuple(getattr(node, "condition_and_nodes", ()) or ()),
        )
        for cond, _body in condition_pairs:
            key = _node_condition_key_8616(cond)
            if key is not None:
                rows.append((key, cond, "if"))
    elif isinstance(node, (CIfBreak, CForLoop)):
        cond = node.condition
        key = _node_condition_key_8616(cond)
        if key is not None:
            tag = "ifbreak" if isinstance(node, CIfBreak) else "for"
            rows.append((key, cond, tag))
    elif hasattr(node, "condition"):
        cond = getattr(node, "condition", None)
        key = _node_condition_key_8616(cond)
        if key is not None:
            rows.append((key, cond, type(node).__name__))
    return rows


def _iter_condition_nodes_8616(codegen: object) -> Iterable[tuple[tuple[int, int], object, str]]:
    """Iterate condition-bearing nodes through the dynamic third-party angr C-AST boundary."""
    cfunc = getattr(codegen, "cfunc", None)
    root = None
    for attr in ("body", "statements", "stmt"):
        value = getattr(cfunc, attr, None)
        if value is not None:
            root = value
            break
    if root is None:
        root = cfunc
    if root is None:
        return ()
    rows: list[tuple[tuple[int, int], object, str]] = []
    for node in _iter_c_nodes_deep_8616(root):
        rows.extend(_condition_rows_for_node_8616(node))
    return tuple(rows)


def record_classified_conditions_trace_8616(project: object, codegen: object, conditions: list[ConditionIR]) -> None:
    """Record classified condition IR in the optional diagnostic trace store."""
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRACE"):
        log.warning(
            "[condition-trace] classified-scan func=%#x conditions=%d",
            _current_original_func_addr_8616(project, codegen) or -1,
            len(conditions),
        )
    for cond in conditions:
        if not isinstance(cond.src_insn, int) or not isinstance(cond.block_addr, int):
            continue
        key = _condition_trace_key_8616(cond.src_insn, cond.block_addr)
        _condition_id_for_key_8616(codegen, key)
        entry = store[key]
        entry["classified"] = render_condition_ir_native_8616(cond) or render_condition_ir_8616(cond)
        entry["condition_op"] = cond.op


def record_materialized_condition_trace_8616(project: object, codegen: object, key: tuple[int, int], expr: object) -> None:
    """Record the C-AST expression materialized for a classified condition."""
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    _condition_id_for_key_8616(codegen, key)
    entry = store[key]
    entry["materialized"] = _render_c_expr_8616(expr)
    entry["materialized_hash"] = _expr_fingerprint(expr, project)


def record_ast_condition_trace_8616(project: object, codegen: object, *, stage: str) -> None:
    """Record condition expressions currently present in the structured C-AST."""
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    for key, cond, owner in _iter_condition_nodes_8616(codegen):
        _condition_id_for_key_8616(codegen, key)
        entry = store[key]
        entry[stage] = _render_c_expr_8616(cond)
        entry[f"{stage}_hash"] = _expr_fingerprint(cond, project)
        entry[f"{stage}_owner"] = owner


def record_tail_validation_condition_trace_8616(
    project: object, codegen: object, validation: dict[str, object] | None
) -> None:
    """Record the tail-validation verdict seen by the optional condition trace."""
    if not _condition_trace_enabled_8616(project, codegen):
        return
    if not isinstance(validation, dict):
        return
    store = _condition_trace_store_8616(codegen)
    summary = validation.get("summary_text") or validation.get("verdict") or validation.get("status")
    for entry in store.values():
        entry["validator_seen"] = summary


def materialized_condition_drift_detected_8616(project: object, codegen: object) -> bool:
    """Report whether materialized condition expressions drifted before emitted C."""
    if not _condition_trace_enabled_8616(project, codegen):
        return False
    store = _condition_trace_store_8616(codegen)
    drifted: list[dict[str, object]] = []
    for entry in store.values():
        materialized = entry.get("materialized_hash")
        emitted = entry.get("emitted_c_hash")
        if isinstance(materialized, str) and isinstance(emitted, str) and materialized != emitted:
            drifted.append(
                {
                    "condition_id": entry.get("condition_id"),
                    "origin_insn": entry.get("origin_insn"),
                    "origin_block": entry.get("origin_block"),
                    "materialized": entry.get("materialized"),
                    "emitted_c": entry.get("emitted_c"),
                }
            )
    # Dynamic codegen boundary: drift diagnostics are optional metadata on angr codegen.
    typing.cast(typing.Any, codegen)._inertia_materialized_condition_drift = bool(drifted)
    # Dynamic codegen boundary: drift detail rows are optional diagnostic metadata on angr codegen.
    typing.cast(typing.Any, codegen)._inertia_materialized_condition_drift_details = tuple(drifted)
    return bool(drifted)


def dump_condition_trace_8616(project: object, codegen: object, *, label: str) -> None:
    """Emit the optional condition trace to logs for diagnostics."""
    if not _condition_trace_enabled_8616(project, codegen):
        return
    store = _condition_trace_store_8616(codegen)
    if not store:
        log.warning(
            "[condition-trace] %s func=%#x store=empty",
            label,
            _current_original_func_addr_8616(project, codegen) or -1,
        )
        return
    for key in sorted(store):
        entry = store[key]
        log.warning(
            "[condition-trace] %s condition_id=%s origin_block=%#x origin_insn=%#x "
            "classified=%r materialized=%r structured=%r emitted_c=%r validator_seen=%r",
            label,
            entry.get("condition_id"),
            entry.get("origin_block"),
            entry.get("origin_insn"),
            entry.get("classified"),
            entry.get("materialized"),
            entry.get("structured"),
            entry.get("emitted_c"),
            entry.get("validator_seen"),
        )
