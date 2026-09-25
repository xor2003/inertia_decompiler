"""Provide bounded execution helpers and runtime diagnostics for CLI runs.

Layer: CLI/fallback/reporting.
Responsibility: install bounded third-party angr/codegen compatibility guards without owning decompiler semantics.

Dynamic attribute boundary: all getattr/setattr use here is limited to third-party
angr/codegen compatibility hooks and diagnostic state attached to angr project objects.
"""

from __future__ import annotations

import contextlib
import faulthandler
import io
import logging
import os
import re
import resource
import sys
import threading
import time
import traceback
import typing
import weakref
from collections.abc import Callable, Iterator, MutableMapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FuturesTimeoutError
from concurrent.futures.thread import _threads_queues, _worker
from dataclasses import dataclass, field
from datetime import datetime

from .analysis_timeout import AnalysisTimeout as AnalysisTimeout
from .analysis_timeout import analysis_timeout as analysis_timeout
from .angr_codegen_tags import normalize_codegen_node_tags_8616
from .fork_timeout import run_with_timeout_in_fork as run_with_timeout_in_fork
from .prefork_job_pool import PreforkJobPool as PreforkJobPool
from .variable_recovery_sub_guard import (
    build_guarded_handle_binop_mul_8616,
    build_guarded_handle_binop_sub_8616,
)

DEFAULT_FREE_RAM_BUDGET_FRACTION: float = 0.45
DEFAULT_WORKER_MEMORY_FLOOR_MB: int = 256
FORCE_SERIAL_FUNCTION_DECOMP_ENV: str = "INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION"

START_TIME: float = time.perf_counter()
LAST_STEP_TIME: float = START_TIME
DECOMPILATION_PREP_LOCK: threading.Lock = threading.Lock()
_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr
_CURRENT_PROJECT = None
_FORMAT_FIRST_BLOCK_ASM: Callable[[object, int], str] | None = None
PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT: int = 96

# Probe artifacts mirror heterogeneous angr node/plugin metadata and prefork
# worker payloads. Keep their dynamic values behind one explicit boundary type;
# owned runtime decisions and public results remain concretely annotated.
type DynamicRecord = dict[str, typing.Any]
type AngrProjectSurface = typing.Any
type AngrPatchSurface = typing.Any


def _dynamic_record(value: object) -> DynamicRecord:
    """Return a dynamic boundary record, or an empty record for invalid input."""
    if not isinstance(value, dict):
        return {}
    return typing.cast(DynamicRecord, value)


def _int_path_tuple(value: object) -> tuple[int, ...] | None:
    """Return a validated integer path from heterogeneous probe metadata."""
    if not isinstance(value, list | tuple) or not all(isinstance(item, int) for item in value):
        return None
    return tuple(value)


def _record_paths(records: object, *, key: str = "path") -> tuple[tuple[int, ...], ...]:
    """Extract validated integer paths from heterogeneous diagnostic records."""
    if not isinstance(records, list | tuple):
        return ()
    paths: list[tuple[int, ...]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        path = _int_path_tuple(record.get(key))
        if path is not None:
            paths.append(path)
    return tuple(paths)


def timing_output_enabled() -> bool:
    """Return whether runtime timing diagnostics are enabled."""
    value = os.environ.get("INERTIA_DEBUG_TIMING")
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def _expr_child_nodes(expr: object) -> tuple[object, ...]:
    children: list[object] = []
    operand = getattr(expr, "operand", None)
    if operand is not None:
        children.append(operand)
    operands = getattr(expr, "operands", None)
    if isinstance(operands, tuple | list):
        children.extend(node for node in operands if node is not None)
    for attr in ("addr", "cond", "iftrue", "iffalse"):
        node = getattr(expr, attr, None)
        if node is not None:
            children.append(node)
    return tuple(children)


def _expr_tree_node_count(expr: object, cache: dict[int, int]) -> int:
    expr_id = id(expr)
    cached = cache.get(expr_id)
    if cached is not None:
        return cached
    total = 1
    for child in _expr_child_nodes(expr):
        if hasattr(child, "__dict__") or hasattr(type(child), "__slots__"):
            total += _expr_tree_node_count(child, cache)
            if total > PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT:
                break
    cache[expr_id] = total
    return total


def _stmt_expr_children(stmt: object) -> tuple[object, ...]:
    children: list[object] = []
    for attr in ("dst", "src", "addr", "data", "condition", "true_target", "false_target", "ret_exprs"):
        value = getattr(stmt, attr, None)
        if isinstance(value, tuple | list):
            children.extend(node for node in value if node is not None)
        elif value is not None:
            children.append(value)
    return tuple(children)


def _block_has_pathologically_complex_expr(
    block: object,
    limit: int = PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT,
) -> bool:
    """Return whether an AIL block contains an expression too deep to simplify safely."""
    cache: dict[int, int] = {}
    for stmt in getattr(block, "statements", ()) or ():
        for expr in _stmt_expr_children(stmt):
            if _expr_tree_node_count(expr, cache) > limit:
                return True
    return False


def install_jumpkind_logging_context(
    project: AngrProjectSurface | None,
    formatter: Callable[[object, int], str] | None,
) -> None:
    """Install the current angr project and block formatter for logging diagnostics."""
    global _CURRENT_PROJECT, _FORMAT_FIRST_BLOCK_ASM
    _CURRENT_PROJECT = project
    _FORMAT_FIRST_BLOCK_ASM = formatter


def default_exe_showcase_cap(total_functions: int, timeout: int) -> int:
    """Choose a bounded default number of functions for executable showcases."""
    if total_functions > 256:
        return 4
    return min(24, max(8, timeout))


def _normalize_replacement_bits_8616(expr: object, replacement: object) -> object:
    """Re-wrap a peephole replacement at the original expression's bit width."""
    expr_bits = getattr(expr, "bits", None)
    replacement_bits = getattr(replacement, "bits", None)
    if expr_bits is None or replacement_bits is None or expr_bits == replacement_bits:
        return replacement

    try:
        from angr.ailment.expression import BasePointerOffset, Const
    except ImportError:
        return replacement

    if isinstance(replacement, BasePointerOffset):
        return BasePointerOffset(
            replacement.idx,
            expr_bits,
            replacement.base,
            replacement.offset,
            variable=getattr(replacement, "variable", None),
            variable_offset=getattr(replacement, "variable_offset", None),
            **getattr(replacement, "tags", {}),
        )

    if isinstance(replacement, Const) and isinstance(replacement.value, int):
        mask = (1 << expr_bits) - 1
        return Const(
            replacement.idx,
            getattr(replacement, "variable", None),
            replacement.value & mask,
            expr_bits,
            **getattr(replacement, "tags", {}),
        )

    return replacement


def _clinic_skip_complex_expr_gate_8616(
    self: AngrPatchSurface,
    expr: object,
    stmt_idx: object,
    expr_idx: object,
    block: object,
    project: AngrProjectSurface | None,
) -> bool:
    """Return whether the peephole rewrite must be skipped for a huge expr."""
    if getattr(project, "_inertia_disable_complex_expr_scan", False):
        return False
    expr_node_cache = getattr(self, "_inertia_expr_node_cache", None)
    if not isinstance(expr_node_cache, dict):
        expr_node_cache = {}
        self._inertia_expr_node_cache = expr_node_cache
    expr_node_count = _expr_tree_node_count(expr, expr_node_cache)
    if expr_node_count <= PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT:
        return False
    complex_seen = getattr(self, "_inertia_complex_expr_skip_seen", None)
    if not isinstance(complex_seen, set):
        complex_seen = set()
        self._inertia_complex_expr_skip_seen = complex_seen
    block_addr = getattr(block, "addr", None)
    skip_key = (block_addr, stmt_idx, expr_idx, type(expr).__name__)
    if skip_key in complex_seen:
        return True
    complex_seen.add(skip_key)
    if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
        print(
            "[dbg] clinic:skip-peephole-complex-expr "
            f"block={block_addr:#x} "
            f"stmt_idx={stmt_idx} "
            f"expr_idx={expr_idx} "
            f"expr_type={type(expr).__name__} "
            f"node_count={expr_node_count}",
            file=sys.stderr,
        )
        sys.stderr.flush()
    return True


def _peephole_rewrite_loop_8616(
    self: AngrPatchSurface,
    expr: object,
    stmt_idx: object,
    expr_idx: object,
    block: object,
) -> object:
    """Iterate peephole expr_opts rewrites until a stable shape is reached."""
    redo = True
    rewrite_iter = 0
    seen_shapes: set[tuple[str, int | None]] = set()
    while redo:
        redo = False
        rewrite_iter += 1
        expr_shape = (type(expr).__name__, getattr(expr, "bits", None))
        if expr_shape in seen_shapes or rewrite_iter > 32:
            if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                block_addr = getattr(block, "addr", None)
                print(
                    "[dbg] clinic:stop-peephole-rewrite-loop "
                    f"block={block_addr:#x} "
                    f"stmt_idx={stmt_idx} expr_idx={expr_idx} "
                    f"iter={rewrite_iter} shape={expr_shape!r}",
                    file=sys.stderr,
                )
                sys.stderr.flush()
            break
        seen_shapes.add(expr_shape)
        for expr_opt in self.expr_opts:
            if not isinstance(expr, expr_opt.expr_classes):
                continue
            try:
                replacement = expr_opt.optimize(expr, stmt_idx=stmt_idx, block=block)
            except AssertionError:
                continue
            if replacement is None or replacement is expr:
                continue
            replacement = _normalize_replacement_bits_8616(expr, replacement)
            if getattr(expr, "bits", None) == getattr(replacement, "bits", None):
                expr = replacement
                redo = True
                break
            block_addr = getattr(block, "addr", None)
            if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                print(
                    "[dbg] clinic:peephole-bits-mismatch "
                    f"opt={type(expr_opt).__name__} "
                    f"block={block_addr:#x} "
                    f"stmt_idx={stmt_idx} "
                    f"expr_bits={getattr(expr, 'bits', None)} "
                    f"replacement_bits={getattr(replacement, 'bits', None)} "
                    f"expr={expr!s} replacement={replacement!s}",
                    file=sys.stderr,
                )
                sys.stderr.flush()
    return expr


def _guarded_peephole_handle_expr_8616(
    walker_cls: AngrPatchSurface,
    project: AngrProjectSurface | None,
    self: AngrPatchSurface,
    expr_idx: object,
    expr: object,
    stmt_idx: object,
    stmt: object,
    block: object,
) -> object:
    """Peephole ``_handle_expr`` body preserving bit widths and complexity gates."""
    if getattr(project, "_inertia_skip_clinic_simplify_block", False):
        return expr
    try:
        expr = super(walker_cls, self)._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
    except AssertionError:
        if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
            block_addr = getattr(block, "addr", None)
            print(
                "[dbg] clinic:skip-expr-assertion "
                f"block={block_addr:#x} stmt_idx={stmt_idx} expr_idx={expr_idx}"
                f"{_project_current_function_context_suffix(project)}",
                file=sys.stderr,
            )
            sys.stderr.flush()
        return expr
    old_expr = expr
    if _clinic_skip_complex_expr_gate_8616(self, expr, stmt_idx, expr_idx, block, project):
        return expr
    expr = _peephole_rewrite_loop_8616(self, expr, stmt_idx, expr_idx, block)
    if expr is not old_expr:
        self.any_update = True
    return expr


def install_angr_peephole_expr_bitwidth_guard(
    walker_cls: AngrPatchSurface,
    project: AngrProjectSurface | None = None,
) -> object:
    """Patch angr's peephole walker to preserve expression bit widths."""
    original_handle_expr = walker_cls._handle_expr

    def _guarded_handle_expr(
        self: AngrPatchSurface,
        expr_idx: object,
        expr: object,
        stmt_idx: object,
        stmt: object,
        block: object,
    ) -> object:
        return _guarded_peephole_handle_expr_8616(
            walker_cls, project, self, expr_idx, expr, stmt_idx, stmt, block
        )

    walker_cls._handle_expr = _guarded_handle_expr
    return original_handle_expr


def enable_line_buffered_stdio() -> None:
    """Enable line-buffered standard streams when the host streams support it."""
    for stream in (_REAL_STDOUT, _REAL_STDERR):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            with contextlib.suppress(Exception):
                reconfigure(line_buffering=True)


def _project_current_function_context(project: AngrProjectSurface) -> tuple[int | None, str | None, int | None]:
    context = getattr(project, "_inertia_current_function_debug", None)
    if not isinstance(context, dict):
        return (None, None, None)
    addr = context.get("addr")
    name = context.get("name")
    slice_addr = context.get("slice_addr")
    return (
        addr if isinstance(addr, int) else None,
        name if isinstance(name, str) else None,
        slice_addr if isinstance(slice_addr, int) else None,
    )


def _project_current_function_context_suffix(project: AngrProjectSurface) -> str:
    addr, name, slice_addr = _project_current_function_context(project)
    parts: list[str] = []
    if isinstance(addr, int):
        parts.append(f"addr={addr:#x}")
    if isinstance(slice_addr, int) and slice_addr != addr:
        parts.append(f"slice={slice_addr:#x}")
    if isinstance(name, str) and name:
        parts.append(f"name={name}")
    return f" {' '.join(parts)}" if parts else ""


def install_angr_variable_recovery_binop_sub_size_guard(
    engine_cls: typing.Any,
    *,
    richr_cls: typing.Any | None = None,
    typevars_module: typing.Any | None = None,
    project: AngrProjectSurface | None = None,
) -> tuple[object, object | None]:
    """Patch angr variable-recovery binops while preserving original handlers."""
    if richr_cls is None or typevars_module is None:
        from angr.analyses.typehoon import typevars as angr_typevars
        from angr.analyses.variable_recovery import engine_ail as variable_recovery_engine

        richr_cls = variable_recovery_engine.RichR
        typevars_module = angr_typevars
    resolved_richr_cls = typing.cast(Callable[..., object], richr_cls)

    original_handle_binop_sub = engine_cls._handle_binop_Sub
    original_handle_binop_mul = getattr(engine_cls, "_handle_binop_Mul", None)
    engine_cls._handle_binop_Sub = build_guarded_handle_binop_sub_8616(
        richr_cls=resolved_richr_cls,
        typevars_module=typevars_module,
        project=project,
        context_suffix=(_project_current_function_context, _project_current_function_context_suffix),
    )
    if original_handle_binop_mul is not None:
        engine_cls._handle_binop_Mul = build_guarded_handle_binop_mul_8616(
            richr_cls=resolved_richr_cls,
            typevars_module=typevars_module,
            project=project,
            context_suffix=(_project_current_function_context, _project_current_function_context_suffix),
        )
    return original_handle_binop_sub, original_handle_binop_mul


def install_angr_basepointeroffset_codegen_guard(codegen_cls: AngrPatchSurface) -> object:
    """Patch angr codegen to route base-pointer offsets through stack handling."""
    original_handle = codegen_cls._handle

    def _guarded_handle(
        self: AngrPatchSurface,
        node: object,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        try:
            from angr.ailment.expression import BasePointerOffset
        except ImportError:
            return original_handle(self, node, *args, **kwargs)

        if isinstance(node, BasePointerOffset):
            stackbase_handler = getattr(self, "_handle_Expr_StackBaseOffset", None)
            if callable(stackbase_handler):
                return normalize_codegen_node_tags_8616(stackbase_handler(node, *args, **kwargs))
        return normalize_codegen_node_tags_8616(original_handle(self, node, *args, **kwargs))

    codegen_cls._handle = _guarded_handle
    return original_handle


def _seqnode_attr_children_8616(node: object) -> list[object]:
    """Collect direct child nodes carried by named sequence-node attributes."""
    children: list[object] = []
    for attr in ("node", "nodes", "sequence_node", "true_node", "false_node", "else_node", "default_node", "head"):
        value = getattr(node, attr, None)
        if value is None:
            continue
        if isinstance(value, dict):
            children.extend(child for child in value.values() if child is not None)
        elif isinstance(value, list | tuple | set):
            children.extend(child for child in value if child is not None)
        else:
            children.append(value)
    return children


def _seqnode_cases_children_8616(node: object) -> list[object]:
    """Collect child nodes carried by ``cases`` dict/list payloads."""
    children: list[object] = []
    cases = getattr(node, "cases", None)
    if isinstance(cases, dict):
        children.extend(child for child in cases.values() if child is not None)
    elif isinstance(cases, list | tuple):
        for item in cases:
            if isinstance(item, tuple) and item:
                child = item[-1]
                if child is not None:
                    children.append(child)
            elif item is not None:
                children.append(item)
    return children


def _seqnode_children_8616(node: object) -> tuple[object, ...]:
    children = _seqnode_attr_children_8616(node)
    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if isinstance(condition_and_nodes, list | tuple):
        children.extend(child for _condition, child in condition_and_nodes if child is not None)
    children.extend(_seqnode_cases_children_8616(node))
    return tuple(children)


def _seqnode_subtree_summaries_8616(sequence: object) -> tuple[DynamicRecord, ...]:
    summaries: list[DynamicRecord] = []
    seen: set[int] = set()

    def _collect(node: object, path: tuple[int, ...]) -> frozenset[int]:
        if node is None:
            return frozenset()
        marker = id(node)
        if marker in seen:
            return frozenset()
        seen.add(marker)
        addr = getattr(node, "addr", None)
        addrs: set[int] = {addr} if isinstance(addr, int) else set()
        children = _seqnode_children_8616(node)
        child_summaries: list[DynamicRecord] = []
        for index, child in enumerate(children):
            child_addr = getattr(child, "addr", None)
            child_summaries.append(
                {
                    "addr": child_addr if isinstance(child_addr, int) else None,
                    "type": type(child).__name__,
                }
            )
            addrs.update(_collect(child, (*path, index)))
        summaries.append(
            {
                "addr": addr if isinstance(addr, int) else None,
                "addr_count": len(addrs),
                "addrs": tuple(sorted(addrs)),
                "children": tuple(child_summaries),
                "path": path,
                "type": type(node).__name__,
            }
        )
        return frozenset(addrs)

    _collect(sequence, ())
    return tuple(sorted(summaries, key=lambda item: (len(item["path"]), item["path"], item["type"])))


def _seqnode_node_at_path_8616(sequence: object, path: object) -> object | None:
    if sequence is None or not isinstance(path, list | tuple):
        return None
    current = sequence
    for index in path:
        if not isinstance(index, int):
            return None
        children = _seqnode_children_8616(current)
        if index < 0 or index >= len(children):
            return None
        current = children[index]
    return current


def _seqnode_owner_node_summary_8616(sequence: object, owner_paths: DynamicRecord) -> DynamicRecord:
    summaries: DynamicRecord = {}
    for name, path in owner_paths.items():
        node = _seqnode_node_at_path_8616(sequence, path)
        children = _seqnode_children_8616(node)
        summaries[name] = {
            "addr": getattr(node, "addr", None),
            "child_count": len(children),
            "path": list(path) if isinstance(path, list | tuple) else None,
            "type": type(node).__name__ if node is not None else None,
        }
    return summaries


def _seqnode_materialization_owner_blocker_8616(owner_summaries: DynamicRecord) -> str | None:
    ladder = owner_summaries.get("ladder")
    external_default = owner_summaries.get("external_default")
    if not isinstance(ladder, dict) or not isinstance(external_default, dict):
        return "missing_owner_summary"
    if ladder.get("type") == "LoopNode":
        return "ladder_owner_is_loop_node"
    if ladder.get("type") not in {"SequenceNode", "CascadingConditionNode", "ConditionNode"}:
        return "unsupported_ladder_owner_type"
    if external_default.get("type") not in {"Block", "SequenceNode"}:
        return "unsupported_external_default_owner_type"
    return None


def _seqnode_target_addr_8616(target: object) -> int | None:
    if isinstance(target, int):
        return target
    addr = getattr(target, "addr", None)
    return addr if isinstance(addr, int) else None


def _collect_loop_exit_nodes_8616(
    node: object,
    path: tuple[int, ...],
    break_targets: list[int],
    conditional_break_targets: list[int],
    continue_targets: list[int],
    break_samples: list[DynamicRecord],
) -> None:
    """Record break/continue node targets inside a loop sequence subtree."""
    node_type = type(node).__name__
    target_addr = _seqnode_target_addr_8616(getattr(node, "target", None))
    if node_type in {"BreakNode", "ConditionalBreakNode"}:
        if isinstance(target_addr, int):
            break_targets.append(target_addr)
            if node_type == "ConditionalBreakNode":
                conditional_break_targets.append(target_addr)
        break_samples.append(
            {
                "addr": getattr(node, "addr", None),
                "path": list(path),
                "target_addr": target_addr,
                "type": node_type,
            }
        )
    elif node_type == "ContinueNode" and isinstance(target_addr, int):
        continue_targets.append(target_addr)
    for index, child in enumerate(_seqnode_children_8616(node)):
        _collect_loop_exit_nodes_8616(
            child, (*path, index), break_targets, conditional_break_targets, continue_targets, break_samples
        )


def _loop_exit_default_status_8616(
    loop_sequence: object | None,
    external_default_addr: object,
    unique_break_targets: list[int],
    external_default_is_break_target: bool,
) -> str:
    """Classify the external default node's relation to loop break targets."""
    if loop_sequence is None:
        return "missing_loop_sequence"
    if not isinstance(external_default_addr, int):
        return "missing_external_default_addr"
    if external_default_is_break_target:
        return "external_default_is_loop_break_target"
    if unique_break_targets:
        return "external_default_not_loop_break_target"
    return "loop_has_no_break_target"


def _loop_exit_default_relation_8616(loop_node: object, external_default_node: object | None) -> DynamicRecord:
    loop_sequence = getattr(loop_node, "sequence_node", None)
    external_default_addr = getattr(external_default_node, "addr", None)
    break_targets: list[int] = []
    conditional_break_targets: list[int] = []
    continue_targets: list[int] = []
    break_samples: list[DynamicRecord] = []

    if loop_sequence is not None:
        _collect_loop_exit_nodes_8616(
            loop_sequence, (), break_targets, conditional_break_targets, continue_targets, break_samples
        )
    unique_break_targets = sorted(set(break_targets))
    unique_conditional_break_targets = sorted(set(conditional_break_targets))
    unique_continue_targets = sorted(set(continue_targets))
    external_default_is_break_target = (
        isinstance(external_default_addr, int) and external_default_addr in set(unique_break_targets)
    )
    status = _loop_exit_default_status_8616(
        loop_sequence, external_default_addr, unique_break_targets, external_default_is_break_target
    )
    return {
        "break_path_samples": break_samples[:8],
        "break_target_addrs": unique_break_targets,
        "conditional_break_target_addrs": unique_conditional_break_targets,
        "continue_addr": getattr(loop_node, "_continue_addr", None),
        "continue_target_addrs": unique_continue_targets,
        "external_default_addr": external_default_addr if isinstance(external_default_addr, int) else None,
        "external_default_is_break_target": external_default_is_break_target,
        "loop_addr": getattr(loop_node, "addr", None),
        "loop_sort": getattr(loop_node, "sort", None),
        "status": status,
    }


def _loop_preserving_switch_plan_8616(mapping: DynamicRecord, exit_relation: DynamicRecord) -> DynamicRecord:
    """Build the dynamic-boundary input record for Structuring switch materialization."""
    case_samples = tuple(mapping.get("expanded_root_case_path_samples", ()) or ())
    case_values = tuple(mapping.get("expanded_root_normalized_case_values", ()) or ())
    case_paths = [
        list(path)
        for sample in case_samples
        if isinstance(sample, dict) and (path := _int_path_tuple(sample.get("path"))) is not None
    ]
    body_status = mapping.get("expanded_root_body_mapping_status")
    common_parent_path = list(mapping.get("expanded_root_common_parent_path", ()) or ())
    break_samples = tuple(exit_relation.get("break_path_samples", ()) or ())
    break_paths = [
        list(path)
        for sample in break_samples
        if isinstance(sample, dict) and (path := _int_path_tuple(sample.get("path"))) is not None
    ]
    if exit_relation.get("status") != "external_default_is_loop_break_target":
        return {
            "blocker": "external_default_not_proven_loop_break_target",
            "case_count": len(case_samples),
            "case_path_common_parent": common_parent_path,
            "case_value_count": len(case_values),
            "ready": False,
            "status": "blocked",
        }
    if not case_samples or len(case_samples) != len(case_values):
        return {
            "blocker": "case_path_value_count_mismatch",
            "case_count": len(case_samples),
            "case_path_common_parent": common_parent_path,
            "case_value_count": len(case_values),
            "ready": False,
            "status": "blocked",
        }
    if body_status != "blocked_missing_region":
        return {
            "blocker": "unexpected_loop_body_mapping_status",
            "body_mapping_status": body_status,
            "case_count": len(case_samples),
            "case_path_common_parent": common_parent_path,
            "case_value_count": len(case_values),
            "ready": False,
            "status": "blocked",
        }
    return {
        "blocker": "seqnode_loop_break_default_materialization_pending",
        "body_mapping_status": body_status,
        "break_paths": break_paths[:4],
        "break_target_addrs": list(exit_relation.get("break_target_addrs", ()) or ()),
        "case_count": len(case_samples),
        "case_path_common_parent": common_parent_path,
        "case_paths": case_paths[:16],
        "case_value_count": len(case_values),
        "external_default_addr": exit_relation.get("external_default_addr"),
        "ready": False,
        "status": "candidate_loop_break_default_switch",
    }


def _materialize_loop_break_default_switch_8616(
    project: AngrProjectSurface | None,
    sequence: object,
    artifacts: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Bridge runtime SeqNode metadata to the Structuring-owned materializer."""
    from angr_platforms.X86_16.structuring.typed_switch_seqnode import (
        materialize_typed_switch_seqnode_8616,
    )

    mappings = _seqnode_switch_artifact_mappings_8616(sequence, artifacts)
    first_mapping = mappings[0] if mappings and isinstance(mappings[0], dict) else {}
    owner_paths = _external_default_owner_paths_8616(first_mapping) if first_mapping else {}
    loop_internal = _loop_internal_switch_mapping_8616(sequence, owner_paths, artifacts)
    mapping = _dynamic_record(loop_internal.get("mapping"))
    plan = _dynamic_record(loop_internal.get("materialization_plan"))
    result = materialize_typed_switch_seqnode_8616(
        project,
        sequence,
        first_mapping=first_mapping,
        owner_paths=owner_paths,
        loop_mapping=mapping,
        materialization_plan=plan,
    )
    return typing.cast(DynamicRecord, result.as_runtime_record())


def _maybe_materialize_pre_codegen_typed_switch_8616(
    project: AngrProjectSurface | None,
    sequence: object,
    artifacts: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Materialize only complete typed switch plans at the pre-codegen boundary."""
    if not artifacts:
        return {
            "attempted_count": 0,
            "changed": False,
            "refusal_reasons": ("missing_grouped_switch_artifacts",),
            "replaced_count": 0,
        }
    return _materialize_loop_break_default_switch_8616(project, sequence, artifacts)


def _loop_internal_switch_mapping_8616(
    sequence: object,
    owner_paths: DynamicRecord,
    artifacts: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Map switch artifacts inside a loop owner so materialization can preserve the loop."""
    ladder_path = owner_paths.get("ladder_owner_path")
    external_default_path = owner_paths.get("external_default_owner_path")
    ladder_node = _seqnode_node_at_path_8616(sequence, ladder_path)
    external_default_node = _seqnode_node_at_path_8616(sequence, external_default_path)
    exit_relation = _loop_exit_default_relation_8616(ladder_node, external_default_node)
    loop_sequence = getattr(ladder_node, "sequence_node", None)
    if type(ladder_node).__name__ != "LoopNode" or loop_sequence is None:
        return {
            "blocker": "ladder_owner_not_loop_node",
            "exit_relation": exit_relation,
            "mapping": None,
            "owner_paths": None,
            "owner_summaries": {},
            "ready": False,
        }
    loop_mappings = _seqnode_switch_artifact_mappings_8616(loop_sequence, artifacts)
    if not loop_mappings:
        return {
            "blocker": "loop_internal_mapping_missing",
            "exit_relation": exit_relation,
            "mapping": None,
            "owner_paths": None,
            "owner_summaries": {},
            "ready": False,
        }
    mapping = loop_mappings[0]
    loop_owner_paths = _external_default_owner_paths_8616(mapping)
    if loop_owner_paths.get("ready") is not True:
        return {
            "blocker": loop_owner_paths.get("blocker") or "loop_internal_owner_paths_not_ready",
            "exit_relation": exit_relation,
            "mapping": mapping,
            "materialization_plan": _loop_preserving_switch_plan_8616(mapping, exit_relation),
            "owner_paths": loop_owner_paths,
            "owner_summaries": {},
            "ready": False,
        }
    owner_summaries = _seqnode_owner_node_summary_8616(
        loop_sequence,
        {
            "external_default": loop_owner_paths["external_default_owner_path"],
            "ladder": loop_owner_paths["ladder_owner_path"],
        },
    )
    owner_blocker = _seqnode_materialization_owner_blocker_8616(owner_summaries)
    return {
        "blocker": owner_blocker,
        "exit_relation": exit_relation,
        "mapping": mapping,
        "materialization_plan": _loop_preserving_switch_plan_8616(mapping, exit_relation),
        "owner_paths": loop_owner_paths,
        "owner_summaries": owner_summaries,
        "ready": owner_blocker is None,
    }


def _graphregion_subtree_summaries_8616(region: object) -> tuple[DynamicRecord, ...]:
    graph = getattr(region, "graph", None)
    head = getattr(region, "head", None)
    if graph is None or head is None:
        return ()
    summaries: list[DynamicRecord] = []
    visiting: set[int] = set()

    def _node_children(node: object, active_graph: object) -> tuple[tuple[object, object], ...]:
        children: list[tuple[object, object]] = []
        nested_graph = getattr(node, "graph", None)
        nested_head = getattr(node, "head", None)
        if nested_graph is not None and nested_head is not None:
            children.append((nested_head, nested_graph))
        try:
            successors = list(typing.cast(typing.Any, active_graph).successors(node))
        except Exception:
            successors = []
        children.extend((successor, active_graph) for successor in successors)
        return tuple(
            sorted(children, key=lambda item: (getattr(item[0], "addr", -1), type(item[0]).__name__))
        )

    def _collect(node: object, path: tuple[int, ...], active_graph: object) -> frozenset[int]:
        if node is None:
            return frozenset()
        marker = id(node)
        if marker in visiting:
            return frozenset()
        visiting.add(marker)
        addr = getattr(node, "addr", None)
        addrs: set[int] = {addr} if isinstance(addr, int) else set()
        child_summaries: list[DynamicRecord] = []
        for index, (child, child_graph) in enumerate(_node_children(node, active_graph)):
            child_addr = getattr(child, "addr", None)
            child_summaries.append(
                {
                    "addr": child_addr if isinstance(child_addr, int) else None,
                    "type": type(child).__name__,
                }
            )
            addrs.update(_collect(child, (*path, index), child_graph))
        visiting.remove(marker)
        summaries.append(
            {
                "addr": addr if isinstance(addr, int) else None,
                "addr_count": len(addrs),
                "addrs": tuple(sorted(addrs)),
                "children": tuple(child_summaries),
                "path": path,
                "type": type(node).__name__,
            }
        )
        return frozenset(addrs)

    _collect(head, (), graph)
    return tuple(sorted(summaries, key=lambda item: (len(item["path"]), item["path"], item["type"])))


_SEQNODE_PREFERRED_TYPES_8616 = {
    "SequenceNode": 0,
    "MultiNode": 1,
    "ConditionNode": 2,
    "CascadingConditionNode": 2,
    "LoopNode": 2,
    "SwitchCaseNode": 2,
    "CodeNode": 3,
    "Block": 4,
}


def _seqnode_candidate_payload_8616(summary: DynamicRecord) -> DynamicRecord:
    """Render a subtree summary as the region-mapping candidate record."""
    children = tuple(summary.get("children", ()) or ())
    return {
        "addr": summary.get("addr"),
        "addr_count": summary.get("addr_count"),
        "child_count": len(children),
        "children": list(children[:6]),
        "path": list(summary.get("path", ()) or ()),
        "type": summary.get("type"),
    }


def _preferred_exact_region_summary_8616(candidates: list[DynamicRecord]) -> DynamicRecord | None:
    """Select the single preferred exact-addr subtree summary, if unambiguous."""
    if not candidates:
        return None
    ordered = sorted(
        candidates,
        key=lambda item: (
            _SEQNODE_PREFERRED_TYPES_8616.get(str(item.get("type")), 99),
            -int(item.get("addr_count", 0) or 0),
            len(item.get("path", ()) or ()),
            item.get("path", ()) or (),
        ),
    )
    best_key = (
        _SEQNODE_PREFERRED_TYPES_8616.get(str(ordered[0].get("type")), 99),
        -int(ordered[0].get("addr_count", 0) or 0),
    )
    tied = [
        candidate
        for candidate in ordered
        if (
            _SEQNODE_PREFERRED_TYPES_8616.get(str(candidate.get("type")), 99),
            -int(candidate.get("addr_count", 0) or 0),
        )
        == best_key
    ]
    return ordered[0] if len(tied) == 1 else None


def _region_missing_result_8616(region_id: object) -> DynamicRecord:
    """Return the shared missing-region mapping record."""
    return {
        "addr_count": 0,
        "candidate_count": 0,
        "candidates": [],
        "matched_addr": None,
        "path": None,
        "region_id": region_id,
        "status": "missing",
        "type": None,
    }


def _region_containing_summaries_8616(
    region_id: int,
    subtree_summaries: tuple[DynamicRecord, ...],
) -> list[DynamicRecord]:
    """Return subtree summaries whose addr sets contain ``region_id``."""
    return [
        summary
        for summary in subtree_summaries
        if isinstance(addrs := summary.get("addrs"), tuple) and region_id in addrs
    ]


def _exact_region_match_8616(
    region_id: int,
    subtree_summaries: tuple[DynamicRecord, ...],
    selected: DynamicRecord,
    exact: list[DynamicRecord],
) -> DynamicRecord:
    """Resolve the selected exact-addr summary against containing sequences."""
    small_sequence_containing = [
        summary
        for summary in _region_containing_summaries_8616(region_id, subtree_summaries)
        if summary is not selected
        and summary.get("type") == "SequenceNode"
        and 1 < int(summary.get("addr_count", 0) or 0) <= 8
        and len(summary.get("path", ()) or ()) <= len(selected.get("path", ()) or ())
    ]
    if small_sequence_containing:
        smallest_addr_count = min(int(summary.get("addr_count", 0) or 0) for summary in small_sequence_containing)
        small_sequence_containing = [
            summary
            for summary in small_sequence_containing
            if int(summary.get("addr_count", 0) or 0) == smallest_addr_count
        ]
    if (
        selected.get("type") == "Block"
        and int(selected.get("addr_count", 0) or 0) == 1
        and len(small_sequence_containing) == 1
    ):
        selected = small_sequence_containing[0]
    return {
        "addr_count": selected["addr_count"],
        "candidate_count": len(exact),
        "candidates": [_seqnode_candidate_payload_8616(summary) for summary in exact[:4]],
        "matched_addr": selected["addr"],
        "path": list(selected["path"]),
        "region_id": region_id,
        "status": "exact" if selected in exact else "contained",
        "type": selected["type"],
    }


def _seqnode_map_region_id_8616(
    region_id: object,
    subtree_summaries: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    if not isinstance(region_id, int):
        return _region_missing_result_8616(region_id)

    exact = [summary for summary in subtree_summaries if summary.get("addr") == region_id]
    selected = _preferred_exact_region_summary_8616(exact)
    if selected is not None:
        return _exact_region_match_8616(region_id, subtree_summaries, selected, exact)
    if exact:
        return {
            "addr_count": 0,
            "candidate_count": len(exact),
            "candidates": [_seqnode_candidate_payload_8616(summary) for summary in exact[:4]],
            "matched_addr": region_id,
            "path": None,
            "region_id": region_id,
            "status": "ambiguous_exact",
            "type": None,
        }

    containing = _region_containing_summaries_8616(region_id, subtree_summaries)
    if not containing:
        return _region_missing_result_8616(region_id)
    containing = sorted(containing, key=lambda item: (int(item["addr_count"]), len(item["path"]), item["path"]))
    smallest_count = containing[0]["addr_count"]
    smallest = [summary for summary in containing if summary["addr_count"] == smallest_count]
    if len(smallest) > 1:
        return {
            "addr_count": smallest_count,
            "candidate_count": len(smallest),
            "candidates": [_seqnode_candidate_payload_8616(summary) for summary in smallest[:4]],
            "matched_addr": None,
            "path": None,
            "region_id": region_id,
            "status": "ambiguous_containing",
            "type": None,
        }
    selected = smallest[0]
    return {
        "addr_count": selected["addr_count"],
        "candidate_count": 1,
        "candidates": [_seqnode_candidate_payload_8616(selected)],
        "matched_addr": selected["addr"],
        "path": list(selected["path"]),
        "region_id": region_id,
        "status": "contained",
        "type": selected["type"],
    }


def _expanded_root_body_shape_status_8616(
    *,
    case_paths: tuple[tuple[int, ...], ...],
    default_paths: tuple[tuple[int, ...], ...],
    common_parent_path: tuple[int, ...],
    direct_sibling_span: bool,
) -> str:
    """Classify the proven expanded-root body shape without enabling lowering."""
    if direct_sibling_span:
        return "direct_sibling_span"
    if not case_paths or not default_paths:
        return "missing_case_or_default_path"
    common_len = len(common_parent_path)
    if any(len(path) <= common_len or path[:common_len] != common_parent_path for path in (*case_paths, *default_paths)):
        return "non_sibling_subtrees"
    case_child_indexes = {path[common_len] for path in case_paths}
    default_child_indexes = {path[common_len] for path in default_paths}
    external_default_child_indexes = default_child_indexes - case_child_indexes
    if (
        len(case_child_indexes) == 1
        and len(external_default_child_indexes) == 1
        and all(path[common_len] in case_child_indexes or len(path) == common_len + 1 for path in default_paths)
    ):
        return "ladder_subtree_with_external_default_sibling"
    return "non_sibling_subtrees"


def _common_int_path_8616(paths: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    """Return the shared prefix path across mapped node paths."""
    if not paths:
        return ()
    prefix: list[int] = []
    for values in zip(*paths, strict=False):
        if len(set(values)) != 1:
            break
        prefix.append(values[0])
    return tuple(prefix)


def _switch_mapping_status_8616(statuses: list[str]) -> str:
    """Classify a case/default region-mapping status set."""
    if any(status == "missing" for status in statuses):
        return "blocked_missing_region"
    if any(status == "ambiguous_exact" for status in statuses):
        return "blocked_ambiguous_exact"
    if any(status == "ambiguous_containing" for status in statuses):
        return "blocked_ambiguous_containing"
    if any(status == "contained" for status in statuses):
        return "mapped_contained"
    return "mapped_exact"


def _expanded_path_samples_8616(mappings: tuple[DynamicRecord, ...], limit: int) -> list[DynamicRecord]:
    """Render mapped region records as path samples, capped at ``limit``."""
    return [
        {
            "path": list(path),
            "region_id": mapping.get("region_id"),
            "status": mapping.get("status"),
            "type": mapping.get("type"),
        }
        for mapping in mappings
        if (path := _int_path_tuple(mapping.get("path"))) is not None
    ][:limit]


def _expanded_region_mappings_8616(
    expanded_root_body: DynamicRecord,
    subtree_summaries: tuple[DynamicRecord, ...],
) -> tuple[tuple[DynamicRecord, ...], tuple[DynamicRecord, ...]]:
    """Map normalized expanded-root case/default region ids to subtree paths."""
    case_mappings = tuple(
        _seqnode_map_region_id_8616(region_id, subtree_summaries)
        for region_id in expanded_root_body["normalized_case_region_ids"]
        if isinstance(region_id, int)
    )
    default_mappings = tuple(
        _seqnode_map_region_id_8616(region_id, subtree_summaries)
        for region_id in expanded_root_body["default_region_ids"]
        if isinstance(region_id, int)
    )
    return case_mappings, default_mappings


def _expanded_root_geometry_8616(
    expanded_case_mappings: tuple[DynamicRecord, ...],
    expanded_default_mappings: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Compute shared-path geometry for expanded-root case/default mappings."""
    expanded_paths = _record_paths((*expanded_case_mappings, *expanded_default_mappings))
    common_parent_path = _common_int_path_8616(expanded_paths)
    direct_sibling_span = bool(expanded_paths) and all(
        len(path) == len(common_parent_path) + 1 for path in expanded_paths
    )
    return {
        "body_shape_status": _expanded_root_body_shape_status_8616(
            case_paths=_record_paths(expanded_case_mappings),
            common_parent_path=common_parent_path,
            default_paths=_record_paths(expanded_default_mappings),
            direct_sibling_span=direct_sibling_span,
        ),
        "common_parent_path": common_parent_path,
        "direct_sibling_span": direct_sibling_span,
    }


def _expanded_root_verdict_8616(
    expanded_root_body: DynamicRecord,
    expanded_case_mappings: tuple[DynamicRecord, ...],
    expanded_default_mappings: tuple[DynamicRecord, ...],
    geometry: DynamicRecord,
) -> tuple[str, bool, object]:
    """Classify expanded-root body mapping status and transform readiness."""
    expanded_statuses = [str(mapping["status"]) for mapping in expanded_case_mappings]
    expanded_statuses.extend(str(mapping["status"]) for mapping in expanded_default_mappings)
    transform_ready = bool(expanded_root_body["ready"]) and bool(expanded_case_mappings)
    blocker_reason = None
    if not expanded_root_body["ready"]:
        body_mapping_status = "normalization_not_ready"
        transform_ready = False
        blocker_reason = "expanded_root_normalization_not_ready"
    elif len(expanded_case_mappings) != len(expanded_root_body["normalized_case_values"]):
        body_mapping_status = "case_value_count_mismatch"
        transform_ready = False
        blocker_reason = "case_value_count_mismatch"
    elif any(status == "missing" for status in expanded_statuses):
        body_mapping_status = "blocked_missing_region"
        transform_ready = False
        blocker_reason = "missing_expanded_root_region"
    elif any(status.startswith("ambiguous") for status in expanded_statuses):
        body_mapping_status = "blocked_ambiguous_region"
        transform_ready = False
        blocker_reason = "ambiguous_expanded_root_region"
    elif any(status == "contained" for status in expanded_statuses):
        body_mapping_status = "mapped_contained"
    else:
        body_mapping_status = "mapped_exact"
    if transform_ready and not geometry["direct_sibling_span"]:
        transform_ready = False
        blocker_reason = (
            "expanded_root_ladder_subtree_with_external_default_sibling"
            if geometry["body_shape_status"] == "ladder_subtree_with_external_default_sibling"
            else "expanded_root_non_sibling_subtrees"
        )
    return body_mapping_status, transform_ready, blocker_reason


def _expanded_root_switch_fields_8616(
    expanded_root_body: DynamicRecord,
    expanded_case_mappings: tuple[DynamicRecord, ...],
    expanded_default_mappings: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Compute the shared ``expanded_root_*`` mapping record fields."""
    geometry = _expanded_root_geometry_8616(expanded_case_mappings, expanded_default_mappings)
    body_mapping_status, transform_ready, blocker_reason = _expanded_root_verdict_8616(
        expanded_root_body, expanded_case_mappings, expanded_default_mappings, geometry
    )
    return {
        "expanded_root_body_mapping_status": body_mapping_status,
        "expanded_root_body_shape_status": geometry["body_shape_status"],
        "expanded_root_case_path_samples": _expanded_path_samples_8616(expanded_case_mappings, 12),
        "expanded_root_default_path_samples": _expanded_path_samples_8616(expanded_default_mappings, 6),
        "expanded_root_default_region_ids": list(expanded_root_body["default_region_ids"]),
        "expanded_root_direct_sibling_span": geometry["direct_sibling_span"],
        "expanded_root_common_parent_path": list(geometry["common_parent_path"]),
        "expanded_root_mapped_case_count": sum(
            1 for mapping in expanded_case_mappings if mapping["status"] in {"exact", "contained"}
        ),
        "expanded_root_normalization_ready": bool(expanded_root_body["ready"]),
        "expanded_root_normalization_status": expanded_root_body["status"],
        "expanded_root_normalized_case_region_ids": list(expanded_root_body["normalized_case_region_ids"]),
        "expanded_root_normalized_case_values": list(expanded_root_body["normalized_case_values"]),
        "expanded_root_transform_blocker_reason": blocker_reason,
        "expanded_root_transform_ready": transform_ready,
        "expanded_root_unmapped_case_region_ids": [
            mapping["region_id"]
            for mapping in expanded_case_mappings
            if mapping["status"] not in {"exact", "contained"}
        ],
    }


def _seqnode_switch_artifact_mapping_8616(
    artifact: DynamicRecord,
    subtree_summaries: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Map one switch artifact's case/default regions into seqnode paths."""
    case_region_ids = tuple(value for value in artifact.get("case_region_ids", ()) if isinstance(value, int))
    case_mappings = tuple(_seqnode_map_region_id_8616(region_id, subtree_summaries) for region_id in case_region_ids)
    default_mapping = _seqnode_map_region_id_8616(artifact.get("default_region_id"), subtree_summaries)
    statuses = [str(mapping["status"]) for mapping in case_mappings]
    if artifact.get("default_region_id") is not None:
        statuses.append(str(default_mapping["status"]))
    status = _switch_mapping_status_8616(statuses)
    case_paths = tuple(
        path for mapping in case_mappings if (path := _int_path_tuple(mapping.get("path"))) is not None
    )
    default_path = _int_path_tuple(default_mapping.get("path"))
    default_contains_case_count = 0
    if default_path is not None:
        default_contains_case_count = sum(
            1 for case_path in case_paths if len(case_path) > len(default_path) and case_path[: len(default_path)] == default_path
        )
    transform_ready = status in {"mapped_exact", "mapped_contained"}
    transform_blocker_reason = None
    if transform_ready and default_contains_case_count:
        status = "blocked_partial_switch_ladder"
        transform_ready = False
        transform_blocker_reason = "default_subtree_contains_more_switch_cases"
    common_paths = (*case_paths, *((default_path,) if default_path is not None else ()))
    decision_tree_summary = dict(artifact.get("decision_tree_summary") or {})
    expanded_root_body = _expanded_root_normalized_body_from_summary_8616(decision_tree_summary)
    expanded_case_mappings, expanded_default_mappings = _expanded_region_mappings_8616(
        expanded_root_body, subtree_summaries
    )
    expanded_fields = _expanded_root_switch_fields_8616(
        expanded_root_body, expanded_case_mappings, expanded_default_mappings
    )
    return {
        "case_region_ids": list(case_region_ids),
        "case_mappings": list(case_mappings),
        "case_values": list(artifact.get("case_values", ()) or ()),
        "common_parent_path": list(_common_int_path_8616(common_paths)),
        "decision_tree_case_region_ids": list(artifact.get("decision_tree_case_region_ids", ()) or ()),
        "decision_tree_case_values": list(artifact.get("decision_tree_case_values", ()) or ()),
        "decision_tree_summary": decision_tree_summary,
        "default_contains_case_count": default_contains_case_count,
        "default_mapping": default_mapping,
        "default_region_id": artifact.get("default_region_id"),
        **expanded_fields,
        "expanded_root_default_mappings": list(expanded_default_mappings),
        "expanded_root_normalized_case_mappings": list(expanded_case_mappings),
        "mapped_case_count": sum(1 for mapping in case_mappings if mapping["status"] in {"exact", "contained"}),
        "region_id": artifact.get("region_id"),
        "status": status,
        "switch_condition_lhs": artifact.get("switch_condition_lhs"),
        "transform_blocker_reason": transform_blocker_reason,
        "transform_ready": transform_ready,
        "unmapped_case_region_ids": [
            mapping["region_id"]
            for mapping in case_mappings
            if mapping["status"] not in {"exact", "contained"}
        ],
    }


def _seqnode_switch_artifact_mappings_8616(
    sequence: object, artifacts: tuple[DynamicRecord, ...]
) -> tuple[DynamicRecord, ...]:
    subtree_summaries = _seqnode_subtree_summaries_8616(sequence)
    return tuple(
        _seqnode_switch_artifact_mapping_8616(artifact, subtree_summaries) for artifact in artifacts
    )


def _append_int_values_8616(target: list[int], values: object) -> None:
    """Append integer items from a heterogeneous record field."""
    if not isinstance(values, list | tuple):
        return
    for value in values:
        if isinstance(value, int):
            target.append(value)


def _accumulate_branch_subtree_ids_8616(
    subtree: object,
    case_region_ids: list[int],
    case_values: list[int],
    default_region_ids: list[int],
) -> None:
    """Accumulate normalized case/default ids from one branch subtree."""
    if not isinstance(subtree, dict):
        return
    _append_int_values_8616(case_region_ids, subtree.get("normalized_case_region_ids"))
    _append_int_values_8616(case_values, subtree.get("normalized_case_values"))
    _append_int_values_8616(default_region_ids, subtree.get("default_candidate_region_ids"))


def _accumulate_branch_split_ids_8616(
    split: object,
    case_region_ids: list[int],
    case_values: list[int],
    default_region_ids: list[int],
) -> None:
    """Accumulate normalized ids from one decision-tree branch split."""
    if not isinstance(split, dict):
        return
    _append_int_values_8616(case_region_ids, split.get("current_case_region_ids"))
    _append_int_values_8616(case_values, split.get("current_case_values"))
    for subtree in split.get("subtrees", ()) or ():
        _accumulate_branch_subtree_ids_8616(subtree, case_region_ids, case_values, default_region_ids)


def _expanded_root_normalized_body_from_summary_8616(summary: DynamicRecord) -> DynamicRecord:
    readiness = summary.get("expanded_root_normalization_readiness")
    ready = isinstance(readiness, dict) and readiness.get("ready") is True
    branch_subtrees = summary.get("expanded_root_normalization_branch_subtrees")
    case_region_ids: list[int] = []
    case_values: list[int] = []
    default_region_ids: list[int] = []
    if isinstance(branch_subtrees, list):
        for split in branch_subtrees:
            _accumulate_branch_split_ids_8616(split, case_region_ids, case_values, default_region_ids)
    return {
        "default_region_ids": list(dict.fromkeys(default_region_ids)),
        "normalized_case_region_ids": list(dict.fromkeys(case_region_ids)),
        "normalized_case_values": case_values,
        "ready": ready,
        "status": readiness.get("status") if isinstance(readiness, dict) else None,
    }


def _common_prefix_len_8616(lhs: tuple[int, ...], rhs: tuple[int, ...]) -> int:
    """Return the shared leading path length between two node paths."""
    count = 0
    for left_value, right_value in zip(lhs, rhs, strict=False):
        if left_value != right_value:
            break
        count += 1
    return count


def _default_case_region_ids_by_default_8616(summary: DynamicRecord) -> dict[int, tuple[int, ...]]:
    """Map each expanded default candidate region id to its sibling case ids."""
    result: dict[int, tuple[int, ...]] = {}
    branch_subtrees = summary.get("expanded_root_normalization_branch_subtrees")
    if not isinstance(branch_subtrees, list):
        return result
    for split in branch_subtrees:
        if not isinstance(split, dict):
            continue
        for subtree in split.get("subtrees", ()) or ():
            if not isinstance(subtree, dict):
                continue
            case_ids = tuple(
                region_id
                for region_id in tuple(subtree.get("normalized_case_region_ids", ()) or ())
                if isinstance(region_id, int)
            )
            for default_id in tuple(subtree.get("default_candidate_region_ids", ()) or ()):
                if isinstance(default_id, int) and case_ids:
                    result[default_id] = case_ids
    return result


def _resolve_ambiguous_default_mapping_8616(
    mapping: DynamicRecord,
    associated_case_region_ids: tuple[int, ...],
    case_mappings_by_region_id: dict[int, DynamicRecord],
) -> DynamicRecord:
    """Resolve an ambiguous default candidate by shared-prefix proximity."""
    if mapping.get("status") != "ambiguous_exact":
        return mapping
    case_paths = tuple(
        path
        for region_id in associated_case_region_ids
        if (path := _int_path_tuple(case_mappings_by_region_id.get(region_id, {}).get("path"))) is not None
    )
    if not case_paths:
        return mapping
    scored_candidates: list[tuple[int, int, tuple[int, ...], DynamicRecord]] = []
    for candidate in tuple(mapping.get("candidates", ()) or ()):
        if not isinstance(candidate, dict):
            continue
        candidate_path = candidate.get("path")
        if (path_tuple := _int_path_tuple(candidate_path)) is None:
            continue
        score = sum(_common_prefix_len_8616(path_tuple, case_path) for case_path in case_paths)
        scored_candidates.append((score, len(path_tuple), path_tuple, candidate))
    if not scored_candidates:
        return mapping
    scored_candidates.sort(reverse=True, key=lambda item: (item[0], item[1], item[2]))
    if len(scored_candidates) > 1 and scored_candidates[0][:2] == scored_candidates[1][:2]:
        return mapping
    _score, _depth, _path, selected = scored_candidates[0]
    resolved = dict(mapping)
    resolved["addr_count"] = selected.get("addr_count")
    resolved["candidate_count"] = int(mapping.get("candidate_count", 0) or 0)
    resolved["matched_addr"] = selected.get("addr")
    resolved["path"] = list(selected.get("path", ()) or ())
    resolved["status"] = "exact"
    resolved["type"] = selected.get("type")
    resolved["disambiguation"] = {
        "associated_case_region_ids": list(associated_case_region_ids),
        "source": "expanded_root_branch_subtree_default",
    }
    return resolved


def _disambiguated_default_mappings_8616(
    expanded_default_mappings: tuple[DynamicRecord, ...],
    expanded_case_mappings: tuple[DynamicRecord, ...],
    decision_tree_summary: DynamicRecord,
) -> tuple[DynamicRecord, ...]:
    """Resolve ambiguous default candidates against sibling case mappings."""
    case_mappings_by_region_id = {
        int(mapping["region_id"]): mapping
        for mapping in expanded_case_mappings
        if isinstance(mapping.get("region_id"), int)
    }
    default_case_region_ids_by_default = _default_case_region_ids_by_default_8616(decision_tree_summary)
    return tuple(
        _resolve_ambiguous_default_mapping_8616(
            mapping,
            default_case_region_ids_by_default.get(int(mapping["region_id"]), ())
            if isinstance(mapping.get("region_id"), int)
            else (),
            case_mappings_by_region_id,
        )
        for mapping in expanded_default_mappings
    )


def _ambiguous_mapping_samples_8616(
    expanded_case_mappings: tuple[DynamicRecord, ...],
    expanded_default_mappings: tuple[DynamicRecord, ...],
) -> list[DynamicRecord]:
    """Render ambiguous expanded-root mappings as diagnostic samples."""
    return [
        {
            "candidate_count": mapping.get("candidate_count"),
            "candidates": list(mapping.get("candidates", ()) or ())[:3],
            "region_id": mapping.get("region_id"),
            "status": mapping.get("status"),
        }
        for mapping in (*expanded_case_mappings, *expanded_default_mappings)
        if str(mapping["status"]).startswith("ambiguous")
    ][:6]


def _graphregion_switch_artifact_mapping_8616(
    artifact: DynamicRecord,
    subtree_summaries: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Map one switch artifact's expanded regions into graphregion paths."""
    decision_tree_summary = dict(artifact.get("decision_tree_summary") or {})
    expanded_root_body = _expanded_root_normalized_body_from_summary_8616(decision_tree_summary)
    expanded_case_mappings, expanded_default_mappings = _expanded_region_mappings_8616(
        expanded_root_body, subtree_summaries
    )
    expanded_default_mappings = _disambiguated_default_mappings_8616(
        expanded_default_mappings, expanded_case_mappings, decision_tree_summary
    )
    expanded_fields = _expanded_root_switch_fields_8616(
        expanded_root_body, expanded_case_mappings, expanded_default_mappings
    )
    return {
        **expanded_fields,
        "expanded_root_ambiguous_case_region_ids": [
            mapping["region_id"]
            for mapping in expanded_case_mappings
            if str(mapping["status"]).startswith("ambiguous")
        ],
        "expanded_root_ambiguous_default_region_ids": [
            mapping["region_id"]
            for mapping in expanded_default_mappings
            if str(mapping["status"]).startswith("ambiguous")
        ],
        "expanded_root_ambiguous_mapping_samples": _ambiguous_mapping_samples_8616(
            expanded_case_mappings, expanded_default_mappings
        ),
        "expanded_root_disambiguated_default_region_ids": [
            mapping["region_id"]
            for mapping in expanded_default_mappings
            if isinstance(mapping.get("disambiguation"), dict)
        ],
        "region_id": artifact.get("region_id"),
    }


def _graphregion_switch_artifact_mappings_8616(
    region: object, artifacts: tuple[DynamicRecord, ...]
) -> tuple[DynamicRecord, ...]:
    subtree_summaries = _graphregion_subtree_summaries_8616(region)
    return tuple(
        _graphregion_switch_artifact_mapping_8616(artifact, subtree_summaries) for artifact in artifacts
    )


def _condition_operand_payload_8616(value: object) -> object:
    if hasattr(value, "to_dict"):
        try:
            return typing.cast(typing.Any, value).to_dict()
        except Exception:
            return repr(value)
    if isinstance(value, int | str | float | bool) or value is None:
        return value
    return repr(value)


def _condition_ir_payload_8616(condition: object) -> DynamicRecord:
    return {
        "block_addr": getattr(condition, "block_addr", None),
        "lhs": _condition_operand_payload_8616(getattr(condition, "lhs", None)),
        "op": getattr(condition, "op", None),
        "producer_insn": getattr(condition, "producer_insn", None),
        "rhs": _condition_operand_payload_8616(getattr(condition, "rhs", None)),
        "src_insn": getattr(condition, "src_insn", None),
    }


def _seqnode_probe_summary_8616(sequence: object) -> DynamicRecord:
    counts: dict[str, int] = {}
    addr_samples: list[int] = []
    seen: set[int] = set()

    def _visit(node: object) -> None:
        if node is None:
            return
        marker = id(node)
        if marker in seen:
            return
        seen.add(marker)
        name = type(node).__name__
        counts[name] = counts.get(name, 0) + 1
        addr = getattr(node, "addr", None)
        if isinstance(addr, int) and len(addr_samples) < 16:
            addr_samples.append(addr)
        for child in _seqnode_children_8616(node):
            _visit(child)

    _visit(sequence)
    return {
        "root_type": type(sequence).__name__ if sequence is not None else None,
        "node_count": sum(counts.values()),
        "switch_case_node_count": counts.get("SwitchCaseNode", 0),
        "incomplete_switch_case_node_count": counts.get("IncompleteSwitchCaseNode", 0),
        "condition_node_count": counts.get("ConditionNode", 0),
        "cascading_condition_node_count": counts.get("CascadingConditionNode", 0),
        "loop_node_count": counts.get("LoopNode", 0),
        "addr_samples": addr_samples,
        "type_counts": dict(sorted(counts.items())),
    }


def _record_seqnode_stage_probe_8616(project: AngrProjectSurface | None, label: str, func: object, sequence: object) -> None:
    if project is None or sequence is None:
        return
    records = getattr(project, "_inertia_structuring_seqnode_stage_probe_8616", None)
    if not isinstance(records, list):
        records = []
        project._inertia_structuring_seqnode_stage_probe_8616 = records
    summary = _seqnode_probe_summary_8616(sequence)
    summary["function_addr"] = getattr(func, "addr", None)
    summary["function_name"] = getattr(func, "name", None)
    summary["stage"] = label
    summary["_sequence"] = sequence
    records.append(summary)


def _build_grouped_switch_artifacts_from_source_graph_8616(
    project: AngrProjectSurface | None,
    func: object,
    source_graph: object,
) -> tuple[tuple[DynamicRecord, ...], str | None]:
    """Build diagnostic grouped-switch artifacts from the pre-region Clinic graph."""
    func_addr = getattr(func, "addr", None)
    if project is None or not isinstance(func_addr, int) or source_graph is None:
        return (), "missing_project_function_or_source_graph"
    cache_snapshot: tuple[object, object] | None = None
    try:
        from types import SimpleNamespace

        from angr_platforms.X86_16.lift_86_16 import Instruction_ANY
        from angr_platforms.X86_16.lowering.condition_transfer import (
            collect_typed_condition_artifacts_8616,
        )
        from angr_platforms.X86_16.structuring_abnormal_loops import (
            AbnormalLoopStructureAnalysis,
        )
        from angr_platforms.X86_16.structuring_grouped_graph_builder import (
            build_grouped_region_graph,
        )

        module_cache = Instruction_ANY._inertia_module_condition_cache
        pending_sources = Instruction_ANY._inertia_pending_condition_sources_by_addr
        cache_snapshot = (
            {key: list(value) if isinstance(value, list) else value for key, value in dict(module_cache).items()},
            dict(dict(pending_sources).items()),
        )
        conditions, edge_evidence = collect_typed_condition_artifacts_8616(project, func_addr)
        if not edge_evidence:
            return (), "edge_evidence_unavailable_before_codegen"
        adapter = SimpleNamespace(
            project=project,
            cfunc=SimpleNamespace(addr=func_addr, name=getattr(func, "name", None)),
            _clinic=SimpleNamespace(graph=source_graph),
            _inertia_condition_edge_evidence=tuple(edge_evidence),
            _inertia_typed_conditions=tuple(conditions),
        )
        graph_result = build_grouped_region_graph(adapter)
        graph = graph_result.graph_result.graph
        if graph is None:
            return (), "grouped_graph_missing"
        structured = AbnormalLoopStructureAnalysis(graph).structure()
        artifacts = tuple(
            dict(artifact)
            for region in structured.nodes
            if isinstance(artifact := region.metadata.get("typed_edge_switch_region_artifact"), dict)
        )
        return artifacts, None
    except Exception as ex:  # pragma: no cover - diagnostic fail-closed path
        return (), f"{type(ex).__name__}: {ex}"
    finally:
        if cache_snapshot is not None:
            try:
                from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

                module_cache, pending_sources = cache_snapshot
                Instruction_ANY._inertia_module_condition_cache = module_cache
                Instruction_ANY._inertia_pending_condition_sources_by_addr = pending_sources
            except Exception:
                pass


def _pre_recursive_switch_materialization_readiness_8616(
    artifacts: tuple[DynamicRecord, ...],
    mappings: tuple[DynamicRecord, ...],
) -> DynamicRecord:
    """Return a fail-closed readiness summary for pre-recursive switch materialization."""
    ready_region_ids: list[int] = []
    blocker_reasons: dict[str, int] = {}
    for artifact, mapping in zip(artifacts, mappings, strict=False):
        if not isinstance(artifact, dict) or not isinstance(mapping, dict):
            blocker_reasons["invalid_artifact_or_mapping"] = blocker_reasons.get("invalid_artifact_or_mapping", 0) + 1
            continue
        artifact_status = artifact.get("status")
        mapping_status = mapping.get("expanded_root_body_mapping_status")
        shape_status = mapping.get("expanded_root_body_shape_status")
        transform_blocker = mapping.get("expanded_root_transform_blocker_reason")
        normalization_ready = mapping.get("expanded_root_normalization_ready") is True
        if artifact_status != "partial_ladder":
            reason = "artifact_not_partial_ladder"
        elif mapping_status != "mapped_exact":
            reason = "expanded_root_not_mapped_exact"
        elif shape_status != "ladder_subtree_with_external_default_sibling":
            reason = "unsupported_body_shape"
        elif transform_blocker != "expanded_root_ladder_subtree_with_external_default_sibling":
            reason = "unsupported_transform_blocker"
        elif not normalization_ready:
            reason = "expanded_root_normalization_not_ready"
        else:
            region_id = artifact.get("region_id")
            if isinstance(region_id, int):
                ready_region_ids.append(region_id)
                continue
            reason = "missing_artifact_region_id"
        blocker_reasons[reason] = blocker_reasons.get(reason, 0) + 1
    return {
        "blocker_reasons": dict(sorted(blocker_reasons.items())),
        "ready_count": len(ready_region_ids),
        "ready_region_ids": ready_region_ids,
    }


def _external_default_owner_paths_8616(mapping: DynamicRecord) -> DynamicRecord:
    """Summarize owner paths for the supported ladder-subtree/default-sibling shape."""
    case_samples = tuple(mapping.get("expanded_root_case_path_samples", ()) or ())
    default_samples = tuple(mapping.get("expanded_root_default_path_samples", ()) or ())
    if not case_samples or not default_samples:
        return {
            "blocker": "missing_case_or_default_paths",
            "external_default_owner_path": None,
            "ladder_owner_path": None,
            "ready": False,
        }
    case_paths = _record_paths(case_samples)
    default_paths = _record_paths(default_samples)
    if not case_paths or not default_paths:
        return {
            "blocker": "invalid_case_or_default_paths",
            "external_default_owner_path": None,
            "ladder_owner_path": None,
            "ready": False,
        }
    common_parent_path = _int_path_tuple(mapping.get("expanded_root_common_parent_path")) or ()
    common_len = len(common_parent_path)
    child_indexes = {path[common_len] for path in (*case_paths, *default_paths) if len(path) > common_len}
    case_child_indexes = {path[common_len] for path in case_paths if len(path) > common_len}
    default_child_indexes = {path[common_len] for path in default_paths if len(path) > common_len}
    external_default_child_indexes = default_child_indexes - case_child_indexes
    if len(case_child_indexes) != 1 or len(external_default_child_indexes) != 1 or child_indexes != (
        case_child_indexes | external_default_child_indexes
    ):
        return {
            "blocker": "owner_paths_not_ladder_plus_external_default",
            "external_default_owner_path": None,
            "ladder_owner_path": None,
            "ready": False,
        }
    ladder_child = next(iter(case_child_indexes))
    external_child = next(iter(external_default_child_indexes))
    return {
        "blocker": None,
        "external_default_owner_path": [*common_parent_path, external_child],
        "ladder_owner_path": [*common_parent_path, ladder_child],
        "ready": True,
    }


def _graphregion_node_at_path_8616(region: object, path: object) -> object | None:
    graph = getattr(region, "graph", None)
    head = getattr(region, "head", None)
    if graph is None or head is None or not isinstance(path, list | tuple):
        return None

    def _node_children(node: object, active_graph: object) -> tuple[tuple[object, object], ...]:
        children: list[tuple[object, object]] = []
        nested_graph = getattr(node, "graph", None)
        nested_head = getattr(node, "head", None)
        if nested_graph is not None and nested_head is not None:
            children.append((nested_head, nested_graph))
        try:
            successors = list(typing.cast(typing.Any, active_graph).successors(node))
        except Exception:
            successors = []
        children.extend((successor, active_graph) for successor in successors)
        return tuple(sorted(children, key=lambda item: (getattr(item[0], "addr", -1), type(item[0]).__name__)))

    current = head
    active_graph = graph
    for index in path:
        if not isinstance(index, int):
            return None
        children = _node_children(current, active_graph)
        if index < 0 or index >= len(children):
            return None
        current, active_graph = children[index]
    return typing.cast(object, current)


def _graphregion_owner_node_summary_8616(region: object, owner_paths: DynamicRecord) -> DynamicRecord:
    summaries: DynamicRecord = {}
    for name, path in owner_paths.items():
        node = _graphregion_node_at_path_8616(region, path)
        graph = getattr(node, "graph", None)
        try:
            child_count = len(tuple(graph.nodes)) if graph is not None else None
        except Exception:
            child_count = None
        summaries[name] = {
            "addr": getattr(node, "addr", None),
            "child_count": child_count,
            "path": list(path) if isinstance(path, list | tuple) else None,
            "type": type(node).__name__ if node is not None else None,
        }
    return summaries


def _record_graphregion_stage_probe_8616(project: AngrProjectSurface | None, label: str, func: object, region: object) -> None:
    if project is None or region is None:
        return
    records = getattr(project, "_inertia_structuring_graphregion_stage_probe_8616", None)
    if not isinstance(records, list):
        records = []
        project._inertia_structuring_graphregion_stage_probe_8616 = records
    graph = getattr(region, "graph", None)
    full_graph = getattr(region, "full_graph", None)
    func_addr = getattr(func, "addr", None)
    source_graph_by_func = getattr(project, "_inertia_recursive_structurer_source_graph_by_func_8616", None)
    source_graph_available = (
        isinstance(source_graph_by_func, dict)
        and isinstance(func_addr, int)
        and source_graph_by_func.get(func_addr) is not None
    )
    source_graph = source_graph_by_func.get(func_addr) if source_graph_available and isinstance(source_graph_by_func, dict) else None
    pre_recursive_artifacts, pre_recursive_error = _build_grouped_switch_artifacts_from_source_graph_8616(
        project,
        func,
        source_graph,
    )
    pre_recursive_mappings = (
        _graphregion_switch_artifact_mappings_8616(region, pre_recursive_artifacts)
        if pre_recursive_artifacts
        else ()
    )
    materialization_readiness = _pre_recursive_switch_materialization_readiness_8616(
        pre_recursive_artifacts,
        pre_recursive_mappings,
    )
    owner_paths = (
        _external_default_owner_paths_8616(pre_recursive_mappings[0])
        if materialization_readiness["ready_count"] == 1 and pre_recursive_mappings
        else {
            "blocker": "materialization_not_ready",
            "external_default_owner_path": None,
            "ladder_owner_path": None,
            "ready": False,
        }
    )
    owner_node_summaries = _graphregion_owner_node_summary_8616(
        region,
        {
            "external_default": owner_paths["external_default_owner_path"],
            "ladder": owner_paths["ladder_owner_path"],
        },
    )
    node_count = len(tuple(graph.nodes)) if graph is not None else 0
    summary = {
        "function_addr": func_addr,
        "function_name": getattr(func, "name", None),
        "full_graph_available": full_graph is not None,
        "node_count": node_count,
        "pre_recursive_grouped_switch_artifact_count": len(pre_recursive_artifacts),
        "pre_recursive_grouped_switch_artifact_statuses": [
            artifact.get("status") for artifact in pre_recursive_artifacts if isinstance(artifact, dict)
        ],
        "pre_recursive_grouped_switch_error": pre_recursive_error,
        "pre_recursive_grouped_switch_mappings": pre_recursive_mappings,
        "pre_recursive_materialization_blocker_reasons": materialization_readiness["blocker_reasons"],
        "pre_recursive_materialization_external_default_owner_path": owner_paths[
            "external_default_owner_path"
        ],
        "pre_recursive_materialization_ladder_owner_path": owner_paths["ladder_owner_path"],
        "pre_recursive_materialization_owner_node_summaries": owner_node_summaries,
        "pre_recursive_materialization_owner_path_blocker": owner_paths["blocker"],
        "pre_recursive_materialization_owner_paths_ready": owner_paths["ready"],
        "pre_recursive_materialization_ready_count": materialization_readiness["ready_count"],
        "pre_recursive_materialization_ready_region_ids": materialization_readiness["ready_region_ids"],
        "root_type": type(region).__name__ if region is not None else None,
        "source_graph_available": source_graph_available,
        "stage": label,
        "_pre_recursive_grouped_switch_artifacts": pre_recursive_artifacts,
        "_region": region,
    }
    records.append(summary)


def _map_seqnode_stage_records_8616(
    records: tuple[DynamicRecord, ...],
    artifacts: tuple[DynamicRecord, ...],
) -> tuple[DynamicRecord, ...]:
    mapped_records: list[DynamicRecord] = []
    for record in records:
        sequence = record.get("_sequence")
        if sequence is None:
            continue
        mapped = {
            key: value
            for key, value in record.items()
            if key
            in {
                "addr_samples",
                "cascading_condition_node_count",
                "condition_node_count",
                "function_addr",
                "function_name",
                "incomplete_switch_case_node_count",
                "loop_node_count",
                "node_count",
                "root_type",
                "stage",
                "switch_case_node_count",
                "type_counts",
            }
        }
        mappings = _seqnode_switch_artifact_mappings_8616(sequence, artifacts)
        first_mapping = mappings[0] if mappings and isinstance(mappings[0], dict) else {}
        owner_paths = _external_default_owner_paths_8616(first_mapping) if first_mapping else {}
        if owner_paths.get("ready") is True:
            mapped["expanded_root_external_default_owner_path"] = owner_paths["external_default_owner_path"]
            mapped["expanded_root_ladder_owner_path"] = owner_paths["ladder_owner_path"]
            owner_summaries = _seqnode_owner_node_summary_8616(
                sequence,
                {
                    "external_default": owner_paths["external_default_owner_path"],
                    "ladder": owner_paths["ladder_owner_path"],
                },
            )
            mapped["expanded_root_owner_node_summaries"] = owner_summaries
            mapped["expanded_root_materialization_owner_blocker"] = _seqnode_materialization_owner_blocker_8616(
                owner_summaries
            )
            loop_internal = (
                _loop_internal_switch_mapping_8616(sequence, owner_paths, artifacts)
                if mapped["expanded_root_materialization_owner_blocker"] == "ladder_owner_is_loop_node"
                else None
            )
            if isinstance(loop_internal, dict):
                loop_mapping = _dynamic_record(loop_internal.get("mapping"))
                loop_owner_paths = _dynamic_record(loop_internal.get("owner_paths"))
                loop_exit_relation = _dynamic_record(loop_internal.get("exit_relation"))
                loop_materialization_plan = _dynamic_record(loop_internal.get("materialization_plan"))
                mapped["expanded_root_loop_internal_body_mapping_status"] = loop_mapping.get(
                    "expanded_root_body_mapping_status"
                )
                mapped["expanded_root_loop_internal_body_shape_status"] = loop_mapping.get(
                    "expanded_root_body_shape_status"
                )
                mapped["expanded_root_loop_exit_default_relation"] = loop_exit_relation
                mapped["expanded_root_loop_preserving_materialization_plan"] = loop_materialization_plan
                mapped["expanded_root_loop_internal_external_default_owner_path"] = loop_owner_paths.get(
                    "external_default_owner_path"
                )
                mapped["expanded_root_loop_internal_ladder_owner_path"] = loop_owner_paths.get("ladder_owner_path")
                mapped["expanded_root_loop_internal_owner_blocker"] = loop_internal.get("blocker")
                mapped["expanded_root_loop_internal_owner_node_summaries"] = loop_internal.get("owner_summaries") or {}
                mapped["expanded_root_loop_internal_ready"] = bool(loop_internal.get("ready", False))
            else:
                mapped["expanded_root_loop_internal_body_mapping_status"] = None
                mapped["expanded_root_loop_internal_body_shape_status"] = None
                mapped["expanded_root_loop_exit_default_relation"] = {}
                mapped["expanded_root_loop_preserving_materialization_plan"] = {}
                mapped["expanded_root_loop_internal_external_default_owner_path"] = None
                mapped["expanded_root_loop_internal_ladder_owner_path"] = None
                mapped["expanded_root_loop_internal_owner_blocker"] = None
                mapped["expanded_root_loop_internal_owner_node_summaries"] = {}
                mapped["expanded_root_loop_internal_ready"] = False
            mapped["expanded_root_owner_path_blocker"] = None
            mapped["expanded_root_owner_paths_ready"] = True
        else:
            mapped["expanded_root_external_default_owner_path"] = None
            mapped["expanded_root_ladder_owner_path"] = None
            mapped["expanded_root_loop_internal_body_mapping_status"] = None
            mapped["expanded_root_loop_internal_body_shape_status"] = None
            mapped["expanded_root_loop_exit_default_relation"] = {}
            mapped["expanded_root_loop_preserving_materialization_plan"] = {}
            mapped["expanded_root_loop_internal_external_default_owner_path"] = None
            mapped["expanded_root_loop_internal_ladder_owner_path"] = None
            mapped["expanded_root_loop_internal_owner_blocker"] = "owner_paths_not_ready"
            mapped["expanded_root_loop_internal_owner_node_summaries"] = {}
            mapped["expanded_root_loop_internal_ready"] = False
            mapped["expanded_root_materialization_owner_blocker"] = "owner_paths_not_ready"
            mapped["expanded_root_owner_node_summaries"] = {}
            mapped["expanded_root_owner_path_blocker"] = owner_paths.get("blocker") if owner_paths else "missing_mapping"
            mapped["expanded_root_owner_paths_ready"] = False
        mapped["grouped_switch_artifact_count"] = len(artifacts)
        mapped["grouped_switch_artifact_mappings"] = list(mappings)
        mapped_records.append(mapped)
    return tuple(mapped_records)


def _map_graphregion_stage_records_8616(
    records: tuple[DynamicRecord, ...],
    artifacts: tuple[DynamicRecord, ...],
) -> tuple[DynamicRecord, ...]:
    mapped_records: list[DynamicRecord] = []
    for record in records:
        region = record.get("_region")
        if region is None:
            continue
        mapped = {
            key: value
            for key, value in record.items()
            if key
            in {
                "function_addr",
                "function_name",
                "full_graph_available",
                "node_count",
                "pre_recursive_grouped_switch_artifact_count",
                "pre_recursive_grouped_switch_artifact_statuses",
                "pre_recursive_grouped_switch_error",
                "pre_recursive_grouped_switch_mappings",
                "pre_recursive_materialization_blocker_reasons",
                "pre_recursive_materialization_external_default_owner_path",
                "pre_recursive_materialization_ladder_owner_path",
                "pre_recursive_materialization_owner_node_summaries",
                "pre_recursive_materialization_owner_path_blocker",
                "pre_recursive_materialization_owner_paths_ready",
                "pre_recursive_materialization_ready_count",
                "pre_recursive_materialization_ready_region_ids",
                "root_type",
                "source_graph_available",
                "stage",
            }
        }
        mappings = _graphregion_switch_artifact_mappings_8616(region, artifacts)
        mapped["grouped_switch_artifact_count"] = len(artifacts)
        mapped["grouped_switch_artifact_mappings"] = list(mappings)
        mapped_records.append(mapped)
    return tuple(mapped_records)


def _pre_codegen_condition_evidence_8616(
    target_project: AngrProjectSurface,
    func_addr: int,
    summary: DynamicRecord,
) -> object:
    """Collect typed-condition artifacts for a pre-codegen seqnode probe."""
    try:
        from angr_platforms.X86_16.lowering.condition_transfer import (
            collect_typed_condition_artifacts_8616,
        )

        conditions, edge_evidence = collect_typed_condition_artifacts_8616(target_project, func_addr)
    except Exception:
        conditions, edge_evidence = [], []
    summary["condition_fact_count"] = len(conditions)
    summary["condition_edge_evidence_count"] = len(edge_evidence)
    summary["condition_edge_block_addrs"] = [
        edge.edge_block_addr
        for edge in edge_evidence[:16]
        if isinstance(getattr(edge, "edge_block_addr", None), int)
    ]
    summary["condition_edge_summaries"] = [
        {
            "edge_block_addr": getattr(edge, "edge_block_addr", None),
            "edge_kind": getattr(edge, "edge_kind", None),
            "condition": _condition_ir_payload_8616(getattr(edge, "condition", None)),
            "producer_semantics": list(getattr(edge, "producer_semantics", ()) or ()),
            "source_jcc": getattr(edge, "source_jcc", None),
        }
        for edge in edge_evidence[:16]
    ]
    return edge_evidence


def _pre_codegen_grouped_switch_artifacts_8616(
    target_project: AngrProjectSurface,
    func_addr: int,
    func: object,
    ail_graph: object,
    edge_evidence: object,
    summary: DynamicRecord,
) -> tuple[DynamicRecord, ...]:
    """Rebuild grouped-region switch artifacts for the probe summary."""
    try:
        from types import SimpleNamespace

        from angr_platforms.X86_16.structuring.switch_artifact_identity import (
            canonicalize_switch_artifacts_8616,
        )
        from angr_platforms.X86_16.structuring_abnormal_loops import (
            AbnormalLoopStructureAnalysis,
        )
        from angr_platforms.X86_16.structuring_grouped_graph_builder import (
            build_grouped_region_graph,
        )

        adapter = SimpleNamespace(
            project=target_project,
            cfunc=SimpleNamespace(addr=func_addr, name=getattr(func, "name", None)),
            _clinic=SimpleNamespace(graph=ail_graph),
            _inertia_condition_edge_evidence=tuple(edge_evidence),
        )
        graph_result = build_grouped_region_graph(adapter)
        graph = graph_result.graph_result.graph
        if graph is not None:
            structured = AbnormalLoopStructureAnalysis(graph).structure()
            raw_artifacts = tuple(
                typing.cast(DynamicRecord, artifact)
                for region in structured.nodes
                if isinstance(
                    artifact := region.metadata.get("typed_edge_switch_region_artifact"),
                    dict,
                )
            )
            canonicalization = canonicalize_switch_artifacts_8616(raw_artifacts)
            artifacts = tuple(
                typing.cast(DynamicRecord, artifact)
                for artifact in canonicalization.artifacts
            )
            summary["pre_codegen_grouped_switch_raw_artifact_count"] = canonicalization.raw_fact_count
            summary["pre_codegen_grouped_switch_normalized_artifact_count"] = (
                canonicalization.normalized_fact_count
            )
            summary["pre_codegen_grouped_switch_classified_artifact_count"] = (
                canonicalization.classified_fact_count
            )
            summary["pre_codegen_grouped_switch_materialized_artifact_count"] = (
                canonicalization.materialized_count
            )
            summary["pre_codegen_grouped_switch_failure_count"] = canonicalization.failure_count
            summary["pre_codegen_grouped_switch_duplicate_artifact_count"] = (
                canonicalization.duplicate_fact_count
            )
            return artifacts
    except Exception as ex:
        summary["pre_codegen_grouped_switch_error"] = f"{type(ex).__name__}: {ex}"
    return ()


def _pre_codegen_stage_mappings_8616(
    target_project: AngrProjectSurface,
    func_addr: int,
    artifacts: tuple[DynamicRecord, ...],
    summary: DynamicRecord,
) -> None:
    """Attach recorded seqnode/graphregion stage mappings to the probe."""
    stage_records = getattr(target_project, "_inertia_structuring_seqnode_stage_probe_8616", None)
    if isinstance(stage_records, list):
        func_stage_records = tuple(
            record
            for record in stage_records
            if isinstance(record, dict) and record.get("function_addr") == func_addr
        )
        summary["pre_codegen_structuring_stage_mappings"] = _map_seqnode_stage_records_8616(
            func_stage_records,
            artifacts,
        )
    graph_region_stage_records = getattr(
        target_project,
        "_inertia_structuring_graphregion_stage_probe_8616",
        None,
    )
    if isinstance(graph_region_stage_records, list):
        func_graph_region_stage_records = tuple(
            record
            for record in graph_region_stage_records
            if isinstance(record, dict) and record.get("function_addr") == func_addr
        )
        summary["pre_codegen_graphregion_stage_mappings"] = _map_graphregion_stage_records_8616(
            func_graph_region_stage_records,
            artifacts,
        )


def _pre_codegen_switch_replacement_probe_8616(
    target_project: AngrProjectSurface,
    sequence: object,
    artifacts: tuple[DynamicRecord, ...],
    func_addr: int,
    func: object,
    summary: DynamicRecord,
) -> None:
    """Attempt the pre-codegen typed-switch replacement and record verdicts."""
    replacement_result = _maybe_materialize_pre_codegen_typed_switch_8616(
        target_project,
        sequence,
        artifacts,
    )
    summary["typed_switch_seqnode_replacement"] = replacement_result
    replacement_results = getattr(target_project, "_inertia_typed_switch_seqnode_replacement_8616", None)
    if not isinstance(replacement_results, list):
        replacement_results = []
        target_project._inertia_typed_switch_seqnode_replacement_8616 = replacement_results
    replacement_results.append(
        {
            "function_addr": func_addr,
            "function_name": getattr(func, "name", None),
            "stage": "pre_codegen",
            **replacement_result,
        }
    )
    if replacement_result.get("changed") is True:
        summary.update(_seqnode_probe_summary_8616(sequence))
    _pre_codegen_stage_mappings_8616(target_project, func_addr, artifacts, summary)


def _record_pre_codegen_seqnode_probe_8616(
    project: AngrProjectSurface | None,
    self: object,
    func: object,
    sequence: object,
    kwargs: dict[object, object],
) -> None:
    """Record the pre-codegen seqnode probe summary for ``func``."""
    target_project = project if project is not None else getattr(self, "project", None)
    if target_project is None:
        return
    records = getattr(target_project, "_inertia_pre_codegen_seqnode_probe_8616", None)
    if not isinstance(records, list):
        records = []
        target_project._inertia_pre_codegen_seqnode_probe_8616 = records
    summary = _seqnode_probe_summary_8616(sequence)
    summary["function_addr"] = getattr(func, "addr", None)
    summary["function_name"] = getattr(func, "name", None)
    func_addr = getattr(func, "addr", None)
    if isinstance(func_addr, int):
        edge_evidence = _pre_codegen_condition_evidence_8616(target_project, func_addr, summary)
        ail_graph = kwargs.get("ail_graph")
        if edge_evidence and ail_graph is not None:
            artifacts = _pre_codegen_grouped_switch_artifacts_8616(
                target_project, func_addr, func, ail_graph, edge_evidence, summary
            )
            summary["pre_codegen_grouped_switch_artifact_count"] = len(artifacts)
            summary["pre_codegen_grouped_switch_artifact_mappings"] = _seqnode_switch_artifact_mappings_8616(
                sequence, artifacts
            )
            _pre_codegen_switch_replacement_probe_8616(
                target_project, sequence, artifacts, func_addr, func, summary
            )
    records.append(summary)


def install_angr_pre_codegen_seqnode_probe_guard(
    codegen_cls: AngrPatchSurface,
    project: AngrProjectSurface | None = None,
) -> object:
    """Patch angr codegen initialization to capture pre-codegen sequence diagnostics."""
    original_init = codegen_cls.__init__

    def _guarded_init(self: object, func: object, sequence: object, *args: object, **kwargs: object) -> object:
        _record_pre_codegen_seqnode_probe_8616(project, self, func, sequence, kwargs)
        return original_init(self, func, sequence, *args, **kwargs)

    codegen_cls.__init__ = _guarded_init
    return original_init


def install_angr_structuring_seqnode_stage_probe_guard(project: AngrProjectSurface | None = None) -> tuple[object, object]:
    """Patch angr structuring stages to record sequence and region diagnostics."""
    from angr.analyses.decompiler.region_simplifiers.region_simplifier import RegionSimplifier
    from angr.analyses.decompiler.structuring.recursive_structurer import RecursiveStructurer

    recursive_structurer_cls = typing.cast(AngrPatchSurface, RecursiveStructurer)
    region_simplifier_cls = typing.cast(AngrPatchSurface, RegionSimplifier)
    original_rs_init: Callable[..., typing.Any] = recursive_structurer_cls.__init__
    original_region_simplifier_init: Callable[..., typing.Any] = region_simplifier_cls.__init__

    def _probe_rs_init(self: object, *args: object, **kwargs: object) -> object:
        target_project = project if project is not None else getattr(self, "project", None)
        func = kwargs.get("func") or getattr(self, "function", None)
        region = args[0] if args else kwargs.get("region")
        _record_graphregion_stage_probe_8616(target_project, "recursive_structurer_input_region", func, region)
        result = original_rs_init(self, *args, **kwargs)
        if target_project is not None:
            func_addr = getattr(func, "addr", None)
            source_graph_by_func = getattr(target_project, "_inertia_recursive_structurer_source_graph_by_func_8616", None)
            source_graph = (
                source_graph_by_func.get(func_addr)
                if isinstance(source_graph_by_func, dict) and isinstance(func_addr, int)
                else None
            )
            artifacts, error = _build_grouped_switch_artifacts_from_source_graph_8616(
                target_project,
                func,
                source_graph,
            )
            replacement_result = (
                _materialize_loop_break_default_switch_8616(target_project, getattr(self, "result", None), artifacts)
                if error is None and artifacts
                else {
                    "attempted_count": 0,
                    "changed": False,
                    "refusal_reasons": (error or "missing_grouped_switch_artifacts",),
                    "replaced_count": 0,
                }
            )
            results = getattr(target_project, "_inertia_typed_switch_seqnode_replacement_8616", None)
            if not isinstance(results, list):
                results = []
                target_project._inertia_typed_switch_seqnode_replacement_8616 = results
            results.append(
                {
                    "function_addr": func_addr,
                    "function_name": getattr(func, "name", None),
                    **replacement_result,
                }
            )
        _record_seqnode_stage_probe_8616(target_project, "recursive_structurer_result", func, getattr(self, "result", None))
        return result

    def _probe_region_simplifier_init(
        self: object,
        func: object,
        region: object,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        target_project = project if project is not None else getattr(self, "project", None)
        _record_seqnode_stage_probe_8616(target_project, "region_simplifier_input", func, region)
        result = original_region_simplifier_init(self, func, region, *args, **kwargs)
        _record_seqnode_stage_probe_8616(
            target_project,
            "region_simplifier_result",
            func,
            getattr(self, "result", None),
        )
        return result

    recursive_structurer_cls.__init__ = _probe_rs_init
    region_simplifier_cls.__init__ = _probe_region_simplifier_init
    return original_rs_init, original_region_simplifier_init


@contextlib.contextmanager
def guard_angr_structuring_seqnode_stage_probe(project: AngrProjectSurface | None = None) -> Iterator[None]:
    """Temporarily enable angr structuring sequence and graph-region diagnostics."""
    from angr.analyses.decompiler.decompiler import Decompiler
    from angr.analyses.decompiler.region_simplifiers.region_simplifier import RegionSimplifier
    from angr.analyses.decompiler.structuring.recursive_structurer import RecursiveStructurer

    decompiler_cls = typing.cast(AngrPatchSurface, Decompiler)
    recursive_structurer_cls = typing.cast(AngrPatchSurface, RecursiveStructurer)
    region_simplifier_cls = typing.cast(AngrPatchSurface, RegionSimplifier)
    original_recover_regions: Callable[..., typing.Any] = decompiler_cls._recover_regions
    original_rs_init, original_region_simplifier_init = install_angr_structuring_seqnode_stage_probe_guard(
        project=project
    )

    def _recover_regions_with_source_graph(
        self: object,
        graph: object,
        cond_proc: object,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        target_project = project if project is not None else getattr(self, "project", None)
        func_addr = getattr(getattr(self, "func", None), "addr", None)
        if target_project is not None and isinstance(func_addr, int) and graph is not None:
            source_graph_by_func = getattr(target_project, "_inertia_recursive_structurer_source_graph_by_func_8616", None)
            if not isinstance(source_graph_by_func, dict):
                source_graph_by_func = {}
                target_project._inertia_recursive_structurer_source_graph_by_func_8616 = source_graph_by_func
            source_graph_by_func[func_addr] = graph
        return original_recover_regions(self, graph, cond_proc, *args, **kwargs)

    decompiler_cls._recover_regions = _recover_regions_with_source_graph
    try:
        yield
    finally:
        decompiler_cls._recover_regions = original_recover_regions
        recursive_structurer_cls.__init__ = original_rs_init
        region_simplifier_cls.__init__ = original_region_simplifier_init


@contextlib.contextmanager
def guard_angr_peephole_expr_bitwidth_assertion(
    project: AngrProjectSurface | None = None,
) -> Iterator[None]:
    """Temporarily guard angr peephole handling at its dynamic walker boundary."""
    if project is not None and getattr(project, "_inertia_disable_peephole_expr_guard", False):
        yield
        return
    from angr.analyses.decompiler import utils as decompiler_utils

    walker_cls = typing.cast(AngrPatchSurface, decompiler_utils._PeepholeExprsWalker)
    original_handle_expr = install_angr_peephole_expr_bitwidth_guard(walker_cls, project=project)
    try:
        yield
    finally:
        walker_cls._handle_expr = original_handle_expr


@contextlib.contextmanager
def guard_angr_basepointeroffset_codegen_support() -> Iterator[None]:
    """Temporarily teach angr codegen to dispatch base-pointer offset nodes."""
    from angr.analyses.decompiler.structured_codegen import c as structured_codegen_c

    codegen_cls = typing.cast(AngrPatchSurface, structured_codegen_c.CStructuredCodeGenerator)
    original_handle = install_angr_basepointeroffset_codegen_guard(codegen_cls)
    try:
        yield
    finally:
        codegen_cls._handle = original_handle


@contextlib.contextmanager
def guard_angr_pre_codegen_seqnode_probe(project: AngrProjectSurface | None = None) -> Iterator[None]:
    """Temporarily patch angr codegen to capture pre-codegen sequence diagnostics."""
    from angr.analyses.decompiler.structured_codegen import c as structured_codegen_c

    codegen_cls = typing.cast(AngrPatchSurface, structured_codegen_c.CStructuredCodeGenerator)
    original_init = install_angr_pre_codegen_seqnode_probe_guard(codegen_cls, project=project)
    try:
        yield
    finally:
        codegen_cls.__init__ = original_init


@contextlib.contextmanager
def guard_angr_variable_recovery_binop_sub_size_mismatch(
    project: AngrProjectSurface | None = None,
) -> Iterator[None]:
    """Temporarily guard angr variable recovery against mixed-width binops."""
    from angr.analyses.variable_recovery import engine_ail as variable_recovery_engine

    engine_cls = typing.cast(AngrPatchSurface, variable_recovery_engine.SimEngineVRAIL)
    original_handle_binop_sub, original_handle_binop_mul = install_angr_variable_recovery_binop_sub_size_guard(
        engine_cls, project=project
    )
    try:
        yield
    finally:
        engine_cls._handle_binop_Sub = original_handle_binop_sub
        if original_handle_binop_mul is not None:
            engine_cls._handle_binop_Mul = original_handle_binop_mul


@dataclass(slots=True)
class _ClinicGuardState8616:
    """Mutable counters and stage clock for the Clinic stage-marker guard."""

    start: float = field(default_factory=time.perf_counter)
    last_stage: str = "start"
    stage_entry: float = 0.0
    emit_logs: bool = False
    simplify_count: int = 0
    peephole_count: int = 0
    simplify_total: float = 0.0
    peephole_total: float = 0.0

    def __post_init__(self) -> None:
        self.stage_entry = self.start

    def emit_stage_time(self, new_stage: str) -> None:
        """Emit a stage-transition timing log and advance the clock."""
        now = time.perf_counter()
        elapsed_since_start = now - self.start
        elapsed_in_prev = now - self.stage_entry
        if self.emit_logs:
            print(
                f"[dbg] stage-time: {new_stage} elapsed={elapsed_since_start:.2f}s "
                f"(prev={self.last_stage} took {elapsed_in_prev:.2f}s)",
                file=sys.stderr,
            )
            sys.stderr.flush()
        self.last_stage = new_stage
        self.stage_entry = now

    def record_peephole_stats(self, project: AngrProjectSurface, elapsed: float) -> None:
        """Accumulate per-function peephole timing stats on the project."""
        self.peephole_total += elapsed
        if not os.environ.get("INERTIA_DEBUG_CLINIC_FLAGS"):
            return
        stats = getattr(project, "_inertia_debug_peephole_stats", None)
        if not isinstance(stats, dict):
            stats = {}
            project._inertia_debug_peephole_stats = stats
        addr, _name, slice_addr = _project_current_function_context(project)
        stats_key = (addr if isinstance(addr, int) else -1, slice_addr if isinstance(slice_addr, int) else -1)
        calls, total = stats.get(stats_key, (0, 0.0))
        calls = int(calls) + 1
        total = float(total) + float(elapsed)
        stats[stats_key] = (calls, total)
        if calls in (1, 10, 50, 100, 200, 500, 1000):
            print(
                "[dbg] clinic:peephole-stats "
                f"calls={calls} total={total:.3f}s avg={(total / calls):.6f}s"
                f"{_project_current_function_context_suffix(project)}",
                file=sys.stderr,
            )
            sys.stderr.flush()


def _clinic_stage_guard_8616(
    state: _ClinicGuardState8616,
    project: AngrProjectSurface,
    orig: Callable[..., object],
    label: str,
    marker: str,
) -> Callable[..., object]:
    """Build a Clinic stage wrapper that records the stage marker."""

    def _guarded(self: AngrPatchSurface, *args: typing.Any, **kwargs: typing.Any) -> object:
        state.emit_stage_time(label)
        project._inertia_decompiler_stage = marker
        return orig(self, *args, **kwargs)

    return _guarded


def _guarded_simplify_block_8616(
    state: _ClinicGuardState8616,
    project: AngrProjectSurface,
    orig_simplify_block: Callable[..., object],
    self: AngrPatchSurface,
    args: tuple[typing.Any, ...],
    kwargs: dict[str, typing.Any],
) -> object:
    """Clinic ``_simplify_block`` wrapper with skip gates and stage timing."""
    project._inertia_decompiler_stage = "core:clinic:simplify_block"
    block = args[0] if args else kwargs.get("block")
    if getattr(project, "_inertia_skip_clinic_simplify_block", False) and block is not None:
        return block
    if getattr(project, "_inertia_tiny_core_disable_peephole", False) and block is not None:
        return block
    state.simplify_count += 1
    t_start = time.perf_counter()
    try:
        result = orig_simplify_block(self, *args, **kwargs)
    except AssertionError:
        if block is not None:
            if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                print(
                    "[dbg] clinic:skip-simplify-block-assertion "
                    f"block={getattr(block, 'addr', None)!r}"
                    f"{_project_current_function_context_suffix(project)}",
                    file=sys.stderr,
                )
                sys.stderr.flush()
            return block
        raise
    state.simplify_total += time.perf_counter() - t_start
    if (timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR")) and (
        state.simplify_count % 20 == 0
    ):
        print(
            f"[dbg] stage-time: simplify_block x{state.simplify_count} cumulative={state.simplify_total:.2f}s "
            f"(peephole x{state.peephole_count} cumulative={state.peephole_total:.2f}s)"
        )
        sys.stderr.flush()
    return result


def _debug_clinic_flags_8616(project: AngrProjectSurface, block: object) -> None:
    """Emit the once-per-function clinic flag debug line."""
    if not os.environ.get("INERTIA_DEBUG_CLINIC_FLAGS"):
        return
    seen = getattr(project, "_inertia_debug_clinic_flags_seen", None)
    if not isinstance(seen, set):
        seen = set()
        project._inertia_debug_clinic_flags_seen = seen
    addr, _name, slice_addr = _project_current_function_context(project)
    key = (addr, slice_addr, "peephole")
    if key in seen:
        return
    seen.add(key)
    print(
        "[dbg] clinic:flags "
        f"skip_simplify={bool(getattr(project, '_inertia_skip_clinic_simplify_block', False))} "
        f"tiny_disable_peephole={bool(getattr(project, '_inertia_tiny_core_disable_peephole', False))} "
        f"disable_expr_guard={bool(getattr(project, '_inertia_disable_peephole_expr_guard', False))} "
        f"block_is_none={block is None}"
        f"{_project_current_function_context_suffix(project)}",
        file=sys.stderr,
    )
    sys.stderr.flush()


def _clinic_peephole_capped_8616(project: AngrProjectSurface, block: object) -> tuple[object, bool, bool]:
    """Return the skipped peephole result while enforcing the per-function cap."""
    cap = int(getattr(project, "_inertia_clinic_peephole_cap", 128) or 128)
    key_addr = None
    ctx = getattr(project, "_inertia_current_function_debug", None)
    if isinstance(ctx, dict):
        key_addr = ctx.get("slice_addr") or ctx.get("addr")
    if not isinstance(key_addr, int):
        key_addr = getattr(block, "addr", None)
    counts = getattr(project, "_inertia_clinic_peephole_counts", None)
    if not isinstance(counts, dict):
        counts = {}
        project._inertia_clinic_peephole_counts = counts
    peephole_key = int(key_addr) if isinstance(key_addr, int) else -1
    count = int(counts.get(peephole_key, 0)) + 1
    counts[peephole_key] = count
    if count > cap and os.environ.get("INERTIA_DEBUG_CLINIC_FLAGS"):
        print(
            "[dbg] clinic:peephole-cap-hit "
            f"count={count} cap={cap}{_project_current_function_context_suffix(project)}",
            file=sys.stderr,
        )
        sys.stderr.flush()
    return block, False, False


def _fast_block_peephole_8616(
    self: AngrPatchSurface,
    block: object,
    peephole_optimize_stmts: Callable[..., object],
    peephole_optimize_multistmts: Callable[..., object],
) -> tuple[object, bool, bool]:
    """Run the stmt/multistmt peephole passes on a block directly."""
    statements, stmts_updated = peephole_optimize_stmts(block, self._stmt_peephole_opts)
    new_block = block.copy(statements=statements) if stmts_updated else block
    statements, multi_stmts_updated = peephole_optimize_multistmts(new_block, self._multistmt_peephole_opts)
    if multi_stmts_updated:
        new_block = new_block.copy(statements=statements)
    return new_block, bool(stmts_updated or multi_stmts_updated), False


def _debug_skip_complex_block_8616(project: AngrProjectSurface, block: object) -> None:
    """Emit the once-per-block complex-expr peephole skip debug line."""
    skipped = getattr(project, "_inertia_complex_block_skip_seen", None)
    if not isinstance(skipped, set):
        skipped = set()
        project._inertia_complex_block_skip_seen = skipped
    block_addr = getattr(block, "addr", None)
    if block_addr in skipped:
        return
    skipped.add(block_addr)
    if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
        print(
            "[dbg] clinic:skip-peephole-complex-block "
            f"block={block_addr:#x}{_project_current_function_context_suffix(project)}",
            file=sys.stderr,
        )
        sys.stderr.flush()


def _guarded_peephole_optimize_8616(
    state: _ClinicGuardState8616,
    project: AngrProjectSurface,
    orig_peephole_optimize: Callable[..., object],
    peephole_optimize_stmts: Callable[..., object],
    peephole_optimize_multistmts: Callable[..., object],
    self: AngrPatchSurface,
    args: tuple[typing.Any, ...],
    kwargs: dict[str, typing.Any],
) -> object:
    """Block-simplifier ``_peephole_optimize`` wrapper with fast-path bounds."""
    project._inertia_decompiler_stage = "core:clinic:peephole_optimize"
    state.peephole_count += 1
    t_start = time.perf_counter()
    try:
        block = args[0] if args else kwargs.get("block")
        _debug_clinic_flags_8616(project, block)
        if getattr(project, "_inertia_skip_clinic_simplify_block", False):
            return _clinic_peephole_capped_8616(project, block)
        if block is not None and getattr(project, "_inertia_tiny_core_disable_peephole", False):
            return block, False, False
        if block is not None and (
            getattr(project, "_inertia_fast_block_peephole", False)
            or getattr(getattr(project, "arch", None), "name", None) == "86_16"
        ):
            return _fast_block_peephole_8616(
                self, block, peephole_optimize_stmts, peephole_optimize_multistmts
            )
        if block is not None and _block_has_pathologically_complex_expr(block):
            _debug_skip_complex_block_8616(project, block)
            return _fast_block_peephole_8616(
                self, block, peephole_optimize_stmts, peephole_optimize_multistmts
            )
        return orig_peephole_optimize(self, *args, **kwargs)
    finally:
        state.record_peephole_stats(project, time.perf_counter() - t_start)


def _guarded_peephole_optimize_exprs_8616(
    project: AngrProjectSurface,
    orig_peephole_optimize_exprs: Callable[..., object],
    block: object,
    expr_opts: object,
    *args: typing.Any,
    **kwargs: typing.Any,
) -> object:
    """decompiler-utils ``peephole_optimize_exprs`` wrapper honoring skip flags."""
    if getattr(project, "_inertia_skip_clinic_simplify_block", False):
        return False
    return orig_peephole_optimize_exprs(block, expr_opts, *args, **kwargs)


class _NoPropagationResult8616:
    """Empty propagation result substituted when angr drops a Tmp definition."""

    def __init__(self) -> None:
        self.replacements: dict[object, object] = {}
        self.dead_vvar_ids: set[object] = set()
        self.model = self


def _guarded_compute_propagation_8616(
    project: AngrProjectSurface,
    orig_compute_propagation: Callable[..., object],
    refused_attr: str,
    debug_label: str,
    with_dead_vvar_ids: bool,
    tmp_types: tuple[type, ...],
    self: AngrPatchSurface,
    args: tuple[typing.Any, ...],
    kwargs: dict[str, typing.Any],
) -> object:
    """Refuse missing-Tmp propagation instead of raising through angr."""
    try:
        return orig_compute_propagation(self, *args, **kwargs)
    except KeyError as exc:
        missing = exc.args[0] if exc.args else None
        if not isinstance(missing, tmp_types):
            raise
        count = int(getattr(project, refused_attr, 0) or 0) + 1
        setattr(project, refused_attr, count)
        if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
            print(
                f"[dbg] clinic:{debug_label} "
                f"tmp={missing}{_project_current_function_context_suffix(project)}",
                file=sys.stderr,
            )
            sys.stderr.flush()
        result = _NoPropagationResult8616()
        self._propagator = result
        if with_dead_vvar_ids:
            self._propagator_dead_vvar_ids = result.dead_vvar_ids
        return result


@contextlib.contextmanager
def guard_angr_clinic_stage_markers(project: AngrProjectSurface) -> Iterator[None]:
    """Temporarily record and bound third-party angr Clinic stages."""
    from angr.ailment.expression import Tmp as AILTmp
    from angr.analyses.decompiler import utils as decompiler_utils
    from angr.analyses.decompiler.ail_simplifier import AILSimplifier
    from angr.analyses.decompiler.block_simplifier import BlockSimplifier
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.decompiler.utils import peephole_optimize_multistmts, peephole_optimize_stmts
    from angr.knowledge_plugins.key_definitions.atoms import Tmp as AtomTmp

    clinic_cls = typing.cast(AngrPatchSurface, Clinic)
    block_simplifier_cls = typing.cast(AngrPatchSurface, BlockSimplifier)
    ail_simplifier_cls = typing.cast(AngrPatchSurface, AILSimplifier)
    decompiler_utils_surface = typing.cast(AngrPatchSurface, decompiler_utils)
    orig_stage_pre_ssa = clinic_cls._stage_pre_ssa_level1_simplifications
    orig_stage_ssa_level1 = clinic_cls._stage_transform_to_ssa_level1
    orig_stage_post_ssa = clinic_cls._stage_post_ssa_level1_simplifications
    orig_stage_recover_vars = clinic_cls._stage_recover_variables
    orig_simplify_block = clinic_cls._simplify_block
    orig_block_compute_propagation = block_simplifier_cls._compute_propagation
    orig_compute_propagation = ail_simplifier_cls._compute_propagation
    orig_peephole_optimize = block_simplifier_cls._peephole_optimize
    orig_peephole_optimize_exprs = decompiler_utils_surface.peephole_optimize_exprs
    state = _ClinicGuardState8616(
        emit_logs=bool(timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"))
    )

    def _simplify_block(
        self: AngrPatchSurface,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        return _guarded_simplify_block_8616(state, project, orig_simplify_block, self, args, kwargs)

    def _peephole_optimize(
        self: AngrPatchSurface,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        return _guarded_peephole_optimize_8616(
            state,
            project,
            orig_peephole_optimize,
            peephole_optimize_stmts,
            peephole_optimize_multistmts,
            self,
            args,
            kwargs,
        )

    def _peephole_optimize_exprs_guarded(
        block: object,
        expr_opts: object,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        return _guarded_peephole_optimize_exprs_8616(
            project, orig_peephole_optimize_exprs, block, expr_opts, *args, **kwargs
        )

    def _compute_propagation_guarded(
        self: AngrPatchSurface,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        return _guarded_compute_propagation_8616(
            project,
            orig_compute_propagation,
            "_inertia_clinic_missing_tmp_propagation_refused",
            "refuse-missing-tmp-propagation",
            True,
            (AILTmp, AtomTmp),
            self,
            args,
            kwargs,
        )

    def _block_compute_propagation_guarded(
        self: AngrPatchSurface,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        return _guarded_compute_propagation_8616(
            project,
            orig_block_compute_propagation,
            "_inertia_block_missing_tmp_propagation_refused",
            "refuse-block-missing-tmp-propagation",
            False,
            (AILTmp, AtomTmp),
            self,
            args,
            kwargs,
        )

    clinic_cls._stage_pre_ssa_level1_simplifications = _clinic_stage_guard_8616(
        state,
        project,
        orig_stage_pre_ssa,
        "clinic:pre_ssa_l1",
        "core:clinic:pre_ssa_level1_simplifications",
    )
    clinic_cls._stage_transform_to_ssa_level1 = _clinic_stage_guard_8616(
        state,
        project,
        orig_stage_ssa_level1,
        "clinic:ssa_level1",
        "core:clinic:ssa_level1_transformation",
    )
    clinic_cls._stage_post_ssa_level1_simplifications = _clinic_stage_guard_8616(
        state,
        project,
        orig_stage_post_ssa,
        "clinic:post_ssa_l1",
        "core:clinic:post_ssa_level1_simplifications",
    )
    # Variable recovery is semantic materialization, not an optional
    # optimization. Resource policies may bound simplification around it,
    # but must never bypass it or invent empty recovery inputs.
    clinic_cls._stage_recover_variables = _clinic_stage_guard_8616(
        state,
        project,
        orig_stage_recover_vars,
        "clinic:recover_vars",
        "core:clinic:recover_variables",
    )
    clinic_cls._simplify_block = _simplify_block
    block_simplifier_cls._compute_propagation = _block_compute_propagation_guarded
    ail_simplifier_cls._compute_propagation = _compute_propagation_guarded
    block_simplifier_cls._peephole_optimize = _peephole_optimize
    decompiler_utils_surface.peephole_optimize_exprs = _peephole_optimize_exprs_guarded
    try:
        yield
    finally:
        clinic_cls._stage_pre_ssa_level1_simplifications = orig_stage_pre_ssa
        clinic_cls._stage_transform_to_ssa_level1 = orig_stage_ssa_level1
        clinic_cls._stage_post_ssa_level1_simplifications = orig_stage_post_ssa
        clinic_cls._stage_recover_variables = orig_stage_recover_vars
        clinic_cls._simplify_block = orig_simplify_block
        block_simplifier_cls._compute_propagation = orig_block_compute_propagation
        ail_simplifier_cls._compute_propagation = orig_compute_propagation
        block_simplifier_cls._peephole_optimize = orig_peephole_optimize
        decompiler_utils_surface.peephole_optimize_exprs = orig_peephole_optimize_exprs


@contextlib.contextmanager
def guard_angr_fast_post_ssa_8616(project: AngrProjectSurface) -> Iterator[None]:
    """Skip redundant ``_simplify_function`` calls in angr Clinic for 86_16.

    Clinic calls ``_simplify_function`` seven times across stages.  Calls 4 and 5 (0-indexed)
    are the 3rd and 4th whole-graph simplification rounds inside
    ``_stage_post_ssa_level1_simplifications``, which redundantly redo variable unification
    and expression narrowing that the x86_16 platform handles in its own structuring and
    postprocess passes.  We turn those two calls into no-ops.

    This wrapper is more robust than replacing the entire stage method because it does not
    duplicate angr's internal stage implementation — it only intercepts one leaf method.
    """
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        yield
        return

    from angr.analyses.decompiler.clinic import Clinic

    clinic_cls = typing.cast(AngrPatchSurface, Clinic)
    orig_simplify_function = clinic_cls._simplify_function
    _counter: dict[int, int] = {}  # id(instance) -> call count

    def _fast_simplify_function(
        self: AngrPatchSurface,
        ail_graph: object,
        **kwargs: typing.Any,
    ) -> object:
        c = _counter.get(id(self), 0)
        _counter[id(self)] = c + 1
        if getattr(project, "_inertia_tiny_core_aggressive_simplify", False) and c >= 1:
            return None
        # Calls 0-2 are earlier stages; calls 3 and 4 are the 3rd and 4th
        # post-SSA whole-graph rounds that 86_16 does not need.
        if c in (3, 4):
            return None
        return orig_simplify_function(self, ail_graph, **kwargs)

    clinic_cls._simplify_function = _fast_simplify_function
    try:
        yield
    finally:
        clinic_cls._simplify_function = orig_simplify_function


@contextlib.contextmanager
def guard_angr_ail_narrowing(project: AngrProjectSurface) -> Iterator[None]:
    """Temporarily allow runtime policy to disable angr AIL narrowing."""
    from angr.analyses.decompiler.ail_simplifier import AILSimplifier

    ail_simplifier_cls = typing.cast(AngrPatchSurface, AILSimplifier)
    original_narrow_exprs = ail_simplifier_cls._narrow_exprs

    def _guarded_narrow_exprs(
        self: AngrPatchSurface,
        *args: typing.Any,
        **kwargs: typing.Any,
    ) -> object:
        if getattr(project, "_inertia_disable_ail_narrowing", False):
            project._inertia_decompiler_stage = "core:clinic:narrowing-skipped"
            return False
        return original_narrow_exprs(self, *args, **kwargs)

    ail_simplifier_cls._narrow_exprs = _guarded_narrow_exprs
    try:
        yield
    finally:
        ail_simplifier_cls._narrow_exprs = original_narrow_exprs


class _ThreadStreamState(threading.local):
    """Hold the optional stream owned by one thread."""

    stream: typing.TextIO | None = None


class ThreadBoundTextIO(io.TextIOBase):
    """Delegate text output to a typed per-thread stream when one is active."""

    def __init__(self, fallback: typing.TextIO) -> None:
        self._fallback = fallback
        self._local = _ThreadStreamState()

    @contextlib.contextmanager
    def target(self, stream: typing.TextIO) -> Iterator[None]:
        """Route writes from the current thread to ``stream`` for this scope."""
        previous = self._local.stream
        self._local.stream = stream
        try:
            yield
        finally:
            self._local.stream = previous

    def _stream(self) -> typing.TextIO:
        return self._local.stream or self._fallback

    def write(self, data: str) -> int:
        """Write text to the active stream."""
        return self._stream().write(data)

    def flush(self) -> None:
        """Flush the active stream unless it has already closed."""
        with contextlib.suppress(ValueError):
            self._stream().flush()

    def isatty(self) -> bool:
        """Report whether the active stream is attached to a terminal."""
        return self._stream().isatty()

    @property
    def encoding(self) -> str:  # type: ignore[override]
        """Expose the active stream encoding with a stable fallback."""
        return self._stream().encoding or self._fallback.encoding or "utf-8"

    @property
    def errors(self) -> str | None:  # type: ignore[override]
        """Expose the active stream error policy."""
        return self._stream().errors or self._fallback.errors or "strict"

    def __getattr__(self, item: str) -> typing.Any:
        """Delegate optional text-stream APIs at the standard-library boundary."""
        return getattr(self._stream(), item)


_THREAD_STDOUT = ThreadBoundTextIO(_REAL_STDOUT)
_THREAD_STDERR = ThreadBoundTextIO(_REAL_STDERR)
sys.stdout = _THREAD_STDOUT
sys.stderr = _THREAD_STDERR


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    """Run executor workers as daemons through CPython's private pool contract."""

    def _adjust_thread_count(self) -> None:
        executor = typing.cast(AngrPatchSurface, self)
        work_queue = executor._work_queue
        if executor._idle_semaphore.acquire(timeout=0):
            return

        def weakref_cb(_reference: object, q: AngrPatchSurface = work_queue) -> None:
            q.put(None)

        num_threads = len(executor._threads)
        if num_threads < executor._max_workers:
            thread_name = "%s_%d" % (executor._thread_name_prefix or self, num_threads)  # noqa: UP031
            worker_args: tuple[object, ...]
            if hasattr(executor, "_create_worker_context"):
                worker_args = (
                    weakref.ref(self, weakref_cb),
                    executor._create_worker_context(),
                    work_queue,
                )
            else:
                worker_args = (
                    weakref.ref(self, weakref_cb),
                    work_queue,
                    executor._initializer,
                    executor._initargs,
                )
            t = threading.Thread(
                name=thread_name,
                target=_worker,
                args=worker_args,
                daemon=True,
            )
            t.start()
            executor._threads.add(t)
            thread_queues = typing.cast(MutableMapping[threading.Thread, object], _threads_queues)
            thread_queues[t] = work_queue

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        """Shut down workers and detach daemon queues when not waiting."""
        try:
            super().shutdown(wait=wait, cancel_futures=cancel_futures)
        finally:
            if not wait:
                executor = typing.cast(AngrPatchSurface, self)
                thread_queues = typing.cast(MutableMapping[threading.Thread, object], _threads_queues)
                for thread in list(executor._threads):
                    thread_queues.pop(thread, None)


def log_step(step: str) -> None:
    """Emit elapsed timing for one named runtime step."""
    global LAST_STEP_TIME
    now = time.perf_counter()
    elapsed_total = now - START_TIME
    since_last = now - LAST_STEP_TIME
    LAST_STEP_TIME = now
    timestamp = datetime.utcnow().isoformat()
    print(f"[dbg][{timestamp}] {step} (total {elapsed_total:.2f}s, +{since_last:.2f}s)")
    sys.stdout.flush()


def format_address(addr: int) -> str:
    """Format an integer address in canonical hexadecimal form."""
    return f"{addr:#x}"


class JumpkindLoggingHandler(logging.Handler):
    """Expand angr unsupported-jumpkind logs with local block diagnostics."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit one enriched unsupported-jumpkind diagnostic."""
        msg = record.getMessage()
        if "Unsupported jumpkind" in msg and "address" in msg:
            match = re.search(r"address\s+(0x[0-9a-fA-F]+|[0-9]+)", msg)
            if match and _CURRENT_PROJECT is not None and _FORMAT_FIRST_BLOCK_ASM is not None:
                try:
                    addr = int(match.group(1), 0)
                    asm = _FORMAT_FIRST_BLOCK_ASM(_CURRENT_PROJECT, addr)
                    print(f"[dbg][{datetime.utcnow().isoformat()}] NON-DECODED BLOCK {addr:#x}:\n{asm}")
                except Exception as exc:
                    print(f"[dbg] failed to format assembly for {msg}: {exc}")
            else:
                print(f"[dbg] {msg}")


def _faulthandler_output_file() -> typing.TextIO | None:
    for stream in (getattr(sys, "stderr", None), getattr(sys, "__stderr__", None)):
        if stream is None:
            continue
        try:
            stream.fileno()
        except Exception:
            continue
        return typing.cast(typing.TextIO, stream)
    return None


def _enable_thread_stack_dump_8616() -> int | None:
    """Enable periodic faulthandler stack dumps when configured via env."""
    stack_dump_raw = os.environ.get("INERTIA_THREAD_STACK_DUMP_SEC", "").strip()
    if not stack_dump_raw:
        return None
    stack_dump_sec: int | None = None
    with contextlib.suppress(Exception):
        stack_dump_sec = max(1, int(float(stack_dump_raw)))
        stack_dump_file = _faulthandler_output_file()
        if stack_dump_file is not None:
            faulthandler.enable(file=stack_dump_file, all_threads=True)
            faulthandler.dump_traceback_later(stack_dump_sec, repeat=True, file=stack_dump_file)
    return stack_dump_sec


def _daemon_thread_result_8616(
    completed: threading.Event,
    result_box: dict[str, object],
    timeout_seconds: int,
) -> object:
    """Wait for the daemon thread and return or re-raise its outcome."""
    if not completed.wait(timeout_seconds):
        raise _FuturesTimeoutError(f"Timed out after {timeout_seconds}s.")
    if result_box.get("kind") == "err":
        error = result_box.get("error")
        if isinstance(error, BaseException):
            raise error
        raise RuntimeError(f"daemon thread failed: {result_box.get('traceback')}")
    if "result" not in result_box:
        raise RuntimeError(f"daemon thread completed without result after {timeout_seconds}s")
    return result_box["result"]


def run_with_timeout_in_daemon_thread[TimeoutResultT](
    func: Callable[[], TimeoutResultT],
    *,
    timeout: int,
    thread_name_prefix: str,
    prefer_process_alarm: bool = False,
) -> TimeoutResultT:
    """Run a callable with a process alarm or daemon-thread bounded wait.

    Main-thread callers may request the process alarm when timed-out work must
    stop instead of continuing in an abandoned daemon thread.
    """
    timeout_seconds = max(1, timeout)
    if prefer_process_alarm and threading.current_thread() is threading.main_thread():
        with analysis_timeout(timeout_seconds):
            return func()
    completed = threading.Event()
    result_box: dict[str, object] = {}

    def _runner() -> None:
        try:
            result_box["result"] = func()
            result_box["kind"] = "ok"
        except BaseException as ex:
            result_box["kind"] = "err"
            result_box["error"] = ex
            result_box["traceback"] = traceback.format_exc()
        finally:
            completed.set()

    thread = threading.Thread(target=_runner, daemon=True, name=thread_name_prefix)
    thread.start()
    stack_dump_sec = _enable_thread_stack_dump_8616()
    try:
        return typing.cast(TimeoutResultT, _daemon_thread_result_8616(completed, result_box, timeout_seconds))
    finally:
        if stack_dump_sec is not None:
            with contextlib.suppress(Exception):
                faulthandler.cancel_dump_traceback_later()
        with contextlib.suppress(Exception):
            thread.join(0)


def emit_timeout_and_exit(args_timeout: int, recovery_detail: str | None) -> None:
    """Emit the CLI timeout comment and terminate with the timeout status."""
    if recovery_detail is None:
        print(f"/* Timed out while recovering a function after {args_timeout}s. */")
    else:
        print(f"/* Timed out while recovering a function after {args_timeout}s {recovery_detail}. */")
    print("/* Tip: try a larger --timeout for larger binaries. */")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(3)


def apply_memory_limit(max_memory_mb: int | None) -> None:
    """Apply a best-effort process address-space limit in megabytes."""
    if max_memory_mb is None or max_memory_mb <= 0:
        return
    limit = max_memory_mb * 1024 * 1024
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def memory_available_mb() -> int | None:
    """Read available Linux memory in megabytes when procfs is available."""
    try:
        meminfo = {}
        with open("/proc/meminfo", encoding="utf-8") as fp:
            for line in fp:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if parts:
                    meminfo[key] = int(parts[0])
        available = meminfo.get("MemAvailable")
        if available:
            return available // 1024
    except OSError:
        pass
    return None


def prefer_low_memory_path() -> bool:
    """Return whether current memory pressure requires the low-memory path."""
    available_mb = memory_available_mb()
    return available_mb is not None and available_mb < 4096


def lower_process_priority() -> None:
    """Lower process scheduling priority on hosts that support ``nice``."""
    with contextlib.suppress(AttributeError, OSError):
        os.nice(10)


def choose_function_parallelism(function_count: int) -> int:
    """Choose worker parallelism from function count, CPU, and memory evidence."""
    if function_count <= 1:
        return 1
    if os.environ.get(FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
        return 1
    if prefer_low_memory_path():
        return 1
    cpu_count = os.cpu_count() or 1
    workers = max(1, cpu_count - 1)
    available_mb = memory_available_mb()
    if available_mb is None:
        return min(workers, function_count)
    budget_mb = int(available_mb * DEFAULT_FREE_RAM_BUDGET_FRACTION)
    if budget_mb < DEFAULT_WORKER_MEMORY_FLOOR_MB:
        return 1
    workers_by_mem = max(1, budget_mb // DEFAULT_WORKER_MEMORY_FLOOR_MB)
    return min(workers, function_count, workers_by_mem)


@contextlib.contextmanager
def guard_angr_structurer_codegen_timing(project: AngrProjectSurface) -> Iterator[None]:
    """Emit per-stage timing for RecursiveStructurer, RegionSimplifier, and StructuredCodeGenerator."""
    if not timing_output_enabled():
        yield
        return
    import time as _time

    from angr.analyses.decompiler.region_simplifiers.region_simplifier import RegionSimplifier
    from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator
    from angr.analyses.decompiler.structuring.recursive_structurer import RecursiveStructurer

    orig_rs_init = RecursiveStructurer.__init__
    orig_ri_init = RegionSimplifier.__init__
    orig_codegen_init = CStructuredCodeGenerator.__init__

    def _timed_rs_init(self: typing.Any, *args: typing.Any, **kwargs: typing.Any) -> None:
        _t0 = _time.perf_counter()
        print("[dbg] stage-time: structurer:recursive start")
        sys.stderr.flush()
        try:
            orig_rs_init(self, *args, **kwargs)
            return None
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: structurer:recursive done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    def _timed_ri_init(self: typing.Any, *args: typing.Any, **kwargs: typing.Any) -> None:
        _t0 = _time.perf_counter()
        print("[dbg] stage-time: region_simplifier start")
        sys.stderr.flush()
        try:
            orig_ri_init(self, *args, **kwargs)
            return None
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: region_simplifier done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    def _timed_codegen_init(self: typing.Any, *args: typing.Any, **kwargs: typing.Any) -> None:
        _t0 = _time.perf_counter()
        print("[dbg] stage-time: codegen:C start")
        sys.stderr.flush()
        try:
            orig_codegen_init(self, *args, **kwargs)
            return None
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: codegen:C done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    RecursiveStructurer.__init__ = _timed_rs_init
    RegionSimplifier.__init__ = _timed_ri_init
    CStructuredCodeGenerator.__init__ = _timed_codegen_init
    try:
        yield
    finally:
        RecursiveStructurer.__init__ = orig_rs_init
        RegionSimplifier.__init__ = orig_ri_init
        CStructuredCodeGenerator.__init__ = orig_codegen_init


@contextlib.contextmanager
def guard_angr_tail_validation_collection_timing() -> Iterator[None]:
    """Emit timing for the tail validation 'before' collection in _decompile_structuring_8616."""
    if not timing_output_enabled():
        yield
        return
    import time as _time

    from angr_platforms.X86_16.tail_validation import (
        collect_x86_16_tail_validation_summary,
        fingerprint_x86_16_tail_validation_boundary,
    )

    wrapped_fingerprint = fingerprint_x86_16_tail_validation_boundary
    wrapped_collect = collect_x86_16_tail_validation_summary

    import angr_platforms.X86_16.decompiler_structuring_stage as _ds_mod

    orig_fingerprint = _ds_mod.fingerprint_x86_16_tail_validation_boundary
    orig_collect = _ds_mod.collect_x86_16_tail_validation_summary

    def _timed_fingerprint(project: object, codegen: object, *, mode: str) -> object:
        _t0 = _time.perf_counter()
        print("[dbg] stage-time: tail_validation:fingerprint:before start")
        sys.stderr.flush()
        try:
            return wrapped_fingerprint(project, codegen, mode=mode)
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: tail_validation:fingerprint:before done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    def _timed_collect(
        project: object,
        codegen: object,
        *,
        mode: str,
        boundary_fingerprint: str | None = None,
    ) -> object:
        _t0 = _time.perf_counter()
        print("[dbg] stage-time: tail_validation:collect:before start")
        sys.stderr.flush()
        try:
            return wrapped_collect(
                project,
                codegen,
                mode=mode,
                boundary_fingerprint=boundary_fingerprint,
            )
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: tail_validation:collect:before done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    # Patch the module that _decompile_structuring_8616 imports from.
    _ds_mod.fingerprint_x86_16_tail_validation_boundary = _timed_fingerprint
    _ds_mod.collect_x86_16_tail_validation_summary = _timed_collect
    try:
        yield
    finally:
        _ds_mod.fingerprint_x86_16_tail_validation_boundary = orig_fingerprint
        _ds_mod.collect_x86_16_tail_validation_summary = orig_collect


def _timed_stage_guard_8616(
    orig: Callable[..., object],
    label: str,
    emit_timing: bool,
) -> Callable[..., object]:
    """Build a stage wrapper that emits start/done timing lines."""

    def _timed(codegen: object, *args: typing.Any, **kwargs: typing.Any) -> object:
        t0 = time.perf_counter()
        if emit_timing:
            print(f"[dbg] stage-time: x86_16:{label} start")
            sys.stderr.flush()
        try:
            return orig(codegen, *args, **kwargs)
        finally:
            if emit_timing:
                elapsed = time.perf_counter() - t0
                print(f"[dbg] stage-time: x86_16:{label} done elapsed={elapsed:.2f}s")
                sys.stderr.flush()

    return _timed


def _bounded_stage_guard_8616(
    orig: Callable[..., object],
    budget_seconds: int,
    label: str,
    emit_timing: bool,
) -> Callable[..., object]:
    """Build a stage wrapper that refuses work after one analysis timeout."""
    timed_out = False

    def _timed(codegen: object, **kwargs: object) -> object:
        nonlocal timed_out
        if timed_out:
            return False
        t0 = time.perf_counter()
        if emit_timing:
            print(f"[dbg] stage-time: x86_16:{label} start")
            sys.stderr.flush()
        try:
            with analysis_timeout(int(budget_seconds)):
                return orig(codegen, **kwargs)
        except AnalysisTimeout:
            timed_out = True
            if emit_timing:
                elapsed = time.perf_counter() - t0
                print(
                    f"[dbg] stage-time: x86_16:{label} TIMEOUT elapsed={elapsed:.2f}s "
                    f"budget={budget_seconds}s",
                    file=sys.stderr,
                    flush=True,
                )
            return False
        finally:
            if emit_timing:
                elapsed = time.perf_counter() - t0
                print(f"[dbg] stage-time: x86_16:{label} done elapsed={elapsed:.2f}s")
                sys.stderr.flush()

    return _timed


def _install_bounded_lowering_guards_8616(emit_timing: bool) -> tuple[object, object]:
    """Patch stable-ss-linear lowering entry points with bounded-stage guards.

    Returns the ``stack_lowering_from_facts`` module and its original symbol so
    the caller can restore it; the ss-linear guard intentionally stays patched
    for the remaining fork budget.
    """
    slf_mod: object = None
    orig_slf: object = None
    try:
        import angr_platforms.X86_16.lowering.real_mode_linear as _rml_module

        rml_mod = typing.cast(AngrPatchSurface, _rml_module)
        timed_rml = _bounded_stage_guard_8616(
            rml_mod.lower_stable_ss_linear_stack_dereferences_8616,
            30,
            "lower_ss_linear_stack",
            emit_timing,
        )
        rml_mod.lower_stable_ss_linear_stack_dereferences_8616 = timed_rml
        # Also patch the import-time reference in stack_lowering.py that
        # bypasses the module-level monkey-patch (see issue with
        # "from .real_mode_linear import lower_stable_ss..." at module load).
        import angr_platforms.X86_16.lowering.stack_lowering as _sl_module

        sl_mod = typing.cast(AngrPatchSurface, _sl_module)
        sl_mod.lower_stable_ss_linear_stack_dereferences_8616 = timed_rml
    except Exception:
        pass
    try:
        import angr_platforms.X86_16.lowering.stack_lowering_from_facts as _slf_module

        slf_mod = typing.cast(AngrPatchSurface, _slf_module)
        orig_slf = slf_mod.lower_stack_accesses_from_alias_facts_8616
        slf_mod.lower_stack_accesses_from_alias_facts_8616 = _timed_stage_guard_8616(
            orig_slf, "lower_stack_from_facts", emit_timing
        )
    except Exception:
        pass
    return slf_mod, orig_slf


@contextlib.contextmanager
def guard_angr_structuring_codegen_internal_timing() -> Iterator[None]:
    """Emit timing for internal steps of _structuring_codegen_8616 before the pass loop."""
    emit_timing = timing_output_enabled()

    import angr_platforms.X86_16.decompiler_structuring_stage as _ds_mod
    import angr_platforms.X86_16.pipeline.contracts as _contracts_mod

    orig_alias = _ds_mod._assert_alias_complete_8616
    orig_contracts = _contracts_mod.assert_pipeline_contracts_8616
    _ds_mod._assert_alias_complete_8616 = _timed_stage_guard_8616(
        orig_alias, "_assert_alias_complete", emit_timing
    )
    _contracts_mod.assert_pipeline_contracts_8616 = _timed_stage_guard_8616(
        orig_contracts, "assert_pipeline_contracts", emit_timing
    )

    slf_mod, orig_slf = _install_bounded_lowering_guards_8616(emit_timing)

    try:
        yield
    finally:
        _ds_mod._assert_alias_complete_8616 = orig_alias
        _contracts_mod.assert_pipeline_contracts_8616 = orig_contracts
        # NOTE: lower_stable_ss_linear_stack_dereferences_8616 is KEPT patched
        # with the 30s bounded-stage guard.  Without this, post-decompilation
        # passes (tail_validation snapshots, recompilable storage, etc.) can
        # re-enter unconstrained lower_ss_linear walks that consume the entire
        # remaining fork budget.
        if orig_slf is not None and slf_mod is not None:
            slf_mod.lower_stack_accesses_from_alias_facts_8616 = orig_slf


def should_force_serial_supplemental_decompilation(function_count: int) -> bool:
    """Return whether supplemental decompilation must remain serial."""
    if function_count > 8:
        return False
    if prefer_low_memory_path():
        return True
    available_mb = memory_available_mb()
    if available_mb is None:
        return True
    return available_mb < (DEFAULT_WORKER_MEMORY_FLOOR_MB * 4)


@contextlib.contextmanager
def capture_thread_output() -> Iterator[tuple[io.StringIO, io.StringIO]]:
    """Capture stdout and stderr for only the current thread."""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with _THREAD_STDOUT.target(stdout_buf), _THREAD_STDERR.target(stderr_buf):
        yield stdout_buf, stderr_buf


enable_line_buffered_stdio()
