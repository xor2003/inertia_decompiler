"""Structuring-owned loop-exit return guard repair.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Responsibility: convert proven loop-local ``if (exit) return;`` guards into
``if (exit) break;`` when the enclosing function tail has only empty return
flow. This module may inspect dynamic angr C AST nodes, but it must not use
rendered C text, source declarations, alias recovery, or validation policy.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CWhileLoop,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callee_name_normalization import normalize_callee_name_8616

_RUNTIME_SEGMENT_HELPERS_8616 = frozenset(
    {"SEG_U8", "SEG_U16", "SEG_U32", "MK_FP", "SEG_PTR", "MEM_U8", "MEM_U16", "MEM_U32"}
)

type LoopExitGuardStats8616 = dict[str, int]


class _LoopExitGuardCodegenLike8616(Protocol):
    """Structural view of dynamic angr/codegen state used by loop-exit guard repair."""

    cfunc: object
    _inertia_loop_exit_guard_stats_8616: LoopExitGuardStats8616


class _CFunctionStatementsLike8616(Protocol):
    """Structural view of a dynamic angr/codegen C function statement root."""

    statements: list[object]


@dataclass(frozen=True, slots=True)
class LoopExitReturnGuardCallbacks8616:
    """Dynamic adapters for classifying calls inside loop-exit return guards."""

    is_runtime_segment_helper_call: Callable[[CFunctionCall], bool]
    call_node_name: Callable[[CFunctionCall], str | None]


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Dynamic boundary: read optional angr/codegen C AST attributes."""
    return getattr(obj, name, default)


def _dynamic_sequence_8616(obj: object) -> tuple[object, ...]:
    """Return a tuple from a dynamic angr/codegen boundary sequence-like object."""
    if isinstance(obj, tuple):
        return obj
    if isinstance(obj, list):
        return tuple(obj)
    return ()


def _dynamic_int_8616(obj: object, default: int = -1) -> int:
    """Return an int from a dynamic angr/codegen boundary value."""
    return obj if isinstance(obj, int) else default


def call_node_name_8616(node: CFunctionCall) -> str | None:
    """Return a normalized C AST call target name for loop-guard classification."""
    callee_func = _dynamic_attr_8616(node, "callee_func", None)
    for raw in (
        _dynamic_attr_8616(callee_func, "name", None),
        _dynamic_attr_8616(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw if isinstance(raw, str) else None)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def is_runtime_segment_helper_call_8616(node: CFunctionCall) -> bool:
    """Return whether a C AST call is a generated segmented-memory helper."""
    tags = _dynamic_attr_8616(node, "tags", None)
    marker_name = tags.get("inertia_x86_16_runtime_segment_helper") if isinstance(tags, dict) else None
    if isinstance(marker_name, str) and marker_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616:
        return True
    call_name = call_node_name_8616(node)
    return isinstance(call_name, str) and call_name.upper() in _RUNTIME_SEGMENT_HELPERS_8616


def default_loop_exit_return_guard_callbacks_8616() -> LoopExitReturnGuardCallbacks8616:
    """Build default dynamic callbacks for loop-exit return guard repair."""
    return LoopExitReturnGuardCallbacks8616(
        is_runtime_segment_helper_call=is_runtime_segment_helper_call_8616,
        call_node_name=call_node_name_8616,
    )


def _emptyish_loop_guard_else_node_8616(node: object) -> bool:
    """Return whether a dynamic C AST else-node has no control-flow semantics."""
    if not isinstance(node, CStatements):
        return False
    statements = list(_dynamic_sequence_8616(_dynamic_attr_8616(node, "statements", ())))
    for child in statements:
        if not isinstance(child, CStatements) or not _emptyish_loop_guard_else_node_8616(child):
            return False
    return True


def _log_guard_debug_8616(enabled: object, message: str, *args: object) -> None:
    """Emit one loop-guard debug line when the env flag is set."""
    if enabled:
        logging.getLogger(__name__).warning("[loop-guard-debug] " + message, *args)


def _guard_body_statements_8616(body: object, debug: object) -> list[object] | None:
    """Return the single return body of one guard arm, or refuse."""
    if isinstance(body, CStatements):
        return list(_dynamic_sequence_8616(_dynamic_attr_8616(body, "statements", ())))
    if isinstance(body, CReturn):
        return [body]
    _log_guard_debug_8616(debug, "extract-if-guard reject-body-type=%s", type(body).__name__)
    return None


def _else_node_rejected_8616(else_node: object, debug: object) -> bool:
    """Return whether a guard else-node carries real control flow."""
    if (
        else_node is None
        or isinstance(else_node, CBreak)
        or _emptyish_loop_guard_else_node_8616(else_node)
    ):
        return False
    else_statements = list(_dynamic_sequence_8616(_dynamic_attr_8616(else_node, "statements", ())))
    _log_guard_debug_8616(
        debug,
        "extract-if-guard reject-non-empty-else len=%d kinds=%r",
        len(else_statements),
        [type(child).__name__ for child in else_statements],
    )
    return True


def _extract_if_return_guard_8616(stmt: object) -> object | None:
    """Extract the condition from ``if (cond) return;`` loop-exit guard shapes."""
    debug = os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD")
    _log_guard_debug_8616(debug, "extract-if-guard node=%s", type(stmt).__name__)
    if not isinstance(stmt, CIfElse):
        return None
    cond_nodes = _dynamic_sequence_8616(_dynamic_attr_8616(stmt, "condition_and_nodes", None))
    if len(cond_nodes) != 1:
        _log_guard_debug_8616(debug, "extract-if-guard reject-cond-count=%d", len(cond_nodes))
        return None

    cond_body = cond_nodes[0]
    if not isinstance(cond_body, tuple) or len(cond_body) != 2:
        _log_guard_debug_8616(debug, "extract-if-guard reject-cond-shape=%s", type(cond_body).__name__)
        return None
    cond, body = cond_body
    body_statements = _guard_body_statements_8616(body, debug)
    if body_statements is None:
        return None

    if len(body_statements) != 1 or not isinstance(body_statements[0], CReturn):
        _log_guard_debug_8616(debug, "extract-if-guard reject-body-kind=%s len=%d", type(body).__name__, len(body_statements))
        return None
    if _dynamic_attr_8616(body_statements[0], "retval", None) is not None:
        _log_guard_debug_8616(debug, "extract-if-guard reject-return-value=%r", _dynamic_attr_8616(body_statements[0], "retval", None))
        return None

    else_node = _dynamic_attr_8616(stmt, "else_node", None)
    if _else_node_rejected_8616(else_node, debug):
        return None

    _log_guard_debug_8616(debug, "extract-if-guard accepted")
    return cast(object | None, cond)


def _loop_call_nodes_8616(
    statements: Sequence[object],
    callbacks: LoopExitReturnGuardCallbacks8616,
    debug_all: bool,
    logger: logging.Logger,
) -> Iterator[tuple[int, CFunctionCall]]:
    """Yield non-runtime-helper calls with their owning statement index."""
    for stmt_idx, stmt in enumerate(statements):
        for node in _iter_c_nodes_deep_8616(stmt):
            if not isinstance(node, CFunctionCall):
                continue
            if callbacks.is_runtime_segment_helper_call(node):
                if debug_all:
                    logger.warning(
                        "[loop-guard-debug] callable-scan-skip-helper stmt=%d call=%s",
                        stmt_idx,
                        callbacks.call_node_name(node),
                    )
                continue
            yield stmt_idx, node


def _has_callable_after_guard_8616(
    statements: Sequence[object],
    start_idx: int,
    callbacks: LoopExitReturnGuardCallbacks8616,
) -> bool:
    """Return whether a loop body has a non-runtime helper call after a guard."""
    debug_all = os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD_DEBUG_ALL", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    logger = logging.getLogger(__name__)

    for stmt_idx, node in _loop_call_nodes_8616(statements, callbacks, debug_all, logger):
        if stmt_idx <= start_idx:
            continue
        if debug_all:
            logger.warning(
                "[loop-guard-debug] callable-after-call stmt=%d call=%s",
                stmt_idx,
                callbacks.call_node_name(node),
            )
        return True

    observed_user_calls: list[tuple[int, CFunctionCall]] = []
    for stmt_idx, node in _loop_call_nodes_8616(statements, callbacks, debug_all, logger):
        observed_user_calls.append((stmt_idx, node))
        if debug_all:
            logger.warning(
                "[loop-guard-debug] callable-fallback-call stmt=%d call=%s",
                stmt_idx,
                callbacks.call_node_name(node),
            )
    if observed_user_calls:
        return True

    if debug_all:
        logger.warning("[loop-guard-debug] callable-fallback-no-user-call start_idx=%d", start_idx)
    return False


def _post_loop_only_returns_8616(statements: Sequence[object], loop_idx: int) -> bool:
    """Return whether control after a loop is only empty return/break flow."""
    for stmt in statements[loop_idx + 1 :]:
        if isinstance(stmt, CReturn) and _dynamic_attr_8616(stmt, "retval", None) is None:
            continue
        if isinstance(stmt, CBreak):
            continue
        return False
    return True


def _debug_all_guard_enabled_8616() -> bool:
    """Return whether the exhaustive loop-guard debug flag is set."""
    return os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD_DEBUG_ALL", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@dataclass(slots=True)
class _LoopExitGuardRepair8616:
    """Shared state for the loop-exit return-guard repair pass."""

    codegen: object
    callbacks: LoopExitReturnGuardCallbacks8616
    cfunc: object
    root_statements: list[object]
    stats: LoopExitGuardStats8616
    debug: object
    debug_all: bool

    def log_debug(self, message: str, *args: object) -> None:
        """Emit one loop-guard debug line when the env flag is set."""
        _log_guard_debug_8616(self.debug, message, *args)

    def _dump_loop_body_8616(self, body_statements: list[object]) -> None:
        """Debug-dump per-statement call kinds inside one loop body."""
        loop_calls: list[str] = []
        for stmt_idx, stmt in enumerate(body_statements):
            stmt_calls = 0
            for node in _iter_c_nodes_deep_8616(stmt):
                if isinstance(node, CFunctionCall):
                    loop_calls.append(type(node).__name__)
                    stmt_calls += 1
            self.log_debug(
                "loop-body-stmt-dump idx=%d kind=%s call_count=%d text=%r",
                stmt_idx,
                type(stmt).__name__,
                stmt_calls,
                str(stmt)[:220],
            )
        if loop_calls:
            self.log_debug("loop-body-call-kinds=%r", loop_calls)

    def _log_loop_addr_8616(
        self,
        loop_node: object,
        body_statements: list[object],
    ) -> None:
        """Debug-log one loop boundary address and body size."""
        if_code_addr = _dynamic_attr_8616(loop_node, "addr", None)
        if if_code_addr is None:
            condition = _dynamic_attr_8616(loop_node, "condition", None)
            if_code_addr = _dynamic_attr_8616(condition, "addr", -1)
        self.log_debug(
            "inspect-loop addr=%#x kind=%s body_len=%d",
            if_code_addr if isinstance(if_code_addr, int) else -1,
            type(loop_node).__name__,
            len(body_statements),
        )

    def _repair_guard_8616(
        self,
        candidate: object,
        guard_idx: int,
        body_statements: list[object],
        loop_body: CStatements,
        loop_idx: int,
    ) -> bool:
        """Repair one proven loop-exit return guard into a break."""
        guard_cond = _extract_if_return_guard_8616(candidate)
        if guard_cond is None:
            self.log_debug(
                "loop-body-stmt-miss kind=%s idx=%d node=%s",
                hex(_dynamic_int_8616(_dynamic_attr_8616(self.cfunc, "addr", -1))),
                guard_idx,
                type(candidate).__name__,
            )
            if self.debug_all:
                self.stats["candidate_node_mismatch"] += 1
            return False
        self.stats["candidates"] += 1
        self.log_debug(
            "loop-body-guard-candidate idx=%d func=%#x cond=%r",
            guard_idx,
            _dynamic_attr_8616(self.cfunc, "addr", -1),
            guard_cond,
        )
        if not _has_callable_after_guard_8616(body_statements, guard_idx, self.callbacks):
            self.stats["refused_no_call"] += 1
            self.log_debug(
                "loop-body-guard-refused-no-call idx=%d func=%#x",
                guard_idx,
                _dynamic_attr_8616(self.cfunc, "addr", -1),
            )
            return False
        if not _post_loop_only_returns_8616(self.root_statements, loop_idx):
            self.stats["refused_post_loop_flow"] += 1
            self.log_debug(
                "loop-body-guard-refused-postflow idx=%d func=%#x",
                guard_idx,
                _dynamic_attr_8616(self.cfunc, "addr", -1),
            )
            return False
        body_statements[guard_idx] = CIfBreak(guard_cond, codegen=self.codegen, cstyle_ifs=True)
        loop_body.statements = body_statements
        self.stats["repaired"] += 1
        self.stats["preserved_exit_polarity"] = self.stats.get("preserved_exit_polarity", 0) + 1
        self.log_debug(
            "loop-body-guard-repaired-preserve-exit-polarity idx=%d func=%#x",
            guard_idx,
            _dynamic_attr_8616(self.cfunc, "addr", -1),
        )
        return True

    def repair_loop(self, loop_node: object, loop_idx: int) -> bool:
        """Repair the first proven exit-return guard inside one loop body."""
        loop_body = _dynamic_attr_8616(loop_node, "body", None)
        if not isinstance(loop_body, CStatements):
            return False
        body_statements = list(_dynamic_sequence_8616(_dynamic_attr_8616(loop_body, "statements", ())))
        if len(body_statements) < 1:
            return False
        self._dump_loop_body_8616(body_statements)
        self._log_loop_addr_8616(loop_node, body_statements)
        for guard_idx, candidate in enumerate(body_statements):
            if self._repair_guard_8616(
                candidate, guard_idx, body_statements, loop_body, loop_idx,
            ):
                return True
        loop_body.statements = body_statements
        return False


def repair_loop_exit_return_guards_8616(
    codegen: object,
    callbacks: LoopExitReturnGuardCallbacks8616,
) -> bool:
    """Convert proven loop-local ``if (exit) return;`` guards into breaks."""
    typed_codegen = cast(_LoopExitGuardCodegenLike8616, codegen)
    cfunc = _dynamic_attr_8616(typed_codegen, "cfunc", None)
    if cfunc is None:
        return False

    root = _dynamic_attr_8616(cfunc, "statements", None)
    if not isinstance(root, (list, tuple, CStatements)):
        return False

    stats = _dynamic_attr_8616(codegen, "_inertia_loop_exit_guard_stats_8616", None)
    if not isinstance(stats, dict):
        stats = {
            "candidates": 0,
            "repaired": 0,
            "preserved_exit_polarity": 0,
            "refused_no_call": 0,
            "refused_post_loop_flow": 0,
            "candidate_node_mismatch": 0,
        }
        typed_codegen._inertia_loop_exit_guard_stats_8616 = stats

    changed = False
    root_statements = (
        list(_dynamic_sequence_8616(_dynamic_attr_8616(root, "statements", ())))
        if isinstance(root, CStatements)
        else list(root)
    )
    repair = _LoopExitGuardRepair8616(
        codegen=codegen,
        callbacks=callbacks,
        cfunc=cfunc,
        root_statements=root_statements,
        stats=cast(LoopExitGuardStats8616, stats),
        debug=os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD"),
        debug_all=_debug_all_guard_enabled_8616(),
    )
    for idx, stmt in enumerate(tuple(root_statements)):
        if isinstance(stmt, (CForLoop, CWhileLoop, CDoWhileLoop)) and repair.repair_loop(stmt, idx):
            changed = True
    if not changed:
        return False

    if isinstance(root, CStatements):
        root.statements = root_statements
    else:
        cfunc_root = cast(_CFunctionStatementsLike8616, typed_codegen.cfunc)
        cfunc_root.statements = root_statements
    return True
