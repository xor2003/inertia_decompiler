# cython: language_level=3, infer_types=True
"""Architecture enforcement: block legacy paths in normal runs, gate final C emission.

Layer: Pipeline governance.
Responsibility: owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.

AGENTS.md rules:
- No text-based recovery on generated C
- No flattening of segmented memory
- No guessing structs, arrays, or intent
- No silent fallback
- rewrite must not do semantic recovery

This module is the single chokepoint that enforces these rules.
"""

from __future__ import annotations
import typing
import cython
import dataclasses
import builtins

__all__ = [
    "FORBIDDEN_NORMAL_PATHS",
    "assert_final_c_quality_8616",
    "assert_no_legacy_path_8616",
    "final_c_has_unreachable_call_after_return_8616",
]

import os
import re
from dataclasses import dataclass, field
from typing import Protocol, cast

from inertia.validation.validation_semantics import assert_known_call_semantics_8616

FORBIDDEN_NORMAL_PATHS: set[str] = {
    "collect_semantic_alias_facts_from_project_8616",
    "_inertia_module_alias_fact_cache",
    "apply_stack_variable_bindings_to_c_text",
    "substitute_ss_bp_dereferences_with_variables",
}


class _ArchitectureGuardProjectBoundary(Protocol):
    """External project flag surface used by architecture guards."""

    _inertia_debug_allow_legacy_paths: object


@cython.ccall
def _legacy_allowed(project: object) -> cython.bint:
    try:
        return bool(cast(_ArchitectureGuardProjectBoundary, project)._inertia_debug_allow_legacy_paths)
    except AttributeError:
        return False


@cython.ccall
def assert_no_legacy_path_8616(name: object, *, project: object = None) -> None:
    """Raise when a forbidden legacy semantic path is used in a normal run."""
    if _legacy_allowed(project):
        return
    if name in FORBIDDEN_NORMAL_PATHS:
        from .errors import PipelineHardError

        raise PipelineHardError(
            f"legacy semantic path used in normal run: {name}",
            layer="architecture",
        )


_FORBIDDEN_FINAL_C_TOKENS: tuple[str, ...] = (
    "ds << 4",
    "es << 4",
    "ss << 4",
    "*((ds << 4)",
    "*((es << 4)",
    "*((ss << 4)",
    "stack[",
)

_UNARY_NOT_SHIFT_PRECEDENCE_RE = re.compile(
    r"(?<![\w$?@])!(?:\([A-Za-z_][\w$?@]*(?:\s*\[[^\]\n]+\])?\)|[A-Za-z_][\w$?@]*(?:\s*\[[^\]\n]+\])?)"
    r"\s*(?:>>|<<)"
)


def _strip_c_comments_8616(c_text: object) -> str:
    c_text = re.sub(r"/\*.*?\*/", "", c_text, flags=re.DOTALL)
    return "\n".join(line for line in builtins.iter(c_text.splitlines()) if not line.lstrip().startswith("///"))


@cython.dataclasses.dataclass()
class _ReturnDepthScan8616:
    """Brace-depth state for the post-return call emission scan."""

    returned_depths: object = field(default_factory=set)
    pending_single_stmt_control_depths: object = field(default_factory=set)
    depth: cython.longlong = 0

    @cython.ccall
    def process_line(
        self,
        raw_line: object,
        call_re: re.Pattern[str],
        ignored_calls: object,
    ) -> cython.bint:
        """Return whether one line emits a call after a same-depth return."""
        match: object
        stripped = raw_line.strip()
        if not stripped:
            return False

        line_depth = self.depth
        controlled_by_single_stmt = line_depth in self.pending_single_stmt_control_depths
        if line_depth > 0 and line_depth in self.returned_depths:
            for match in call_re.finditer(stripped):
                name = match.group(1)
                if name not in ignored_calls:
                    return True

        self._update_control_state(stripped, line_depth, controlled_by_single_stmt)
        self._advance_depth(raw_line)
        return False

    @cython.ccall
    def _update_control_state(
        self,
        stripped: object,
        line_depth: cython.longlong,
        controlled_by_single_stmt: cython.bint,
    ) -> None:
        """Track return markers and single-statement control parents."""
        if line_depth > 0 and not controlled_by_single_stmt and re.match(r"^return\b[^;]*;", stripped):
            self.returned_depths.add(line_depth)

        if controlled_by_single_stmt:
            self.pending_single_stmt_control_depths.discard(line_depth)
        if (
            line_depth > 0
            and "{" not in stripped
            and not stripped.endswith(";")
            and re.match(r"^(?:if|else\s+if|else|for|while)\b", stripped)
        ):
            self.pending_single_stmt_control_depths.add(line_depth)

    @cython.ccall
    def _advance_depth(self, raw_line: object) -> None:
        """Apply the line's brace delta and prune stale tracked depths."""
        self.depth += raw_line.count("{") - raw_line.count("}")
        if self.depth < 0:
            self.depth = 0
        if self.returned_depths:
            self.returned_depths = {
                returned_depth for returned_depth in iter(self.returned_depths) if returned_depth <= self.depth
            }
        if self.pending_single_stmt_control_depths:
            self.pending_single_stmt_control_depths = {
                pending_depth
                for pending_depth in iter(self.pending_single_stmt_control_depths)
                if pending_depth <= self.depth
            }


@cython.ccall
def final_c_has_unreachable_call_after_return_8616(c_text: object) -> cython.bint:
    """Detect same-block call statements emitted after a terminal return.

    This is a final emission invariant, not a recovery pass.  It prevents stale
    rendered text from bypassing the structured AST that validation inspected.
    """
    raw_line: object
    if not isinstance(c_text, str) or not c_text.strip():
        return False

    text = _strip_c_comments_8616(c_text)
    call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    ignored_calls = frozenset({"if", "for", "while", "switch", "return", "sizeof"})
    scan = _ReturnDepthScan8616()

    for raw_line in text.splitlines():
        if scan.process_line(raw_line, call_re, ignored_calls):
            return True

    return False


@cython.ccall
def assert_final_c_quality_8616(c_text: object, *, function_addr: int | None = None) -> None:
    """Raise when final emitted C violates non-negotiable architecture invariants."""
    token: object
    if os.environ.get("INERTIA_DEBUG_ALLOW_FORBIDDEN_FINAL_C"):
        return
    stripped_text = _strip_c_comments_8616(c_text)
    for token in _FORBIDDEN_FINAL_C_TOKENS:
        if token in stripped_text:
            from .errors import PipelineHardError

            raise PipelineHardError(
                f"forbidden final C token leaked: {token!r}",
                layer="final_emission",
                function_addr=function_addr,
            )
    if final_c_has_unreachable_call_after_return_8616(stripped_text):
        from .errors import PipelineHardError

        raise PipelineHardError(
            "unreachable call statement leaked after return",
            layer="final_emission",
            function_addr=function_addr,
        )
    if _UNARY_NOT_SHIFT_PRECEDENCE_RE.search(stripped_text):
        from .errors import PipelineHardError

        raise PipelineHardError(
            "unary-not shift precedence leaked in final C",
            layer="final_emission",
            function_addr=function_addr,
        )
    assert_known_call_semantics_8616(c_text, function_addr=function_addr)
