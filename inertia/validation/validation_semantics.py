"""Layer: Validation.

Responsibility: assert generic semantic invariants over recovered output and pipeline state.
Forbidden: source-backed, COD-backed, or sample-specific semantic recovery.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

from inertia.pipeline.errors import PipelineHardError

__all__ = [
    "KnownCallArgKind8616",
    "KnownCallSemanticIssue8616",
    "ValidationSemanticsReport8616",
    "assert_known_call_semantics_8616",
    "check_segment_linearization_laundering_8616",
    "validate_known_call_semantics_8616",
]


class KnownCallArgKind8616(Enum):
    """Expected semantic class for one known call argument."""

    POINTER = "pointer"
    VALUE = "value"


_KNOWN_CALL_ARG_KINDS_8616: dict[str, dict[int, KnownCallArgKind8616]] = {
}

_CALL_STMT_RE_8616 = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)\s*;\s*$")
_SIMPLE_ASSIGN_RE_8616 = re.compile(
    r"^(?:[A-Za-z_]\w*(?:\s+|\s*\*\s*)+)?(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]+)\s*;\s*$"
)
_PLACEHOLDER_STACK_RE_8616 = re.compile(
    r"(?<![A-Za-z0-9_])(?:&\s*)?"
    r"(?:s_[0-9a-f]+|stack_(?!object_[0-9a-f]+\b)\w*)"
    r"(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_RAW_STACK_NAME_RE_8616 = re.compile(r"(?<![A-Za-z0-9_])s_[0-9a-f]+(?![A-Za-z0-9_])", re.IGNORECASE)
_UNRESOLVED_STACK_BASE_ACCESS_RE_8616 = re.compile(
    r"\bSEG_U(?:8|16|32)\s*\(\s*ss\s*,[^)]*\bvvar_[0-9a-f]+\b",
    re.IGNORECASE,
)
_IDENT_RE_8616 = re.compile(r"\b[A-Za-z_]\w*\b")


@dataclass(frozen=True, slots=True)
class KnownCallSemanticIssue8616:
    """Validation issue for one known call or segmented-memory invariant."""

    callee: str
    arg_index: int | None
    arg_text: str | None
    message: str


@dataclass(slots=True)
class ValidationSemanticsReport8616:
    """Counters and issues produced by final semantic validation checks."""

    checked_call_count: int = 0
    checked_arg_count: int = 0
    pointer_arg_count: int = 0
    value_arg_count: int = 0
    segment_linearization_issue_count: int = 0
    failure_count: int = 0
    issues: list[KnownCallSemanticIssue8616] = field(default_factory=list)


def _split_c_args_8616(arg_text: str) -> tuple[str, ...]:
    def _impl() -> tuple[str, ...]:
        text = str(arg_text or "").strip()
        if not text or text == "void":
            return ()
        parts: list[str] = []
        current: list[str] = []
        depth = 0
        for ch in text:
            if ch == "," and depth == 0:
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                continue
            current.append(ch)
            if ch in "([{":
                depth += 1
            elif ch in ")]}" and depth > 0:
                depth -= 1
        tail = "".join(current).strip()
        if tail:
            parts.append(tail)
        return tuple(parts)

    return _impl()


def _iter_statement_calls_8616(c_text: str) -> Iterator[tuple[str, tuple[str, ...], str]]:
    for raw_line in str(c_text or "").splitlines():
        stripped = raw_line.strip()
        if not stripped or not stripped.endswith(";"):
            continue
        if stripped.startswith(("if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(", "return ")):
            continue
        match = _CALL_STMT_RE_8616.match(stripped)
        if match is None:
            continue
        yield match.group("name"), _split_c_args_8616(match.group("args")), stripped


def _has_stack_placeholder_8616(arg_text: str) -> bool:
    text = str(arg_text or "")
    return bool(_PLACEHOLDER_STACK_RE_8616.search(text) or "&(&" in text)


def _is_pointer_like_8616(arg_text: str) -> bool:
    text = str(arg_text or "").strip()
    if not text:
        return False
    if "SEG_PTR(" in text or "MK_FP(" in text:
        return True
    return re.search(r"&\s*[A-Za-z_]\w*(?:\[[^\]]+\])?", text) is not None


def _is_value_like_8616(arg_text: str) -> bool:
    text = str(arg_text or "").strip()
    if not text:
        return False
    if _is_pointer_like_8616(text):
        return False
    if _has_stack_placeholder_8616(text):
        return False
    return not any(token in text for token in ("ds << 4", "es << 4", "ss << 4", "stack["))


def _normalized_non_preprocessor_lines_8616(c_text: str) -> tuple[str, ...]:
    lines: list[str] = []
    text = re.sub(r"/\*.*?\*/", "", str(c_text or ""), flags=re.DOTALL)
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return tuple(lines)


def _strip_comments_for_placeholder_scan_8616(c_text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", str(c_text or ""), flags=re.DOTALL)
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def _dangerous_segment_linearization_expr_8616(expr_text: str, tainted_names: set[str]) -> bool:
    text = str(expr_text or "").strip()
    if not text or any(
        helper in text
        for helper in (
            "SEG_PTR(",
            "SEG_U8(",
            "SEG_U16(",
            "SEG_U32(",
            "MK_FP(",
            "MEM_U8(",
            "MEM_U16(",
            "MEM_U32(",
        )
    ):
        return False
    lowered = text.lower()
    for name in {"ss", "ds", "es", *tainted_names}:
        escaped = re.escape(name)
        if re.search(rf"\b{escaped}\b\s*<<\s*4\b", lowered, flags=re.IGNORECASE):
            return True
        if re.search(rf"\b{escaped}\b\s*\*\s*16\b", lowered, flags=re.IGNORECASE):
            return True
        if re.search(rf"\b16\s*\*\s*\b{escaped}\b", lowered, flags=re.IGNORECASE):
            return True
    return False


def check_segment_linearization_laundering_8616(c_text: str) -> str | None:
    """Return a failure reason when segment registers leak into linear arithmetic."""
    tainted_names: set[str] = set()
    for line in _normalized_non_preprocessor_lines_8616(c_text):
        if _dangerous_segment_linearization_expr_8616(line, tainted_names):
            return "segment register value escaped into linearized arithmetic"
        match = _SIMPLE_ASSIGN_RE_8616.match(line)
        if match is None:
            continue
        lhs = match.group("lhs")
        rhs = match.group("rhs").strip()
        rhs_lower = rhs.lower()
        if rhs_lower in {"ss", "ds", "es"}:
            tainted_names.add(lhs.lower())
            continue
        if re.fullmatch(r"\(?\s*[A-Za-z_]\w*\s*\)?", rhs):
            rhs_name = rhs.strip("() ").lower()
            if rhs_name in tainted_names:
                tainted_names.add(lhs.lower())
                continue
        if _dangerous_segment_linearization_expr_8616(rhs, tainted_names):
            return "segment register value escaped into linearized arithmetic"
        tainted_names.discard(lhs.lower())
    return None


def _record_issue_8616(
    report: ValidationSemanticsReport8616,
    *,
    callee: str,
    arg_index: int | None,
    arg_text: str | None,
    message: str,
) -> None:
    if "segment register value escaped into linearized arithmetic" in message:
        report.segment_linearization_issue_count += 1
    report.failure_count += 1
    report.issues.append(
        KnownCallSemanticIssue8616(
            callee=callee,
            arg_index=arg_index,
            arg_text=arg_text,
            message=message,
        )
    )


def _validate_known_call_arg_kinds_8616(
    report: ValidationSemanticsReport8616,
    *,
    callee: str,
    args: tuple[str, ...],
) -> None:
    kinds = _KNOWN_CALL_ARG_KINDS_8616.get(callee)
    if not kinds:
        return
    report.checked_call_count += 1
    for arg_index, kind in sorted(kinds.items()):
        if arg_index >= len(args):
            _record_issue_8616(
                report,
                callee=callee,
                arg_index=arg_index,
                arg_text=None,
                message=f"{callee} missing argument {arg_index}",
            )
            continue
        arg_text = args[arg_index]
        report.checked_arg_count += 1
        if kind is KnownCallArgKind8616.POINTER:
            report.pointer_arg_count += 1
            if not _is_pointer_like_8616(arg_text) or _has_stack_placeholder_8616(arg_text):
                _record_issue_8616(
                    report,
                    callee=callee,
                    arg_index=arg_index,
                    arg_text=arg_text,
                    message=f"{callee} arg{arg_index} must stay pointer-like",
                )
        elif kind is KnownCallArgKind8616.VALUE:
            report.value_arg_count += 1
            if not _is_value_like_8616(arg_text):
                _record_issue_8616(
                    report,
                    callee=callee,
                    arg_index=arg_index,
                    arg_text=arg_text,
                    message=f"{callee} arg{arg_index} must stay value-like",
                )


def validate_known_call_semantics_8616(
    c_text: str,
    *,
    function_addr: int | None = None,
) -> ValidationSemanticsReport8616:
    """Validate final C text against generic known-call semantic contracts."""
    _ = function_addr
    report = ValidationSemanticsReport8616()
    segment_laundering_issue = check_segment_linearization_laundering_8616(c_text)
    if segment_laundering_issue is not None:
        _record_issue_8616(
            report,
            callee="segmented_memory",
            arg_index=None,
            arg_text=None,
            message=segment_laundering_issue,
        )
    for callee, args, _line in _iter_statement_calls_8616(c_text):
        _validate_known_call_arg_kinds_8616(report, callee=callee, args=args)
    return report


def assert_known_call_semantics_8616(c_text: str, *, function_addr: int | None = None) -> None:
    """Raise a hard pipeline failure when final C violates semantic contracts."""
    report = validate_known_call_semantics_8616(c_text, function_addr=function_addr)
    semantic_text = _strip_comments_for_placeholder_scan_8616(c_text)
    if (
        _RAW_STACK_NAME_RE_8616.search(semantic_text) is not None
        or _PLACEHOLDER_STACK_RE_8616.search(semantic_text) is not None
        or _UNRESOLVED_STACK_BASE_ACCESS_RE_8616.search(semantic_text) is not None
    ):
        raise PipelineHardError(
            "function leaked unresolved stack locals into final C",
            layer="final_emission_semantics",
            function_addr=function_addr,
        )
    if report.failure_count <= 0:
        return
    first = report.issues[0]
    detail = first.message
    if first.arg_text:
        detail = f"{detail}: {first.arg_text}"
    raise PipelineHardError(
        detail,
        layer="final_emission_semantics",
        function_addr=function_addr,
    )
