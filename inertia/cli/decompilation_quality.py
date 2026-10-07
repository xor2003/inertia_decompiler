"""Refusal gates for unresolved decompiler output.

Layer: CLI/fallback/reporting.
Responsibility: owns final-output refusal checks for unresolved decompiler text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DecompilationQualityAssessment:
    """Final-output quality verdict and the markers that triggered it."""

    reject_as_decompiled: bool
    markers: tuple[str, ...]


_RAW_IR_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("store-op", re.compile(r"\bSTORE\s*\(addr=")),
    ("load-op", re.compile(r"\bLoad\s*\(addr=")),
    ("conv-op", re.compile(r"\bConv\s*\(")),
    ("raw-endness", re.compile(r"\bIend_LE\b")),
    ("raw-guard", re.compile(r"\bguard=None\b")),
    ("goto-none", re.compile(r"\bGoto None\b")),
    ("stack-base", re.compile(r"\bstack_base(?:[+-]\d+)?\b")),
    ("raw-reference", re.compile(r"\bReference\s+vvar_\d+")),
    ("missing-type", re.compile(r"<missing-type>")),
    ("ellipsis-condition", re.compile(r"\bif\s*\(\s*\.\.\.\s*\)")),
    ("raw-register-frag", re.compile(r"\b[a-z_]\w*\{r\d+\|\d+b\}")),
    ("unresolved-callee-namespace", re.compile(r"::0x[0-9a-fA-F]+::[A-Za-z_]\w*")),
    ("stack-pointer-address-escape", re.compile(r"=\s*&sp_0\s*;")),
    ("stack-base-return-escape", re.compile(r"\breturn\s+(?:&\s*)?(?:sp|bp)_0\s*;")),
)

_FATAL_MARKERS = frozenset(
    {
        "goto-none",
        "missing-type",
        "ellipsis-condition",
        "unresolved-callee-namespace",
        "stack-base",
        "stack-base-return-escape",
    }
)

_RAW_IR_LINE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bSTORE\s*\(addr="),
    re.compile(r"\bLoad\s*\(addr="),
    re.compile(r"\bReference\s+vvar_\d+"),
    re.compile(r"\bConv\s*\("),
    re.compile(r"\bIend_LE\b"),
    re.compile(r"\bguard=None\b"),
    re.compile(r"\bstack_base(?:[+-]\d+)?\b"),
    re.compile(r"\bGoto None\b"),
)


_FINAL_OUTPUT_LEAKAGE_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("expr-cycle", re.compile(r"\bexpr_cycle\b")),
    ("raw-ds-segmented-access", re.compile(r"\b(?:SEG_PTR|SEG_U8|SEG_U16|SEG_U32|MK_FP)\s*\(\s*ds\s*,")),
    ("raw-ss-segmented-access", re.compile(r"\b(?:SEG_PTR|SEG_U8|SEG_U16|SEG_U32|MK_FP)\s*\(\s*ss\s*,")),
    ("raw-memory-symbol", re.compile(r"\bmem_[0-9a-fA-F]{4,}\b")),
)

_VIRTUAL_TEMP_RE = re.compile(r"\bvvar_\d+\b")
_VIRTUAL_TEMP_DECL_RE = re.compile(
    r"^\s*(?!(?:return|case|goto|if|while|for|switch)\b)"
    r"(?:[A-Za-z_]\w*\s+)+(?:\*+\s*)?(?P<name>vvar_\d+)"
    r"(?:\s*\[[^\]]+\])?\s*(?:=[^;]*)?;\s*$"
)

_BP_STACK_LOCAL_DECL_RE = re.compile(
    r"^\s*(?!extern\b|typedef\b|return\b)(?:[A-Za-z_]\w*(?:\s+|\s*\*)+)+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*=\s*[^;]+)?\s*;\s*//\s*\[bp-0x[0-9a-fA-F]+\]"
)


def _bp_stack_locals_read_without_assignment(rendered_text: str) -> tuple[str, ...]:
    """Return named BP locals that are read but never assigned.

    This is a final quality gate, not semantic recovery. A stack local that
    survives as a named C variable must have its defining store materialized by
    lowering; otherwise validation can appear clean while emitted C still reads
    an uninitialized recovered local.
    """
    locals_: list[str] = []
    code_lines = _code_only_text(rendered_text).splitlines()
    for line in code_lines:
        match = _BP_STACK_LOCAL_DECL_RE.match(line)
        if match is not None:
            locals_.append(match.group("name"))
    if not locals_:
        return ()

    body_without_decls = "\n".join(line for line in code_lines if _BP_STACK_LOCAL_DECL_RE.match(line) is None)
    missing: list[str] = []
    for name in locals_:
        name_re = re.compile(rf"\b{re.escape(name)}\b")
        if not name_re.search(body_without_decls):
            continue
        assignment_re = re.compile(
            rf"(?:\b{re.escape(name)}\s*(?:[+\-*/%&|^]?=|\+\+|--)|(?:\+\+|--)\s*{re.escape(name)}\b)"
        )
        if assignment_re.search(body_without_decls):
            continue
        address_taken_re = re.compile(rf"(?:&\s*{re.escape(name)}\b|\b{re.escape(name)}\s*(?:\+|\[))")
        if address_taken_re.search(body_without_decls):
            continue
        missing.append(name)
    return tuple(missing)


def _code_only_text(rendered_text: str) -> str:
    code_lines = [
        line.strip()
        for line in rendered_text.splitlines()
        if line.strip() and line.strip() not in {"{", "}"} and not line.strip().startswith(("/*", "*", "//"))
    ]
    return "\n".join(code_lines)


def _unresolved_virtual_temporaries(code_only_text: str) -> tuple[str, ...]:
    """Return virtual-temp names referenced without an emitted C declaration."""
    referenced = set(_VIRTUAL_TEMP_RE.findall(code_only_text))
    declared = {
        match.group("name")
        for line in code_only_text.splitlines()
        if (match := _VIRTUAL_TEMP_DECL_RE.match(line)) is not None
    }
    return tuple(sorted(referenced - declared))


def assess_decompiled_c_text(rendered_text: str) -> DecompilationQualityAssessment:
    """Classify emitted C text as acceptable or unresolved IR-shaped output."""

    def _impl() -> DecompilationQualityAssessment:
        if not isinstance(rendered_text, str) or not rendered_text.strip():
            return DecompilationQualityAssessment(reject_as_decompiled=False, markers=())

        code_only_text = _code_only_text(rendered_text)
        code_lines = code_only_text.splitlines()
        markers = tuple(label for label, pattern in _RAW_IR_MARKERS if pattern.search(code_only_text))
        if not markers:
            return DecompilationQualityAssessment(reject_as_decompiled=False, markers=())

        if _FATAL_MARKERS.intersection(markers):
            return DecompilationQualityAssessment(reject_as_decompiled=True, markers=markers)

        raw_ir_line_count = sum(
            1 for line in code_lines if any(pattern.search(line) for pattern in _RAW_IR_LINE_PATTERNS)
        )
        readable_line_count = max(len(code_lines), 1)
        reject = raw_ir_line_count >= 4 and raw_ir_line_count * 2 >= readable_line_count
        return DecompilationQualityAssessment(
            reject_as_decompiled=reject,
            markers=markers,
        )

    return _impl()


def assess_final_generated_c_text(rendered_text: str) -> DecompilationQualityAssessment:
    """Refuse final generated C that still exposes unresolved recovery state.

    The generic quality gate intentionally allows some ugly but honest C during
    intermediate diagnostics. Final emitted C cannot expose unresolved
    undeclared temporaries, raw segmented accesses, or named stack locals whose
    stores were not materialized before rewrite. Declared generic temporaries
    remain readability debt, but cannot suppress validated recompilable C.
    """
    base = assess_decompiled_c_text(rendered_text)
    if base.reject_as_decompiled:
        return base
    if not isinstance(rendered_text, str) or not rendered_text.strip():
        return DecompilationQualityAssessment(reject_as_decompiled=False, markers=())

    code_only_text = _code_only_text(rendered_text)
    markers = [label for label, pattern in _FINAL_OUTPUT_LEAKAGE_MARKERS if pattern.search(code_only_text)]
    if _unresolved_virtual_temporaries(code_only_text):
        markers.append("unresolved-vvar")
    if _bp_stack_locals_read_without_assignment(rendered_text):
        markers.append("unassigned-stack-local")
    return DecompilationQualityAssessment(
        reject_as_decompiled=bool(markers),
        markers=tuple(markers),
    )
