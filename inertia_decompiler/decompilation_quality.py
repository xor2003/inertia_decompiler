from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class DecompilationQualityAssessment:
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
)

_FATAL_MARKERS = frozenset(
    {
        "goto-none",
        "stack-base",
        "missing-type",
        "ellipsis-condition",
        "raw-register-frag",
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


def assess_decompiled_c_text(rendered_text: str) -> DecompilationQualityAssessment:
    """
    Classify emitted C text as acceptable or unresolved IR-shaped output.

    This is a refusal gate only. It does not infer semantics from text; it
    rejects output that still exposes raw AIL/VEX/storage internals and should
    not be presented as successful decompilation.
    """

    if not isinstance(rendered_text, str) or not rendered_text.strip():
        return DecompilationQualityAssessment(reject_as_decompiled=False, markers=())

    markers = tuple(label for label, pattern in _RAW_IR_MARKERS if pattern.search(rendered_text))
    if not markers:
        return DecompilationQualityAssessment(reject_as_decompiled=False, markers=())

    if _FATAL_MARKERS.intersection(markers):
        return DecompilationQualityAssessment(reject_as_decompiled=True, markers=markers)

    code_lines = [
        line.strip()
        for line in rendered_text.splitlines()
        if line.strip() and line.strip() not in {"{", "}"} and not line.strip().startswith(("/*", "*", "//"))
    ]
    raw_ir_line_count = sum(
        1
        for line in code_lines
        if any(pattern.search(line) for pattern in _RAW_IR_LINE_PATTERNS)
    )
    readable_line_count = max(len(code_lines), 1)
    reject = raw_ir_line_count >= 4 and raw_ir_line_count * 2 >= readable_line_count
    return DecompilationQualityAssessment(
        reject_as_decompiled=reject,
        markers=markers,
    )
