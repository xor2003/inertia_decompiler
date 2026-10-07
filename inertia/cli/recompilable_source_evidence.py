"""Layer: Recompilable output.

Responsibility: preserve legacy evidence helpers as inert compatibility surfaces.
Forbidden: source-backed generated-C fallback, validation, persistence, or repair.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

import re
from pathlib import Path

from .recompilable_cases import RecompilableSubsetCase

__all__ = [
    "load_or_build_recompilable_source_evidence",
]


_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVIDENCE_SUBSET_ROOT = _REPO_ROOT / ".codex_automation" / "evidence_subset" / "cod"


def _evidence_dec_path(case: RecompilableSubsetCase) -> Path | None:
    if case.cod_path is None:
        return None
    cod_root = _REPO_ROOT / "cod"
    try:
        rel_path = case.cod_path.resolve().relative_to(cod_root)
    except ValueError:
        return None
    return (_EVIDENCE_SUBSET_ROOT / rel_path).with_suffix(".dec")


def _extract_source_function_lines(source_lines: tuple[str, ...], proc_name: str) -> tuple[str, ...]:
    bare_name = proc_name.lstrip("_")
    start_index = next(
        (
            idx
            for idx, line in enumerate(source_lines)
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(bare_name)}\s*\(", line)
        ),
        None,
    )
    if start_index is None:
        return ()

    collected: list[str] = []
    depth = 0
    saw_open = False
    for line in source_lines[start_index:]:
        collected.append(line.rstrip())
        depth += line.count("{")
        if "{" in line:
            saw_open = True
        depth -= line.count("}")
        if saw_open and depth <= 0:
            break
    if saw_open and depth > 0:
        collected.append("}")
    return tuple(collected)


def _normalize_source_evidence_text(text: str, *, proc_name: str | None = None) -> str:
    normalized = text
    normalized = re.sub(r"(?m)^static\s+int\s+loadprog\(", "int loadprog(", normalized)
    if proc_name:
        bare_name = proc_name.lstrip("_")
        normalized = re.sub(
            rf"(?m)^((?:static\s+)?(?:(?:unsigned short|int|void)\s+)?)"
            rf"{re.escape(bare_name)}\(",
            rf"\1{proc_name}(",
            normalized,
            count=1,
        )
    normalized = normalized.replace("const uint16 ", "unsigned short ")
    normalized = normalized.replace("uint16 ", "unsigned short ")
    normalized = normalized.replace("const uint8 ", "unsigned short ")
    normalized = normalized.replace("uint8 ", "unsigned short ")
    normalized = normalized.replace("const char FAR*", "const char *")
    normalized = normalized.replace("const char FAR *", "const char *")
    normalized = normalized.replace("const char* ", "const char *")
    normalized = normalized.replace("const char * ", "const char *")
    normalized = normalized.replace("unsigned short FAR *", "unsigned short *")
    normalized = normalized.replace("MK_FP(SEG_LOWMEM, OFF_BDA_KEYFLAGS)", "MK_FP(0x40, 0x17)")
    normalized = re.sub(r";\s*Line\s+\d+\s*$", "", normalized, flags=re.MULTILINE)
    normalized = re.sub(r"\btype\b", "mode", normalized)
    normalized = re.sub(
        r"if \(\((?P<lhs>[A-Za-z_]\w*) = (?P<rhs>.+?)\) != 0\)\s*\n\s*return (?P=lhs);",
        r"\g<lhs> = \g<rhs>;\nif (\g<lhs>) return \g<lhs>;",
        normalized,
    )
    return normalized


def load_or_build_recompilable_source_evidence(case: RecompilableSubsetCase) -> tuple[str | None, Path | None]:
    """Return the legacy evidence path while refusing to load or persist source text."""
    evidence_path = _evidence_dec_path(case)
    return None, evidence_path
