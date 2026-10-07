"""Emit file-level decompilation summaries for diagnostics and reporting.

Layer: CLI/fallback/reporting.
Responsibility: print reporting-only file summaries without changing decompiler semantics.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path, PureWindowsPath


def _summary_comment(text: str) -> str:
    return f"/* summary: {text} */"


def emit_file_decompilation_summary(
    project: object,
    metadata: object | None,
    *,
    shown_total: int,
    decompiled: int,
    failed: int,
    skipped_signature_labels: int,
    same_family_retry_stops: int = 0,
    fallback_family_labels: Sequence[str] = (),
    dead_setup_candidates: int = 0,
    dead_setup_pruned: int = 0,
    dead_setup_refused: int = 0,
    dead_setup_escaped: int = 0,
) -> None:
    """Print one reporting-only summary block for a decompilation run."""
    compiler_versions = _compiler_versions(project)
    if compiler_versions:
        print(_summary_comment(f"probable compiler versions: {', '.join(compiler_versions[:4])}"))
    signature_sources = _signature_sources(project)
    if signature_sources:
        print(_summary_comment(f"probable library/signature sources: {', '.join(signature_sources[:4])}"))
    # dynamic compatibility boundary: sidecar metadata may expose optional legacy fields.
    signature_code_addrs = len(getattr(metadata, "signature_code_addrs", ())) if metadata is not None else 0
    if signature_code_addrs:
        print(_summary_comment(f"signature-matched library functions: {signature_code_addrs}"))
    if skipped_signature_labels:
        print(_summary_comment(f"hidden signature-matched labels: {skipped_signature_labels}"))
    fallback_labels = ", ".join(fallback_family_labels) if fallback_family_labels else "none"
    print(
        _summary_comment(f"same_family_retry_stops={same_family_retry_stops} fallback_family_labels={fallback_labels}")
    )
    if any((dead_setup_candidates, dead_setup_pruned, dead_setup_refused, dead_setup_escaped)):
        print(
            _summary_comment(
                f"dead_setup_candidates={int(dead_setup_candidates)} "
                f"dead_setup_pruned={int(dead_setup_pruned)} "
                f"dead_setup_refused={int(dead_setup_refused)} "
                f"dead_setup_escaped={int(dead_setup_escaped)}"
            )
        )
    print(_summary_comment(f"shown={shown_total} decompiled={decompiled} asm_or_detail_fallback={failed}"))


def _compiler_versions(project: object) -> list[str]:
    # dynamic compatibility boundary: project carries optional reporting attributes.
    raw = getattr(project, "_inertia_signature_compiler_names", ())
    filtered: list[str] = []
    for name in raw:
        normalized = str(name).strip()
        if not normalized or normalized.lower() in {"ida flair", "v"}:
            continue
        filtered.append(normalized)
    return _stable_unique_sorted(filtered)


def _signature_sources(project: object) -> list[str]:
    values: list[str] = []
    # dynamic compatibility boundary: project carries optional reporting attributes.
    values.extend(_normalize_source_names(getattr(project, "_inertia_flair_sig_titles", ())))
    return _stable_unique_sorted(values)


def _normalize_source_names(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        looks_like_path = _looks_like_filesystem_path(text)
        if looks_like_path:
            windows_path = PureWindowsPath(text)
            candidate = windows_path.stem if windows_path.suffix else text
        else:
            path = Path(text)
            candidate = path.stem if path.suffix else text
        normalized.append(candidate)
    return normalized


def _looks_like_filesystem_path(text: str) -> bool:
    if text.startswith(("/", "\\")):
        return True
    if len(text) >= 3 and text[1] == ":" and text[2] in {"\\", "/"}:
        return True
    return "\\" in text


def _stable_unique_sorted(values: Iterable[str]) -> list[str]:
    deduped: dict[str, str] = {}
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        key = text.casefold()
        if key not in deduped or text < deduped[key]:
            deduped[key] = text
    return sorted(deduped.values(), key=lambda item: (item.casefold(), item))
