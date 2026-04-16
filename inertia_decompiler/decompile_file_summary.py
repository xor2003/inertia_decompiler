from __future__ import annotations

from pathlib import Path
from typing import Iterable


def emit_file_decompilation_summary(
    project,
    metadata,
    *,
    shown_total: int,
    decompiled: int,
    failed: int,
    skipped_signature_labels: int,
) -> None:
    compiler_versions = _compiler_versions(project)
    if compiler_versions:
        print(f"summary: probable compiler versions: {', '.join(compiler_versions[:4])}")
    signature_sources = _signature_sources(project)
    if signature_sources:
        print(f"summary: probable library/signature sources: {', '.join(signature_sources[:4])}")
    signature_code_addrs = len(getattr(metadata, "signature_code_addrs", ())) if metadata is not None else 0
    if signature_code_addrs:
        print(f"summary: signature-matched library functions: {signature_code_addrs}")
    if skipped_signature_labels:
        print(f"summary: hidden signature-matched labels: {skipped_signature_labels}")
    print(f"summary: shown={shown_total} decompiled={decompiled} asm_or_detail_fallback={failed}")


def _compiler_versions(project) -> list[str]:
    raw = getattr(project, "_inertia_signature_compiler_names", ())
    filtered: list[str] = []
    for name in raw:
        normalized = str(name).strip()
        if not normalized or normalized.lower() in {"ida flair", "v"}:
            continue
        if normalized not in filtered:
            filtered.append(normalized)
    return filtered


def _signature_sources(project) -> list[str]:
    values: list[str] = []
    values.extend(_normalize_source_names(getattr(project, "_inertia_flair_sig_titles", ())))
    values.extend(_normalize_source_names(getattr(project, "_inertia_flair_local_pat_sources", ())))
    values.extend(_normalize_source_names(getattr(project, "_inertia_peer_exe_titles", ())))
    deduped: list[str] = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _normalize_source_names(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        looks_like_path = text.startswith(("/", "\\")) or "\\" in text
        path = Path(text)
        candidate = path.stem if looks_like_path and path.suffix else text
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized
