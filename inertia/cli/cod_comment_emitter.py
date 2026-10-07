"""Emit original COD assembly and C source as comment blocks in .dec output.

Layer: Optional evidence/reporting.
Responsibility: format optional COD/source evidence as comments only.
Forbidden: semantic recovery, validation success, or output repair from COD/source text.

AGENTS rule: no semantic recovery — this is pure formatting/fidelity output.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

type CODCommentEntry = Mapping[str, object]

__all__ = (
    "CODCommentEntry",
    "format_cod_comment_block",
    "format_cod_comment_block_from_proc_metadata",
)


def _cod_comment_offset(entry: CODCommentEntry) -> int:
    value = entry["offset"]
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def format_cod_comment_block(
    *,
    func_name: str,
    proc_kind: str = "NEAR",
    cod_path: str | None = None,
    entries: Sequence[CODCommentEntry] | None = None,
    source_lines: tuple[str, ...] = (),
) -> str:
    """Produce a ``/// ORIGINAL: ...`` comment block for a function.

    Args:
        func_name: Name of the function (e.g. ``_sort_array``).
        proc_kind: ``NEAR`` or ``FAR``.
        cod_path: Path to the .COD file (for provenance).
        entries: List of ``{"offset": int, "bytes": bytes, "text": str}``.
        source_lines: Original C source lines from the COD prelude/proc header.
    """
    lines: list[str] = []

    cod_source = Path(cod_path).name if cod_path else "unknown.COD"
    header = f"/// ORIGINAL: {func_name} ({proc_kind}) — {cod_source}"
    lines.append("/// " + "═" * 68)
    lines.append(header)

    if source_lines:
        lines.append("///")
        lines.append("/// C source:")
        for src_line in source_lines:
            safe_line = src_line.rstrip("\n\r")
            if safe_line.endswith("\\"):
                safe_line = safe_line[:-1] + "<backslash>"
            lines.append(f"///   {safe_line}")

    if entries:
        lines.append("///")
        lines.append("/// Assembly:")
        for entry in entries:
            offset = _cod_comment_offset(entry)
            raw_bytes = entry["bytes"]
            if not isinstance(raw_bytes, bytes):
                raw_bytes = bytes(raw_bytes) if isinstance(raw_bytes, Sequence) else b""
            asm_text = str(entry.get("text", "")).strip()
            hex_bytes = " ".join(f"{b:02X}" for b in raw_bytes)
            # Pad hex bytes to 16 chars for alignment
            hex_padded = hex_bytes.ljust(16)
            lines.append(f"///   {offset:04X}  {hex_padded}  {asm_text}")

    lines.append("/// " + "═" * 68)
    return "\n".join(lines)


def format_cod_comment_block_from_proc_metadata(
    *,
    func_name: str,
    proc_kind: str = "NEAR",
    cod_path: str | None = None,
    entries: Sequence[CODCommentEntry] | None = None,
    source_lines: tuple[str, ...] = (),
) -> str:
    """Return the COD comment block for direct ``CODProcMetadata`` field callers."""
    return format_cod_comment_block(
        func_name=func_name,
        proc_kind=proc_kind,
        cod_path=cod_path,
        entries=entries,
        source_lines=source_lines,
    )
