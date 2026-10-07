"""Read source sidecars as optional labels and display-only evidence.

Layer: CLI/fallback/reporting.
Responsibility: read local source sidecars for display-only labels, never semantic recovery.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_COMMENT_PREFIXES = ("/*", "*", "*/", "//")


def _strip_c_comments_and_strings(line: str) -> str:
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r"//.*$", "", line)
    return line


@lru_cache(maxsize=16)
def _read_lines(path: Path) -> tuple[str, ...]:
    return tuple(path.read_text(errors="ignore").splitlines())


def _candidate_source_paths(binary_path: Path | None) -> tuple[Path, ...]:
    if binary_path is None:
        return ()
    stem = binary_path.with_suffix("")
    candidates = []
    for suffix in (".c", ".C"):
        path = stem.with_suffix(suffix)
        if path.exists():
            candidates.append(path)
    return tuple(candidates)


_FUNCTION_HEADER_KEYWORDS = frozenset(
    {
        "for",
        "if",
        "switch",
        "while",
    }
)


def _looks_like_function_header(line: str, function_name: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES):
        return False
    if ";" in stripped:
        return False
    if not re.search(rf"\b{re.escape(function_name)}\s*\(", stripped):
        return False
    return bool(re.match(rf"^\s*(?:[A-Za-z_][\w\s\*\[\]]+\s+)?{re.escape(function_name)}\s*\(", stripped))


def _function_header_span_8616(lines: tuple[str, ...], function_name: str) -> tuple[int, int] | None:
    """Locate the header line and opening-brace line for a function definition."""
    for idx, raw in enumerate(lines):
        line = _strip_c_comments_and_strings(raw)
        if not _looks_like_function_header(line, function_name):
            continue
        if "{" in line:
            return idx, idx
        for probe in range(idx + 1, min(idx + 12, len(lines))):
            probe_line = _strip_c_comments_and_strings(lines[probe])
            if "{" in probe_line:
                return idx, probe
        # Header without an opening brace: keep scanning later candidates.
    return None


def _leading_comment_start_8616(lines: tuple[str, ...], start_idx: int) -> int:
    """Walk backwards over blank and comment lines belonging to the function."""
    comment_start = start_idx
    while comment_start > 0:
        prev = lines[comment_start - 1].strip()
        if not prev:
            comment_start -= 1
            continue
        if prev.startswith(_COMMENT_PREFIXES):
            comment_start -= 1
            continue
        break
    return comment_start


def _function_body_end_8616(lines: tuple[str, ...], open_idx: int) -> int | None:
    """Find the line where the brace depth first returns to zero."""
    depth = 0
    for idx in range(open_idx, len(lines)):
        line = _strip_c_comments_and_strings(lines[idx])
        depth += line.count("{")
        depth -= line.count("}")
        if idx > open_idx and depth <= 0 and "}" in line:
            return idx
    return None


def _extract_function_from_lines(lines: tuple[str, ...], function_name: str) -> str | None:
    span = _function_header_span_8616(lines, function_name)
    if span is None or span[1] is None:
        return None
    start_idx, open_idx = span

    comment_start = _leading_comment_start_8616(lines, start_idx)
    end_idx = _function_body_end_8616(lines, open_idx)
    if end_idx is None:
        return None
    selected = list(lines[comment_start : end_idx + 1])
    while selected and not selected[0].strip():
        selected.pop(0)
    return "\n".join(selected).rstrip() + "\n"


def _source_function_header_match(line: str) -> re.Match[str] | None:
    stripped = _strip_c_comments_and_strings(line).strip()
    if not stripped or stripped.startswith("#") or ";" in stripped or "}" in stripped:
        return None
    match = re.match(
        r"^(?:(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+)?"
        r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}()]*\)\s*\{?\s*$",
        stripped,
    )
    if match is None:
        return None
    if match.group("name") in _FUNCTION_HEADER_KEYWORDS:
        return None
    return match


def _source_header_has_body(lines: tuple[str, ...], header_index: int) -> bool:
    if "{" in _strip_c_comments_and_strings(lines[header_index]):
        return True
    for probe in range(header_index + 1, min(header_index + 12, len(lines))):
        stripped = _strip_c_comments_and_strings(lines[probe]).strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "{" in stripped:
            return True
        if ";" in stripped:
            return False
    return False


@lru_cache(maxsize=16)
def _collect_source_return_types_for_path(path: Path) -> dict[str, str]:
    lines = _read_lines(path)
    result: dict[str, str] = {}
    for index, line in enumerate(lines):
        match = _source_function_header_match(line)
        if match is None or not _source_header_has_body(lines, index):
            continue
        name = match.group("name")
        return_type = " ".join((match.group("ret") or "int").split())
        if not name or name in result:
            continue
        result[name] = return_type
    for name, return_type in list(result.items()):
        if name.startswith("_"):
            result.setdefault(name[1:], return_type)
    return result


def collect_local_source_sidecar_return_types(binary_path: Path | None) -> dict[str, str]:
    """Collect display-only source return-type labels from local sidecars."""
    if binary_path is None:
        return {}
    merged: dict[str, str] = {}
    for path in _candidate_source_paths(binary_path):
        for name, return_type in _collect_source_return_types_for_path(path).items():
            merged.setdefault(name, return_type)
    return merged


def render_local_source_sidecar_function(binary_path: Path | None, function_name: str | None) -> str | None:
    """Render a display-only local source function body when a sidecar exists."""
    if binary_path is None or not isinstance(function_name, str) or not function_name:
        return None
    source_name = function_name.lstrip("_")
    if not source_name:
        return None
    for path in _candidate_source_paths(binary_path):
        rendered = _extract_function_from_lines(_read_lines(path), source_name)
        if rendered is not None:
            return rendered
    return None
