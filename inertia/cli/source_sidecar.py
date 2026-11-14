# cython: language_level=3, infer_types=True
"""Read source sidecars as optional labels and display-only evidence.

Layer: CLI/fallback/reporting.
Responsibility: read local source sidecars for display-only labels, never semantic recovery.
"""

from __future__ import annotations
import typing
import cython

import re
from functools import lru_cache
from pathlib import Path

_COMMENT_PREFIXES = ("/*", "*", "*/", "//")


@cython.ccall
def _strip_c_comments_and_strings(line: object) -> object:
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r"//.*$", "", line)
    return line


@lru_cache(maxsize=16)
def _read_lines(path: Path) -> tuple[str, ...]:
    return tuple(path.read_text(errors="ignore").splitlines())


@cython.ccall
def _candidate_source_paths(binary_path: object) -> tuple[Path, ...]:
    suffix: object
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


@cython.ccall
def _looks_like_function_header(line: object, function_name: object) -> cython.bint:
    stripped = line.strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES):
        return False
    if ";" in stripped:
        return False
    if not re.search(rf"\b{re.escape(function_name)}\s*\(", stripped):
        return False
    return bool(re.match(rf"^\s*(?:[A-Za-z_][\w\s\*\[\]]+\s+)?{re.escape(function_name)}\s*\(", stripped))


@cython.ccall
def _function_header_span_8616(lines: object, function_name: object) -> object:
    """Locate the header line and opening-brace line for a function definition."""
    idx: object
    raw: object
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


@cython.ccall
def _leading_comment_start_8616(lines: object, start_idx: cython.longlong) -> cython.longlong:
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


@cython.ccall
def _function_body_end_8616(lines: object, open_idx: cython.longlong) -> int | None:
    """Find the line where the brace depth first returns to zero."""
    depth = 0
    for idx in range(open_idx, len(lines)):
        line = _strip_c_comments_and_strings(lines[idx])
        depth += line.count("{")
        depth -= line.count("}")
        if idx > open_idx and depth <= 0 and "}" in line:
            return idx
    return None


@cython.ccall
def _extract_function_from_lines(lines: object, function_name: object) -> object:
    end_idx: object
    span: object
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


@cython.ccall
def _source_function_header_match(line: object) -> re.Match[str] | None:
    match: object
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


@cython.ccall
def _source_header_has_body(lines: object, header_index: cython.longlong) -> cython.bint:
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
def _collect_source_return_types_for_path(path: Path) -> object:
    match: object
    index: object
    line: object
    name: object
    return_type: object
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


@cython.ccall
def collect_local_source_sidecar_return_types(binary_path: object) -> object:
    """Collect display-only source return-type labels from local sidecars."""
    name: object
    path: object
    return_type: object
    if binary_path is None:
        return {}
    merged: dict[str, str] = {}
    for path in _candidate_source_paths(binary_path):
        for name, return_type in _collect_source_return_types_for_path(path).items():
            merged.setdefault(name, return_type)
    return merged


@cython.ccall
def render_local_source_sidecar_function(binary_path: object, function_name: object) -> object:
    """Render a display-only local source function body when a sidecar exists."""
    rendered: object
    path: object
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
