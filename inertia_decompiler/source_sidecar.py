from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re


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


def _looks_like_function_header(line: str, function_name: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES):
        return False
    if ";" in stripped:
        return False
    if not re.search(rf"\b{re.escape(function_name)}\s*\(", stripped):
        return False
    return bool(
        re.match(rf"^\s*(?:[A-Za-z_][\w\s\*\[\]]+\s+)?{re.escape(function_name)}\s*\(", stripped)
    )


def _extract_function_from_lines(lines: tuple[str, ...], function_name: str) -> str | None:
    start_idx = None
    open_idx = None
    for idx, raw in enumerate(lines):
        line = _strip_c_comments_and_strings(raw)
        if not _looks_like_function_header(line, function_name):
            continue
        start_idx = idx
        if "{" in line:
            open_idx = idx
            break
        for probe in range(idx + 1, min(idx + 12, len(lines))):
            probe_line = _strip_c_comments_and_strings(lines[probe])
            if "{" in probe_line:
                open_idx = probe
                break
        if open_idx is not None:
            break
    if start_idx is None or open_idx is None:
        return None

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

    depth = 0
    end_idx = None
    for idx in range(open_idx, len(lines)):
        line = _strip_c_comments_and_strings(lines[idx])
        depth += line.count("{")
        depth -= line.count("}")
        if idx > open_idx and depth <= 0 and "}" in line:
            end_idx = idx
            break
    if end_idx is None:
        return None
    selected = list(lines[comment_start : end_idx + 1])
    while selected and not selected[0].strip():
        selected.pop(0)
    return "\n".join(selected).rstrip() + "\n"


def render_local_source_sidecar_function(binary_path: Path | None, function_name: str | None) -> str | None:
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
