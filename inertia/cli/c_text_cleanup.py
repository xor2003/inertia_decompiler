"""Final C-text hygiene for unresolved output.

Layer: CLI/fallback/reporting.
Responsibility: perform final textual cleanup without recovering decompiler semantics.

This module is restricted to textual cleanup that does not recover program
semantics. Semantic recovery belongs in the X86_16 IR, alias, lowering,
structuring, or validated postprocess layers.
"""

from __future__ import annotations

import re

_RAW_REGISTER_FRAGMENT_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\{r\d+\|\d+b\}")
_CALLEE_NAMESPACE_RE = re.compile(r"::0x[0-9a-fA-F]+::(?P<name>[A-Za-z_]\w*)")
_PLACEHOLDER_RE = re.compile(r"<(?P<body>0x[^>\n]+)>")


def _placeholder_name(body: str, ordinal: int) -> str:
    stack_match = re.search(
        r"Stack bp(?P<sign>[+-])0x(?P<offset>[0-9A-Fa-f]+),\s*(?P<size>\d+)\s*B",
        body,
    )
    if stack_match is not None:
        sign = "p" if stack_match.group("sign") == "+" else "m"
        offset = stack_match.group("offset").lower()
        size = stack_match.group("size")
        return f"stack_bp_{sign}{offset}_b{size}"
    return f"tmp_slot_{ordinal}"


def _sanitize_placeholder_names(c_text: str) -> str:
    mapping: dict[str, str] = {}

    def _replace(match: re.Match[str]) -> str:
        token = match.group(0)
        existing = mapping.get(token)
        if existing is not None:
            return existing
        name = _placeholder_name(match.group("body"), len(mapping) + 1)
        mapping[token] = name
        return name

    return _PLACEHOLDER_RE.sub(_replace, c_text)


_DECL_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
)
_DECL_LOCAL_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
)


def _decl_body_bounds_8616(lines: list[str], index: int) -> tuple[int | None, int, int]:
    """Locate the opening brace and closing line for a function starting at index."""
    brace_index = None
    scan_index = index
    while scan_index < len(lines):
        if "{" in lines[scan_index]:
            brace_index = scan_index
            break
        if ";" in lines[scan_index] and "{" not in lines[scan_index]:
            break
        scan_index += 1
    if brace_index is None:
        return None, index, scan_index

    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return brace_index, body_start, body_end


def _duplicate_decl_lines_8616(lines: list[str], body_start: int, body_end: int) -> set[int]:
    """Collect line indices of duplicate local declarations inside one body."""
    decls_by_name: dict[str, list[tuple[int, bool]]] = {}
    for line_index in range(body_start, body_end):
        decl_match = _DECL_LOCAL_RE_8616.match(lines[line_index])
        if decl_match is None:
            continue
        name = decl_match.group("name")
        decls_by_name.setdefault(name, []).append((line_index, decl_match.group("comment") is not None))

    remove_lines: set[int] = set()
    for decls in decls_by_name.values():
        if len(decls) < 2:
            continue
        best_index, _ = max(decls, key=lambda item: (item[1], item[0]))
        for line_index, _ in decls:
            if line_index != best_index:
                remove_lines.add(line_index)
    return remove_lines


def _dedupe_local_declarations(c_text: str) -> str:
    """Remove duplicate same-name local declarations inside each function body."""
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()

    index = 0
    while index < len(lines):
        match = _DECL_HEADER_RE_8616.match(lines[index])
        if match is None:
            index += 1
            continue
        brace_index, body_start, body_end = _decl_body_bounds_8616(lines, index)
        if brace_index is None:
            index = body_end + 1
            continue

        remove_lines = _duplicate_decl_lines_8616(lines, body_start, body_end)
        if remove_lines:
            lines = [line for i, line in enumerate(lines) if i not in remove_lines]
            index = max(index - len([i for i in remove_lines if i < index]), 0)
            continue
        index = body_end

    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def normalize_unresolved_c_text(c_text: str) -> str:
    """Normalize still-structured decompiler output without inventing semantics."""
    normalized = _CALLEE_NAMESPACE_RE.sub(lambda match: match.group("name"), c_text)
    normalized = _RAW_REGISTER_FRAGMENT_RE.sub(lambda match: match.group("name"), normalized)
    normalized = _normalize_concat_insert_artifacts(normalized)
    normalized = _normalize_numeric_call_targets(normalized)
    normalized = _sanitize_placeholder_names(normalized)
    normalized = _dedupe_local_declarations(normalized)
    normalized = re.sub(r"\s*/\*\s*do not return\s*\*/", "", normalized)
    return normalized


def _normalize_concat_insert_artifacts(c_text: str) -> str:
    # Normalize textual CONCAT/_INSERT artifacts emitted by upstream IR printer.
    normalized = re.sub(r"\(\s*([A-Za-z_]\w*)\s+CONCAT\s+0\s*\)", r"\1", c_text)
    normalized = re.sub(r"(?<![A-Za-z_])([A-Za-z_]\w*)\s+CONCAT\s+0(?![A-Za-z_])", r"\1", normalized)
    normalized = re.sub(r"0\s+CONCAT\s+([A-Za-z_]\w*)", r"\1", normalized)
    normalized = re.sub(
        r"_INSERT\s*\(\s*[^,]+,\s*0\s*,\s*([^)]+?)\s*\)",
        r"\1",
        normalized,
    )
    return normalized


def _normalize_numeric_call_targets(c_text: str) -> str:
    # Rewrite numeric call targets like `1169()` into stable identifiers.
    return re.sub(r"(?<![A-Za-z0-9_])(?P<num>\d+)\s*\(", lambda m: f"sub_{m.group('num')}(", c_text)
