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


def _dedupe_local_declarations(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    decl_re = re.compile(
        r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
    )

    changed = False
    index = 0
    while index < len(lines):
        match = header_re.match(lines[index])
        if match is None:
            index += 1
            continue
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
            index = scan_index + 1
            continue

        body_start = brace_index + 1
        body_end = body_start
        brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
        while body_end < len(lines) and brace_depth > 0:
            brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
            body_end += 1

        decls_by_name: dict[str, list[tuple[int, bool]]] = {}
        for line_index in range(body_start, body_end):
            decl_match = decl_re.match(lines[line_index])
            if decl_match is None:
                continue
            name = decl_match.group("name")
            decls_by_name.setdefault(name, []).append((line_index, decl_match.group("comment") is not None))

        remove_lines: set[int] = set()
        for decls in decls_by_name.values():
            if len(decls) < 2:
                continue
            changed = True
            best_index, _ = max(decls, key=lambda item: (item[1], item[0]))
            for line_index, _ in decls:
                if line_index != best_index:
                    remove_lines.add(line_index)

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
    """Normalize still-structured decompiler output into valid-ish C identifiers."""

    normalized = _CALLEE_NAMESPACE_RE.sub(lambda match: match.group("name"), c_text)
    normalized = _RAW_REGISTER_FRAGMENT_RE.sub(lambda match: match.group("name"), normalized)
    normalized = _sanitize_placeholder_names(normalized)
    normalized = _dedupe_local_declarations(normalized)
    normalized = re.sub(r"\s*/\*\s*do not return\s*\*/", "", normalized)
    return normalized
