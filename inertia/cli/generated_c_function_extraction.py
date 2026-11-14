# cython: language_level=3, infer_types=True
"""Locate exact generated C function definitions for export tooling.

Layer: CLI/fallback/reporting.
Responsibility: identify balanced generated definitions without recovering or
changing decompiler semantics.
"""

from __future__ import annotations
import cython

import re
from pathlib import Path


@cython.ccall
def generated_function_definition_span(
    source: object,
    function_name: object,
) -> tuple[cython.longlong, cython.longlong]:
    """Return the exact span of one balanced generated C definition."""
    signature: object
    signature = re.search(
        rf"(?m)^[ \t]*[A-Za-z_][^\n;]*\b{re.escape(function_name)}"
        r"\s*\([^;\n]*\)\s*\{",
        source,
    )
    if signature is None:
        raise ValueError(f"missing generated definition for {function_name}")
    brace_start = source.find("{", signature.start())
    depth = 0
    for index in range(brace_start, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return signature.start(), index + 1
    raise ValueError(f"unterminated generated definition for {function_name}")


@cython.ccall
def relabel_generated_function_definition(
    source: object,
    old_name: object,
    new_name: object,
) -> object:
    """Relabel one exact generated definition without changing its body or calls."""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", new_name) is None:
        raise ValueError(f"invalid generated function label {new_name!r}")
    definition_pattern = re.compile(
        rf"\b{re.escape(old_name)}(?=\s*\([^;\n]*\)\s*\{{)"
    )
    matches = tuple(definition_pattern.finditer(source))
    if not matches:
        labeled_pattern = re.compile(
            rf"\b{re.escape(new_name)}(?=\s*\([^;\n]*\)\s*\{{)"
        )
        labeled_matches = tuple(labeled_pattern.finditer(source))
        if len(labeled_matches) != 1:
            raise ValueError(
                f"expected one generated definition for {old_name} or {new_name}, "
                f"found {len(labeled_matches)}"
            )
        generated_function_definition_span(source, new_name)
        return source
    if len(matches) != 1:
        raise ValueError(
            f"expected one generated definition for {old_name}, found {len(matches)}"
        )
    match = matches[0]
    generated_function_definition_span(source, old_name)
    return source[: match.start()] + new_name + source[match.end() :]


@cython.ccall
def load_generated_function_artifacts(
    directory: Path,
    addresses: object,
) -> object:
    """Load one exact generated C artifact for every requested address."""
    address: object
    sources: dict[cython.longlong, str] = {}
    for address in addresses:
        matches = tuple(sorted(tuple(directory.glob(f"{address:08x}-*.c"))))
        if len(matches) != 1:
            raise ValueError(
                f"expected one generated artifact for {address:#x}, found {len(matches)}"
            )
        source = matches[0].read_text(encoding="utf-8", errors="replace")
        generated_function_definition_span(source, f"sub_{address:04x}")
        sources[address] = source
    return sources
