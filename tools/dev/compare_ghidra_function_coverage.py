#!/usr/bin/env python3
"""Compare Inertia and Ghidra function coverage by canonical binary address.

Layer: Tooling/gates.
Responsibility: map external decompiler entries through MZ load-image NOP
padding and report coverage/call-edge differences without treating rendered C
or either decompiler as semantic proof.

This module is deliberately outside the decompilation pipeline. Its parsed C
facts are diagnostics only and must never feed IR, Alias, Widening, Types,
Structuring, Rewrite, or Tail Validation.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

_GHIDRA_FILE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:thunk_)?FUN_(?P<segment>[0-9a-fA-F]{4})_(?P<offset>[0-9a-fA-F]{4})_.*\.c$"
)
_INERTIA_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"/\* == function (?P<address>0x[0-9a-fA-F]+) [^=]+ == \*/"
)
_INERTIA_DEFINITION_RE: Final[re.Pattern[str]] = re.compile(
    r"(?m)^[^;{}\n]*\bsub_(?P<address>[0-9a-fA-F]+)\s*\([^;{}]*\)\s*\n\{"
)
_INERTIA_CALL_RE: Final[re.Pattern[str]] = re.compile(r"\bsub_(?P<address>[0-9a-fA-F]+)\s*\(")
_GHIDRA_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:FUN_(?P<segment>[0-9a-fA-F]{4})_(?P<offset>[0-9a-fA-F]{4})"
    r"|func_0x(?P<linear>[0-9a-fA-F]+))\s*\("
)


@dataclass(frozen=True, slots=True)
class GhidraFunction:
    """One Ghidra function entry mapped to its first non-NOP body byte."""

    path: str
    nominal_address: int
    body_address: int
    nop_prefix_bytes: int
    application_calls: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class FunctionComparison:
    """Address-matched coverage and application call-edge observations."""

    body_address: int
    ghidra_path: str | None
    ghidra_nominal_address: int | None
    ghidra_nop_prefix_bytes: int | None
    inertia_application_calls: tuple[int, ...]
    ghidra_application_calls: tuple[int, ...]
    calls_only_in_inertia: tuple[int, ...]
    calls_only_in_ghidra: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CoverageComparison:
    """Deterministic whole-input comparison result."""

    inertia_function_count: int
    ghidra_function_count: int
    matched_function_count: int
    missing_from_ghidra: tuple[int, ...]
    ambiguous_ghidra_bodies: tuple[int, ...]
    functions: tuple[FunctionComparison, ...]


def load_mz_module(binary: Path) -> bytes:
    """Return the bytes DOS maps after the MZ header, excluding overlays."""
    data = binary.read_bytes()
    if len(data) < 0x1C or data[:2] != b"MZ":
        raise ValueError(f"{binary} is not a complete MZ executable")
    bytes_in_last_page = int.from_bytes(data[2:4], "little")
    page_count = int.from_bytes(data[4:6], "little")
    header_size = int.from_bytes(data[8:10], "little") * 16
    image_end = page_count * 512 if bytes_in_last_page == 0 else (page_count - 1) * 512 + bytes_in_last_page
    if page_count == 0 or header_size < 0x1C or header_size > image_end or image_end > len(data):
        raise ValueError(f"{binary} has inconsistent MZ header bounds")
    return data[header_size:image_end]


def canonical_body_address(
    module: bytes,
    nominal_address: int,
    *,
    image_base: int,
    maximum_nop_prefix: int,
) -> int:
    """Skip bounded 0x90 entry padding and return the canonical body address."""
    offset = nominal_address - image_base
    if offset < 0 or offset >= len(module):
        raise ValueError(f"entry {nominal_address:#x} lies outside the MZ load module")
    body_offset = offset
    maximum_offset = min(len(module), offset + maximum_nop_prefix + 1)
    while body_offset < maximum_offset and module[body_offset] == 0x90:
        body_offset += 1
    if body_offset == maximum_offset and module[body_offset - 1] == 0x90:
        raise ValueError(
            f"entry {nominal_address:#x} exceeds the {maximum_nop_prefix}-byte NOP-prefix limit"
        )
    return image_base + body_offset


def inertia_function_addresses(c_text: str) -> tuple[int, ...]:
    """Return sorted unique Inertia function-body addresses from generated C."""
    marker_addresses = tuple(int(match.group("address"), 16) for match in _INERTIA_MARKER_RE.finditer(c_text))
    matches = marker_addresses or tuple(
        int(match.group("address"), 16) for match in _INERTIA_DEFINITION_RE.finditer(c_text)
    )
    return tuple(sorted(set(matches)))


def _function_segment(c_text: str, address: int) -> str:
    """Return a marker-delimited Inertia function transcript segment."""
    matches = tuple(_INERTIA_MARKER_RE.finditer(c_text))
    for index, match in enumerate(matches):
        if int(match.group("address"), 16) != address:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(c_text)
        return c_text[match.start() : end]
    return c_text


def _named_function_body(c_text: str, function_name: str) -> str:
    """Return one definition body, excluding declarations in its transcript."""
    definition_re = re.compile(
        rf"(?m)^[^;{{}}\n]*\b{re.escape(function_name)}\s*\([^;{{}}]*\)\s*\n?\s*\{{"
    )
    match = definition_re.search(c_text)
    if match is None:
        return ""
    opening_brace = match.end() - 1
    depth = 0
    for index in range(opening_brace, len(c_text)):
        if c_text[index] == "{":
            depth += 1
        elif c_text[index] == "}":
            depth -= 1
            if depth == 0:
                return c_text[opening_brace : index + 1]
    return ""


def inertia_application_calls(c_text: str, address: int, application_addresses: frozenset[int]) -> tuple[int, ...]:
    """Collect diagnostic application call targets from one Inertia segment."""
    segment = _function_segment(c_text, address)
    body = _named_function_body(segment, f"sub_{address:x}")
    calls = {
        int(match.group("address"), 16)
        for match in _INERTIA_CALL_RE.finditer(body)
        if int(match.group("address"), 16) in application_addresses
        and int(match.group("address"), 16) != address
    }
    return tuple(sorted(calls))


def ghidra_application_calls(
    c_text: str,
    application_addresses: frozenset[int],
    *,
    module: bytes,
    image_base: int,
    maximum_nop_prefix: int,
) -> tuple[int, ...]:
    """Collect and canonicalize diagnostic application calls from Ghidra C."""
    calls: set[int] = set()
    for match in _GHIDRA_CALL_RE.finditer(c_text):
        linear_text = match.group("linear")
        if linear_text is not None:
            target = int(linear_text, 16)
        else:
            target = int(match.group("segment"), 16) * 16 + int(match.group("offset"), 16)
        try:
            target = canonical_body_address(
                module,
                target,
                image_base=image_base,
                maximum_nop_prefix=maximum_nop_prefix,
            )
        except ValueError:
            continue
        if target in application_addresses:
            calls.add(target)
    return tuple(sorted(calls))


def collect_ghidra_functions(
    directory: Path,
    application_addresses: frozenset[int],
    *,
    module: bytes,
    image_base: int,
    maximum_nop_prefix: int,
) -> tuple[GhidraFunction, ...]:
    """Read Ghidra per-function files into deterministic address records."""
    functions: list[GhidraFunction] = []
    for path in sorted(directory.glob("*.c")):
        match = _GHIDRA_FILE_RE.fullmatch(path.name)
        if match is None:
            continue
        nominal_address = int(match.group("segment"), 16) * 16 + int(match.group("offset"), 16)
        try:
            body_address = canonical_body_address(
                module,
                nominal_address,
                image_base=image_base,
                maximum_nop_prefix=maximum_nop_prefix,
            )
        except ValueError:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        application_calls = ghidra_application_calls(
            text,
            application_addresses,
            module=module,
            image_base=image_base,
            maximum_nop_prefix=maximum_nop_prefix,
        )
        functions.append(
            GhidraFunction(
                path=str(path),
                nominal_address=nominal_address,
                body_address=body_address,
                nop_prefix_bytes=body_address - nominal_address,
                application_calls=tuple(target for target in application_calls if target != body_address),
            )
        )
    return tuple(functions)


def compare_coverage(inertia_c: str, ghidra_functions: Sequence[GhidraFunction]) -> CoverageComparison:
    """Compare application coverage and direct application calls by body address."""
    addresses = inertia_function_addresses(inertia_c)
    application_addresses = frozenset(addresses)
    by_body: dict[int, list[GhidraFunction]] = {}
    for function in ghidra_functions:
        if function.body_address in application_addresses:
            by_body.setdefault(function.body_address, []).append(function)

    functions: list[FunctionComparison] = []
    for address in addresses:
        candidates = by_body.get(address, [])
        ghidra = candidates[0] if len(candidates) == 1 else None
        inertia_calls = inertia_application_calls(inertia_c, address, application_addresses)
        ghidra_calls = ghidra.application_calls if ghidra is not None else ()
        functions.append(
            FunctionComparison(
                body_address=address,
                ghidra_path=ghidra.path if ghidra is not None else None,
                ghidra_nominal_address=ghidra.nominal_address if ghidra is not None else None,
                ghidra_nop_prefix_bytes=ghidra.nop_prefix_bytes if ghidra is not None else None,
                inertia_application_calls=inertia_calls,
                ghidra_application_calls=ghidra_calls,
                calls_only_in_inertia=tuple(sorted(set(inertia_calls) - set(ghidra_calls))),
                calls_only_in_ghidra=tuple(sorted(set(ghidra_calls) - set(inertia_calls))),
            )
        )
    return CoverageComparison(
        inertia_function_count=len(addresses),
        ghidra_function_count=len(ghidra_functions),
        matched_function_count=sum(function.ghidra_path is not None for function in functions),
        missing_from_ghidra=tuple(function.body_address for function in functions if function.ghidra_path is None),
        ambiguous_ghidra_bodies=tuple(sorted(body for body, records in by_body.items() if len(records) > 1)),
        functions=tuple(functions),
    )


def _format_addresses(addresses: Sequence[int]) -> str:
    """Format one compact deterministic address list."""
    return ", ".join(f"{address:#x}" for address in addresses) or "-"


def render_markdown(comparison: CoverageComparison) -> str:
    """Render a human-readable diagnostic report."""
    lines = [
        "# Ghidra Function Coverage Comparison",
        "",
        "Diagnostic only: binary/source evidence and tail validation remain the correctness oracle.",
        "",
        f"- Inertia application functions: {comparison.inertia_function_count}",
        f"- Ghidra functions scanned: {comparison.ghidra_function_count}",
        f"- Address-matched application functions: {comparison.matched_function_count}",
        f"- Missing from Ghidra: {_format_addresses(comparison.missing_from_ghidra)}",
        f"- Ambiguous Ghidra body mappings: {_format_addresses(comparison.ambiguous_ghidra_bodies)}",
        "",
        "| Body | Ghidra entry | NOPs | Calls only in Inertia | Calls only in Ghidra |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for function in comparison.functions:
        entry = f"{function.ghidra_nominal_address:#x}" if function.ghidra_nominal_address is not None else "missing"
        nops = str(function.ghidra_nop_prefix_bytes) if function.ghidra_nop_prefix_bytes is not None else "-"
        lines.append(
            f"| {function.body_address:#x} | {entry} | {nops} | "
            f"{_format_addresses(function.calls_only_in_inertia)} | "
            f"{_format_addresses(function.calls_only_in_ghidra)} |"
        )
    return "\n".join(lines) + "\n"


def _parse_int(value: str) -> int:
    """Parse a decimal or 0x-prefixed integer for argparse."""
    return int(value, 0)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the address-based Ghidra coverage comparison CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("inertia_c", type=Path)
    parser.add_argument("ghidra_directory", type=Path)
    parser.add_argument("--image-base", type=_parse_int, default=0x10000)
    parser.add_argument("--maximum-nop-prefix", type=int, default=64)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    module = load_mz_module(args.binary)
    inertia_c = args.inertia_c.read_text(encoding="utf-8", errors="replace")
    application_addresses = frozenset(inertia_function_addresses(inertia_c))
    ghidra_functions = collect_ghidra_functions(
        args.ghidra_directory,
        application_addresses,
        module=module,
        image_base=args.image_base,
        maximum_nop_prefix=args.maximum_nop_prefix,
    )
    comparison = compare_coverage(inertia_c, ghidra_functions)
    if args.as_json:
        print(json.dumps(asdict(comparison), indent=2, sort_keys=True))
    else:
        print(render_markdown(comparison), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
