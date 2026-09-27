"""Layer: validation input adapters.

Responsibility: turn verified binary/sidecar symbol metadata into flat32 catalogs.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import angr


@dataclass(frozen=True)
class Symbol:
    """Linked symbol address, byte size, and nm symbol class."""

    address: int
    size: int
    kind: str


def lst_functions(path: Path) -> dict[str, tuple[int, int]]:
    """Read only IDA function-boundary metadata; endp denotes the last instruction."""
    functions: dict[str, tuple[int, int]] = {}
    opened: tuple[str, int] | None = None
    with path.open(errors="replace") as stream:
        for line in stream:
            match = re.match(r"(?:\.text|CODE):([0-9A-Fa-f]+)\s+(\S+)\s+(proc|endp)\b", line)
            if match is None:
                continue
            address, name, marker = match.groups()
            if marker == "proc":
                opened = name, int(address, 16)
            elif opened is not None and opened[0] == name:
                functions[name] = opened[1], int(address, 16)
                opened = None
    return functions


def nm_symbols(path: Path) -> dict[str, Symbol]:
    """Read defined ELF symbols; preserve zero-size assembler aliases."""
    output = subprocess.run(
        ["nm", "-S", "--defined-only", str(path)], check=True, capture_output=True, text=True
    ).stdout
    symbols: dict[str, Symbol] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 4:
            address, size, kind, name = parts
        elif len(parts) == 3:
            address, kind, name = parts
            size = "0"
        else:
            continue
        symbols[name] = Symbol(int(address, 16), int(size, 16), kind)
    return symbols


def catalog(module: str, functions: dict[str, tuple[int, int]], linked_base: int) -> dict[str, Any]:
    """Encode offsets against the base dosunit actually adds, using mapped VAs."""
    return {
        "schema": "dosunit.functions.v1",
        "module": module,
        "functions": [
            {
                "id": f"{module}:{name}",
                "names": [name],
                "entry": {"kind": "module_relative", "linear": hex(address), "offset": hex(address - linked_base)},
                "return_kind": "near",
                "size": size,
            }
            for name, (address, size) in sorted(functions.items())
        ],
    }


def mapping(oracle: str, candidate: str, names: list[str]) -> dict[str, Any]:
    """Name matches select proof obligations; they never establish callee equality."""
    return {
        "schema": "dosunit.mapping.v1",
        "oracle_module": oracle,
        "candidate_module": candidate,
        "functions": [
            {
                "oracle_id": f"{oracle}:{name}",
                "oracle_name": name,
                "candidate_id": f"{candidate}:{name}",
                "candidate_name": name,
                "sources": ["name_match"],
            }
            for name in names
        ],
    }


def lst_data_symbols(path: Path) -> dict[str, int]:
    """Read original data-symbol labels (name -> VA) as relocation evidence.

    Accepts any identifier-shaped label on a DATA-segment line, not only
    address-encoded `byte_/dword_/...` names: string labels such as
    `aAtSegmentC1095` carry their VA in the listing column, which is the
    correspondence evidence we need.  Embedded data also occurs inside
    CODE/.text (e.g. `CODE:0049911A word_49911A dw 3Ch`): a label followed
    by a data directive (db/dw/dd/dq/dt/df/dp) is a data label, while
    `proc`/`endp`/instruction lines are not."""
    symbols: dict[str, int] = {}
    directive = re.compile(
        r"(?:\.data|\.rdata|\.bss|\.text|DATA|CODE):([0-9A-Fa-f]+)\s+"
        r"([A-Za-z_]\w*)\s+(d[bwdqtfp]\b|db\b)"
    )
    plain = re.compile(
        r"(?:\.data|\.rdata|\.bss|DATA):([0-9A-Fa-f]+)\s+([A-Za-z_]\w*)\s"
    )
    with path.open(errors="replace") as stream:
        for line in stream:
            match = directive.match(line) or plain.match(line)
            if match:
                symbols[match[2]] = int(match[1], 16)
    return symbols


def global_map(
    symbols: dict[str, Symbol], candidate: angr.Project, oracle: angr.Project, oracle_symbols: dict[str, int]
) -> dict[int, int]:
    """Match data aliases when the oracle address is independently evidenced.

    Address-encoded names (`byte_4A1234`) self-describe their oracle VA;
    other names use the .lst-derived `oracle_symbols` entry. Both still
    require the candidate symbol to land on a mapped data address and the
    oracle label to exist in the oracle image."""
    delta = candidate.loader.main_object.mapped_base - candidate.loader.main_object.linked_base
    normalization: dict[int, int] = {}
    for name, symbol in symbols.items():
        if symbol.kind not in "bBdDrRsS":
            continue
        match = re.fullmatch(r"(?:byte|word|dword|qword|off|unk|tbyte|asc)_([0-9A-Fa-f]+)", name)
        original = int(match.group(1), 16) if match else oracle_symbols.get(name)
        if original is None or oracle_symbols.get(name) != original:
            continue
        mapped = symbol.address + delta
        if oracle.loader.find_section_containing(original) is None:
            continue
        if mapped in normalization and normalization[mapped] != original:
            raise ValueError(f"conflicting data aliases at {mapped:#x}")
        normalization[mapped] = original
    return normalization


