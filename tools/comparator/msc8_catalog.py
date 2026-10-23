"""Layer: validation input adapters.

Responsibility: turn verified binary/sidecar symbol metadata into flat32 catalogs.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import angr

from tools.comparator.catalog import catalog as catalog
from tools.comparator.catalog import mapping as mapping
from tools.dosunit.catalog.pe32_link_map import MapPublic, Pe32LinkMap


class ListingEndKind(StrEnum):
    """Distinguish an IDA instruction head from an inclusive byte scan bound."""

    INSTRUCTION = "last-instruction"
    BYTE = "last-byte"


def listing_size(project: angr.Project, start: int, end: int, kind: ListingEndKind) -> int:
    """Interpret declared bounds without decoding a synthetic byte as code.

    A byte bound is only a scan envelope. The existing CFG/call owners must
    still establish complete reachable control and refuse escapes or ambiguity.
    No padding, return, or function-completeness property is inferred here.
    """
    if not 0 <= start <= end <= 0xFFFFFFFF:
        raise ValueError("invalid listing address range")
    end_size = 1 if kind is ListingEndKind.BYTE else project.factory.block(end, num_inst=1).vex.size
    return end - start + end_size


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
            match = re.match(r"\.text:([0-9A-Fa-f]+)\s+(\S+)\s+(proc|endp)\b", line)
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






def lst_data_symbols(path: Path) -> dict[str, int]:
    """Read data labels as correspondence evidence, rejecting ambiguous names.

    Ordinary named labels require a data-definition directive in a data
    section. This is symbol metadata only, not type or extent recovery.
    """
    symbols: dict[str, int] = {}
    with path.open(errors="replace") as stream:
        for line in stream:
            match = re.match(
                r"\.(?:data|rdata|bss):([0-9A-Fa-f]+)\s+((?:byte|word|dword|qword|off|unk)_[0-9A-Fa-f]+)\s", line
            )
            if match is None:
                match = re.match(
                    r"\.(?:data|rdata|bss):([0-9A-Fa-f]+)\s+([A-Za-z_][A-Za-z_0-9]*)\s+(?:db|dw|dd|dq|dt)\b", line
                )
            if match:
                name, address = match[2], int(match[1], 16)
                if name in symbols and symbols[name] != address:
                    raise ValueError(f"conflicting original data labels for {name}")
                symbols[name] = address
    return symbols


def lst_data_rows(path: Path) -> dict[int, str]:
    """Map every data-directive row address to its directive, anonymous included.

    Anonymous ``db``/``dw``/``dd``/``dq``/``dt`` rows carry no listing label,
    yet they are still declared data cells; named rows are covered too so the
    result is a complete row-index, not a symbol table.  Rows outside
    ``.data``/``.rdata``/``.bss`` are never recorded, so a claimed address that
    is actually code (``.text``) can never satisfy this evidence class.
    """
    rows: dict[int, str] = {}
    with path.open(errors="replace") as stream:
        for line in stream:
            match = re.match(
                r"\.(?:data|rdata|bss):([0-9A-Fa-f]+)\s+(?:(\S+)\s+)?(db|dw|dd|dq|dt)\b", line
            )
            if match:
                rows[int(match.group(1), 16)] = match.group(3)
    return rows


def global_map(
    symbols: dict[str, Symbol], candidate: angr.Project, oracle: angr.Project, oracle_symbols: dict[str, int]
) -> dict[int, int]:
    """Match address-encoded data aliases only when both addresses are mapped data."""
    delta = candidate.loader.main_object.mapped_base - candidate.loader.main_object.linked_base
    normalization: dict[int, int] = {}
    for name, symbol in symbols.items():
        match = re.fullmatch(r"(?:byte|word|dword|qword|off|unk)_([0-9A-Fa-f]+)", name)
        if match is None or symbol.kind not in "bBdDrRsS":
            continue
        original = int(match.group(1), 16)
        mapped = symbol.address + delta
        if oracle_symbols.get(name) != original or oracle.loader.find_section_containing(original) is None:
            continue
        if mapped in normalization and normalization[mapped] != original:
            raise ValueError(f"conflicting data aliases at {mapped:#x}")
        normalization[mapped] = original
    return normalization


def _mapped_data_section(project: angr.Project, address: int) -> bool:
    """True only when the loader places the address in non-executable data."""
    section = project.loader.find_section_containing(address)
    return section is not None and not section.is_executable


def _public_data_pair(public: MapPublic, oracle_symbols: dict[str, int]) -> tuple[str, int] | None:
    """Propose an address alias or an exactly C-decorated original data name."""
    alias = public.data_alias()
    if alias is not None:
        return alias
    if not public.name.startswith("_") or public.name[1:] not in oracle_symbols:
        return None
    canonical = public.name[1:]
    return canonical, oracle_symbols[canonical]


def _oracle_data_evidence(
    canonical: str, original: int, oracle_symbols: dict[str, int], oracle_rows: dict[int, str]
) -> bool:
    """True when oracle listing evidence places claimed VA ``original`` in data.

    A listing label bound to the claimed VA is the ordinary evidence.  When the
    label is absent, only a declared data-directive row at the same VA can
    satisfy the claim, because anonymous rows carry no label.  A label bound
    to a *different* VA contradicts the claim and can never be displaced by an
    anonymous row.
    """
    label = oracle_symbols.get(canonical)
    if label is not None:
        return label == original
    return original in oracle_rows


def link_map_global_map(
    link_map: Pe32LinkMap,
    candidate: angr.Project,
    oracle: angr.Project,
    oracle_symbols: dict[str, int],
    oracle_rows: dict[int, str] | None = None,
) -> dict[int, int]:
    """Match verified LINK-map data publics against oracle listing labels.

    Every ``_(byte|word|dword|qword|off|unk)_<va>`` public is a claimed data
    correspondence: its map segment must be DATA class, its ``Rva+Base`` must
    land in mapped non-executable candidate data, and oracle evidence must
    place the same original VA in mapped non-executable oracle data.  The
    oracle side is satisfied by a listing label encoding the claimed VA, or —
    for address-encoded claims only — by a declared data-directive row at that
    VA, because anonymous rows carry no label.  Missing oracle evidence skips
    the pair; contradictory claims — a code segment, an unmapped or
    executable counterpart, or two aliases disagreeing on an address — refuse
    instead of guessing.
    """
    rows = oracle_rows or {}
    delta = candidate.loader.main_object.mapped_base - candidate.loader.main_object.linked_base
    normalization: dict[int, int] = {}
    claimed: dict[str, int] = {}
    for public in link_map.publics:
        alias = _public_data_pair(public, oracle_symbols)
        if alias is None:
            continue
        canonical, original = alias
        mapped = public.address + delta
        if claimed.get(canonical, mapped) != mapped:
            raise ValueError(f"conflicting data aliases for {canonical}")
        claimed[canonical] = mapped
        segment = link_map.segment(public.segment, public.offset)
        if segment is None:
            raise ValueError(f"{canonical}: public in undeclared segment {public.segment:04x}")
        if segment.is_code:
            raise ValueError(f"{canonical}: data alias in CODE segment is contradictory")
        if not _mapped_data_section(candidate, mapped):
            raise ValueError(f"{canonical}: {mapped:#x} is not mapped non-executable data")
        if not _oracle_data_evidence(canonical, original, oracle_symbols, rows):
            continue
        if not _mapped_data_section(oracle, original):
            raise ValueError(f"{canonical}: oracle {original:#x} is not mapped non-executable data")
        if normalization.get(mapped, original) != original:
            raise ValueError(f"conflicting data aliases at {mapped:#x}")
        normalization[mapped] = original
    return normalization

