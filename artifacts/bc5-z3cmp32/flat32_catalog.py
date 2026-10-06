"""Layer: validation input adapters.

Responsibility: turn verified binary/sidecar symbol metadata into flat32 catalogs.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import angr

_LISTING_CACHE_VERSION = 1


def _listing_entries_digest(entries: object) -> str:
    """Detect accidental cache-content changes without reparsing the listing."""
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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


def _cached_listing[ListingValue](
    path: Path,
    cache_dir: Path | None,
    kind: str,
    parser: Callable[[Path], dict[str, ListingValue]],
    decode: Callable[[object], dict[str, ListingValue] | None],
) -> dict[str, ListingValue]:
    """Share parsed listing metadata across shards with content-based invalidation.

    ``cache_dir=None`` bypasses the cache outright: the parser result is
    returned directly with no read, write or lock of any cache artifact.
    """
    if cache_dir is None:
        return parser(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"lst-v{_LISTING_CACHE_VERSION}-{kind}-{digest}.json"
    lock_path = cache_path.with_suffix(".lock")
    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            try:
                payload = json.loads(cache_path.read_text())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict) and payload.get("digest") == digest and payload.get("kind") == kind:
                entries = payload.get("entries")
                if payload.get("entries_sha256") == _listing_entries_digest(entries):
                    decoded = decode(entries)
                    if decoded is not None:
                        return decoded
            result = parser(path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"listing changed while parsing: {path}")
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=cache_dir, prefix=f"{cache_path.name}.", delete=False
            ) as temporary:
                json.dump(
                    {"digest": digest, "kind": kind, "entries_sha256": _listing_entries_digest(result),
                     "entries": result},
                    temporary, sort_keys=True,
                )
                temporary_path = Path(temporary.name)
            try:
                os.replace(temporary_path, cache_path)
            finally:
                temporary_path.unlink(missing_ok=True)
            return result
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _decode_cached_functions(entries: object) -> dict[str, tuple[int, int]] | None:
    """Reject malformed cached function bounds before using them for scans."""
    if not isinstance(entries, dict):
        return None
    if not all(
        isinstance(name, str)
        and isinstance(bounds, list)
        and len(bounds) == 2
        and all(type(address) is int for address in bounds)
        for name, bounds in entries.items()
    ):
        return None
    return {name: (bounds[0], bounds[1]) for name, bounds in entries.items()}


def cached_lst_functions(path: Path, cache_dir: Path | None) -> dict[str, tuple[int, int]]:
    """Load function bounds from a validated cache or parse the listing."""
    return _cached_listing(path, cache_dir, "functions", lst_functions, _decode_cached_functions)


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
    directives = frozenset({"db", "dw", "dd", "dq", "dt", "df", "dp"})
    with path.open(errors="replace") as stream:
        for line in stream:
            if line.startswith(("CODE:", ".text:")):
                # Code lines dominate IDA listings. Only a label followed by a
                # data directive can contribute to this map.
                fields = line.split(None, 3)
                if len(fields) < 3 or fields[2] not in directives:
                    continue
                match = directive.match(line)
            elif line.startswith(("DATA:", ".data:", ".rdata:", ".bss:")):
                match = directive.match(line) or plain.match(line)
            else:
                continue
            if match:
                symbols[match[2]] = int(match[1], 16)
    return symbols


def _decode_cached_data_symbols(entries: object) -> dict[str, int] | None:
    """Reject malformed cached data addresses before relocation matching."""
    if not isinstance(entries, dict):
        return None
    if not all(isinstance(name, str) and type(address) is int for name, address in entries.items()):
        return None
    return entries


def cached_lst_data_symbols(path: Path, cache_dir: Path | None) -> dict[str, int]:
    """Load data labels from a validated cache or parse the listing."""
    return _cached_listing(path, cache_dir, "data", lst_data_symbols, _decode_cached_data_symbols)


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
