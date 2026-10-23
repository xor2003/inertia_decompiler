"""Layer: validation external environment intake.

Responsibility: load explicit per-root imported-call premises with immutable
source identity; never infer a Windows ABI from an import's spelling.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.dosunit.compare.flat32_external_call import ExternalMemoryAccess, ExternalStackCleanup, Flat32ExternalCall


def _memory_ranges(value: object) -> tuple[tuple[int, int], ...]:
    """Decode immutable physical intervals; the contract validates their bounds."""
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("memory ranges require a list of at most 32 pairs")
    result = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2 or any(type(x) is not int for x in item):
            raise ValueError("memory ranges require plain integer pairs")
        result.append((item[0], item[1]))
    return tuple(result)


def _contracts(items: object) -> tuple[Flat32ExternalCall, ...]:
    """Validate one bounded list, rejecting unknown fields and duplicate identities."""
    if not isinstance(items, list) or not 1 <= len(items) <= 64:
        raise ValueError("external function entry requires 1..64 import contracts")
    result = []
    for item in items:
        required = {"dll", "name", "argument_count", "cleanup"}
        optional = {"preserve_import_bindings", "memory_access", "write_size_argument", "write_address_argument", "write_size_bytes", "preserved_memory_ranges", "read_excluded_memory_ranges"}
        if not isinstance(item, dict) or not required <= set(item) or set(item) - required - optional:
            raise ValueError("external import requires dll, name, argument_count and cleanup")
        result.append(Flat32ExternalCall(
            item["dll"], item["name"], item["argument_count"], ExternalStackCleanup(item["cleanup"]),
            preserve_import_bindings=item.get("preserve_import_bindings", False),
            memory_access=ExternalMemoryAccess(item.get("memory_access", "arbitrary")),
            write_size_argument=item.get("write_size_argument"),
            write_address_argument=item.get("write_address_argument"),
            write_size_bytes=item.get("write_size_bytes"),
            preserved_memory_ranges=_memory_ranges(item.get("preserved_memory_ranges", [])),
            read_excluded_memory_ranges=_memory_ranges(item.get("read_excluded_memory_ranges", [])),
        ))
    if len({(item.dll, item.name) for item in result}) != len(result):
        raise ValueError("duplicate external import contract")
    return tuple(result)


def load_external_catalog(
    path: Path | None, mode: str,
) -> tuple[dict[str, tuple[Flat32ExternalCall, ...]], dict[str, str]]:
    """Bind explicit per-function external premises to their JSON source hash."""
    if path is None:
        return {}, {}
    if mode != "matched-cfg":
        raise ValueError("external call catalogs currently require matched-cfg mode")
    raw = path.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict) or set(document) != {"schema", "functions"}:
        raise ValueError("external catalog requires schema and functions")
    if document["schema"] != "dosunit.flat32_external_calls.v1" or not isinstance(document["functions"], dict):
        raise ValueError("unsupported external call catalog schema")
    contracts = {}
    for name, items in document["functions"].items():
        if not isinstance(name, str) or not name:
            raise ValueError("invalid external function name")
        contracts[name] = _contracts(items)
    return contracts, {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}
