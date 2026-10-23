"""Layer: validation observation intake.

Responsibility: load explicit per-function scalar ABI and private-stack lifetime
premises, retaining their source identity rather than inferring C types.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.contracts.flat32_buffer_domain import Flat32EntryMemoryRange, Flat32StackDisjointBuffer


def _buffers(raw: object) -> tuple[Flat32StackDisjointBuffer, ...]:
    """Validate optional fixed-size root buffer premises without inferring types."""
    if not isinstance(raw, list) or len(raw) > 32:
        raise ValueError("stack_disjoint_buffers must be a list of at most 32 buffers")
    result = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"argument_index", "size_bytes"}:
            raise ValueError("buffer requires argument_index and size_bytes")
        result.append(Flat32StackDisjointBuffer(item["argument_index"], item["size_bytes"]))
    return tuple(result)


def _memory_ranges(raw: object) -> tuple[Flat32EntryMemoryRange, ...]:
    """Validate explicit live-entry memory bounds without reading initializers."""
    if not isinstance(raw, list) or len(raw) > 32:
        raise ValueError("entry_memory_ranges must be a list of at most 32 ranges")
    result = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"address", "width", "min", "max"}:
            raise ValueError("memory range requires address, width, min and max")
        result.append(Flat32EntryMemoryRange(item["address"], item["width"], item["min"], item["max"]))
    return tuple(result)


def load_abi_catalog(path: Path | None, mode: str) -> tuple[dict[str, Flat32AbiObservation], dict[str, str]]:
    """Validate the opt-in catalog; unknown fields and unsupported modes fail."""
    if path is None:
        return {}, {}
    if mode != "matched-cfg":
        raise ValueError("ABI observation catalogs currently require matched-cfg mode")
    raw = path.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict) or set(document) != {"schema", "functions"}:
        raise ValueError("ABI catalog requires schema and functions")
    if document["schema"] != "dosunit.flat32_abi_observation.v1" or not isinstance(document["functions"], dict):
        raise ValueError("unsupported ABI observation catalog schema")
    contracts = {}
    for name, item in document["functions"].items():
        if not isinstance(name, str) or not name or not isinstance(item, dict):
            raise ValueError("invalid ABI function entry")
        required = {"return_bits", "private_stack_bytes"}
        if (not required <= set(item) or set(item) - required - {"stack_disjoint_buffers", "entry_memory_ranges"}
                or any(type(item[key]) is not int for key in required)):
            raise ValueError("ABI function requires integer return_bits and private_stack_bytes")
        contracts[name] = Flat32AbiObservation(item["return_bits"], item["private_stack_bytes"],
                                             _buffers(item.get("stack_disjoint_buffers", [])),
                                             _memory_ranges(item.get("entry_memory_ranges", [])))
    return contracts, {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}
