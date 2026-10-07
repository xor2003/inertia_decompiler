"""Layer: validation catalog contracts.

Responsibility: encode deterministic function coordinates and name-paired obligations.
"""

from __future__ import annotations

from typing import Any


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
