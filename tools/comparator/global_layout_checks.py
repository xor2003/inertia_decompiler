"""Layer: comparator structural evidence.

Responsibility: check order, spacing and declared initial-byte extents of global
address pairs. These finite facts do not establish types or live-memory equivalence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from enum import StrEnum
from itertools import pairwise
from typing import Any

import pefile

from tools.comparator.table_checks import read_pe_initial_bytes


class GlobalLayoutStatus(StrEnum):
    """Partial layout outcomes, independent of function proof verdicts."""

    CHECKED = "checked"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"


def check_global_layout(candidate_to_original: Mapping[int, int]) -> dict[str, Any]:
    """Check a finite map using signed gaps, without guessing object extents.

    Sorting once and checking adjacent pairs suffices to establish order and
    spacing for every pair of mapped positions. Zero/one position cannot prove
    an order relation. Addresses use integer arithmetic, never modular gaps.
    A mismatch may indicate padding or a wrong declared correspondence; it is
    not a behavioral counterexample.
    """
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
           for pair in candidate_to_original.items() for value in pair):
        raise ValueError("global coordinates must be 32-bit integer addresses")
    pairs = sorted(candidate_to_original.items())
    edges = []
    for (candidate_a, original_a), (candidate_b, original_b) in pairwise(pairs):
        candidate_gap, original_gap = candidate_b - candidate_a, original_b - original_a
        equal = candidate_gap == original_gap
        edges.append({
            "candidate": [hex(candidate_a), hex(candidate_b)],
            "original": [hex(original_a), hex(original_b)],
            "candidate_gap": candidate_gap, "original_gap": original_gap,
            "status": GlobalLayoutStatus.CHECKED if equal else GlobalLayoutStatus.MISMATCH,
        })
    order = all(right[1] > left[1] for left, right in pairwise(pairs)) if edges else None
    spacing = all(row["status"] == GlobalLayoutStatus.CHECKED for row in edges) if edges else None
    status = (GlobalLayoutStatus.INCOMPLETE if not edges else
              GlobalLayoutStatus.CHECKED if order and spacing else GlobalLayoutStatus.MISMATCH)
    shifts = sorted({candidate - original for candidate, original in pairs})
    return {
        "schema": "comparator.global_layout_check.v1", "status": status,
        "scope": "declared_global_address_order_and_spacing",
        "function_equivalence_proved": False,
        "map_sha256": hashlib.sha256(json.dumps(pairs, separators=(",", ":")).encode()).hexdigest(),
        "mapped_positions": len(pairs), "unique_original_positions": len({original for _, original in pairs}),
        "order_preserved": order, "spacing_preserved": spacing,
        "uniform_displacement": shifts[0] if len(shifts) == 1 else None,
        "adjacent_pairs": edges,
        "checked_adjacent_pairs": sum(row["status"] == GlobalLayoutStatus.CHECKED for row in edges),
        "pending_conditions": [
            "complete coverage of globals and aliases beyond the declared address map",
            "object extents, access widths and source type correspondence",
            "initial byte contents, pointer fields and runtime loader relocations",
            "preservation of the related memory through writes and external effects",
            "pointer arithmetic and observations outside the mapped positions",
        ],
    }


def check_global_initial_bytes(
    original_image: bytes, candidate_image: bytes, extents: Sequence[tuple[int, int, int]],
) -> dict[str, Any]:
    """Check explicit (original VA, candidate VA, width) initialization proposals.

    Raw equality is partial evidence, not pointer relocation, type, live-memory
    or function equivalence. No adjacent-label gap is treated as object size.
    """
    if not 1 <= len(extents) <= 4096:
        raise ValueError("initial-byte check requires 1..4096 declared extents")
    rows = []
    for original, candidate, width in extents:
        row: dict[str, Any] = {"original": original, "candidate": candidate, "width": width}
        try:
            left, left_file = read_pe_initial_bytes(original_image, original, width)
            right, right_file = read_pe_initial_bytes(candidate_image, candidate, width)
        except (ValueError, pefile.PEFormatError) as error:
            row.update(status="incomplete", detail=str(error))
        else:
            row.update(status="checked" if left == right else "mismatch",
                       original_bytes=left.hex(), candidate_bytes=right.hex(),
                       original_file_bytes=left_file, candidate_file_bytes=right_file,
                       both_zero=not any(left) and not any(right))
        rows.append(row)
    status = "mismatch" if any(row["status"] == "mismatch" for row in rows) else (
        "incomplete" if any(row["status"] == "incomplete" for row in rows) else "checked")
    return {"schema": "comparator.global_initial_bytes.v1", "status": status,
            "scope": "declared_section_initialization_before_relocations",
            "function_equivalence_proved": False, "live_values_proved": False, "extents": rows,
            "image_sha256": {"original": hashlib.sha256(original_image).hexdigest(),
                             "candidate": hashlib.sha256(candidate_image).hexdigest()},
            "pending_conditions": ["declared object correspondence, extent and type",
                "loader relocations, import and TLS initialization",
                "all runtime writes and escaped aliases",
                "preservation across external effects before each use"]}
