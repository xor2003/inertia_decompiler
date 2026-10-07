#!/usr/bin/env python3
"""Validate the machine-readable pytest purpose and evidence inventory.

Layer: Tooling/gates.
Responsibility: reject incomplete, duplicate, or unresolved test inventory
records without changing pytest collection or execution.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MIN_SCHEMA_VERSION: Final[int] = 11
REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "assertion_count",
        "cache_hints",
        "cache_hit_count",
        "cache_invalid_count",
        "cache_keys",
        "cache_miss_count",
        "cache_operations",
        "cache_store_count",
        "cache_store_failed_count",
        "child_cpu_measured",
        "child_cpu_seconds",
        "child_system_seconds",
        "child_user_seconds",
        "cost_sources",
        "direct_function_address_hints",
        "direct_input_hints",
        "direct_option_hints",
        "direct_static_subprocess_count",
        "effective_assertion_count",
        "effective_expectation_count",
        "function_address_hints",
        "input_hints",
        "inventory_status",
        "module_hints",
        "nodeid",
        "option_hints",
        "owner_layers",
        "purpose",
        "required_pipeline_evidence",
        "static_subprocess_count",
        "validation_statuses",
    }
)


@dataclass(frozen=True, slots=True)
class InventoryAudit:
    """Hold deterministic inventory validation results."""

    record_count: int
    status_counts: tuple[tuple[str, int], ...]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Return whether every inventory contract is satisfied."""

        return not self.errors


def _nonempty_string_list(record: dict[str, object], key: str) -> bool:
    """Return whether a record field is a non-empty list of non-empty strings."""

    value = record.get(key)
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item for item in value)


def _audit_record(
    record: dict[str, object],
    index: int,
    seen: set[str],
    statuses: dict[str, int],
) -> list[str]:
    """Audit one inventory record, updating seen nodeids and status counts."""
    errors: list[str] = []
    missing = sorted(REQUIRED_FIELDS - record.keys())
    if missing:
        errors.append(f"record[{index}] missing fields: {', '.join(missing)}")
    nodeid = record.get("nodeid")
    if not isinstance(nodeid, str) or not nodeid:
        errors.append(f"record[{index}] has invalid nodeid")
        node_label = f"record[{index}]"
    else:
        node_label = nodeid
        if nodeid in seen:
            errors.append(f"{nodeid}: duplicate nodeid")
        seen.add(nodeid)
    if not _nonempty_string_list(record, "owner_layers"):
        errors.append(f"{node_label}: missing owner layers")
    if not _nonempty_string_list(record, "required_pipeline_evidence"):
        errors.append(f"{node_label}: missing required evidence")
    purpose = record.get("purpose")
    if not isinstance(purpose, str) or not purpose or purpose == "unclassified":
        errors.append(f"{node_label}: unclassified purpose")
    status = record.get("inventory_status")
    if not isinstance(status, str) or not status:
        errors.append(f"{node_label}: invalid inventory status")
    else:
        statuses[status] = statuses.get(status, 0) + 1
        if status == "review-needed":
            errors.append(f"{node_label}: inventory review is unresolved")
    return errors


def validate_inventory_payload(payload: object) -> InventoryAudit:
    """Validate one decoded profile payload without relying on text output."""

    if not isinstance(payload, dict):
        return InventoryAudit(0, (), ("inventory payload is not an object",))
    errors: list[str] = []
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, int) or schema_version < MIN_SCHEMA_VERSION:
        errors.append(f"schema_version must be >= {MIN_SCHEMA_VERSION}")
    raw_records = payload.get("records")
    if not isinstance(raw_records, list):
        return InventoryAudit(0, (), (*errors, "records is not a list"))
    seen: set[str] = set()
    statuses: dict[str, int] = {}
    for index, raw_record in enumerate(raw_records):
        if not isinstance(raw_record, dict):
            errors.append(f"record[{index}] is not an object")
            continue
        errors.extend(_audit_record(raw_record, index, seen, statuses))
    collected_count = payload.get("collected_count")
    if collected_count != len(raw_records):
        errors.append(f"collected_count={collected_count!r} does not match records={len(raw_records)}")
    return InventoryAudit(len(raw_records), tuple(sorted(statuses.items())), tuple(errors))


def main(argv: list[str] | None = None) -> int:
    """Validate one inventory JSON file and report a compact status summary."""

    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args(argv)
    payload = json.loads(args.inventory.read_text(encoding="utf-8"))
    audit = validate_inventory_payload(payload)
    if audit.errors:
        for error in audit.errors:
            print(f"pytest inventory error: {error}")
        return 1
    statuses = ", ".join(f"{status}={count}" for status, count in audit.status_counts)
    print(f"pytest inventory passed: records={audit.record_count}; {statuses}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
