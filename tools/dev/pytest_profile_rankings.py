"""Build compact cost rankings from pytest profile records.

Layer: Tooling/gates.
Responsibility: identify the dominant wall-time and child-CPU nodes without
duplicating full test records in profile artifacts.
"""

from __future__ import annotations

from collections.abc import Iterable


def _seconds(record: dict[str, object], key: str) -> float:
    """Return one numeric duration field or zero for malformed input."""

    value = record.get(key)
    return float(value) if isinstance(value, int | float) else 0.0


def _rank(
    records: Iterable[dict[str, object]],
    *,
    key: str,
    limit: int,
) -> list[dict[str, object]]:
    """Rank executed records by one duration while preserving useful identity."""

    executed = [record for record in records if record.get("outcome") != "not-run"]
    ranked = sorted(executed, key=lambda record: (-_seconds(record, key), str(record.get("nodeid", ""))))
    return [
        {
            "nodeid": record.get("nodeid"),
            "seconds": _seconds(record, key),
            "setup_seconds": _seconds(record, "setup_seconds"),
            "call_seconds": _seconds(record, "call_seconds"),
            "teardown_seconds": _seconds(record, "teardown_seconds"),
            "static_subprocess_count": record.get("static_subprocess_count"),
            "function_address_hints": record.get("function_address_hints"),
            "input_hints": record.get("input_hints"),
        }
        for record in ranked[:limit]
    ]


def profile_cost_rankings(
    records: Iterable[dict[str, object]],
    *,
    limit: int = 50,
) -> dict[str, list[dict[str, object]]]:
    """Return deterministic top-node rankings for required cost dimensions."""

    materialized = list(records)
    return {
        "wall_seconds": _rank(materialized, key="total_seconds", limit=limit),
        "child_cpu_seconds": _rank(materialized, key="child_cpu_seconds", limit=limit),
    }
