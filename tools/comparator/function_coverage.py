"""Layer: validation reporting.

Responsibility: measure checked proof verdicts against every original function,
including named, unmapped and unselected entries, without changing verdicts.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from tools.comparator.verdict import Status


def original_function_coverage(
    original_names: Sequence[str], results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Count unique original obligations; duplicate evidence cannot earn coverage.

    The denominator is the complete original listing catalog, rather than the
    selected sample or the subset with a candidate mapping. Conditional proofs
    remain separate. Missing and duplicate rows remain visibly unproved.
    """
    names = set(original_names)
    if len(names) != len(original_names) or any(not name for name in names):
        raise ValueError("original function manifest must contain unique nonempty names")
    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for row in results:
        function = row.get("function")
        if not isinstance(function, Mapping) or not isinstance(function.get("name"), str):
            raise ValueError("coverage result lacks a function identity")
        by_name.setdefault(function["name"], []).append(row)
    counts: Counter[Status] = Counter()
    missing: list[str] = []
    duplicate: list[str] = []
    for name in sorted(names):
        rows = by_name.get(name, [])
        if not rows:
            missing.append(name)
        elif len(rows) != 1:
            duplicate.append(name)
        else:
            counts[Status(rows[0]["status"])] += 1
    total = len(names)
    return {
        "schema": "comparator.original_function_coverage.v1",
        "denominator": "all functions in the original listing catalog",
        "original_functions": total,
        "reported_original_functions": sum(counts.values()),
        **{status.value: counts[status] for status in Status},
        "unselected_or_missing": missing,
        "duplicate_results": duplicate,
        "non_original_results": sorted(by_name.keys() - names),
        "proved_percent": 100 * counts[Status.PASSED] / total if total else 0.0,
        "conditional_percent": 100 * counts[Status.CONDITIONAL] / total if total else 0.0,
        "target_percent": 80,
        "target_comparison": ">",
        "target_met": bool(total) and counts[Status.PASSED] * 100 > total * 80,
    }
