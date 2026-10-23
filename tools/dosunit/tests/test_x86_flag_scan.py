"""Bounded SSA flag scans must distinguish evidence from missing coverage.

Layer: tests.
Responsibility: retain honest mismatch diagnostics for shared DAGs, incomplete
scans and cyclic references without silently admitting unseen helper terms.
"""
from typing import Any

import pytest

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.ssa.flag_scan import FlagScanOutcome, scan_flag_evidence


def _scan(
    root: object, assignments: dict[str, dict[str, Any]], budget: int = 1024,
) -> FlagScanOutcome:
    """Use a single deliberately abstract operator for graph-only controls."""
    return scan_flag_evidence(
        root, assignments, summary_ops={"summary_test"},
        summary_is_uninterpreted=lambda _term, _assignments: True,
        step_budget=budget,
    )


def _chain(count: int) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Build a shared binary DAG with linear unique size."""
    assignments: dict[str, dict[str, Any]] = {}
    value: dict[str, Any] = {"op": "const", "width": 16, "value": "0x0"}
    for index in range(count):
        key = f"v{index}"
        assignments[key] = {"id": key, "op": "add", "width": 16, "args": [value, value]}
        value = {"ref": key}
    return value, assignments


def test_shared_dag_is_complete_without_counting_references_twice() -> None:
    """A repeated edge does not consume another compound-node expansion."""
    root, assignments = _chain(400)
    assert _scan(root, assignments, 400) is FlagScanOutcome.CLEAN
    assert _scan(root, assignments, 399) is FlagScanOutcome.INCOMPLETE


def test_large_helper_free_mismatch_is_not_reported_as_flags() -> None:
    """The public solver's real zero-versus-one mismatch stays a mismatch."""
    root, assignments = _chain(400)
    oracle = {"inputs": [], "assignments": list(assignments.values()), "outputs": {"ax": root}}
    candidate = {"inputs": [], "assignments": [],
                 "outputs": {"ax": {"op": "const", "width": 16, "value": "0x1"}}}
    result = S._compare_functions(oracle, candidate, timeout_ms=1000)
    assert result["status"] == "failed", result
    assert result["reason"] == "observable_mismatch", result


@pytest.mark.parametrize("assignments", [
    {},
    {"a": {"op": "add", "args": [{"ref": "a"}]}},
    {"a": {"ref": "b"}, "b": {"ref": "a"}},
    {"a": {"op": "add", "args": [{"ref": "b"}, {"ref": "c"}]},
     "b": {"op": "add", "args": [{"ref": "c"}]},
     "c": {"op": "add", "args": [{"ref": "b"}]}},
])
def test_missing_and_cyclic_references_remain_incomplete(assignments: dict[str, dict[str, Any]]) -> None:
    """A sibling queued before a back-edge is not a completed subtree."""
    assert _scan({"ref": "a"}, assignments) is FlagScanOutcome.INCOMPLETE


def test_inline_cycle_is_incomplete() -> None:
    """Defensive in-memory scans do not certify cyclic dictionaries clean."""
    root: dict[str, Any] = {"op": "add"}
    root["args"] = [root]
    assert _scan(root, {}) is FlagScanOutcome.INCOMPLETE


def test_helper_beyond_budget_is_not_invented_evidence() -> None:
    """An unvisited helper leaves unknown coverage, not a positive flag finding."""
    root, assignments = _chain(4)
    assignments["v0"]["args"] = [{"op": "summary_test", "args": []}]
    assert _scan(root, assignments, 2) is FlagScanOutcome.INCOMPLETE
    assert _scan(root, assignments, 4) is FlagScanOutcome.UNINTERPRETED_HELPER


def test_shared_sibling_is_not_a_cycle() -> None:
    """A diamond in the reference graph remains an ordinary shared DAG."""
    assignments = {"a": {"op": "add", "args": [{"ref": "b"}, {"ref": "c"}]},
                   "b": {"op": "add", "args": [{"ref": "c"}]},
                   "c": {"op": "const", "value": "0x0", "width": 16}}
    assert _scan({"ref": "a"}, assignments) is FlagScanOutcome.CLEAN


def test_incomplete_scan_has_its_own_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing scan coverage cannot silently certify a concrete mismatch."""
    monkeypatch.setattr(S, "_output_uses_x86_lazy_flags", lambda *_: FlagScanOutcome.INCOMPLETE)
    oracle = {"inputs": [], "assignments": [],
              "outputs": {"ax": {"op": "const", "width": 16, "value": "0x0"}}}
    candidate = {"inputs": [], "assignments": [],
                 "outputs": {"ax": {"op": "const", "width": 16, "value": "0x1"}}}
    result = S._compare_functions(oracle, candidate, timeout_ms=1000)
    assert result["status"] == "refused", result
    assert result["reason"] == "x86_flag_scan_incomplete", result
