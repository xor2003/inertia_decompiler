"""Ensure SCC reports cannot promote conditional or absent member evidence."""

from collections import Counter

import pytest

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.scc_proof_admission import admit_scc_statuses, scc_status_counters
from tools.dosunit.straightline_ssa import _call_scc_component_result, _scc_gate_summary


@pytest.mark.parametrize("unproved", ["conditional", "unknown", "refused", "unsupported", "unmapped", "unexpected"])
def test_call_cycle_requires_all_unconditional_members(unproved: str) -> None:
    result = _call_scc_component_result(
        ["a", "b"], {"a": {"b"}, "b": {"a"}},
        {"a": Counter({unproved: 1}), "b": Counter({"passed": 1})}, {},
    )
    assert result is not None
    assert result["status"] == "refused"
    assert result["reason"] == "call_cycle_unproven"
    assert result["function_count"] == 2


@pytest.mark.parametrize("unproved", ["conditional", "unknown", "refused", "unsupported", "unmapped", None])
def test_summary_retains_incomplete_denominator(unproved: str | None) -> None:
    results = [{"status": "passed"}, {"status": unproved}]
    summary = _scc_gate_summary(results)
    assert summary["status"] == "refused"
    assert (summary["total"], summary["passed"], summary["failed"], summary["refused"]) == (2, 1, 0, 1)
    assert summary["results"] == results
    assert summary["evidence"] == {
        "raw_fact_count": 2, "normalized_fact_count": 2,
        "classified_fact_count": 2, "materialized_count": 2, "failure_count": 1,
    }


def test_counterexample_dominates_conditional_and_missing_members() -> None:
    summary = _scc_gate_summary([{"status": "conditional"}, {}, {"status": "failed"}])
    assert summary["status"] == "failed"
    assert (summary["total"], summary["passed"], summary["failed"], summary["refused"]) == (3, 0, 1, 2)


def test_only_nonempty_complete_members_prove() -> None:
    assert admit_scc_statuses(()) is ProofStatus.UNKNOWN
    assert admit_scc_statuses((ProofStatus.PROVED, ProofStatus.PROVED)) is ProofStatus.PROVED
    for status in ProofStatus:
        expected = status if status in {ProofStatus.PROVED, ProofStatus.COUNTEREXAMPLE} else ProofStatus.UNKNOWN
        assert admit_scc_statuses((ProofStatus.PROVED, status)) is expected
    assert _scc_gate_summary([])["status"] == "not_applicable"


def test_missing_cycle_member_refuses() -> None:
    result = _call_scc_component_result(["a", "b"], {"a": {"b"}, "b": {"a"}}, {"a": Counter({"passed": 1})}, {})
    assert result is not None
    assert result["status"] == "refused"


def test_complete_cycle_members_keep_proved_rollup() -> None:
    result = _call_scc_component_result(
        ["a", "b"], {"a": {"b"}, "b": {"a"}},
        {"a": Counter({"passed": 1}), "b": Counter({"passed": 2})}, {},
    )
    assert result is not None
    assert result["status"] == "passed"
    summary = _scc_gate_summary([result])
    assert (summary["status"], summary["total"], summary["passed"], summary["refused"]) == ("passed", 1, 1, 0)


def test_status_pipeline_keeps_closed_refusal_evidence() -> None:
    counters = scc_status_counters((ProofStatus.CONDITIONAL, None, ProofStatus.COUNTEREXAMPLE))
    assert counters.closed()
    assert counters.raw_fact_count == counters.normalized_fact_count == counters.classified_fact_count == 3
    assert counters.materialized_count == counters.failure_count == 3
    empty = scc_status_counters(())
    assert empty.closed()
    assert empty.classified_fact_count == empty.materialized_count == 0
