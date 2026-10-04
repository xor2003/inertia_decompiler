from __future__ import annotations

import json

import pytest

from tools.dosunit.proof_contracts import (
    Architecture,
    ContractIdentity,
    ExecutionEvidence,
    ExecutionStatus,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ProofReason,
    ProofStatus,
    evaluate_obligations,
    legacy_status_for,
    proof_status_from_legacy,
    report_json_bytes,
    report_to_document,
)


def _contract(**overrides: object) -> ContractIdentity:
    fields: dict[str, object] = {
        "architecture": Architecture.FLAT32,
        "original_hash": "orig-image",
        "candidate_hash": "cand-image",
        "semantic_hash": "semantics-v1",
        "model_hash": "model-v1",
        "abi_hash": "abi-v1",
    }
    fields.update(overrides)
    return ContractIdentity(**fields)  # type: ignore[arg-type]


def _ob_id(key: str) -> ObligationId:
    return ObligationId(kind="function", key=key)


def _obligation(key: str, deps: tuple[ObligationId, ...] = ()) -> Obligation:
    return Obligation(id=_ob_id(key), dependencies=deps)


def _evidence(
    key: str,
    *,
    contract: ContractIdentity | None = None,
    status: ProofStatus = ProofStatus.PROVED,
    deps: tuple[ObligationId, ...] = (),
    assumptions: tuple[str, ...] = (),
    counters: FactCounters | None = None,
) -> ObligationEvidence:
    return ObligationEvidence(
        id=_ob_id(key),
        contract=contract or _contract(),
        status=status,
        reason="z3_equal",
        method="z3_ssa_relation",
        dependencies=deps,
        assumptions=assumptions,
        counters=counters or FactCounters(),
    )


def _verdicts(report):
    return {verdict.id.key: verdict for verdict in report.verdicts}


def test_complete_evidence_proves() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a"), _obligation("b")],
        [_evidence("a"), _evidence("b")],
    )
    assert report.status is ProofStatus.PROVED
    assert report.problem is None
    assert all(verdict.reason is ProofReason.DISCHARGED for verdict in report.verdicts)


def test_empty_obligation_set_refuses() -> None:
    report = evaluate_obligations(_contract(), [], [])
    assert report.status is ProofStatus.UNKNOWN
    assert report.problem is ProofReason.EMPTY_OBLIGATIONS


def test_missing_evidence_cannot_prove() -> None:
    report = evaluate_obligations(_contract(), [_obligation("a"), _obligation("b")], [_evidence("a")])
    verdicts = _verdicts(report)
    assert verdicts["a"].status is ProofStatus.PROVED
    assert verdicts["b"].status is ProofStatus.UNKNOWN
    assert verdicts["b"].reason is ProofReason.MISSING_EVIDENCE
    assert report.status is ProofStatus.UNKNOWN


def test_duplicate_evidence_cannot_prove() -> None:
    report = evaluate_obligations(_contract(), [_obligation("a")], [_evidence("a"), _evidence("a")])
    assert report.status is ProofStatus.UNKNOWN
    assert report.verdicts[0].reason is ProofReason.DUPLICATE_EVIDENCE


def test_duplicate_required_obligation_rejects_report() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a"), _obligation("a"), _obligation("b")],
        [_evidence("a"), _evidence("b")],
    )
    assert report.status is ProofStatus.UNKNOWN
    assert report.problem is ProofReason.DUPLICATE_OBLIGATION
    assert all(verdict.status is ProofStatus.UNKNOWN for verdict in report.verdicts)


def test_unexpected_evidence_rejects_report() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a")],
        [_evidence("a"), _evidence("ghost")],
    )
    assert report.status is ProofStatus.UNKNOWN
    assert report.problem is ProofReason.UNEXPECTED_EVIDENCE
    assert report.unexpected_evidence == (_ob_id("ghost"),)
    assert report.verdicts[0].reason is ProofReason.UNEXPECTED_EVIDENCE


def test_stale_candidate_identity_cannot_prove() -> None:
    stale = _contract(candidate_hash="older-candidate")
    report = evaluate_obligations(_contract(), [_obligation("a")], [_evidence("a", contract=stale)])
    assert report.status is ProofStatus.UNKNOWN
    assert report.verdicts[0].reason is ProofReason.CONTRACT_MISMATCH


@pytest.mark.parametrize("field", ["original_hash", "candidate_hash", "semantic_hash", "model_hash", "abi_hash"])
def test_narrowed_contract_fields_cannot_prove(field: str) -> None:
    narrowed = _contract(**{field: "narrowed-contract"})
    report = evaluate_obligations(_contract(), [_obligation("a")], [_evidence("a", contract=narrowed)])
    assert report.status is ProofStatus.UNKNOWN
    assert report.verdicts[0].reason is ProofReason.CONTRACT_MISMATCH


def test_assumption_laden_evidence_is_conditional() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a")],
        [_evidence("a", assumptions=("equal_post_call_state",))],
    )
    assert report.status is ProofStatus.CONDITIONAL
    assert report.verdicts[0].reason is ProofReason.UNPROVED_ASSUMPTIONS


def test_conditional_dependency_cannot_prove_dependent() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("leaf"), _obligation("caller", deps=(_ob_id("leaf"),))],
        [_evidence("leaf", status=ProofStatus.CONDITIONAL), _evidence("caller")],
    )
    verdicts = _verdicts(report)
    assert verdicts["leaf"].status is ProofStatus.CONDITIONAL
    assert verdicts["caller"].status is ProofStatus.CONDITIONAL
    assert verdicts["caller"].reason is ProofReason.DEPENDENCY_CONDITIONAL
    assert report.status is ProofStatus.CONDITIONAL


def test_unproved_dependency_cannot_prove_dependent() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("leaf"), _obligation("caller", deps=(_ob_id("leaf"),))],
        [_evidence("caller")],
    )
    verdicts = _verdicts(report)
    assert verdicts["caller"].status is ProofStatus.UNKNOWN
    assert verdicts["caller"].reason is ProofReason.DEPENDENCY_UNPROVED
    assert report.status is ProofStatus.UNKNOWN


def test_evidence_declared_dependency_is_enforced() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("caller")],
        [_evidence("caller", deps=(_ob_id("leaf"),))],
    )
    assert report.verdicts[0].status is ProofStatus.UNKNOWN
    assert report.verdicts[0].reason is ProofReason.DEPENDENCY_MISSING


def test_dependency_cycle_cannot_bootstrap() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a", deps=(_ob_id("b"),)), _obligation("b", deps=(_ob_id("a"),))],
        [_evidence("a"), _evidence("b")],
    )
    verdicts = _verdicts(report)
    assert verdicts["a"].reason is ProofReason.DEPENDENCY_CYCLE
    assert verdicts["b"].reason is ProofReason.DEPENDENCY_CYCLE
    assert report.status is ProofStatus.UNKNOWN


def test_self_dependency_cannot_bootstrap() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a", deps=(_ob_id("a"),))],
        [_evidence("a")],
    )
    assert report.verdicts[0].reason is ProofReason.DEPENDENCY_CYCLE
    assert report.status is ProofStatus.UNKNOWN


def test_cycle_member_cannot_propagate_proof() -> None:
    report = evaluate_obligations(
        _contract(),
        [
            _obligation("a", deps=(_ob_id("b"),)),
            _obligation("b", deps=(_ob_id("a"),)),
            _obligation("top", deps=(_ob_id("a"),)),
        ],
        [_evidence("a"), _evidence("b"), _evidence("top")],
    )
    verdicts = _verdicts(report)
    assert verdicts["top"].status is ProofStatus.UNKNOWN
    assert verdicts["top"].reason is ProofReason.DEPENDENCY_UNPROVED


def test_unmaterialized_facts_fail_closed() -> None:
    counters = FactCounters(raw_fact_count=5, normalized_fact_count=4, classified_fact_count=3, materialized_count=0)
    report = evaluate_obligations(_contract(), [_obligation("a")], [_evidence("a", counters=counters)])
    assert report.status is ProofStatus.UNKNOWN
    assert report.verdicts[0].reason is ProofReason.UNMATERIALIZED_FACTS
    assert report.counters.classified_fact_count == 3


def test_counters_aggregate_across_verdicts() -> None:
    counters_a = FactCounters(raw_fact_count=2, normalized_fact_count=2, classified_fact_count=1, materialized_count=1)
    counters_b = FactCounters(raw_fact_count=3, normalized_fact_count=1, failure_count=1)
    report = evaluate_obligations(
        _contract(),
        [_obligation("a"), _obligation("b")],
        [_evidence("a", counters=counters_a), _evidence("b", counters=counters_b)],
    )
    assert report.status is ProofStatus.UNKNOWN
    assert report.verdicts[1].reason is ProofReason.FAILED_FACTS
    assert report.counters.raw_fact_count == 5
    assert report.counters.materialized_count == 1
    assert report.counters.failure_count == 1


def test_counterexample_marks_aggregate() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("a"), _obligation("b")],
        [_evidence("a"), _evidence("b", status=ProofStatus.COUNTEREXAMPLE)],
    )
    assert report.status is ProofStatus.COUNTEREXAMPLE


def test_execution_state_stays_independent() -> None:
    executions = (ExecutionEvidence(id=_ob_id("a"), status=ExecutionStatus.MISMATCH, detail="ax differs"),)
    report = evaluate_obligations(_contract(), [_obligation("a")], [_evidence("a")], executions=executions)
    assert report.status is ProofStatus.PROVED
    assert report.executions == executions


def test_legacy_status_boundary() -> None:
    assert proof_status_from_legacy("passed") is ProofStatus.PROVED
    assert proof_status_from_legacy("failed") is ProofStatus.COUNTEREXAMPLE
    assert proof_status_from_legacy("refused") is ProofStatus.UNKNOWN
    assert proof_status_from_legacy("conditional") is ProofStatus.CONDITIONAL
    assert proof_status_from_legacy("timeout") is None
    assert proof_status_from_legacy(7) is None
    assert legacy_status_for(ProofStatus.PROVED) == "passed"
    assert legacy_status_for(ProofStatus.CONDITIONAL) == "conditional"
    assert legacy_status_for(ProofStatus.COUNTEREXAMPLE) == "failed"
    assert legacy_status_for(ProofStatus.UNMAPPED) == "refused"
    assert legacy_status_for(ProofStatus.UNSUPPORTED) == "refused"


def test_report_document_is_deterministic() -> None:
    report = evaluate_obligations(
        _contract(),
        [_obligation("b"), _obligation("a")],
        [_evidence("b"), _evidence("a")],
    )
    first = report_to_document(report)
    assert first == report_to_document(report)
    assert report_json_bytes(report) == report_json_bytes(report)
    decoded = json.loads(report_json_bytes(report))
    assert decoded["schema"] == "dosunit.proof_report.v1"
    assert decoded["status"] == "proved"
    assert decoded["obligations"] == {"required": 2, "attempted": 2, "discharged": 2, "conditional": 0, "failed": 0, "unresolved": 0}
    assert [row["id"]["key"] for row in decoded["verdicts"]] == ["a", "b"]
    assert decoded["verdicts"][0]["method"] == "z3_ssa_relation"
    assert decoded["contract"]["key"] == _contract().key()


def test_invalid_counters_rejected() -> None:
    with pytest.raises(ValueError):
        FactCounters(raw_fact_count=-1)
    with pytest.raises(ValueError):
        ContractIdentity(
            architecture=Architecture.REAL16,
            original_hash="",
            candidate_hash="c",
            semantic_hash="s",
            model_hash="m",
            abi_hash="a",
        )
