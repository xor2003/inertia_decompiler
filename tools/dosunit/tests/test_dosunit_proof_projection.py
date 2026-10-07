"""Legacy comparator boundaries must preserve incomplete proof evidence."""

from tools.dosunit.contracts.proof_contracts import (
    Architecture,
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ProofStatus,
    evaluate_obligations,
    report_to_document,
)
from tools.dosunit.reporting.proof_projection import project_backend_report


def _contract():
    return ContractIdentity(Architecture.FLAT32, 'original', 'candidate', 'semantics', 'model', 'abi')


def _report(rows):
    return {'results': rows, 'summary': {'total': len(rows),
            **{s: sum(row['status'] == s for row in rows) for s in ['passed', 'failed', 'refused', 'conditional']}}}


def test_missing_duplicate_and_unexpected_function_evidence_cannot_prove():
    row = {'function': {'name': 'f'}, 'status': 'passed'}
    for names, rows in [(('f', 'g'), [row]), (('f',), [row, row]), (('g',), [row])]:
        report = project_backend_report(_contract(), names, _report(rows))
        assert report.status == ProofStatus.UNKNOWN


def test_backend_assumptions_and_inconsistent_summary_cannot_prove():
    row = {'function': {'name': 'f'}, 'status': 'passed', 'assumptions': {'paired_calls': 'equal'}}
    report = project_backend_report(_contract(), ('f',), _report([row]))
    assert report.status == ProofStatus.CONDITIONAL
    raw = _report([{'function': {'name': 'f'}, 'status': 'passed'}])
    raw['summary']['total'] = 2
    assert project_backend_report(_contract(), ('f',), raw).status == ProofStatus.UNKNOWN


def test_complete_nonempty_report_proves_only_its_declared_obligations():
    raw = _report([{'function': {'name': 'f'}, 'status': 'passed'}])
    report = project_backend_report(_contract(), ('f',), raw)
    assert report.status == ProofStatus.PROVED
    assert report.counters.raw_fact_count == report.counters.materialized_count == 1
    assert project_backend_report(_contract(), (), _report([])).status == ProofStatus.UNKNOWN


def test_failed_fact_cannot_be_published_as_proved():
    identity = ObligationId('function', 'f')
    evidence = ObligationEvidence(identity, _contract(), ProofStatus.PROVED,
                                  counters=FactCounters(1, 1, 1, 1, 1))
    assert evaluate_obligations(_contract(), (Obligation(identity),), (evidence,)).status == ProofStatus.UNKNOWN


def test_consumed_dependencies_and_assumptions_survive_serialization():
    leaf, caller = ObligationId('function', 'leaf'), ObligationId('function', 'caller')
    evidence = (
        ObligationEvidence(leaf, _contract(), ProofStatus.PROVED),
        ObligationEvidence(caller, _contract(), ProofStatus.PROVED, dependencies=(leaf,), assumptions=('environment',)),
    )
    report = evaluate_obligations(_contract(), (Obligation(leaf), Obligation(caller)), evidence)
    document = report_to_document(report)
    caller_row = next(row for row in document['verdicts'] if row['id']['key'] == 'caller')
    assert caller_row['dependencies'] == [{'kind': 'function', 'key': 'leaf'}]
    assert caller_row['assumptions'] == ['environment']
    assert caller_row['evidence_contract_key'] == _contract().key()


def test_malformed_backend_rows_are_retained_as_refusals():
    from tools.dosunit.reporting.flat32_proof_report import _checked_rows

    for raw in ({'results': None, 'summary': None}, {'results': [None], 'summary': {}}):
        report = project_backend_report(_contract(), ('f',), raw)
        rows = _checked_rows(raw, report_to_document(report))
        assert len(rows) == 1
        assert rows[0]['function']['name'] == 'f'
        assert rows[0]['status'] == 'refused'
