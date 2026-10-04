"""Regressions for complete and honestly scoped flat32 proof verdicts."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import angr
import pytest

sys.path.insert(0, str(Path(__file__).parent))
import flat32_cfg
import z3cmp32
from flat32_adapter import OUTPUT_REGS, S, installed
from flat32_catalog import Symbol


def test_cfg_cannot_pass_without_passing_block_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero failures in a summary must not stand in for an actual block proof."""
    project = angr.load_shellcode(b'\xc3', arch='x86', load_address=0x100000)
    raw = {'summary': {'total': 1, 'passed': 0, 'failed': 0, 'refused': 0}, 'results': []}
    monkeypatch.setattr(S, 'compare_ssa_documents', lambda **kwargs: raw)
    result = flat32_cfg.compare_cfg(project, project, name='f', oracle_range=(0x100000, 1),
        candidate_range=(0x100000, 1), outputs=OUTPUT_REGS, timeout_ms=1000)
    assert result['status'] == 'refused'


def scalar_comparison(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, normalize: bool) -> dict[str, Any]:
    """Compare two unequal scalar returns whose constants match a relocation map."""
    original = tmp_path / 'oracle.bin'
    candidate = tmp_path / 'candidate.bin'
    original.write_bytes(bytes.fromhex('b834120000 c3'))
    candidate.write_bytes(bytes.fromhex('b878560000 c3'))
    projects = {path: angr.load_shellcode(path.read_bytes(), arch='x86', load_address=0x100000)
                for path in (original, candidate)}
    monkeypatch.setattr(z3cmp32, 'load32', projects.__getitem__)
    monkeypatch.setattr(S, '_load_lifter_project', projects.__getitem__)
    monkeypatch.setattr(z3cmp32, 'lst_functions', lambda path: {'sub_test': (0x100000, 0x100005)})
    monkeypatch.setattr(z3cmp32, 'nm_symbols', lambda path: {'sub_test': Symbol(0x100000, 6, 'T')})
    monkeypatch.setattr(z3cmp32, 'global_map', lambda *args: {0x5678: 0x1234})
    monkeypatch.setattr(z3cmp32, 'lst_data_symbols', lambda path: {})
    args = argparse.Namespace(oracle_exe=original, candidate_exe=candidate, oracle_lst=original,
        candidate_lst=None, functions='sub_test', mode='leaf', scan_limit=8192,
        output_regs='eax,edx,esp', timeout_ms=1000, normalize_globals=normalize, out_dir=tmp_path)
    return z3cmp32.compare(args)


def test_relocated_scalar_equality_is_not_an_unconditional_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Relocation can hide scalar changes: expose the assumption and return incomplete."""
    with installed():
        raw = scalar_comparison(tmp_path, monkeypatch, False)
        relocated = scalar_comparison(tmp_path, monkeypatch, True)
    assert raw['summary']['failed'] == 1
    assert relocated['results'][0]['status'] == 'conditional'
    assert relocated['summary']['passed'] == 0
    assert z3cmp32.exit_code(relocated['summary']) == 2


def backend_report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build realistic counters independently from each backend result record."""
    return {'results': rows, 'summary': {'total': len(rows), **{
        status: sum(row['status'] == status for row in rows) for status in ('passed', 'failed', 'refused')}}}


def backend_row(name: str = 'f', status: str = 'passed') -> dict[str, Any]:
    """Associate solver evidence with its exact oracle function identity."""
    return {'function': {'id': f'oracle:{name}', 'name': name}, 'status': status}


@pytest.mark.parametrize('corruption', ['missing', 'duplicate', 'unknown_status', 'wrong_id', 'wrong_counter',
                                       'unexpected', 'aborted', 'malformed'])
def test_incomplete_or_inconsistent_evidence_never_passes(corruption: str) -> None:
    """Reject realistic backend boundary failures instead of trusting zero failed counts."""
    from flat32_verdict import aggregate, checked_results

    rows = [backend_row()]
    if corruption == 'missing':
        rows = []
    elif corruption == 'duplicate':
        rows.append(backend_row())
    elif corruption == 'unknown_status':
        rows[0]['status'] = 'timeout'
    elif corruption == 'wrong_id':
        rows[0]['function']['id'] = 'oracle:other'
    elif corruption == 'unexpected':
        rows.append(backend_row('extra'))
    report = backend_report(rows)
    if corruption == 'wrong_counter':
        report['summary']['passed'] = 0
    elif corruption == 'aborted':
        report['summary']['aborted'] = {'phase': 'ssa_pair', 'reason': 'memory_limit'}
    elif corruption == 'malformed':
        report['results'] = None
    verdicts = checked_results({'f': 'oracle:f'}, report)
    assert len(verdicts) == 1
    assert aggregate(verdicts) == 'refused'


def test_partial_batch_keeps_independent_proofs_and_missing_obligations() -> None:
    """A missing function remains visible without discarding a valid independent proof."""
    from flat32_verdict import aggregate, checked_results, summarize

    verdicts = checked_results({'f': 'oracle:f', 'g': 'oracle:g'}, backend_report([backend_row()]))
    assert [row['status'] for row in verdicts] == ['passed', 'refused']
    assert aggregate(verdicts) == 'refused'
    assert z3cmp32.exit_code(summarize(verdicts)) == 2


def test_unmodified_evidence_passes_and_failures_remain_failures() -> None:
    """The proof guard preserves valid PASS and mismatch outcomes."""
    from flat32_verdict import aggregate, checked_results, summarize

    for status, expected_exit in [('passed', 0), ('failed', 1)]:
        verdicts = checked_results({'f': 'oracle:f'}, backend_report([backend_row(status=status)]))
        assert aggregate(verdicts) == status
        assert z3cmp32.exit_code(summarize(verdicts)) == expected_exit
