"""Binary artifact provenance must reject stale data and model identities."""

from pathlib import Path

import pytest

from tools.dosunit.ssa_provenance import begin_lowering, checked_provenance, seal_lowering


def test_binary_and_contract_mutations_invalidate_ssa(tmp_path: Path) -> None:
    executable = tmp_path / 'input.bin'
    executable.write_bytes(b'original')
    document = {'exe': str(executable), 'parameters': {'output_regs': ['ax']}, 'functions': []}
    seal_lowering(document, executable, begin_lowering(executable))
    assert checked_provenance(document)['complete']
    document['parameters']['output_regs'] = ['bx']
    assert not checked_provenance(document)['complete']
    document['parameters']['output_regs'] = ['ax']
    executable.write_bytes(b'changed')
    assert not checked_provenance(document)['complete']


def test_concurrent_binary_mutation_cannot_seal_lowering(tmp_path: Path) -> None:
    executable = tmp_path / 'input.bin'
    executable.write_bytes(b'original')
    before = begin_lowering(executable)
    executable.write_bytes(b'changed')
    with pytest.raises(RuntimeError, match='changed during SSA lowering'):
        seal_lowering({}, executable, before)


def test_legacy_artifact_does_not_acquire_invented_binary_provenance() -> None:
    assert checked_provenance({'exe': '/missing/legacy'}) == {
        'complete': False, 'reason': 'legacy_artifact_without_provenance',
    }
