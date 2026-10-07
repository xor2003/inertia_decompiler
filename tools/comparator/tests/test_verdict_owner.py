"""Qualified verdict ownership, legacy identity and proof-source coverage."""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_legacy_verdict_alias_is_pure_and_preserves_pickle(driver):
    root = Path(__file__).resolve().parents[3]
    script = """
import pickle
import sys
sys.path.insert(0, sys.argv[1])
import flat32_verdict as legacy
from tools.comparator import verdict
assert legacy is verdict
assert pickle.loads(pickle.dumps(legacy.Status.PASSED)) is verdict.Status.PASSED
assert pickle.loads(b'cflat32_verdict\\nStatus\\n(Vpassed\\ntR.') is verdict.Status.PASSED
assert not {'angr', 'pyvex', 'z3', 'tools.dosunit.compare.straightline_ssa'} & sys.modules.keys()
"""
    subprocess.run([sys.executable, "-c", script, str(root / "artifacts" / f"{driver}-z3cmp32")],
                   cwd=root, check=True)


def test_public_proof_seal_includes_canonical_verdict_owner():
    from tools.comparator import verdict
    from tools.dosunit.reporting.flat32_proof_report import _semantic_sources

    root = Path(__file__).resolve().parents[3]
    owner = Path(verdict.__file__)
    sources = _semantic_sources(root / "artifacts" / "msc8-z3cmp32" / "z3cmp32.py")
    assert sources[str(owner)] == hashlib.sha256(owner.read_bytes()).hexdigest()


def test_catalog_owner_is_pure_and_preserves_full_width_coordinates():
    script = """
import sys
from tools.comparator.catalog import catalog, mapping
base = 0x12000000
document = catalog('oracle', {'second': (0x12346000, 7), 'first': (0x12345000, 13)}, base)
assert [row['names'][0] for row in document['functions']] == ['first', 'second']
for row, expected in zip(document['functions'], (0x12345000, 0x12346000), strict=True):
    assert base + int(row['entry']['offset'], 0) == expected
    assert int(row['entry']['linear'], 0) == expected
pairs = mapping('oracle', 'candidate', ['first', 'second'])
assert [row['oracle_id'] for row in pairs['functions']] == ['oracle:first', 'oracle:second']
assert [row['candidate_id'] for row in pairs['functions']] == ['candidate:first', 'candidate:second']
assert not {'angr', 'pyvex', 'z3', 'tools.dosunit.compare.straightline_ssa'} & sys.modules.keys()
"""
    subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[3], check=True)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_target_catalog_legacy_identity_and_historical_pickle(driver):
    root = Path(__file__).resolve().parents[3]
    script = """
import pickle
import sys
sys.path.insert(0, sys.argv[1])
import flat32_catalog as legacy
import importlib
owner = importlib.import_module('tools.comparator.' + sys.argv[2] + '_catalog')
assert legacy is owner
assert legacy.Symbol is owner.Symbol
symbol = legacy.Symbol(0x12345000, 13, 'T')
assert pickle.loads(pickle.dumps(symbol)) == symbol
if sys.argv[2] == 'msc8':
    assert pickle.loads(b'cflat32_catalog\\nListingEndKind\\n(Vlast-byte\\ntR.') is legacy.ListingEndKind.BYTE
"""
    subprocess.run([sys.executable, "-c", script, str(root / "artifacts" / f"{driver}-z3cmp32"), driver],
                   cwd=root, check=True)
