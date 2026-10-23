"""Explicit vectors refute native functions without weakening proof domains."""

import hashlib
import json
from argparse import Namespace
from pathlib import Path

import pytest

from tools.comparator.concrete_witness_catalog import attach_concrete_catalog, prepare_concrete_catalog

pytestmark = pytest.mark.ssa_z3


def _catalog(tmp_path: Path, value: int = 128) -> Path:
    path = tmp_path / 'vectors.json'
    vector = {'id': 'byte', 'registers': {'esp': '0x28000'},
              'memory': [{'address': '0x30000', 'bytes': bytes([value, 0]).hex()},
                         {'address': '0x28004', 'bytes': (0x30000).to_bytes(4, 'little').hex()
                          + value.to_bytes(4, 'little').hex()}],
              'mappings': [{'address': '0x30000', 'size': 4096, 'access': ['read', 'write']}]}
    path.write_text(json.dumps({'schema': 'dosunit.flat32_concrete_witnesses.v1', 'functions': {'f': [vector]}}))
    return path


def _args(path: Path) -> Namespace:
    return Namespace(concrete_counterexample_vectors=path, mode='matched-cfg', normalize_globals=False,
                     output_regs='eax,esp')


@pytest.mark.parametrize('field,value', [('mode', 'leaf'), ('normalize_globals', True),
                                       ('abi_observation_catalog', 'abi.json'),
                                       ('external_call_catalog', 'external.json'), ('output_regs', 'ax,esp')])
def test_incompatible_proof_domains_are_rejected(tmp_path: Path, field: str, value: object) -> None:
    args = _args(_catalog(tmp_path))
    vars(args)[field] = value
    with pytest.raises(ValueError, match='concrete counterexamples'):
        prepare_concrete_catalog(args)


def test_catalog_cannot_override_entry_or_change_after_intake(tmp_path: Path) -> None:
    path = _catalog(tmp_path)
    catalog = prepare_concrete_catalog(_args(path))
    assert catalog is not None
    assert catalog.digest == hashlib.sha256(path.read_bytes()).hexdigest()
    document = json.loads(path.read_text())
    document['functions']['f'][0]['oracle_entry'] = '0x1234'
    path.write_text(json.dumps(document))
    with pytest.raises(RuntimeError, match='changed'):
        attach_concrete_catalog({}, catalog, b'', b'', {'f'})
    with pytest.raises(ValueError, match='entries come from'):
        prepare_concrete_catalog(_args(path))


def test_concrete_input_must_satisfy_declared_root_stack_domain(tmp_path: Path) -> None:
    args = _args(_catalog(tmp_path))
    args.entry_esp_range = '0x30000:0x40000'
    with pytest.raises(ValueError, match='outside the declared entry domain'):
        prepare_concrete_catalog(args)
    args.entry_esp_range = '0x28000:0x28000'
    assert prepare_concrete_catalog(args) is not None


def test_catalog_retains_memory_counterexample_and_original_refusal(tmp_path: Path) -> None:
    from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

    path = _catalog(tmp_path)
    document = json.loads(path.read_text())
    document['functions']['f'][0]['observations'] = [{'address': '0x30000', 'size': 4}]
    path.write_text(json.dumps(document))
    catalog = prepare_concrete_catalog(_args(path))
    assert catalog is not None
    left = bytes.fromhex('c705000003000700000031c0c3')
    right = bytes.fromhex('c705000003000800000031c0c3')
    report = {'function_ranges': {'oracle': {'f': (0x401000, len(left))},
                                  'candidate': {'f': (0x401000, len(right))}},
              'results': [{'function': {'name': 'f'}, 'status': 'refused', 'reason': 'test_boundary'}]}
    attach_concrete_catalog(report, catalog, pe32_bytes(left), pe32_bytes(right), {'f'})
    row, = report['results']
    assert row['reason'] == 'concrete_memory_counterexample'
    assert row['status'] == 'failed'
    assert row['strict_function_result']['reason'] == 'test_boundary'
    assert row['concrete_counterexamples'][0]['mismatches'][0]['oracle_bytes'] == '07000000'


@pytest.mark.parametrize('value,expected', [(127, 'refused'), (128, 'failed')])
def test_public_driver_replays_native_loop_counterexample(tmp_path: Path, value: int, expected: str) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    # CL char_file original/rebuild instruction shapes: byte comparison versus
    # signed character argument compared with a zero-extended string byte.
    left = bytes.fromhex('8b44240480380074138a4c2408380874064080380075f680380075022bc0c3')
    right = bytes.fromhex('8b44240480380075072bc0c38d6424000fbe4c240833d28a103bd174064080380075f2'
                          '80380075022bc0c30500000000')
    original, candidate = tmp_path/'o.exe', tmp_path/'c.exe'
    original.write_bytes(pe32_bytes(left))
    candidate.write_bytes(pe32_bytes(right))
    path = _catalog(tmp_path, value)
    with _driver_lane('msc8') as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.oracle_lst.write_text(f'.text:00401000 f proc near\n.text:{0x401000+len(left)-1:08X} f endp\n')
        listing = tmp_path/'candidate.lst'
        listing.write_text(f'.text:00401000 f proc near\n.text:{0x401000+len(right)-1:08X} f endp\n')
        args.candidate_lst, args.candidate_lst_end_kind = listing, 'last-byte'
        args.mode, args.output_regs = 'matched-cfg', 'eax,esp'
        args.concrete_counterexample_vectors = path
        report = lane.z3cmp32.compare(args)
    row, = report['results']
    assert row['status'] == expected, row
    assert report['auxiliary_inputs']['concrete_counterexample_vectors']['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    evidence, = row['concrete_counterexamples']
    if expected == 'failed':
        assert row['strict_function_result']['status'] == 'refused'
        assert row['proof_scope'] == 'complete_function'
        assert evidence['mismatches'] == [{'reg': 'eax', 'oracle_value': '0x30000', 'candidate_value': '0x0'}]
    else:
        assert evidence['reason'] == 'concrete_agreement_is_not_proof'
