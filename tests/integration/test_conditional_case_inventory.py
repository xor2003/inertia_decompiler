"""Decode retained final records without replacing their source/IPC authority."""
import hashlib
import json
from dataclasses import replace

import pytest

from inertia.cli import cli_core
from inertia.cli.work_items import FunctionWorkResult
from tests.lowering.test_scalar_interface_transport import _world
from tools.compiler_toolchain.compiler_profile import FrozenCompilerContext
from tools.compiler_toolchain.conditional_case_composition import FrozenCaseCompositionInput
from tools.compiler_toolchain.conditional_case_inventory import (
    FinalAttemptInventoryStatus,
    load_final_function_attempts,
)
from tools.compiler_toolchain.conditional_function_receipt import ConditionalTransportOrigin
from tools.compiler_toolchain.msc6_function_targets import BinaryFunctionTarget

pytestmark = pytest.mark.compiler_toolchain


@pytest.fixture
def native_record(tmp_path):
    project, function, binary = _world(tmp_path)
    payload = 'accepted scalar fixture'
    digest = hashlib.sha256(payload.encode()).hexdigest()
    result = FunctionWorkResult(0, 'ok', payload, '', function, None,
                               validated_payload_hash=digest, gcc_checked_payload_hash=digest)
    result = cli_core._with_scalar_interface_8616(result, project)
    records = tmp_path / 'records'
    path = records / f'{function.addr:08x}.result.json'
    cli_core._write_serial_clean_worker_result_8616(result, result_path=path)
    target = BinaryFunctionTarget('leaf', function.addr)
    context = FrozenCompilerContext('test', 'small', '/test', '/evidence', 'a'*64, 'b'*64)
    contract = FrozenCaseCompositionInput((target,), target, hashlib.sha256(binary.read_bytes()).hexdigest(),
                                         (), b'exit=0', context, 0)
    companion = records / 'untouched.c'
    companion.write_text('existing companion')
    return project, contract, records, path, binary


def _load(native_record, **kwargs):
    project, contract, records, _, _ = native_record
    options = {'project': project, 'records_dir': records, 'artifact_dir': records,
               'compiler_context': contract.compiler_context, 'process_returncode': 0}
    options.update(kwargs)
    return load_final_function_attempts(contract, **options)


def test_existing_decoder_rebinds_native_receipt_and_placeholder(native_record):
    project, _, records, _, _ = native_record
    result = _load(native_record)
    assert result.status is FinalAttemptInventoryStatus.DECODED
    assert result.attempts[0].result.function.project is project
    assert result.attempts[0].result.scalar_interface is not None
    assert result.attempts[0].child_returncode == result.process_returncode == 0
    assert (records / 'untouched.c').read_text() == 'existing companion'


@pytest.mark.parametrize('damage', ['missing', 'extra', 'generation', 'source', 'native', 'malformed'])
def test_refuses_missing_foreign_or_corrupted_records(native_record, damage):
    project, _, records, path, _ = native_record
    if damage == 'missing':
        path.unlink()
    elif damage == 'extra':
        (records / '00000000.result.json').write_text(path.read_text())
    elif damage == 'native':
        project.loader.memory.load = lambda addr, size: b'\xcc'
    elif damage == 'malformed':
        path.write_text('{}')
    else:
        record = json.loads(path.read_text())
        if damage == 'generation':
            record['scalar_interface_generation'] = '0'*64
        else:
            record['scalar_interface']['source_sha256'] = '0'*64
        path.write_text(json.dumps(record))
    result = _load(native_record)
    assert result.status is not FinalAttemptInventoryStatus.DECODED
    assert not result.attempts


@pytest.mark.parametrize('exit_code', [1, 3, 4, -9, 5])
def test_aggregate_exit_cannot_be_relabelled(native_record, exit_code):
    result = _load(native_record, process_returncode=exit_code)
    assert result.status is FinalAttemptInventoryStatus.PROCESS_REFUSED
    assert result.process_returncode == exit_code


def test_context_and_direct_origin_refuse(native_record):
    _, contract, _, _, _ = native_record
    result = _load(native_record, compiler_context=replace(contract.compiler_context, profile_sha256='0'*64))
    assert result.status is FinalAttemptInventoryStatus.CONTEXT_REFUSED
    result = _load(native_record, origin=ConditionalTransportOrigin.DIRECT_CLI)
    assert result.status is FinalAttemptInventoryStatus.PROCESS_REFUSED


@pytest.mark.parametrize('field', ['source', 'load'])
def test_actual_project_must_match_independent_contract(native_record, field):
    project, _, _, _, binary = native_record
    if field == 'source':
        binary.write_bytes(b'foreign image')
    else:
        project.loader.main_object.mapped_base += 16
    assert _load(native_record).status is FinalAttemptInventoryStatus.CONTEXT_REFUSED


@pytest.mark.parametrize('exit_code,expected', [(5, True), (0, False)])
def test_decoded_conditional_record_retains_sweep_exit(native_record, exit_code, expected):
    _, _, _, path, _ = native_record
    record = json.loads(path.read_text())
    record['status'] = 'conditional'
    record['scalar_interface'] = None
    path.write_text(json.dumps(record))
    inventory = _load(native_record, process_returncode=exit_code)
    assert (inventory.status is FinalAttemptInventoryStatus.DECODED) is expected
    if expected:
        assert inventory.attempts[0].child_returncode == 5
        assert inventory.attempts[0].result.status == 'conditional'
