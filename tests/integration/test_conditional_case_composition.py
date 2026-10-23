"""Typed conditional case readiness preserves independently frozen inputs."""
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.cli.work_items import FunctionWorkResult
from inertia.lowering.scalar_interface_transport import ScalarInterface8616, ScalarKind8616, ScalarType8616
from tests.integration.test_build_msc6_examples import _conditional_stage_snapshot, _emit_conditional_artifacts
from tools.compiler_toolchain.compiler_profile import FrozenCompilerContext
from tools.compiler_toolchain.conditional_case_composition import (
    CaseCompositionStatus,
    FinalFunctionAttempt,
    FrozenCaseCompositionInput,
    prepare_conditional_case_composition,
)
from tools.compiler_toolchain.msc6_function_targets import BinaryFunctionTarget


@pytest.fixture
def case(tmp_path):
    image = tmp_path / 'case.exe'
    image.write_bytes(b'MZ-fixture')
    artifacts = tmp_path / 'artifacts'
    _emit_conditional_artifacts(['--output-c-dir', str(artifacts)])
    target = BinaryFunctionTarget('entry', 0x10010)
    payload = 'int sub_10010(void) { return 1; }\n'
    digest = hashlib.sha256(payload.encode()).hexdigest()
    snapshot = _conditional_stage_snapshot()
    result = FunctionWorkResult(0, 'conditional', payload, '', SimpleNamespace(addr=target.address), None,
                               tail_validation=snapshot, validated_payload_hash=digest, gcc_checked_payload_hash=digest)
    context = FrozenCompilerContext('test', 'small', '/test', '/test/evidence', 'd'*64, 'e'*64)
    attempts = [FinalFunctionAttempt(target, result, context, artifacts, 5)]
    for index in range(1, 7):
        leaf = BinaryFunctionTarget(f'leaf{index}', 0x10100 + index)
        code = f'int sub_{leaf.address:x}(void) {{ return {index}; }}\n'
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        work = FunctionWorkResult(index, 'ok', code, '', SimpleNamespace(addr=leaf.address), None,
                                  tail_validation={s: {'status': 'stable', 'changed': False}
                                                   for s in ('structuring', 'postprocess')},
                                  validated_payload_hash=code_hash, gcc_checked_payload_hash=code_hash,
                                  scalar_interface=ScalarInterface8616(leaf.address, hashlib.sha256(image.read_bytes()).hexdigest(),
                                      0x10000, "86_16", 32, 1, "f"*64, code_hash, (),
                                      ScalarType8616(2, True, ScalarKind8616.SHORT)))
        attempts.append(FinalFunctionAttempt(leaf, work, context))
    spec = snapshot['structuring']['entry_premise']['payload']['declaration']['spec']
    contract = FrozenCaseCompositionInput(tuple(a.target for a in attempts), target,
                                         hashlib.sha256(image.read_bytes()).hexdigest(),
                                         ((target.address, json.dumps(spec, sort_keys=True)),), b'exit=255', context, 0x10000)
    return image, contract, tuple(attempts)


def test_ready_retains_conditional_premise_without_acceptance(case):
    image, contract, attempts = case
    result = prepare_conditional_case_composition(contract, attempts, image=image,
                                                observations=contract.observations,
                                                compiler_context=contract.compiler_context)
    assert result.status is CaseCompositionStatus.CONDITIONAL_READY
    assert len(result.payloads) == 7 and len(result.premises) == 1
    assert result.contract is contract
    assert json.loads(result.premises[0][1])['status'] == 'conditional'


@pytest.mark.parametrize('damage', ['missing', 'duplicate', 'payload', 'compiler_hash', 'image',
                                    'context', 'observations', 'declaration', 'stale', 'failed', 'self_signed'])
def test_refuses_incomplete_or_changed_case(case, damage):
    image, contract, attempts = case
    attempts = list(attempts)
    observations = contract.observations
    context = contract.compiler_context
    if damage in {'missing', 'duplicate', 'payload', 'compiler_hash'}:
        attempts = _damage_inventory(attempts, damage)
    elif damage == 'image':
        image.write_bytes(b'changed')
    elif damage == 'context':
        context = replace(context, profile_sha256='0'*64)
    elif damage == 'observations':
        observations = b'exit=0'
    elif damage == 'declaration':
        spec = json.loads(contract.declarations[0][1])
        spec['environment_sha256'] = '0'*64
        contract = replace(contract, declarations=((contract.entry.address, json.dumps(spec)),))
    elif damage == 'stale':
        attempts[0] = replace(attempts[0], stale_directory=True)
    elif damage == 'failed':
        attempts[1] = replace(attempts[1], result=replace(attempts[1].result, status='validation_failed'))
    elif damage == 'self_signed':
        _resign_foreign_premise(attempts)
    result = prepare_conditional_case_composition(contract, tuple(attempts), image=image,
                                                observations=observations, compiler_context=context)
    assert result.status is not CaseCompositionStatus.CONDITIONAL_READY
    assert not result.payloads


def _resign_foreign_premise(attempts):
    receipt = next((attempts[0].artifact_dir / 'conditional').glob('*.json'))
    record = json.loads(receipt.read_text())
    for stage in record['tail_validation'].values():
        premise = stage['entry_premise']
        premise['payload']['declaration']['spec']['registers'][1][1] += 2
        premise['sha256'] = hashlib.sha256(json.dumps(premise['payload'], sort_keys=True,
                                                                     separators=(',', ':')).encode()).hexdigest()
    receipt.write_text(json.dumps(record))
    attempts[0] = replace(attempts[0], result=replace(attempts[0].result,
                tail_validation=record['tail_validation']))


def _damage_inventory(attempts, damage):
    if damage == 'missing':
        attempts = attempts[1:]
    elif damage == 'duplicate':
        attempts[-1] = attempts[0]
    elif damage == 'payload':
        attempts[2] = replace(attempts[2], result=replace(attempts[2].result,
                    payload=attempts[2].result.payload + '/* changed */'))
    elif damage == 'compiler_hash':
        attempts[2] = replace(attempts[2], result=replace(attempts[2].result, gcc_checked_payload_hash='0'*64))
    return attempts


@pytest.mark.parametrize('damage', ['foreign_source', 'foreign_load', 'missing_receipt', 'no_function', 'cache'])
def test_owned_source_binding_and_authenticated_cache(case, damage):
    image, contract, attempts = case
    rows = list(attempts)
    result = rows[1].result
    receipt = result.scalar_interface
    if damage == 'foreign_source':
        result = replace(result, scalar_interface=replace(receipt, source_sha256='0'*64))
    elif damage == 'foreign_load':
        result = replace(result, scalar_interface=replace(receipt, mapped_base=0))
    elif damage == 'missing_receipt':
        result = replace(result, scalar_interface=None)
    elif damage == 'no_function':
        result = replace(result, function=None)
    else:
        result = replace(result, from_cache=True)
    rows[1] = replace(rows[1], result=result)
    prepared = prepare_conditional_case_composition(contract, tuple(rows), image=image,
        observations=contract.observations, compiler_context=contract.compiler_context)
    assert (prepared.status is CaseCompositionStatus.CONDITIONAL_READY) == (damage == 'cache')


@pytest.mark.parametrize('origin,code,decoded,expected', [
    ('direct_cli', 5, False, True), ('direct_cli', 0, False, False),
    ('serial_worker', 0, True, True), ('serial_worker', 5, True, False),
    ('serial_worker', 0, False, False), ('direct_cli', 5, True, False),
])
def test_exact_process_origin(case, origin, code, decoded, expected):
    from tools.compiler_toolchain.conditional_function_receipt import (
        ConditionalTransportOrigin,
        bind_conditional_function_artifact,
    )
    image, contract, attempts = case
    attempt = attempts[0]
    bound = bind_conditional_function_artifact(attempt.artifact_dir, target=attempt.target,
        binary_path=image, expected_binary_sha256=contract.image_sha256, child_returncode=code,
        origin=ConditionalTransportOrigin(origin), decoded_result=attempt.result if decoded else None)
    assert bound.bound is expected


@pytest.mark.parametrize('exit_code,expected', [(5, True), (0, False), (4, False), (-9, False)])
def test_full_sweep_retains_actual_aggregate_exit(case, exit_code, expected):
    from tools.compiler_toolchain.conditional_function_receipt import ConditionalTransportOrigin

    image, contract, attempts = case
    attempts = tuple(replace(attempt, origin=ConditionalTransportOrigin.FULL_SWEEP,
                             child_returncode=exit_code) for attempt in attempts)
    result = prepare_conditional_case_composition(contract, attempts, image=image,
        observations=contract.observations, compiler_context=contract.compiler_context)
    assert (result.status is CaseCompositionStatus.CONDITIONAL_READY) is expected
    assert all(attempt.child_returncode == exit_code for attempt in attempts)
