"""Accepted scalar interfaces survive existing worker transport boundaries."""
import hashlib
import pickle
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.cli import cli_core
from inertia.cli.cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_source_digest
from inertia.cli.work_items import FunctionWorkResult
from inertia.lowering.scalar_interface_transport import current_scalar_interface_8616
from tests.lowering.test_scalar_interface_transport import _world

pytestmark = pytest.mark.decompiler


def _accepted(function):
    payload = 'typed acceptance fixture'
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return FunctionWorkResult(1,'ok',payload,'',function,None,
                              validated_payload_hash=digest,gcc_checked_payload_hash=digest)


def test_fork_receipt_pickle_and_parent_import(tmp_path):
    project, function, _ = _world(tmp_path)
    result = cli_core._function_work_result_for_fork_ipc(_accepted(function))
    transported = pickle.loads(pickle.dumps(result))
    assert transported.function is None and transported.function_cfg is None
    assert transported.scalar_interface is not None
    cli_core._import_scalar_interface_8616(transported, project)
    assert current_scalar_interface_8616(project,function.addr) == transported.scalar_interface
    with pytest.raises(ValueError,match='stale'):
        cli_core._import_scalar_interface_8616(replace(transported,scalar_interface_generation='0'*64),project)
    with pytest.raises(ValueError,match='unaccepted'):
        cli_core._import_scalar_interface_8616(replace(transported,payload='changed'),project)


def test_functionless_result_cannot_export_address_zero(tmp_path):
    project, _, _ = _world(tmp_path)
    def unexpected_lookup(**kwargs):
        raise AssertionError('functionless result must not query address zero')
    project.kb.functions.function = unexpected_lookup
    result = cli_core._with_scalar_interface_8616(_accepted(None),project)
    assert result.scalar_interface is None


@pytest.mark.parametrize('stale',[False,True])
def test_direct_tuple_retains_exact_producer_generation(tmp_path,monkeypatch,stale):
    project,function,_ = _world(tmp_path)
    result = cli_core._with_scalar_interface_8616(_accepted(function),project)
    assert result.scalar_interface is not None
    generation = '0'*64 if stale else _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES)
    context = SimpleNamespace(func=function,direct_decompile_timeout=1,use_fork_for_direct=True,
                              _direct_blocks=1,_direct_bytes=1,
                              direct_decompile_job=lambda: ('ok','payload',None,1,1,0.0,
                                                           (result.scalar_interface,generation)))
    monkeypatch.setattr(cli_core,'_run_with_timeout_in_fork',lambda fn,**kwargs:fn())
    consume = cli_core._DirectAddrCliRun8616._phase_direct_probe_recovery_8616_part0_8616_b1
    if stale:
        with pytest.raises(ValueError,match='generation'):
            consume(context)
    else:
        assert consume(context) is None
        assert context.direct_scalar_interface == result.scalar_interface
        assert context.direct_scalar_generation == generation


def test_accepted_worker_interface_reaches_storage_bound_caller_without_callee(tmp_path):
    """Fresh caller projects keep accepted C kinds through physical VALUE storage."""
    from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall
    from angr.sim_type import SimTypeShort

    from inertia.cli.project_evidence_transport import transfer_project_evidence_8616
    from inertia.lowering.callsite_prototype_declarations import _prototype_decl_8616
    from inertia.lowering.interprocedural_storage_contracts import (
        CallsiteStorageBinding8616,
        CallsiteStorageTrials8616,
        FunctionStorageResolution8616,
        FunctionStorageTrials8616,
        ProgramStorageResolution8616,
        StorageTrialRole8616,
        StorageTrialSignedness8616,
        StorageTrialStats8616,
        StorageTrialValueClass8616,
        StorageTrialVerdict8616,
    )
    from inertia.lowering.interprocedural_storage_transaction import apply_program_storage_resolution_8616
    from tests.lowering.test_x86_16_callsite_prototype_declarations import _Codegen, _summary
    from tests.lowering.test_x86_16_interprocedural_storage_prototype_application import _contract, _slot

    source, function, _ = _world(tmp_path)
    transported = pickle.loads(pickle.dumps(cli_core._function_work_result_for_fork_ipc(_accepted(function))))
    parent = SimpleNamespace(arch=source.arch, loader=source.loader)
    cli_core._import_scalar_interface_8616(transported, parent)
    caller = SimpleNamespace(arch=source.arch, loader=source.loader,
                             kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **kwargs: None)))
    assert transfer_project_evidence_8616(parent, caller).scalar_interface_count == 1
    contract = replace(_contract(inputs=(_slot(
        StorageTrialRole8616.INPUT, 0, 2, StorageTrialSignedness8616.UNSIGNED,
        StorageTrialValueClass8616.VALUE, offset=4,
    ),)), callsites=(CallsiteStorageBinding8616(0x1000, 0x1010, (), (), 2),))
    stats = StorageTrialStats8616(1, 1, 1, 1)
    trials = FunctionStorageTrials8616(0x2000, True, (0x1010,), (
        CallsiteStorageTrials8616(0x1000, 0x2000, 0x1010, stack_delta=2),
    ))
    resolution = ProgramStorageResolution8616((trials,), (
        FunctionStorageResolution8616(0x2000, StorageTrialVerdict8616.ACCEPTED, contract, (), stats),
    ), ((0x2000,),), (1,), stats)
    assert apply_program_storage_resolution_8616(caller, resolution)
    codegen = _Codegen()
    codegen.project = caller
    word = SimTypeShort(False).with_arch(caller.arch)
    call = CFunctionCall('combine', None, [CConstant(1, word, codegen=codegen)], codegen=codegen)

    assert _prototype_decl_8616(caller, codegen, call, _summary(0x1010, arg_count=1),
                                'unsigned short') == 'int combine(short a0);'
