"""Fresh complete call records feed later conditional prefix obligations."""
import hashlib
import io
import time
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import real16_native_census_import_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


@pytest.fixture
def two_calls():
    apply_x86_16_bootstrap()
    _project,original,old_link = _world()
    # Backward CALLs cross a paragraph, requiring the declared CS premise.
    body = bytes.fromhex('b83412e8eaffe8e7ffc3')
    source = bytearray(original.source)
    source[0x40:0x40+len(body)] = body
    source[0x30] = 0xc3
    boot = program_from_mz_bytes(bytes(source),original.environment,code_ranges=(
        LinearRange(0x1000,2),LinearRange(0x1010,1),LinearRange(0x1020,len(body)),LinearRange(0x1070,1),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module),main_opts={
        'backend':'blob','arch':Arch86_16(),'base_addr':0x1000,'entry_point':0x1000,
    },auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project,0x1020,0x1020+len(body))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project,boundary)
    assert artifact is not None
    spec = replace(old_link.admission.spec,source_sha256=hashlib.sha256(boot.source).hexdigest(),
                   relocated_sha256=hashlib.sha256(module).hexdigest(),
                   native_sha256=hashlib.sha256(body).hexdigest(),range_end=0x1020+len(body))
    admission = admit_declared_function_entry_8616(spec,source=boot.source,loaded_module=module,
                                                environment_sha256=spec.environment_sha256)
    def resolver(instruction):
        return resolve_direct_call_target_from_instruction_8616(project,instruction)
    index = build_boundary_direct_callsite_index_8616(boundary,direct_target_resolver=resolver)
    owner.install_real16_invocation_source_8616(project,owner.Real16InvocationSource8616(
        boot,_recompute,index,function_entries=(admission,),
    ))
    return project,artifact,boundary,resolver


def _collect(world,monkeypatch,mutation=None):
    project,artifact,boundary,resolver = world
    original = owner.prove_entry_domain_call_preservation_8616
    refreshed=[]
    observed=[]
    def prove(*args,**kwargs):
        instruction=args[4]
        complete=kwargs['collection_phase'] is owner._CallCollectionPhase8616.COMPLETE
        if complete and instruction.addr == 0x1026:
            snapshot=kwargs['entry_call_preservations']
            assert isinstance(snapshot,tuple)
            observed.append(next(record for record in snapshot if record.callsite_addr == 0x1023))
        result=original(*args,**kwargs)
        if complete and instruction.addr == 0x1023:
            assert result.failure is None
            if mutation == 'incomplete':
                result=replace(result,failure=owner.EntryDomainCallPreservationFailure8616.CS_NOT_PRESERVED,
                               materialized_count=0,failure_count=1)
            elif mutation == 'foreign':
                result=replace(result,artifact=replace(artifact))
            elif mutation == 'deadline':
                monkeypatch.setattr(owner,'direct_evidence_deadline_expired_8616',lambda _project:True)
            refreshed.append(result)
        return result
    monkeypatch.setattr(owner,'prove_entry_domain_call_preservation_8616',prove)
    with direct_evidence_deadline_scope_8616(project,time.monotonic()+20),native_import_request_8616():
        result=owner.collect_entry_domain_call_preservations_8616(project,artifact,boundary,direct_target_resolver=resolver)
    return result,refreshed,observed


def test_later_call_consumes_fresh_exact_earlier_record(two_calls,monkeypatch):
    records,refreshed,observed = _collect(two_calls,monkeypatch)
    assert len(records) == 2 and len(refreshed) == 1
    assert observed == [refreshed[0]] and observed[0] is refreshed[0]
    assert all(record.failure is None and record.materialized_count == 1 for record in records)


@pytest.mark.parametrize('mutation',['incomplete','foreign'])
def test_unproved_earlier_record_cannot_admit_later_call(two_calls,monkeypatch,mutation):
    records,_refreshed,_observed = _collect(two_calls,monkeypatch,mutation)
    assert records[1].failure is not None
    assert records[1].materialized_count == 0


def test_expired_budget_keeps_later_call_refused(two_calls,monkeypatch):
    records,_refreshed,_observed = _collect(two_calls,monkeypatch,'deadline')
    assert records[1].failure is owner.EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED
    assert records[1].materialized_count == 0
