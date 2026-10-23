"""Forward declared callee closes its conditional raw body through the caller entry."""
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
from inertia.ir.function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import Real16CallChainLink8616, real16_native_census_import_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


def _forward_world(argument=0x1234, declared=True, guarded=False, known_argument=True, helper_bytes=None, caller_bytes=None):
    apply_x86_16_bootstrap()
    _project,original,old_link = _world()
    argument_setup = b'\xb8' + argument.to_bytes(2,'little') if known_argument else bytes.fromhex('a10080')
    caller = caller_bytes if caller_bytes is not None else argument_setup + bytes.fromhex('e80a00e80700c3')
    # A forward stack helper returns through its popped near-call frame.
    # Its DOS-service failure path is unreachable only for nonzero AX.
    helper = helper_bytes if helper_bytes is not None else bytes.fromhex('5985c07402ffe1cd21c3' if guarded else '59ffe1')
    source = bytearray(original.source)
    source[0x60:0x60+len(caller)] = caller
    source[0x70:0x70+len(helper)] = helper
    boot = program_from_mz_bytes(bytes(source),original.environment,code_ranges=(
        LinearRange(0x1000,2),LinearRange(0x1040,len(caller)),LinearRange(0x1050,len(helper)),LinearRange(0x1070,1),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module),main_opts={
        'backend':'blob','arch':Arch86_16(),'base_addr':0x1000,'entry_point':0x1000,
    },auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project,0x1040,0x1040+len(caller))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project,boundary)
    assert artifact is not None
    spec = replace(old_link.admission.spec,source_sha256=hashlib.sha256(boot.source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(),native_sha256=hashlib.sha256(caller).hexdigest(),
        entry_offset=0x40,range_start=0x1040,range_end=0x1040+len(caller))
    admission = admit_declared_function_entry_8616(spec,source=boot.source,loaded_module=module,
        environment_sha256=spec.environment_sha256)
    def resolver(instruction):
        return resolve_direct_call_target_from_instruction_8616(project,instruction)
    index = build_boundary_direct_callsite_index_8616(boundary,direct_target_resolver=resolver)
    owner.install_real16_invocation_source_8616(project,owner.Real16InvocationSource8616(
        boot,_recompute,index,function_entries=(admission,) if declared else (),
    ))
    return project,boot,artifact,boundary,resolver,admission


@pytest.fixture
def calls_with_forward_helper():
    return _forward_world()


def _collect(world):
    project,_boot,artifact,boundary,resolver,_admission=world
    with direct_evidence_deadline_scope_8616(project,time.monotonic()+20),native_import_request_8616():
        return owner.collect_entry_domain_call_preservations_8616(project,artifact,boundary,direct_target_resolver=resolver)


def test_forward_helper_closes_conditional_body_through_declared_entry(calls_with_forward_helper):
    project,_boot,_artifact,_boundary,_resolver,_admission=calls_with_forward_helper
    assert registered_function_ir_artifact_8616(project,0x1050).verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    records=_collect(calls_with_forward_helper)
    assert len(records)==2 and all(record.failure is None for record in records), [record.failure for record in records]
    first=records[0]
    callee=first.callee
    assert callee is not None
    scope=callee.state.invocation_scope
    assert scope is not None and isinstance(scope.chain,Real16CallChainLink8616)
    assert first.required_scope is not scope
    raw=callee.coverage.artifact
    assert raw is scope.chain.callee_artifact
    assert callee.state.scoped_view is not None and callee.state.scoped_view.source_artifact is raw
    assert any(block.refusals for block in raw.blocks)
    assert registered_function_ir_artifact_8616(project,0x1050).verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE


def test_forward_helper_without_declared_entry_refuses():
    records = _collect(_forward_world(declared=False))
    assert len(records) == 2
    assert all(record.binding is not None and record.binding.failure is None for record in records)
    assert all(record.failure is owner.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE for record in records)
    assert all(record.materialized_count == 0 for record in records)


def test_return_projection_refuses_changed_native_helper(calls_with_forward_helper):
    from inertia.ir.real16_invocation_domain import _projected_callee_return_rows_8616

    project, *_rest = calls_with_forward_helper
    records = _collect(calls_with_forward_helper)
    callee = records[0].callee
    assert callee is not None and records[0].failure is None
    assert _projected_callee_return_rows_8616(callee)
    # Change JMP CX to JMP DX. The old scope must not authorize this return.
    project.loader.memory.store(0x1051, bytes.fromhex('ffe2'))
    assert _projected_callee_return_rows_8616(callee) is None


@pytest.mark.parametrize('known_argument', [True, False])
def test_reachable_or_unknown_external_service_requires_effect_proof(known_argument):
    records = _collect(_forward_world(0,guarded=True,known_argument=known_argument))
    assert records[0].failure is owner.EntryDomainCallPreservationFailure8616.DEPENDENCY_UNPROVEN
    assert records[1].failure is owner.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    assert all(record.materialized_count == 0 for record in records)


def test_guarded_return_excludes_service_only_with_authenticated_dead_edge():
    records = _collect(_forward_world(0x1234,guarded=True))
    assert len(records) == 2
    assert all(record.failure is None for record in records), [record.failure for record in records]
    for record in records:
        assert record.callee is not None
        assert not record.callee.callsite_addrs
        assert record.callee.coverage.scoped_view.reachability_domain is not None


@pytest.mark.parametrize('omit_live', [False, True])
def test_scoped_callee_native_copy_excludes_dead_blocks_but_censuses_their_bytes(monkeypatch, omit_live):
    from inertia.ir import real16_invocation_domain as domain

    selections = []
    censused = set()
    active = False
    native = domain._native_effect_blocks_8616
    census = domain._census_block_bytes_8616
    callee_census = domain._census_callee_bytes_8616

    def census_callee(ctx, proof):
        nonlocal active
        active = True
        try:
            return callee_census(ctx, proof)
        finally:
            active = False

    def select(ctx, boundary, **kwargs):
        if active and boundary.addr == 0x1050:
            selections.append(kwargs.get('selected_blocks'))
            if omit_live and kwargs.get('selected_blocks') is not None:
                kwargs['selected_blocks'] = frozenset()
        return native(ctx, boundary, **kwargs)

    def census_bytes(ctx, block, **kwargs):
        if active:
            censused.add(block.addr)
        return census(ctx, block, **kwargs)

    monkeypatch.setattr(domain, '_native_effect_blocks_8616', select)
    monkeypatch.setattr(domain, '_census_block_bytes_8616', census_bytes)
    monkeypatch.setattr(domain, '_census_callee_bytes_8616', census_callee)
    records = _collect(_forward_world(0x1234, guarded=True))
    if omit_live:
        assert selections and any(row.failure is not None for row in records)
        return
    assert len(records) == 2 and all(row.failure is None for row in records)
    callee = records[0].callee
    assert callee is not None
    projection = callee.coverage.scoped_view.cfg_projection_for(callee.state.invocation_scope)
    assert projection is not None and projection.unreachable_block_addrs
    live = frozenset(block.addr for block in callee.coverage.artifact.blocks) - projection.unreachable_block_addrs
    assert live in selections
    assert projection.unreachable_block_addrs <= censused


def test_native_return_snapshot_detaches_facts_without_copying_decoder_handles(calls_with_forward_helper):
    from inertia.ir.ir_boundary_cfg import _native_boundary_facts_8616

    project,_boot,_artifact,boundary,resolver,_admission = calls_with_forward_helper
    index = build_boundary_direct_callsite_index_8616(boundary,direct_target_resolver=resolver)
    callee = owner._scoped_callee_boundary_8616(project,0x1050,index.for_target(0x1050)[0])
    assert callee is not None and callee.near_return_continuations is not None
    continuation = callee.near_return_continuations
    assert continuation.premise is not None
    captured = _native_boundary_facts_8616(callee)
    assert captured == _native_boundary_facts_8616(callee)
    object.__setattr__(continuation,'raw_fact_count',continuation.raw_fact_count+1)
    assert captured != _native_boundary_facts_8616(callee)
