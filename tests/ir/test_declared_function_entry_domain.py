"""Genuine MZ application-entry premises remain conditional and source-bound."""
import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredEntryMemory8616,
    DeclaredEntryReturn8616,
    DeclaredEntryReturnKind8616,
    DeclaredFunctionEntryAdmission8616,
    DeclaredFunctionEntrySpec8616,
    admit_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    Real16InvocationAssumption8616,
    Real16InvocationFailure8616,
    Real16InvocationKind8616,
    prove_real16_declared_function_entry_domain_8616,
    real16_native_census_import_8616,
    same_real16_entry_scope_8616,
)
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange


@pytest.fixture(autouse=True, scope='module')
def _bootstrap():
    apply_x86_16_bootstrap()


def _world(*, load=False, baseline=False, memory=(), service=False, descendant=None, whole_image=False):
    body = bytes.fromhex('b80030cd21e80000c3' if service else 'a1600089c4e80000c3' if load else 'b83412e80000c3')
    child = None
    if descendant is not None:
        body = bytes.fromhex('b83412e80500c3')
        child = bytes.fromhex('a1600089c4e80000c3' if descendant == 'data' else '5889c4e80000c3')
    image = bytearray(0x80)
    image[:2] = bytes.fromhex('0f0b')  # Header startup is deliberately unsupported.
    image[0x20:0x20+len(body)] = body
    if child is not None:
        image[0x2b:0x2b+len(child)] = child
    image[0x60:0x62] = bytes.fromhex('3412')
    image[0x70] = 0xc3
    header = bytearray(32)
    header[:2] = b'MZ'
    for offset, value in ((2,160),(4,1),(8,2),(10,0x10),(12,0x40),
                          (14,0x10),(16,0x100),(24,0x1c)):
        header[offset:offset+2] = value.to_bytes(2,'little')
    source = bytes(header+image)
    from tests.ir import test_x86_16_declared_interrupt_boundary as native
    environment = replace(native._environment(),psp_segment=0xf0,allocation=bytes(0x500))
    boot = program_from_mz_bytes(source, environment, code_ranges=() if whole_image else (
        LinearRange(0x1000,2), LinearRange(0x1020,len(body)), LinearRange(0x1070,1),
        *((LinearRange(0x102b,len(child)),) if child is not None else ()),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        'backend':'blob','arch':Arch86_16(),'base_addr':0x1000,'entry_point':0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project,0x1020,0x1020+len(body))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project,boundary)
    assert artifact is not None
    digest = declared_environment_digest_8616(environment)
    assert digest is not None
    spec = DeclaredFunctionEntrySpec8616(
        version=1, source_sha256=hashlib.sha256(source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(), load_segment=0x100,
        entry_segment=0x100,entry_offset=0x20,range_start=0x1020,range_end=0x1020+len(body),
        native_sha256=hashlib.sha256(body).hexdigest(),environment_sha256=digest,
        use_environment_memory=baseline,registers=(('ds',0x100),('sp',0x80),('ss',0x120)),
        memory=(DeclaredEntryMemory8616(0x1280,bytes.fromhex('7000')),*memory),
        return_boundary=DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.NEAR,0x100,0x70),
    )
    admission = admit_declared_function_entry_8616(
        spec,source=source,loaded_module=module,environment_sha256=digest,
    )
    assert isinstance(admission,DeclaredFunctionEntryAdmission8616)
    return project,boot,DeclaredFunctionEntryLink8616(admission,artifact,boundary)


@pytest.mark.parametrize("baseline", [False, True])
def test_unproved_ordinary_call_is_not_an_interrupt_service_failure(baseline):
    project, boot, link = _world(baseline=baseline)
    result = prove_real16_declared_function_entry_domain_8616(
        project, link, 0x1026, boot=boot, boot_recompute=_recompute,
    )
    assert result.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def _recompute(boot):
    ranges = () if boot.image.code_scope == 'whole_image' else boot.image.code_ranges
    return program_from_mz_bytes(boot.source,boot.environment,code_ranges=ranges)


def _prove(project,boot,link):
    callsite = 0x1023 if link is None else max(instruction.addr for block in link.artifact.blocks for instruction in block.instrs if instruction.op == "CALL")
    return prove_real16_declared_function_entry_domain_8616(
        project,link,callsite,boot=boot,boot_recompute=_recompute,
    )


def test_declared_local_prefix_bypasses_unproved_startup_without_publication():
    project,boot,link = _world()
    before = registered_function_ir_artifact_8616(project,0x1020)
    premise = _prove(project,boot,link)
    assert premise.failure is None
    assert premise.complete
    assert premise.kind is Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY
    assert Real16InvocationAssumption8616.DECLARED_FUNCTION_ENTRY in premise.assumptions
    assert Real16InvocationAssumption8616.MZ_HEADER_ENTRY not in premise.assumptions
    assert premise.entry_offset == 0x20 and boot.entry.offset == 0
    assert dict(premise.callsite_call_state)['ax'] == 0x1234
    assert not {'bx','dx','eax','ebx'} & dict(premise.callsite_call_state).keys()
    assert registered_function_ir_artifact_8616(project,0x1020) == before
    assert premise.to_dict()['declared_function_entry'] == link.admission.to_dict()


def test_missing_declaration_refuses():
    project,boot,_ = _world()
    assert _prove(project,boot,None).failure is Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN


@pytest.mark.parametrize('mutation', ['source','image','frame','entry'])
def test_stale_declared_entry_refuses(mutation):
    project,boot,link = _world()
    if mutation == 'source':
        link = replace(link,admission=replace(link.admission,source=link.admission.source[:-1]+b'\xff'))
    elif mutation == 'image':
        project.loader.memory.store(0x1060,b'\xff')
    else:
        spec = link.admission.spec
        spec = replace(spec, memory=() if mutation == 'frame' else spec.memory,
                       entry_offset=0x21 if mutation == 'entry' else spec.entry_offset)
        link = replace(link,admission=replace(link.admission,spec=spec))
    assert not _prove(project,boot,link).complete


def test_module_data_is_unknown_without_explicit_baseline():
    project,boot,link = _world(load=True)
    assert not _prove(project,boot,link).complete


@pytest.mark.parametrize('whole_image', [False, True])
def test_declared_memory_overlay_supplies_only_explicit_data(whole_image):
    project,boot,link = _world(load=True,memory=(DeclaredEntryMemory8616(0x1060,bytes.fromhex('3412')),),whole_image=whole_image)
    assert _prove(project,boot,link).complete


@pytest.mark.parametrize('address', [0x1020, 0x1023, 0x1026])
def test_declared_overlay_cannot_replace_root_native_bytes(address):
    project,boot,link = _world(whole_image=True)
    spec = replace(link.admission.spec,memory=(*link.admission.spec.memory,DeclaredEntryMemory8616(address,b'\x90')))
    link = replace(link,admission=replace(link.admission,spec=spec))
    result = _prove(project,boot,link)
    assert not result.complete
    assert result.failure is Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN


@pytest.mark.parametrize('address', [0x1060, 0x102b])
def test_whole_image_declared_memory_rechecked_at_descendant_fetch(address):
    from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    from inertia.ir.real16_invocation_domain import Real16CallChainLink8616, prove_real16_chained_invocation_domain_8616
    from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616

    project,boot,link = _world(descendant='stack',whole_image=True,memory=(DeclaredEntryMemory8616(address,b'\x90'),))
    parent = _prove(project,boot,link)
    assert parent.complete  # Its scope stops before executing the child.
    boundary = exact_function_range_boundary_8616(project,0x102b,0x1032)
    assert boundary is not None
    artifact = real16_native_census_import_8616(project,boundary)
    assert artifact is not None
    index = build_boundary_direct_callsite_index_8616(
        link.boundary,direct_target_resolver=lambda instruction:resolve_direct_call_target_from_instruction_8616(project,instruction),
    )
    row, = index.for_target(0x102b)
    chain = Real16CallChainLink8616(parent,index,row,link.artifact,link.boundary,parent.callsite_call_state,artifact,boundary)
    callsite = max(instruction.addr for block in artifact.blocks for instruction in block.instrs if instruction.op == 'CALL')
    result = prove_real16_chained_invocation_domain_8616(project,None,callsite,boot=boot,boot_recompute=_recompute,chain=chain)
    if address == 0x1060:
        assert result.complete
    else:
        assert not result.complete
        assert result.failure is Real16InvocationFailure8616.CODE_WRITE_VIOLATION


def test_explicit_environment_baseline_supplies_module_data():
    project,boot,link = _world(load=True,baseline=True)
    assert _prove(project,boot,link).complete


def test_scope_identity_requires_identical_declared_authority():
    project,boot,link = _world()
    first = _prove(project,boot,link)
    second = _prove(project,boot,replace(link))
    assert same_real16_entry_scope_8616(first,second)
    foreign = _prove(project,boot,replace(link,admission=replace(link.admission)))
    assert not same_real16_entry_scope_8616(first,foreign)


@pytest.mark.parametrize('baseline', [False,True])
def test_service_cannot_resurrect_unknown_application_ivt(baseline):
    from inertia.ir.real16_declared_interrupt8616 import DeclaredInterruptService8616
    from tools.dosunit.runtime.real16_declared_invocation8616 import declared_int21_version_service_8616
    project,boot,link = _world(service=True,baseline=baseline)
    service = declared_int21_version_service_8616(boot.environment,caller_addr=0x1020,callsite_addr=0x1023)
    assert isinstance(service,DeclaredInterruptService8616)
    result = prove_real16_declared_function_entry_domain_8616(
        project,link,0x1025,boot=boot,boot_recompute=_recompute,declared_services=(service,),
    )
    if baseline:
        assert result.complete and len(result.service_consumptions) == 1
    else:
        assert result.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
        assert not result.complete


@pytest.mark.parametrize('descendant', ['data','stack'])
@pytest.mark.parametrize('baseline', [False,True])
def test_descendant_retains_explicit_memory_policy(descendant,baseline):
    from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    from inertia.ir.real16_invocation_domain import Real16CallChainLink8616, prove_real16_chained_invocation_domain_8616
    from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
    project,boot,link = _world(descendant=descendant,baseline=baseline)
    parent = _prove(project,boot,link)
    assert parent.complete
    length = 9 if descendant == 'data' else 7
    boundary = exact_function_range_boundary_8616(project,0x102b,0x102b+length)
    assert boundary is not None
    artifact = real16_native_census_import_8616(project,boundary)
    assert artifact is not None
    index = build_boundary_direct_callsite_index_8616(
        link.boundary,direct_target_resolver=lambda instruction:resolve_direct_call_target_from_instruction_8616(project,instruction),
    )
    rows = index.for_target(0x102b)
    assert len(rows) == 1
    chain = Real16CallChainLink8616(
        parent,index,rows[0],link.artifact,link.boundary,parent.callsite_call_state,artifact,boundary,
    )
    callsite = max(instruction.addr for block in artifact.blocks for instruction in block.instrs if instruction.op == 'CALL')
    result = prove_real16_chained_invocation_domain_8616(
        project,None,callsite,boot=boot,boot_recompute=_recompute,chain=chain,
    )
    assert result.to_dict()['declared_function_entry'] == link.admission.to_dict()
    if baseline or descendant == 'stack':
        assert result.complete
    else:
        # Unwritten module data stays unknown; native proven stack writes do
        # not depend on the original contents of their authenticated allocation.
        assert not result.complete
        assert result.failure is Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN


@pytest.mark.parametrize('depth', [16,17])
def test_declared_origin_depth_boundary_cannot_restore_baseline(depth):
    from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    from inertia.ir.real16_invocation_domain import (
        Real16CallChainLink8616,
        _boot_evidence_8616,
        _declared_entry_authority_8616,
        _invocation_initial_memory_for_entry_8616,
    )
    from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
    project,boot,root = _world(descendant='data')
    parent = _prove(project,boot,root)
    assert parent.complete
    index = build_boundary_direct_callsite_index_8616(
        root.boundary,direct_target_resolver=lambda instruction:resolve_direct_call_target_from_instruction_8616(project,instruction),
    )
    row = index.for_target(0x102b)[0]
    chain = root
    # Exercise structural origin traversal only. These retained links are not
    # offered as complete invocation proofs for repeated execution of an edge.
    for _ in range(depth):
        chain = Real16CallChainLink8616(
            replace(parent,chain=chain),index,row,root.artifact,root.boundary,
            parent.callsite_call_state,root.artifact,root.boundary,
        )
    authority = _declared_entry_authority_8616(chain)
    if depth == 16:
        assert authority is root.admission
    else:
        assert authority is Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    evidence = _boot_evidence_8616(boot)
    assert not isinstance(evidence,Real16InvocationFailure8616)
    initial = _invocation_initial_memory_for_entry_8616(evidence,chain)
    assert initial is None or initial.byte_at(0x1060) is None
    if depth == 16:
        assert initial is not None and initial.byte_at(0x1280) == 0x70
