"""Conditional near-call effects keep native raw terminal identity."""
import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir import real16_invocation_domain as domain_owner
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import (
    real16_native_census_import_8616,
)
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


@pytest.fixture
def nested_world() -> tuple:
    """Three native call levels share the authentic declared root and index."""
    apply_x86_16_bootstrap()
    _project,original,old_link = _world()
    caller = bytes.fromhex('b83412e8eaffe8e7ffc3')
    middle = bytes.fromhex('e8ddffc3')
    helper = bytes.fromhex('eb13c3') + b'\x90'*18 + bytes.fromhex('33c0ebe9')
    source = bytearray(original.source)
    source[0x60:0x60+len(caller)] = caller
    source[0x50:0x50+len(middle)] = middle
    source[0x30:0x30+len(helper)] = helper
    boot = program_from_mz_bytes(bytes(source),original.environment,code_ranges=(
        LinearRange(0x1000,2),LinearRange(0x1010,len(helper)),LinearRange(0x1030,len(middle)),LinearRange(0x1040,len(caller)),LinearRange(0x1070,1),
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
    from inertia.frontend.x86_16.frontend_direct_callsite_index import (
        DecodedCallerCensus8616,
        build_decoded_direct_callsite_index_8616,
    )
    middle_boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1034)
    index = build_decoded_direct_callsite_index_8616(tuple(
        DecodedCallerCensus8616(item.addr, item.decode_start, item.decode_end,
            tuple(insn for block in item.blocks for insn in block.capstone.insns))
        for item in (boundary, middle_boundary)
    ), direct_target_resolver=resolver, instruction_address_resolver=lambda instruction: instruction.address)
    owner.install_real16_invocation_source_8616(project,owner.Real16InvocationSource8616(
        boot,_recompute,index,function_entries=(admission,),
    ))
    return project,boot,artifact,boundary,resolver,admission



def _prepared_nested(nested_world):
    """Build the authentic root-to-middle entry before testing one nested edge."""
    from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616

    project, _boot, artifact, boundary, _resolver, _admission = nested_world
    source = owner._invocation_premise_source_8616(project)
    entry = source.callsite_index.for_target(0x1030)[0]
    block, row = next((block, row) for block in artifact.blocks for row in block.instrs if row.op == "CALL")
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        _binding, route, scope = owner._deferred_declared_raw_callee_scope_8616(
            project, artifact, boundary, block, row, entry, 0x1030, (),
        )
        assert route is owner._RawCalleeRoute8616.SCOPED_BODY and scope is not None
    chain = scope.chain
    coverage = prove_ir_boundary_coverage_8616(project, chain.callee_boundary, chain.callee_artifact)
    nested = source.callsite_index.for_target(0x1010)[0]
    return project, scope, coverage, nested


def test_native_nested_construction_eliminates_second_parent_replay(nested_world, monkeypatch, record_property):
    """Three genuine native levels transport one fresh caller census directly."""
    import sys

    project, scope, coverage, nested = _prepared_nested(nested_world)
    chain = scope.chain
    calls = []
    def observe(code, offset):
        frame = sys._getframe(1)
        calls.append(frame.f_locals["parent"].callsite_addr)
    sys.monitoring.use_tool_id(5, "nested-chain-test")
    sys.monitoring.register_callback(5, sys.monitoring.events.PY_START, observe)
    sys.monitoring.set_local_events(5, domain_owner._derive_parent_for_chain_8616.__code__, sys.monitoring.events.PY_START)
    try:
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
            assert scope.complete
            calls.clear()
            before = traversal.census_work_units
            prefix = owner._chained_nested_prefix_8616(project, coverage, chain.callee_boundary, nested.callsite_addr, scope, ())
            assert prefix is not None
            from inertia.semantics.direct_near_call_target_binding import (
                _consume_direct_near_call_target_binding_from_decoded_8616,
            )
            block, row = next((block, row) for block in coverage.artifact.blocks for row in block.instrs if row.op == "CALL")
            binding = _consume_direct_near_call_target_binding_from_decoded_8616(
                project, block=block, instruction=row, decoded=nested, invocation=prefix,
                consumer=lambda invocation: invocation.complete,
            )
            _route, ordinary = owner._raw_callee_call_scope_8616(project, 0x1010, nested, prefix, binding)
            assert ordinary is not None
            ordinary_work = traversal.census_work_units-before
            ordinary_calls = list(calls)
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
            assert scope.complete
            calls.clear()
            before = traversal.census_work_units
            _route, binding, actual = owner._construct_chained_nested_scope_8616(project, coverage, chain.callee_boundary, nested, scope, ())
            actual_work = traversal.census_work_units-before
            actual_calls = list(calls)
            assert actual is not None
            assert actual.callsite_call_state == ordinary.callsite_call_state
            assert actual.callsite_memory == ordinary.callsite_memory
            assert actual.path_block_addrs == ordinary.path_block_addrs
            assert actual.failure is ordinary.failure is None
            assert (actual.entry_segment, actual.entry_offset, actual.stack_segment, actual.stack_offset,
                    actual.assumptions, actual.source_sha256, actual.service_consumptions) == (
                ordinary.entry_segment, ordinary.entry_offset, ordinary.stack_segment, ordinary.stack_offset,
                ordinary.assumptions, ordinary.source_sha256, ordinary.service_consumptions)
            assert actual_work < ordinary_work
            assert actual_calls.count(0x1043) < ordinary_calls.count(0x1043)
            record_property("ordinary_work", ordinary_work)
            record_property("actual_work", actual_work)
            record_property("ordinary_parent_calls", ordinary_calls)
            record_property("actual_parent_calls", actual_calls)
    finally:
        sys.monitoring.free_tool_id(5)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        assert actual.complete


@pytest.mark.parametrize("mutation", ["native", "parent", "foreign_parent", "call_state", "callee_boundary", "required_scalar", "services"])
def test_nested_construction_refuses_late_chain_mutation(nested_world, monkeypatch, mutation):
    """Changes after original-scope admission cannot rewrite captured ancestry."""
    project, scope, coverage, nested = _prepared_nested(nested_world)
    chain = scope.chain
    boundary = chain.callee_boundary
    original = domain_owner._derive_chained_invocation_domain_8616
    calls = []
    def mutate(*args, **kwargs):
        if args[2] == nested.callsite_addr and not calls:
            calls.append(1)
            if mutation == "native":
                project.loader.memory.store(0x1041, b"\x00")
            elif mutation == "parent":
                object.__setattr__(chain, "parent", replace(chain.parent, minimum_selector=chain.parent.minimum_selector + 1))
            elif mutation == "foreign_parent":
                object.__setattr__(chain, "parent", object())
            elif mutation == "call_state":
                object.__setattr__(chain, "call_state", tuple((name, value + 2 if name == "sp" else value) for name, value in chain.call_state))
            elif mutation == "callee_boundary":
                object.__setattr__(chain, "callee_boundary", replace(boundary))
            elif mutation == "required_scalar":
                object.__setattr__(scope, "minimum_selector", scope.minimum_selector + 1)
            else:
                object.__setattr__(scope, "declared_services", (object(),))
        return original(*args, **kwargs)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        assert scope.complete
        monkeypatch.setattr(domain_owner, "_derive_chained_invocation_domain_8616", mutate)
        route, _binding, actual = owner._construct_chained_nested_scope_8616(project, coverage, boundary, nested, scope, ())
        assert calls == [1]
        assert route is owner._RawCalleeRoute8616.REFUSED and actual is None


@pytest.mark.parametrize("guard", ["work", "depth", "cycle", "refused"])
def test_nested_construction_preserves_shared_guards(nested_world, guard):
    """No direct construction bypasses aggregate work, active depth or refusal."""
    project, scope, coverage, nested = _prepared_nested(nested_world)
    chain = scope.chain
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        assert scope.complete
        if guard == "work":
            traversal.census_work_units = domain_owner._CENSUS_WORK_LIMIT_8616
        elif guard == "depth":
            traversal.active_domains.update(range(domain_owner._CHAIN_DEPTH_LIMIT_8616))
        elif guard == "cycle":
            traversal.active_domains.add(id(scope))
        else:
            traversal.domain_verdicts[id(scope)] = False
        route, _binding, actual = owner._construct_chained_nested_scope_8616(project, coverage, chain.callee_boundary, nested, scope, ())
        assert route is owner._RawCalleeRoute8616.REFUSED and actual is None


def test_nested_callsite_owner_uses_single_construction(nested_world, monkeypatch):
    """Production callsite routing must not reconnect the old double replay."""
    import sys

    project, scope, coverage, nested = _prepared_nested(nested_world)
    source = owner._invocation_premise_source_8616(project)
    chain = scope.chain
    observed = []
    scopes = []
    def stop_closure(*args, **kwargs):
        scopes.append(kwargs["invocation_scope"])
        return None, owner.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    def start(code, offset):
        observed.append(sys._getframe(1).f_locals["parent"].callsite_addr)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        assert scope.complete
        monkeypatch.setattr(owner, "_callee_closure_8616", stop_closure)
        sys.monitoring.use_tool_id(5, "nested-wiring")
        sys.monitoring.register_callback(5, sys.monitoring.events.PY_START, start)
        sys.monitoring.set_local_events(5, domain_owner._derive_parent_for_chain_8616.__code__, sys.monitoring.events.PY_START)
        try:
            result = owner._nested_callsite_proof_8616(
                project, coverage, chain.callee_boundary, source.callsite_index,
                owner._decoded_instruction_map_8616(chain.callee_boundary), nested.callsite_addr,
                owner._CalleeResolution8616(resolver=lambda row: resolve_direct_call_target_from_instruction_8616(project, row)),
                invocation_scope=scope,
            )
        finally:
            sys.monitoring.free_tool_id(5)
    assert result is None
    assert len(scopes) == 1 and scopes[0] is not None
    assert scopes[0].callsite_addr == 0x1010
    assert scopes[0].chain.parent.callsite_addr == 0x1030
    assert observed == [0x1043]


@pytest.mark.parametrize("root_kind", ["boot", "enclosed"])
def test_nested_snapshot_accepts_existing_ancestor_kinds(nested_world, root_kind):
    """Snapshot admission keeps ordinary boot roots and enclosed ancestry."""
    _project, scope, _coverage, _nested = _prepared_nested(nested_world)
    chain = scope.chain
    root = replace(chain.parent, chain=None)
    if root_kind == "enclosed":
        enclosed = domain_owner.Real16EnclosedEntryLink8616(
            parent=root, callsite_index=chain.callsite_index, callsite=chain.callsite,
            callsite_artifact=chain.callsite_artifact, callsite_boundary=chain.callsite_boundary,
            call_state=chain.call_state, enclosing_artifact=chain.callee_artifact,
            enclosing_boundary=chain.callee_boundary, callee_artifact=chain.callee_artifact,
            callee_boundary=chain.callee_boundary, edge=chain.edge,
        )
        root = replace(chain.parent, chain=enclosed)
    captured = domain_owner._nested_chain_inputs_8616(replace(chain, parent=root))
    assert captured is not None and captured[-1] is None
