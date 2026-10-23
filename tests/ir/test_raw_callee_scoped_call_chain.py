"""Conditional near-call effects keep native raw terminal identity."""
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
from inertia.ir import real16_invocation_domain as domain_owner
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    Real16CallChainLink8616,
    prove_real16_declared_function_entry_domain_8616,
    real16_native_census_import_8616,
)
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_declared_function_entry_domain import _prove, _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


@pytest.fixture
def calls_with_pending_helper() -> tuple[object, ...]:
    """Return through a stack word whose identity requires the near-CALL premise."""
    return _calls_with_helper_8616(bytes.fromhex("5bffe3"))


@pytest.fixture
def calls_with_unconditional_helper() -> tuple[object, ...]:
    """Keep the original complete CFG as a universal-proof regression."""
    return _calls_with_helper_8616(bytes.fromhex("eb13c3") + b"\x90" * 18 + bytes.fromhex("33c0ebe9"))


def _calls_with_helper_8616(helper: bytes) -> tuple[object, ...]:
    """Build authentic caller inputs for a declared native helper body."""
    apply_x86_16_bootstrap()
    _project,original,old_link = _world()
    caller = bytes.fromhex('b83412e8caffe8c7ffc3')
    source = bytearray(original.source)
    source[0x60:0x60+len(caller)] = caller
    source[0x30:0x30+len(helper)] = helper
    boot = program_from_mz_bytes(bytes(source),original.environment,code_ranges=(
        LinearRange(0x1000,2),LinearRange(0x1010,len(helper)),LinearRange(0x1040,len(caller)),LinearRange(0x1070,1),
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
        boot,_recompute,index,function_entries=(admission,),
    ))
    return project,boot,artifact,boundary,resolver,admission


def _collect(world):
    project,_boot,artifact,boundary,resolver,_admission=world
    with direct_evidence_deadline_scope_8616(project,time.monotonic()+20),native_import_request_8616():
        return owner.collect_entry_domain_call_preservations_8616(project,artifact,boundary,direct_target_resolver=resolver)


def test_complete_helper_keeps_universal_body_proof(calls_with_unconditional_helper: tuple[object, ...]) -> None:
    """A complete body keeps unconditional evidence without a scoped rewrite."""
    records = _collect(calls_with_unconditional_helper)
    assert len(records) == 2
    for record in records:
        assert record.failure is None and record.callee is not None
        callee = record.callee
        assert callee.complete
        assert callee.state.invocation_scope is None
        assert callee.coverage.scoped_view is None
        assert callee.coverage.complete
        assert not callee.coverage.artifact.refusals
        assert not any(block.refusals for block in callee.coverage.artifact.blocks)


def test_second_prefix_uses_identical_raw_scoped_helper(calls_with_pending_helper):
    project,boot,artifact,boundary,_resolver,admission=calls_with_pending_helper
    assert registered_function_ir_artifact_8616(project,0x1010).verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    records=_collect(calls_with_pending_helper)
    assert len(records)==2 and all(record.failure is None for record in records)
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
    with direct_evidence_deadline_scope_8616(project,time.monotonic()+20),native_import_request_8616():
        bundle=raw_x86_16_import_bundle_for_artifact_8616(project,scope.chain.callee_boundary,raw)
        assert bundle is not None and bundle.artifact is raw
        prefix=prove_real16_declared_function_entry_domain_8616(project,DeclaredFunctionEntryLink8616(admission,artifact,boundary),
            0x1046,boot=boot,boot_recompute=_recompute,entry_call_preservations=records)
        assert prefix.failure is None and prefix.complete
    assert registered_function_ir_artifact_8616(project,0x1010).verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE


@pytest.mark.parametrize('mutation',['native','call_row','scope'])
def test_changed_native_transport_cannot_consume_scoped_helper(calls_with_pending_helper,mutation):
    project,_boot,_artifact,_boundary,_resolver,_admission=calls_with_pending_helper
    record=_collect(calls_with_pending_helper)[0]
    assert record.failure is None and record.callee is not None
    callee=record.callee
    scope=callee.state.invocation_scope
    assert scope is not None and isinstance(scope.chain,Real16CallChainLink8616)
    if mutation=='native':
        project.loader.memory.store(0x1011,b'\x90')
    else:
        link=scope.chain
        if mutation=='call_row':
            link=replace(link,callsite=replace(link.callsite,callsite_addr=0x1046))
        else:
            parent=link.parent
            assert isinstance(parent.chain,DeclaredFunctionEntryLink8616)
            admission=parent.chain.admission
            changed=replace(admission,spec=replace(admission.spec,entry_offset=0x41))
            link=replace(link,parent=replace(parent,chain=replace(parent.chain,admission=changed)))
        scope=replace(scope,chain=link)
        record=replace(record,callee=replace(callee,state=replace(callee.state,invocation_scope=scope)))
    assert not record.complete_for(record.required_scope)


def test_expired_request_cannot_publish_scoped_call_proof(calls_with_pending_helper):
    project,_boot,artifact,boundary,resolver,_admission=calls_with_pending_helper
    with direct_evidence_deadline_scope_8616(project,time.monotonic()-1),native_import_request_8616():
        records=owner.collect_entry_domain_call_preservations_8616(project,artifact,boundary,direct_target_resolver=resolver)
    assert len(records)==2 and all(record.failure is owner.EntryDomainCallPreservationFailure8616.BUDGET_EXHAUSTED for record in records)
    assert registered_function_ir_artifact_8616(project,0x1010).verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE


def test_entry_binding_rejects_stale_fields_and_retains_pending_edge(calls_with_pending_helper, monkeypatch):
    record = _collect(calls_with_pending_helper)[0]
    assert record.callee is not None
    scope = record.callee.state.invocation_scope
    assert scope is not None and isinstance(scope.chain, Real16CallChainLink8616)
    link = scope.chain
    binding = link.entry_binding
    assert binding is not None and binding.invocation is not None and binding.shape is not None
    pending = next(edge for edge in link.parent.entry_call_preservations if edge.callsite_addr == 0x1043)
    assert pending.failure is not None
    original = domain_owner.Real16CallInvocation8616.complete
    replays = []
    def counted(invocation):
        replays.append(invocation)
        return original.fget(invocation)
    with monkeypatch.context() as observed:
        observed.setattr(domain_owner.Real16CallInvocation8616, 'complete', property(counted))
        assert domain_owner._near_call_entry_binding_bound_8616(link)
    assert len(replays) == 1
    for changed in (
        replace(binding, callsite_addr=0x1046),
        replace(binding, target_addr=0x1012),
        replace(binding, shape=replace(binding.shape, displacement=binding.shape.displacement + 1)),
        replace(binding, invocation=replace(binding.invocation, project=object())),
        replace(binding, invocation=replace(binding.invocation, callsite_addr=0x1046)),
        replace(binding, invocation=replace(binding.invocation, target_addr=0x1012)),
        replace(binding, stats=replace(binding.stats, materialized_count=0)),
        replace(binding, stats=replace(binding.stats, normalized_fact_count=True)),
        replace(binding, invocation=replace(binding.invocation, premise=replace(link.parent, callsite_addr=0x1046))),
    ):
        assert not domain_owner._chain_call_entry_bound_8616(replace(link, entry_binding=changed))
    # Explicit refused return evidence cannot be bypassed by valid entry evidence.
    assert not domain_owner._chain_call_entry_bound_8616(replace(link, edge=pending))
    # The legacy link still requires the retained candidate's return certificate.
    assert not domain_owner._chain_call_entry_bound_8616(replace(link, entry_binding=None))
    receipt = scope.to_dict()['call_entry_binding']
    assert receipt['callsite_addr'] == 0x1043 and receipt['target_addr'] == 0x1010
    assert receipt['entry_only'] is True


@pytest.fixture
def native_chain():
    project, boot, link = _world(descendant="stack", baseline=True)
    parent = _prove(project, boot, link)
    boundary = exact_function_range_boundary_8616(project, 0x102b, 0x1032)
    artifact = domain_owner.real16_native_census_import_8616(project, boundary)
    index = build_boundary_direct_callsite_index_8616(
        link.boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    chain = domain_owner.Real16CallChainLink8616(
        parent, index, index.for_target(0x102b)[0], link.artifact, link.boundary,
        parent.callsite_call_state, artifact, boundary,
    )
    return project, boot, chain


def _factory(world, *, fresh=True):
    project, boot, chain = world
    factory = (domain_owner.prove_fresh_real16_chained_invocation_domain_8616 if fresh else
               domain_owner.prove_real16_chained_invocation_domain_8616)
    return factory(project, None, 0x102b, boot=boot, boot_recompute=_recompute, chain=chain)


def test_exact_chained_derivation_count_two_to_one_then_public_replay(native_chain, monkeypatch):
    _project, _boot, chain = native_chain
    original = domain_owner._derive_invocation_domain_8616
    calls = []

    def tracked(*args, **kwargs):
        if kwargs.get("chain") is chain:
            calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(domain_owner, "_derive_invocation_domain_8616", tracked)
    ordinary = _factory(native_chain, fresh=False)
    assert ordinary.complete
    assert len(calls) == 2
    calls.clear()
    fresh = _factory(native_chain)
    assert fresh is not None
    assert len(calls) == 1
    assert fresh.complete
    assert len(calls) == 2
    assert fresh.kind is domain_owner.Real16InvocationKind8616.CALL_CHAINED


@pytest.mark.parametrize("mutation", ["native", "parent", "call_state", "row"])
@pytest.mark.parametrize("when", ["admission", "replay"])
def test_changed_chained_authority_refuses(native_chain, mutation, when):
    project, _boot, chain = native_chain
    fresh = _factory(native_chain) if when == "replay" else None
    if mutation == "native":
        project.loader.memory.store(0x102b, b"\x90")
    elif mutation == "parent":
        parent = chain.parent
        changed = replace(parent.chain.admission, spec=replace(parent.chain.admission.spec, entry_offset=0x21))
        chain = replace(chain, parent=replace(parent, chain=replace(parent.chain, admission=changed)))
    elif mutation == "call_state":
        chain = replace(chain, call_state=tuple((key, value ^ 1 if key == "cs" else value) for key, value in chain.call_state))
    else:
        chain = replace(chain, callsite=replace(chain.callsite, callsite_addr=0x1024))
    if when == "admission":
        assert _factory((project, _boot, chain)) is None
    else:
        assert fresh is not None
        assert not replace(fresh, chain=chain).complete


@pytest.mark.parametrize("bad_chain", [None, object()])
def test_fresh_chained_factory_cannot_mislabel_boot_derivation(native_chain, bad_chain):
    project, boot, _chain = native_chain
    assert _factory((project, boot, bad_chain)) is None


@pytest.mark.parametrize("guard", ["budget", "depth", "deadline"])
def test_fresh_chained_traversal_guards_remain(native_chain, monkeypatch, guard):
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if guard == "budget":
            traversal.remaining_domains = 0
        elif guard == "depth":
            traversal.active_domains.update(range(domain_owner._CHAIN_DEPTH_LIMIT_8616))
        else:
            monkeypatch.setattr(domain_owner, "_census_deadline_8616", lambda: 0.0)
        assert _factory(native_chain) is None


def test_transport_parent_replay_once(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """One transport consumes exactly one source-authenticated parent census."""
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    parent = scope.chain.parent
    original = domain_owner._derive_invocation_domain_8616
    count = []
    def tracked(*args: object, **kwargs: object) -> domain_owner._Derivation8616:
        if kwargs.get("chain") is parent.chain:
            count.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain_owner, "_derive_invocation_domain_8616", tracked)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert scope.complete
        print({"parent_replays": len(count), "census_work_units": traversal.census_work_units})
    assert len(count) == 1
    assert scope.complete
    assert len(count) == 2


@pytest.mark.parametrize("mutation", ["kind", "register", "memory"])
def test_forged_parent_capture_refuses(calls_with_pending_helper: tuple, mutation: str) -> None:
    """Forged provenance and captures retain an honest refusal."""
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    parent = scope.chain.parent
    if mutation == "kind":
        parent = replace(parent, kind=domain_owner.Real16InvocationKind8616.BOOT_ENTRY_PATH)
    elif mutation == "register":
        parent = replace(parent, callsite_call_state=tuple((name, value ^ 1 if name == "ax" else value) for name, value in parent.callsite_call_state))
    else:
        parent = replace(parent, callsite_memory=None)
    assert not replace(scope, chain=replace(scope.chain, parent=parent)).complete


@pytest.mark.parametrize("mutation", ["native", "environment", "source", "ir", "declaration"])
def test_final_binding_replay_rejects_changed_parent(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Every applicable mutable caller input is replayed after native gates."""
    from inertia.semantics import direct_near_call_target_binding as binding_owner
    project, boot, artifact, _boundary, _resolver, _admission = calls_with_pending_helper
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    parent = scope.chain.parent
    original = binding_owner._target_bytes_bound_8616
    def native_gate(*args: object) -> bool:
        result = original(*args)
        if mutation == "native":
            project.loader.memory.store(0x1040, b"\x90")
        elif mutation == "environment":
            object.__setattr__(boot.environment, "psp_segment", boot.environment.psp_segment ^ 1)
        elif mutation == "source":
            object.__setattr__(boot, "source", bytes([boot.source[0] ^ 1]) + boot.source[1:])
        elif mutation == "ir":
            instruction = artifact.blocks[0].instrs[0]
            object.__setattr__(instruction, "op", "NOP")
        else:
            admission = parent.chain.admission
            object.__setattr__(admission, "spec", replace(admission.spec, entry_offset=admission.spec.entry_offset + 1))
        return result
    monkeypatch.setattr(binding_owner, "_target_bytes_bound_8616", native_gate)
    assert not scope.complete


@pytest.mark.parametrize("field", ["stats", "shape"])
def test_final_reconcile_rejects_foreign_records_without_callbacks(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, field: str,
) -> None:
    """A forged record cannot execute a property/equality hook after the replay."""
    from inertia.semantics import direct_near_call_target_binding as binding_owner
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    binding = scope.chain.entry_binding
    original = binding_owner._target_bytes_bound_8616
    class ForeignRecord:
        def __eq__(self, other: object) -> bool:
            pytest.fail("foreign equality hook executed after census")
        @property
        def closed(self) -> bool:
            pytest.fail("foreign closed property executed after census")
    def native_gate(*args: object) -> bool:
        result = original(*args)
        object.__setattr__(binding, field, ForeignRecord())
        return result
    monkeypatch.setattr(binding_owner, "_target_bytes_bound_8616", native_gate)
    assert not scope.complete


@pytest.mark.parametrize("guard", ["budget", "active", "cached_false", "depth"])
def test_exhausted_parent_budget_avoids_forced_replay(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, guard: str,
) -> None:
    """A normal parent admission refusal prevents expensive forced replay."""
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    def unexpected(*args: object) -> domain_owner._Derivation8616:
        pytest.fail("exhausted parent budget entered full derivation")
    monkeypatch.setattr(domain_owner, "_derive_parent_for_chain_8616", unexpected)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if guard == "budget":
            traversal.remaining_domains = 1
        elif guard == "active":
            traversal.active_domains.add(id(scope.chain.parent))
        elif guard == "cached_false":
            traversal.domain_verdicts[id(scope.chain.parent)] = False
        else:
            traversal.active_domains.update(range(domain_owner._CHAIN_DEPTH_LIMIT_8616 - 1))
        assert not scope.complete


def test_parent_remains_active_during_forced_derivation(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recursive completeness cannot reenter the same active parent replay."""
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    parent = scope.chain.parent
    original = domain_owner._derive_parent_for_chain_8616
    visited = []
    def derive(actual: domain_owner.Real16InvocationDomain8616, depth: int) -> domain_owner._Derivation8616:
        assert actual is parent
        assert not parent.complete
        visited.append(1)
        return original(actual, depth)
    monkeypatch.setattr(domain_owner, "_derive_parent_for_chain_8616", derive)
    assert scope.complete
    assert visited == [1]


@pytest.mark.parametrize("mode", ["fresh", "changed_native", "depth"])
def test_cached_positive_forces_bounded_current_capture(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Cached positives cannot replace current replay or bypass active depth."""
    from inertia.semantics import direct_near_call_target_binding as binding_owner
    project = calls_with_pending_helper[0]
    record = _collect(calls_with_pending_helper)[0]
    scope = record.callee.state.invocation_scope
    parent = scope.chain.parent
    original = domain_owner._derive_parent_for_chain_8616
    visits = []
    def derive(actual: domain_owner.Real16InvocationDomain8616, depth: int) -> domain_owner._Derivation8616:
        assert actual is parent and not parent.complete
        visits.append(1)
        return original(actual, depth)
    monkeypatch.setattr(domain_owner, "_derive_parent_for_chain_8616", derive)
    if mode == "changed_native":
        native = binding_owner._target_bytes_bound_8616
        def gate(*args: object) -> bool:
            result = native(*args)
            project.loader.memory.store(0x1040, b"\x90")
            return result
        monkeypatch.setattr(binding_owner, "_target_bytes_bound_8616", gate)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.domain_verdicts[id(parent)] = True
        if mode == "depth":
            traversal.active_domains.update(range(domain_owner._CHAIN_DEPTH_LIMIT_8616 - 1))
        complete = scope.complete
        assert complete is (mode == "fresh")
    assert len(visits) == (0 if mode == "depth" else 1)
