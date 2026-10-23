"""A declared first CALL constructs its caller exactly once after native intake."""
import time

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsite8616
from inertia.ir import entry_domain_call_preservation as intake
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper


def test_declared_raw_first_call_constructs_parent_once(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Count real native caller derivations across binding and raw callee transport."""
    project, _boot, artifact, boundary, resolver, _admission = calls_with_pending_helper
    source = intake._invocation_premise_source_8616(project)
    assert source is not None
    callsite = source.callsite_index.for_target(0x1010)[0]
    block, instruction = next((b, r) for b in artifact.blocks for r in b.instrs if r.op == 'CALL' and r.addr == callsite.callsite_addr)
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        link = kwargs.get('chain')
        if isinstance(link, domain.DeclaredFunctionEntryLink8616) and args[2] == callsite.callsite_addr:
            calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    scopes = []
    original_closure = intake._callee_closure_8616
    def stop_at_closure(
        current_project: object, callee_addr: int, resolution: intake._CalleeResolution8616,
        invocation_scope: domain.Real16InvocationDomain8616 | None = None,
        callsite: DecodedDirectCallsite8616 | None = None,
    ) -> tuple[object | None, intake.EntryDomainCallPreservationFailure8616 | None]:
        """Delegate universal intake and observe only the conditional frontier."""
        if invocation_scope is None:
            return original_closure(current_project, callee_addr, resolution, callsite=callsite)
        scopes.append(invocation_scope)
        return None, intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    monkeypatch.setattr(intake, '_callee_closure_8616', stop_at_closure)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        result = intake._resolve_callsite_evidence_8616(
            project, artifact, boundary, block, instruction,
            index=source.callsite_index, decoded_by_addr=intake._decoded_instruction_map_8616(boundary),
            resolution=intake._CalleeResolution8616(resolver=resolver),
            entry_call_preservations=(), collection_phase=intake._CallCollectionPhase8616.COMPLETE)
        assert result is not None
        binding = result[4]
        assert binding is not None and binding.invocation is not None
        assert len(scopes) == 1 and scopes[0] is not None
        assert scopes[0].kind is domain.Real16InvocationKind8616.CALL_CHAINED
    assert calls == [1]


def _resolve(world: tuple, monkeypatch: pytest.MonkeyPatch) -> tuple:
    """Run authentic native binding/scope construction without downstream closure replay."""
    project, _boot, artifact, boundary, resolver, _admission = world
    source = intake._invocation_premise_source_8616(project)
    assert source is not None
    row = source.callsite_index.for_target(0x1010)[0]
    block, instruction = next((b, r) for b in artifact.blocks for r in b.instrs if r.op == 'CALL' and r.addr == row.callsite_addr)
    scopes = []
    original_closure = intake._callee_closure_8616
    def stop_at_closure(
        current_project: object, callee_addr: int, resolution: intake._CalleeResolution8616,
        invocation_scope: domain.Real16InvocationDomain8616 | None = None,
        callsite: DecodedDirectCallsite8616 | None = None,
    ) -> tuple[object | None, intake.EntryDomainCallPreservationFailure8616 | None]:
        """Delegate universal intake and observe only the conditional frontier."""
        if invocation_scope is None:
            return original_closure(current_project, callee_addr, resolution, callsite=callsite)
        scopes.append(invocation_scope)
        return None, intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    monkeypatch.setattr(intake, '_callee_closure_8616', stop_at_closure)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        result = intake._resolve_callsite_evidence_8616(
            project, artifact, boundary, block, instruction,
            index=source.callsite_index, decoded_by_addr=intake._decoded_instruction_map_8616(boundary),
            resolution=intake._CalleeResolution8616(resolver=resolver),
            entry_call_preservations=(), collection_phase=intake._CallCollectionPhase8616.COMPLETE)
        work = traversal.census_work_units
    return result, scopes, work


@pytest.mark.parametrize('mutation', ['native', 'callee_native', 'environment', 'source', 'ir', 'declaration', 'far_row'])
def test_binding_callback_mutations_refuse_fresh_construction(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    """Every mutable caller input is checked after the last native binding gate."""
    from dataclasses import replace

    from inertia.semantics import direct_near_call_target_binding as binding
    project, boot, artifact, _boundary, _resolver, admission = calls_with_pending_helper
    source = intake._invocation_premise_source_8616(project)
    original = binding._target_bytes_bound_8616
    events = []
    def mutate(*args: object) -> bool:
        result = original(*args)
        events.append(1)
        if mutation == 'native':
            project.loader.memory.store(0x1040, b'\x90')
        elif mutation == 'callee_native':
            project.loader.memory.store(0x1025, b'\x90')
        elif mutation == 'environment':
            object.__setattr__(boot.environment, 'psp_segment', boot.environment.psp_segment ^ 1)
        elif mutation == 'source':
            object.__setattr__(boot, 'source', bytes([boot.source[0] ^ 1]) + boot.source[1:])
        elif mutation == 'ir':
            object.__setattr__(artifact.blocks[0].instrs[0], 'op', 'NOP')
        elif mutation == 'declaration':
            object.__setattr__(admission, 'spec', replace(admission.spec, entry_offset=admission.spec.entry_offset + 1))
        else:
            object.__setattr__(source.callsite_index.for_target(0x1010)[0], 'is_far', True)
        return result
    monkeypatch.setattr(binding, '_target_bytes_bound_8616', mutate)
    result, scopes, _work = _resolve(calls_with_pending_helper, monkeypatch)
    assert events == [1]
    assert result is not None and result[3] is intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    assert not scopes


def test_callee_boot_callback_runs_before_sole_caller_capture(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """A late callee boot callback cannot leave an already captured caller stale."""
    project, _boot, artifact, _boundary, _resolver, _admission = calls_with_pending_helper
    source = intake._invocation_premise_source_8616(project)
    original = source.boot_recompute
    events = []
    def mutate(boot: object) -> object:
        result = original(boot)
        events.append(1)
        if len(events) == 1:
            object.__setattr__(artifact.blocks[0].instrs[0], 'op', 'NOP')
        return result
    object.__setattr__(source, 'boot_recompute', mutate)
    result, scopes, _work = _resolve(calls_with_pending_helper, monkeypatch)
    assert events
    assert result is not None and result[3] is intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    assert not scopes


@pytest.mark.parametrize('corruption', ['foreign_row', 'changed_parent_surface', 'depth'])
def test_deferred_request_preserves_canonical_identity_and_depth_refusals(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, corruption: str) -> None:
    """Foreign rows, changed identity anchors and excessive links never mint scopes."""
    from dataclasses import replace

    from inertia.semantics import direct_near_call_target_binding as binding
    requests = []
    original_entry = domain._construct_declared_chain_entry_8616
    def entry(request: object) -> object:
        requests.append(request)
        if corruption == 'foreign_row':
            object.__setattr__(request, 'callsite', object())
        return original_entry(request)
    monkeypatch.setattr(domain, '_construct_declared_chain_entry_8616', entry)
    if corruption == 'changed_parent_surface':
        original_gate = binding._target_bytes_bound_8616
        def gate(*args: object) -> bool:
            result = original_gate(*args)
            target = requests[-1].caller
            changed = replace(target.surface, artifact=replace(target.surface.artifact))
            object.__setattr__(target, 'surface', changed)
            return result
        monkeypatch.setattr(binding, '_target_bytes_bound_8616', gate)
    if corruption == 'depth':
        original_seed = domain._construction_entry_seed_8616
        def seed(*args: object) -> object:
            changed = list(args)
            changed[5] = domain._CHAIN_DEPTH_LIMIT_8616
            return original_seed(*changed)
        monkeypatch.setattr(domain, '_construction_entry_seed_8616', seed)
    result, scopes, _work = _resolve(calls_with_pending_helper, monkeypatch)
    assert result is not None and result[3] is intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    assert not scopes
    if corruption == 'depth':
        assert not requests


def test_same_scope_shares_one_replay_for_input_identical_records(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """One fresh derivation authenticates two records with identical replay inputs.

    The declared caller premise and a peer record retaining a distinct but
    fieldwise-identical declared link consume the same
    ``_derive_invocation_domain_8616`` inputs, so one admission-guarded
    replay binds both. The fallback arm pins the previous shape: records
    whose replay inputs differ still run two independent derivations.
    """
    from dataclasses import replace
    _result, scopes, _work = _resolve(calls_with_pending_helper, monkeypatch)
    parent = scopes[0].chain.parent
    assert parent.kind is domain.Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY
    link = parent.chain
    assert type(link) is domain.DeclaredFunctionEntryLink8616
    peer = replace(
        parent,
        chain=domain.DeclaredFunctionEntryLink8616(
            link.admission, link.artifact, link.boundary,
        ),
    )
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    assert domain.same_real16_entry_scope_8616(parent, peer)
    assert calls == [1]
    forged = replace(peer, minimum_selector=peer.minimum_selector + 1)
    assert not domain.same_real16_entry_scope_8616(parent, forged)
    assert calls == [1, 1]
    monkeypatch.setattr(domain, '_shared_replay_inputs_8616', lambda o, r: False)
    calls.clear()
    assert domain.same_real16_entry_scope_8616(parent, peer)
    assert calls == [1, 1]


def test_normal_chain_keeps_state_snapshot_taken_before_native_callbacks(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Repairing retained state inside replay cannot erase its earlier mismatch."""
    from dataclasses import replace
    project = calls_with_pending_helper[0]
    _result, scopes, _work = _resolve(calls_with_pending_helper, monkeypatch)
    chain = scopes[0].chain
    captured = domain._derive_parent_for_chain_8616(chain.parent, 0)
    assert captured.failure is None
    changed = tuple((name, value ^ 1 if name == 'ax' else value) for name, value in chain.call_state)
    forged = replace(chain, call_state=changed)
    calls = []
    def repair(link: object, depth: int) -> object:
        calls.append(1)
        object.__setattr__(link, 'call_state', chain.call_state)
        return captured
    monkeypatch.setattr(domain, '_consume_chain_parent_8616', repair)
    seed = domain._chain_link_seed_8616(project, chain.callee_artifact, chain.callee_boundary, forged, 0)
    assert calls == [1]
    assert forged.call_state == chain.call_state
    assert seed is domain.Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN


def _shared_scope_pair(world: tuple, monkeypatch: pytest.MonkeyPatch) -> tuple:
    """Retain authentic declared entry scopes with independently owned root links."""
    from dataclasses import replace
    _result, scopes, _work = _resolve(world, monkeypatch)
    offered = scopes[0].chain.parent
    link = offered.chain
    assert type(link) is domain.DeclaredFunctionEntryLink8616
    return offered, replace(offered, chain=domain.DeclaredFunctionEntryLink8616(
        link.admission, link.artifact, link.boundary,
    ))


@pytest.mark.parametrize('guard', ['cached_false', 'active', 'one_slot', 'no_slots', 'depth'])
@pytest.mark.parametrize('different_pool', [False, True])
def test_shared_replay_admits_both_subjects(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, guard: str, different_pool: bool) -> None:
    """A warm positive cannot erase the peer's ordinary resource or refusal guards."""
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    if different_pool:
        from dataclasses import replace
        required = replace(required, entry_call_preservations=(object(),))
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if guard == 'cached_false':
            assert offered.complete
            traversal.domain_verdicts[id(required)] = False
        elif guard == 'active':
            traversal.active_domains.add(id(required))
        elif guard == 'depth':
            traversal.active_domains.update(range(domain._CHAIN_DEPTH_LIMIT_8616 - 1))
        else:
            traversal.remaining_domains = 1 if guard == 'one_slot' else 0
        assert not domain.same_real16_entry_scope_8616(offered, required)


@pytest.mark.parametrize('field', [
    'failure', 'kind', 'project', 'coverage', 'boot', 'boot_recompute',
    'callsite_addr', 'call_preservations', 'entry_call_preservations',
    'declared_services', 'chain', 'admission', 'artifact', 'boundary',
])
@pytest.mark.parametrize('both', [False, True])
def test_shared_replay_binds_original_inputs_after_callback(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, field: str, both: bool) -> None:
    """Neither one mutated peer nor two identically mutated peers authenticate."""
    from dataclasses import replace
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    original = offered.boot_recompute
    events = []
    def mutate(boot: object) -> object:
        result = original(boot)
        events.append(1)
        if field == 'failure':
            value = domain.Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
        elif field == 'kind':
            value = domain.Real16InvocationKind8616.CALL_CHAINED
        elif field == 'callsite_addr':
            value = offered.callsite_addr + 1
        elif field == 'chain':
            value = replace(required.chain)
        elif field == 'boot_recompute':
            value = original
        elif field in ('call_preservations', 'entry_call_preservations', 'declared_services'):
            value = (object(),)
        else:
            value = object()
        for subject in (offered, required) if both else (required,):
            target = subject.chain if field in ('admission', 'artifact', 'boundary') else subject
            object.__setattr__(target, field, value)
        return result
    object.__setattr__(offered, 'boot_recompute', mutate)
    object.__setattr__(required, 'boot_recompute', mutate)
    assert not domain.same_real16_entry_scope_8616(offered, required)
    assert events


def test_shared_replay_reentrant_peer_completion_refuses(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both subjects remain active during callbacks, without leaking active guards."""
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    original = offered.boot_recompute
    attempts = []
    def reenter(boot: object) -> object:
        attempts.append(required.complete)
        return original(boot)
    object.__setattr__(offered, 'boot_recompute', reenter)
    object.__setattr__(required, 'boot_recompute', reenter)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert domain.same_real16_entry_scope_8616(offered, required)
        assert not traversal.active_domains
    assert attempts and not any(attempts)


def test_shared_scope_identical_object_and_future_traversal(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Self comparison uses ordinary completion; a later traversal replays again."""
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    assert domain.same_real16_entry_scope_8616(offered, offered)
    assert calls == [1]
    with segment_call_dependency_traversal_scope_8616():
        assert offered.complete
        assert domain.same_real16_entry_scope_8616(offered, required)
    assert calls == [1, 1, 1]
    assert required.complete
    assert calls == [1, 1, 1, 1]


@pytest.mark.parametrize('warm', ['none', 'offered', 'both'])
def test_shared_pair_always_runs_one_current_derivation(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, warm: str) -> None:
    """Positive memoization never skips the verifier binding both exact captures."""
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if warm != 'none':
            assert offered.complete
        if warm == 'both':
            assert required.complete
        calls.clear()
        remaining = traversal.remaining_domains
        assert domain.same_real16_entry_scope_8616(offered, required)
        assert calls == [1]
        assert remaining - traversal.remaining_domains == {'none': 2, 'offered': 1, 'both': 0}[warm]


@pytest.mark.parametrize('same_link', [False, True])
def test_transport_links_keep_independent_replays(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, same_link: bool) -> None:
    """Transported edges replay twice even when both records retain the same link."""
    from dataclasses import replace
    _result, scopes, _work = _resolve(calls_with_pending_helper, monkeypatch)
    offered = scopes[0]
    required = replace(offered, chain=offered.chain if same_link else replace(offered.chain))
    assert not domain._shared_replay_inputs_8616(offered, required)
    original = domain._derive_invocation_domain_8616
    links = []
    def counted(*args: object, **kwargs: object) -> object:
        chain = kwargs.get('chain')
        if chain is offered.chain or chain is required.chain:
            links.append(chain)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    assert domain.same_real16_entry_scope_8616(offered, required)
    assert len(links) == 2
    assert links[0] is offered.chain and links[1] is required.chain


@pytest.mark.parametrize('field', ['call_preservations', 'entry_call_preservations', 'declared_services'])
def test_shared_replay_rejects_forged_empty_containers(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    """Falsey non-tuples never qualify as identical replay consumables."""
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    object.__setattr__(required, field, [])
    assert not domain._shared_replay_inputs_8616(offered, required)


def test_first_call_scope_shares_fresh_replay_across_unused_pools(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Different pools outside a call-free prefix need only one fresh census."""
    from dataclasses import replace
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    required = replace(required, entry_call_preservations=(object(),))
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    assert domain.same_real16_entry_scope_8616(offered, required)
    assert calls == [1]


@pytest.mark.parametrize('receipt', [domain._EntryCallPoolConsultation8616.UNKNOWN, domain._EntryCallPoolConsultation8616.READ])
def test_different_pools_require_explicit_fresh_unused_receipt(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, receipt: domain._EntryCallPoolConsultation8616) -> None:
    """Unknown or read receipts retain two independent ordinary derivations."""
    from dataclasses import replace
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    required = replace(required, entry_call_preservations=(object(),))
    original = domain._derive_invocation_domain_8616
    calls = []
    def incomplete(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return replace(original(*args, **kwargs), entry_call_pool_consultation=receipt)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', incomplete)
    assert domain.same_real16_entry_scope_8616(offered, required)
    assert calls == [1, 1]


@pytest.mark.parametrize('both', [False, True])
def test_unused_distinct_pools_keep_each_original_capture(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, both: bool) -> None:
    """Replacing unused tuples after callbacks still invalidates their authority."""
    from dataclasses import replace
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    required = replace(required, entry_call_preservations=(object(),))
    original = offered.boot_recompute
    changed = (object(),)
    def mutate(boot: object) -> object:
        result = original(boot)
        for subject in (offered, required) if both else (required,):
            object.__setattr__(subject, 'entry_call_preservations', changed)
        return result
    object.__setattr__(offered, 'boot_recompute', mutate)
    object.__setattr__(required, 'boot_recompute', mutate)
    assert not domain.same_real16_entry_scope_8616(offered, required)


def test_unused_pool_gate_includes_later_call_in_stop_block(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """A suffix CALL blocks pool sharing despite being after the requested row."""
    offered, _required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    artifact = offered.chain.artifact
    stop = domain._callsite_block_8616(artifact, offered.callsite_addr)
    later = next(row for block in artifact.blocks for row in block.instrs if row.op == 'CALL' and row.addr != offered.callsite_addr)
    object.__setattr__(stop, 'instrs', (*stop.instrs, later))
    assert not domain._entry_pool_unused_prefix_8616(offered)


@pytest.mark.parametrize('changed_record', [False, True])
@pytest.mark.parametrize('advice', [domain._EntryCallPoolConsultation8616.READ, domain._EntryCallPoolConsultation8616.UNUSED])
def test_actual_read_pool_retains_independent_replay(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, changed_record: bool, advice: domain._EntryCallPoolConsultation8616) -> None:
    """A forged UNUSED hint cannot share a freshly observed READ or hide corruption."""
    from dataclasses import replace

    from tests.ir.test_declared_function_entry_domain import _recompute
    from tests.ir.test_raw_callee_scoped_call_chain import _collect
    project, boot, artifact, boundary, _resolver, admission = calls_with_pending_helper
    records = tuple(_collect(calls_with_pending_helper))
    offered, derived = domain._derive_declared_function_entry_domain_8616(
        project, domain.DeclaredFunctionEntryLink8616(admission, artifact, boundary),
        0x1046, boot=boot, boot_recompute=_recompute, entry_call_preservations=records,
    )
    assert derived.failure is None
    assert offered.entry_call_pool_advice is domain._EntryCallPoolConsultation8616.READ
    offered = replace(offered, entry_call_pool_advice=advice)
    first = records[0]
    if changed_record:
        first = replace(first, failure=intake.EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE)
    required = replace(offered, entry_call_preservations=(first, *records[1:]))
    assert not domain._entry_pool_unused_prefix_8616(offered)
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        if args[2] == offered.callsite_addr:
            calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    assert domain.same_real16_entry_scope_8616(offered, required) is (not changed_record)
    assert calls == [1, 1]


@pytest.mark.parametrize('bound', ['work', 'deadline'])
def test_unused_pool_gate_retains_ambient_resource_bounds(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, bound: str) -> None:
    """Eligibility scans consume the live budget and never renew its deadline."""
    offered, _required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if bound == 'work':
            traversal.census_work_units = domain._CENSUS_WORK_LIMIT_8616
        else:
            traversal.census_deadline = time.monotonic() - 1
        assert not domain._entry_pool_unused_prefix_8616(offered)
        assert traversal.census_work_units > 0
        if bound == 'deadline':
            assert traversal.census_deadline < time.monotonic()


@pytest.mark.parametrize('shape', ['original', 'suffix', 'duplicate_owner', 'foreign_current_call', 'disconnected_call'])
def test_single_scan_pool_gate_matches_canonical_dangerous_rows(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
    """One-pass CALL collection preserves canonical ownership and CFG decisions."""
    from dataclasses import replace
    offered, _required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    artifact = offered.chain.artifact
    stop = domain._callsite_block_8616(artifact, offered.callsite_addr)
    current = next(row for row in stop.instrs if row.op == 'CALL' and row.addr == offered.callsite_addr)
    later = next(row for block in artifact.blocks for row in block.instrs if row.op == 'CALL' and row.addr != offered.callsite_addr)
    if shape == 'suffix':
        object.__setattr__(stop, 'instrs', (*stop.instrs, later))
    elif shape == 'duplicate_owner':
        object.__setattr__(artifact, 'blocks', (*artifact.blocks, stop))
    elif shape in ('foreign_current_call', 'disconnected_call'):
        instruction = current if shape == 'foreign_current_call' else later
        added = replace(stop, addr=stop.addr + 0x200, instrs=(instruction,), successor_addrs=())
        object.__setattr__(artifact, 'blocks', (*artifact.blocks, added))
    owner = domain._callsite_block_8616(artifact, offered.callsite_addr)
    expected = False
    if not isinstance(owner, domain.Real16InvocationFailure8616):
        dangerous = domain._dangerous_block_addrs_8616(artifact, owner)
        expected = not any(
            row.op == 'CALL' and row.addr != offered.callsite_addr
            for block in artifact.blocks if block.addr in dangerous for row in block.instrs
        )
    assert domain._entry_pool_unused_prefix_8616(offered) is expected


def test_authentic_unused_pool_gate_fits_existing_small_work_budget(calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """An authentic eligible prefix remains usable with a small remaining budget."""
    offered, _required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units = domain._CENSUS_WORK_LIMIT_8616 - 200
        assert domain._entry_pool_unused_prefix_8616(offered)
        assert traversal.census_work_units <= domain._CENSUS_WORK_LIMIT_8616


def test_canonical_unused_advice_avoids_redundant_static_scan(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A current replay still proves UNUSED; retained advice only avoids a pre-scan."""
    from dataclasses import replace
    offered, required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    assert offered.entry_call_pool_advice is domain._EntryCallPoolConsultation8616.UNUSED
    required = replace(required, entry_call_preservations=(object(),))
    original = domain._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    def forbidden(*args: object) -> bool:
        raise AssertionError("canonical advice should avoid redundant IR scan")
    monkeypatch.setattr(domain, '_derive_invocation_domain_8616', counted)
    monkeypatch.setattr(domain, '_entry_pool_unused_prefix_8616', forbidden)
    assert domain.same_real16_entry_scope_8616(offered, required)
    assert calls == [1]


@pytest.mark.parametrize('advice', [domain._EntryCallPoolConsultation8616.UNKNOWN, None, 'unused'])
def test_unknown_or_foreign_pool_advice_keeps_eligibility_scan(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch, advice: object,
) -> None:
    """Missing or malformed advisory values do not mint an UNUSED receipt."""
    offered, _required = _shared_scope_pair(calls_with_pending_helper, monkeypatch)
    object.__setattr__(offered, 'entry_call_pool_advice', advice)
    calls = []

    def conservative(subject: domain.Real16InvocationDomain8616) -> bool:
        calls.append(subject)
        return False

    monkeypatch.setattr(domain, '_entry_pool_unused_prefix_8616', conservative)
    assert not domain._unused_pool_replay_selected_8616(offered)
    assert len(calls) == 1 and calls[0] is offered
