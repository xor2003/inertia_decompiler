"""Behavioral parent control: reuse lifting, never suppress a proof attempt."""
import io
from copy import deepcopy
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import vex_import


def test_nested_imports_reuse_lifting_and_repeat_proof(monkeypatch):
    arch = Arch86_16()
    arch.bits = 32
    body = bytes.fromhex('eb00c3')
    project = angr.Project(io.BytesIO(bytes(14) + body + bytes(29) + body),
        main_opts={'backend': 'blob', 'arch': arch, 'base_addr': 0x10000,
                   'entry_point': 0x10000}, auto_load_libs=False)
    root = exact_function_range_boundary_8616(project, 0x1000e, 0x10011)
    child = exact_function_range_boundary_8616(project, 0x1002e, 0x10031)
    assert root is not None and child is not None
    conversions = []
    proofs = []
    native = vex_import._block_to_ir

    def convert(block, **kwargs):
        conversions.append(block.addr)
        return native(block, **kwargs)

    def preserve(current, function, address, artifact):
        proofs.append(address)
        if function is root:
            first = vex_import.build_x86_16_ir_function_artifact(current, child)
            second = vex_import.build_x86_16_ir_function_artifact(current, child)
            assert first.to_dict() == second.to_dict()
        return ()

    monkeypatch.setattr(vex_import, '_block_to_ir', convert)
    monkeypatch.setattr(vex_import, '_entry_domain_call_preservations_8616', preserve)
    vex_import.build_x86_16_ir_function_artifact(project, root)
    assert proofs.count(child.addr) == 2
    assert conversions.count(child.addr) == 1
    vex_import.build_x86_16_ir_function_artifact(project, root)
    assert proofs.count(child.addr) == 4
    assert conversions.count(child.addr) == 2


def _world(code=b'\x89\xd0\xc3'):
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(code),
        main_opts={'backend': 'blob', 'arch': arch, 'base_addr': 0x10000,
                   'entry_point': 0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x10000, 0x10000 + len(code))
    assert boundary is not None
    calls = []

    def importer(current, function):
        calls.append(function)
        return {'capture': [len(calls)]}

    def admit(surface, function):
        return True

    def request():
        return cache.request_native_surface_8616(
            project, boundary, importer, producers=(), admit=admit)

    return project, boundary, calls, request


def test_mutable_consumer_cannot_poison_private_facts():
    _, _, calls, request = _world()
    with cache.native_import_request_8616():
        first = request()
        first['capture'].append(99)
        second = request()
        assert second == {'capture': [1]}
        second['capture'].clear()
        assert request() == {'capture': [1]}
    assert len(calls) == 1


def _conditional_boundary(boundary):
    """Supply typed return-lift inputs, not a callable proof capability."""
    from inertia.frontend.x86_16.frontend_near_return_continuation import (
        NearReturnContinuationArtifact8616,
        NearReturnContinuationKind8616,
        NearReturnContinuationRecord8616,
        NearReturnContinuationVerdict8616,
    )

    continuation = NearReturnContinuationArtifact8616(
        (NearReturnContinuationRecord8616(
            boundary.addr, boundary.addr, NearReturnContinuationVerdict8616.PROVEN,
            None, NearReturnContinuationKind8616.REGISTER, 'ax'),),
        1, 1, 1, 1, 0,
    )
    return replace(boundary, near_return_continuations=continuation)


def test_conditional_raw_inputs_reuse_lift_but_never_finished_artifact():
    """Conditional lift reuse must not enable the completed-artifact cache."""
    from inertia.ir import raw_boot_native_surface_cache as finished
    from inertia.ir.core import IRFunctionArtifact

    project, boundary, _, _ = _world()
    boundary = _conditional_boundary(boundary)
    calls = []

    def importer(current, function):
        calls.append(function)
        return {'returns': sorted(function.near_return_continuations.proven_block_addrs)}

    def admit(surface, function):
        return True

    with cache.native_import_request_8616():
        first = cache.request_native_surface_8616(project, boundary, importer, producers=(), admit=admit)
        second = cache.request_native_surface_8616(project, boundary, importer, producers=(), admit=admit)
        assert first == second and first is not second
        assert len(calls) == 1
        changed = replace(boundary, near_return_continuations=replace(
            boundary.near_return_continuations, records=(),
            raw_fact_count=0, normalized_fact_count=0, classified_fact_count=0, materialized_count=0))
        assert cache.request_native_surface_8616(project, changed, importer, producers=(), admit=admit)['returns'] == []
        assert len(calls) == 2
    completed = finished.RawBootNativeSurfaceCache8616()
    completed_calls = []

    def finish(current, function):
        completed_calls.append(function)
        return IRFunctionArtifact(function.addr)

    source = object()
    finished.request_raw_boot_native_import_8616(completed, project, source, boundary, finish)
    finished.request_raw_boot_native_import_8616(completed, project, source, boundary, finish)
    assert len(completed_calls) == 2 and not completed.records


def _variant_importer(calls):
    """Count lifts and report which request actually ran the importer."""

    def importer(current, function):
        calls.append(function)
        return {'capture': [len(calls)]}

    def admit(surface, function):
        return True

    return importer, admit


def test_alternating_raw_variants_retain_each_private_surface():
    """Unconditional and conditional-return variants share one request.

    The importer alternates boundary variants for one address; each exact
    authenticated raw surface must keep its own bounded record instead of
    evicting the sibling variant on every request.
    """
    project, boundary, calls, _ = _world()
    conditional = _conditional_boundary(boundary)
    importer, admit = _variant_importer(calls)
    with cache.native_import_request_8616():
        for _ in range(3):
            assert cache.request_native_surface_8616(
                project, boundary, importer, producers=(), admit=admit) == {'capture': [1]}
            assert cache.request_native_surface_8616(
                project, conditional, importer, producers=(), admit=admit) == {'capture': [2]}
    assert len(calls) == 2
    assert [function.near_return_continuations is None for function in calls] == [True, False]


def test_retained_variants_stay_isolated_between_boundaries():
    """A consumed conditional copy cannot poison the unconditional variant."""
    project, boundary, calls, _ = _world()
    conditional = _conditional_boundary(boundary)
    importer, admit = _variant_importer(calls)

    def request(function):
        return cache.request_native_surface_8616(
            project, function, importer, producers=(), admit=admit)

    with cache.native_import_request_8616():
        assert request(boundary) == {'capture': [1]}
        second = request(conditional)
        assert second == {'capture': [2]}
        second['capture'].append(99)
        assert request(conditional) == {'capture': [2]}
        assert request(boundary) == {'capture': [1]}
    assert len(calls) == 2


def test_variant_cap_counts_distinct_variants_not_addresses(monkeypatch):
    """_MAX_RECORDS bounds retained variants globally, one address included."""
    project, boundary, calls, _ = _world()
    conditional = _conditional_boundary(boundary)
    other = replace(conditional, near_return_continuations=replace(
        conditional.near_return_continuations, materialized_count=2))
    importer, admit = _variant_importer(calls)

    def request(function):
        return cache.request_native_surface_8616(
            project, function, importer, producers=(), admit=admit)

    monkeypatch.setattr(cache, '_MAX_RECORDS', 2)
    with cache.native_import_request_8616():
        request(boundary)
        request(conditional)
        assert request(boundary) == {'capture': [1]}
        assert request(conditional) == {'capture': [2]}
        request(other)
        request(conditional)
        request(boundary)
        session = cache._ACTIVE.get()
        assert session is not None and len(session.records) == 2
    assert len(calls) == 4
    assert [function.near_return_continuations is None for function in calls] == [
        True, False, False, True]


def test_reentrant_clone_cannot_exceed_global_variant_cap(monkeypatch):
    """A reentrant import during hit copying leaves the global bounds intact.

    The hit path releases its slot before ``clone`` runs; a nested import can
    fill the freed space. Reinsertion must still pass through bound-aware
    retention rather than exceeding ``_MAX_RECORDS``/``_MAX_BLOCKS``.
    """
    project, boundary, calls, _ = _world()
    alternate = _conditional_boundary(boundary)
    armed = False

    def importer(current, function):
        calls.append(function)
        return {'capture': [len(calls)]}

    def admit(surface, function):
        return True

    def clone(surface):
        nonlocal armed
        if armed:
            armed = False
            request(alternate)
        return deepcopy(surface)

    def request(function):
        return cache.request_native_surface_8616(
            project, function, importer, producers=(), admit=admit, clone=clone)

    monkeypatch.setattr(cache, '_MAX_RECORDS', 1)
    monkeypatch.setattr(cache, '_MAX_BLOCKS', len(boundary.blocks))
    with cache.native_import_request_8616():
        request(boundary)
        armed = True
        request(boundary)
        session = cache._ACTIVE.get()
        assert session is not None and len(session.records) <= 1
        assert sum(record.blocks for record in session.records.values()) <= len(boundary.blocks)


def test_reentrant_rebind_callback_cannot_exceed_global_variant_cap(monkeypatch):
    """A reentrant import during fact projection leaves the bounds intact."""
    from inertia.ir.source_graph_binding import capture_immutable_source_graph_facts_8616

    project, boundary, calls, _ = _world()
    alternate = _conditional_boundary(boundary)
    importer, admit = _variant_importer(calls)
    facts = capture_immutable_source_graph_facts_8616(boundary.addr, (), ())
    armed = False

    def native_facts(surface):
        nonlocal armed
        if armed:
            armed = False
            cache.request_native_surface_8616(
                project, alternate, importer, producers=(), admit=admit)
        return facts

    monkeypatch.setattr(cache, '_MAX_RECORDS', 1)
    monkeypatch.setattr(cache, '_MAX_BLOCKS', len(boundary.blocks))
    with cache.native_import_request_8616():
        cache.request_native_surface_8616(
            project, boundary, importer, producers=(), admit=admit)
        armed = True
        rebound = cache.request_native_fact_rebind_8616(
            project, boundary, importer, producers=(), admit=admit,
            native_facts=native_facts, caller_facts=lambda: facts,
            detached_evidence=lambda surface: 'evidence')
        assert rebound.state is cache.NativeFactRebindState8616.AUTHENTICATED
        session = cache._ACTIVE.get()
        assert session is not None and len(session.records) <= 1
        assert sum(record.blocks for record in session.records.values()) <= len(boundary.blocks)


def test_conditional_lift_keys_the_actual_return_projection(monkeypatch):
    """A replaced return-projection producer cannot reuse an old raw lift."""
    from inertia.frontend.x86_16.frontend_near_return_continuation import NearReturnContinuationArtifact8616

    project, boundary, _, _ = _world()
    boundary = _conditional_boundary(boundary)
    calls = []

    def importer(current, function):
        calls.append(function)
        return function.near_return_continuations.proven_block_addrs

    def admit(surface, function):
        return True

    with cache.native_import_request_8616():
        assert cache.request_native_surface_8616(
            project, boundary, importer, producers=(), admit=admit) == frozenset({boundary.addr})
        monkeypatch.setattr(NearReturnContinuationArtifact8616, 'proven_block_addrs',
                            property(lambda self: frozenset()))
        assert cache.request_native_surface_8616(
            project, boundary, importer, producers=(), admit=admit) == frozenset()
        assert len(calls) == 2


def test_production_ir_consumer_cannot_poison_native_rebinding():
    """A changed frozen instruction cannot become its own cached native oracle."""
    project, boundary, _, _ = _world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        object.__setattr__(bundle.artifact.blocks[0].instrs[0], 'op', 'INJECTED_INVALID_OPCODE')
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact,
        ) is None
        fresh = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert fresh.artifact.blocks[0].instrs[0].op != 'INJECTED_INVALID_OPCODE'


@pytest.mark.parametrize('change', ['bytes', 'patches', 'hooks', 'single_step', 'strict_end', 'affine', 'metadata'])
def test_changed_authorities_force_fresh_native_facts(change, monkeypatch):
    project, boundary, calls, request = _world()
    with cache.native_import_request_8616():
        request()
        if change == 'bytes':
            project.loader.memory.store(boundary.addr, b'\x90')
        elif change == 'patches':
            project.kb.patches.add_patch(boundary.addr, b'\x90')
        elif change == 'hooks':
            project.hook(boundary.addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        elif change == 'single_step':
            project.factory.default_engine._single_step = True
        elif change == 'strict_end':
            project.factory.default_engine.default_strict_block_end = True
        elif change == 'affine':
            monkeypatch.setenv('INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS', '1')
        elif change == 'metadata':
            boundary.info['changed'] = True
        assert request() == {'capture': [2]}
    assert len(calls) == 2


def test_registry_changes_rerun_proofs_without_relifting(monkeypatch):
    from inertia.ir import raw_boot_native_surface_cache
    from inertia.ir.core import IRFunctionArtifact

    project, _, _, _ = _world(bytes(14) + bytes.fromhex('eb00c3'))
    boundary = exact_function_range_boundary_8616(project, 0x1000e, 0x10011)
    assert boundary is not None
    registry = {}
    proofs = []
    conversions = []
    native = vex_import._block_to_ir

    def convert(block, **kwargs):
        conversions.append(block.addr)
        return native(block, **kwargs)

    def preserve(current, function, address, artifact):
        proofs.append(tuple(registry))
        return ()

    monkeypatch.setattr(raw_boot_native_surface_cache, '_existing_registry_8616', lambda current: registry)
    monkeypatch.setattr(vex_import, '_block_to_ir', convert)
    monkeypatch.setattr(vex_import, '_entry_domain_call_preservations_8616', preserve)
    with cache.native_import_request_8616():
        first = vex_import.build_x86_16_ir_function_artifact(project, boundary)
        registry[7] = IRFunctionArtifact(7)
        second = vex_import.build_x86_16_ir_function_artifact(project, boundary)
    assert first.to_dict() == second.to_dict()
    assert proofs == [(), (7,)]
    assert conversions == sorted(boundary.block_addrs_set)


def test_expired_request_does_not_reuse_or_retain(monkeypatch):
    _, _, calls, request = _world()
    with cache.native_import_request_8616():
        request()
        monkeypatch.setattr(cache, 'direct_evidence_deadline_expired_8616', lambda current: True)
        assert request() == {'capture': [2]}
        monkeypatch.setattr(cache, 'direct_evidence_deadline_expired_8616', lambda current: False)
        assert request() == {'capture': [3]}
    assert len(calls) == 3


def test_raw_native_key_does_not_serialize_semantic_registry(monkeypatch):
    from inertia.ir import raw_boot_native_surface_cache

    def forbidden(registry):
        pytest.fail('raw lifting must not serialize semantic proof artifacts')

    monkeypatch.setattr(raw_boot_native_surface_cache, '_registry_snapshot_8616', forbidden)
    _, _, calls, request = _world()
    with cache.native_import_request_8616():
        assert request() == request()
    assert len(calls) == 1


def test_equivalent_boundaries_share_lifting_but_not_proof(monkeypatch):
    project, _, _, _ = _world(bytes(14) + bytes.fromhex('eb00c3'))
    first = exact_function_range_boundary_8616(project, 0x1000e, 0x10011)
    second = exact_function_range_boundary_8616(project, 0x1000e, 0x10011)
    assert first is not None and second is not None and first is not second
    conversions = []
    proofs = []
    native = vex_import._block_to_ir

    def convert(block, **kwargs):
        conversions.append(block.addr)
        return native(block, **kwargs)

    def preserve(current, function, address, artifact):
        proofs.append(function)
        return ()

    monkeypatch.setattr(vex_import, '_block_to_ir', convert)
    monkeypatch.setattr(vex_import, '_entry_domain_call_preservations_8616', preserve)
    with cache.native_import_request_8616():
        one = vex_import.build_x86_16_ir_function_artifact(project, first)
        two = vex_import.build_x86_16_ir_function_artifact(project, second)
    assert one.to_dict() == two.to_dict()
    assert len(proofs) == 2 and proofs[0] is first and proofs[1] is second
    assert conversions == sorted(first.block_addrs_set)


@pytest.mark.parametrize('change', ['edges', 'extent', 'metadata'])
def test_changed_boundary_values_cannot_reuse_native_facts(change):
    project, boundary, calls, _ = _world()
    replacement = replace(boundary)
    if change == 'edges':
        replacement = replace(boundary, successor_edges=((boundary.addr, boundary.addr),))
    elif change == 'extent':
        replacement = replace(boundary, size=boundary.size + 1)
    else:
        replacement = replace(boundary, info={'changed': True})

    def importer(current, function):
        calls.append(function)
        return {'capture': [len(calls)]}

    def admit(surface, function):
        return True

    with cache.native_import_request_8616():
        cache.request_native_surface_8616(project, boundary, importer, producers=(), admit=admit)
        result = cache.request_native_surface_8616(project, replacement, importer, producers=(), admit=admit)
    assert result == {'capture': [2]}


def test_unknown_capture_payload_disables_reuse():
    from inertia.ir.condition_ir import ConditionSource
    from inertia.ir.condition_lift_capture import ConditionLiftCaptureSession8616
    from inertia.ir.native_import_capture import native_capture_copyable_8616
    capture = ConditionLiftCaptureSession8616({}, {0: ConditionSource('cmp', lhs=object())})
    assert not native_capture_copyable_8616(capture)


def test_record_count_is_bounded_and_evicted_input_relifts(monkeypatch):
    _, _, calls, request = _world()
    with cache.native_import_request_8616():
        request()
        monkeypatch.setattr(cache, '_MAX_RECORDS', 1)
        _, _, other_calls, other_request = _world()
        other_request()
        assert request() == {'capture': [2]}
    assert len(calls) == 2 and len(other_calls) == 1


def test_transient_decode_failure_is_retried_before_retention(monkeypatch):
    from angr.factory import AngrObjectFactory
    project, boundary, _, _ = _world()
    original = AngrObjectFactory.block
    attempts = []

    def flaky(factory, addr, *args, **kwargs):
        attempts.append(addr)
        if len(attempts) == 1:
            raise ValueError('temporary decoder failure')
        return original(factory, addr, *args, **kwargs)

    monkeypatch.setattr(AngrObjectFactory, 'block', flaky)
    with cache.native_import_request_8616():
        first = vex_import._import_x86_16_function_surface_8616(project, boundary)
        assert not first.blocks
        second = vex_import._import_x86_16_function_surface_8616(project, boundary)
        assert second.blocks
        third = vex_import._import_x86_16_function_surface_8616(project, boundary)
        assert third.blocks
    assert len(attempts) == 2


def test_native_condition_containers_and_pending_records_are_isolated():
    project, boundary, _, _ = _world(bytes.fromhex('39d8750289d0c3'))
    with cache.native_import_request_8616():
        first = vex_import._import_x86_16_function_surface_8616(project, boundary)
        capture = first.condition_capture
        assert capture.condition_cache and capture.pending_sources
        source_address = next(iter(capture.pending_sources))
        original_kind = capture.pending_sources[source_address].kind
        original_terminal_keys = set(first.terminal_evidence)
        capture.pending_sources[source_address].kind = 'tampered'
        for rows in capture.condition_cache.values():
            rows.clear()
        first.terminal_evidence.clear()
        capture._successful_blocks.clear()
        second = vex_import._import_x86_16_function_surface_8616(project, boundary)
        assert second.condition_capture.pending_sources[source_address].kind == original_kind
        assert any(second.condition_capture.condition_cache.values())
        assert second.condition_capture._successful_blocks == boundary.block_addrs_set
        assert set(second.terminal_evidence) == original_terminal_keys


def test_native_cache_binds_flag_policy_without_hit_counters():
    from inertia.ir import status_flag_lift_context as flags
    from inertia.semantics.status_flag_contracts import StatusFlag8616

    project, boundary, calls, request = _world()
    session = flags.StatusFlagLiftSession8616(
        boundary.addr, (), source_project=project,
        owned_instruction_addresses=boundary.reachable_instruction_addrs,
    )
    with cache.native_import_request_8616():
        request()
        token = flags._active_session.set(session)
        try:
            request()
            assert len(calls) == 2
            session._materialized_addresses.add(boundary.addr)
            request()
            assert len(calls) == 2
            session.candidates = (flags.StatusFlagLiftCandidate8616(
                boundary.addr, StatusFlag8616.ZERO, StatusFlag8616.ZERO,
            ),)
            request()
            assert len(calls) == 3
            with flags.architectural_status_flag_replay_8616():
                request()
                # The suspended-session policy key is identical to the first
                # variant's; its retained record is reused, never relifted.
                assert len(calls) == 3
            request()
            assert len(calls) == 3
        finally:
            flags._active_session.reset(token)


def test_identical_new_flag_session_requires_fresh_consumer_lift():
    from inertia.ir import status_flag_lift_context as flags

    project, boundary, calls, request = _world()
    first = flags.StatusFlagLiftSession8616(
        boundary.addr, (), source_project=project,
        owned_instruction_addresses=boundary.reachable_instruction_addrs,
    )
    second = flags.StatusFlagLiftSession8616(
        boundary.addr, (), source_project=project,
        owned_instruction_addresses=boundary.reachable_instruction_addrs,
    )
    with cache.native_import_request_8616():
        token = flags._active_session.set(first)
        try:
            request()
            request()
            assert len(calls) == 1
        finally:
            flags._active_session.reset(token)
        token = flags._active_session.set(second)
        try:
            request()
            assert len(calls) == 2
        finally:
            flags._active_session.reset(token)
