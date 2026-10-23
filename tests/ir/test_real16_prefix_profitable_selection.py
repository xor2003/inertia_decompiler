"""Work advice declines losing extensions without granting proof authority."""

from time import monotonic
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import entry_domain_call_preservation as entry_owner
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_real16_prefix_capture_core import _extension_world, _install_high_capture_advice
from tests.ir.test_real16_prefix_extension_controls import _assert_derived_equal

pytestmark = pytest.mark.decompiler


def advice(saved, *, limit=10000, deadline=None):
    blocks = tuple(IRBlock(i, tuple(IRInstr("NOP", None, (), addr=i*100+j) for j in range(40)), successor_addrs=(i+1,) if i < 23 else ())
                   for i in range(1, 24))
    artifact = IRFunctionArtifact(1, blocks)
    boundary = ExactFunctionRangeBoundary8616(object(), 1, 100, frozenset(range(1, 24)), frozenset(),
                                            tuple((i, i+1) for i in range(1, 23)))
    ctx = SimpleNamespace(work_units=0, accounted_work_units=0, work_limit=limit,
                          deadline=monotonic()+10 if deadline is None else deadline)
    old = SimpleNamespace(edge_feasibility=SimpleNamespace(live_blocks=frozenset((1,))),
                          native_blocks={1: {1: blocks[0]}})
    data = SimpleNamespace(context=old, artifact=artifact, simulation_work=saved)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        accepted = owner._prefix_extension_profitable_8616(ctx, artifact, boundary, data)
        assert traversal.census_work_units == ctx.work_units
    return accepted, ctx.work_units


@pytest.mark.parametrize("saved,accepted,work", [
    (608, False, 11), (1278, False, 25), (1279, True, 25),
    (1539, True, 25), (10000, True, 25),
])
def test_structural_minimum_vs_saved_work(saved, accepted, work):
    # Mandatory structural scans cost 1237, retained native rows another 41.
    # Advice requires a strict saving. The 608 case stops after nine headers,
    # then visits the retained function/block pair; it must not scan all 23.
    assert advice(saved) == (accepted, work)


@pytest.mark.parametrize("limit,deadline,expected_work", [(0, None, 1), (10000, 0, 0)])
def test_estimate_resources_are_honest(limit, deadline, expected_work):
    accepted, work = advice(100000, limit=limit, deadline=deadline)
    # An expired deadline refuses before any header; an exhausted work limit
    # records the first attempted header and refuses without further visits.
    assert not accepted and work == expected_work


@pytest.mark.parametrize("high_advice,corrupt", [(False, False), (True, False), (True, True)])
def test_native_selection_advice_preserves_full_ordinary_census(monkeypatch, high_advice, corrupt):
    if high_advice:
        _install_high_capture_advice(monkeypatch)
    project, source, sites = _extension_world(monkeypatch)
    boundary = entry_owner._exact_boundary_for_8616(project, 0x1000)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        artifact = owner.real16_native_census_import_8616(project, boundary)
        records = entry_owner.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda instruction:
            resolve_direct_call_target_from_instruction_8616(project, instruction),
        )
    assert all(record.failure is None for record in records)
    captures = []
    subjects = []
    enroll = owner._enroll_prefix_census_data_8616

    def observe(subject, derived):
        enroll(subject, derived)
        captures.append(derived)
        subjects.append(subject.callsite_addr)
        if derived.prefix_census is not None and high_advice:
            # Test-only selection advice: every independent authority guard
            # remains live, as the corrupted-seed branch demonstrates.
            object.__setattr__(derived.prefix_census, "simulation_work", 100000)
            if corrupt:
                derived.prefix_census.seed.registers["ax"] = derived.prefix_census.seed.registers.get("ax", 0) ^ 1

    monkeypatch.setattr(owner, "_enroll_prefix_census_data_8616", observe)

    def sequence():
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
            for site in sites:
                premise = entry_owner._declared_function_premise_8616(
                    project, source, source.function_entries[0], artifact, boundary, site, records,
                )
                assert premise is not None and premise.complete
        return tuple(captures)

    actual = sequence()
    if high_advice:
        assert any(result.prefix_census is not None for result in actual)
    else:
        # A later, larger census may be worth retaining for a future invocation.
        losing = [result for site, result in zip(subjects, actual, strict=True) if site == sites[0]]
        assert losing and all(result.failure is None and result.prefix_census is None for result in losing)
    consumed = any(result.prefix_census is not None and result.prefix_census.context.prefix_consumed for result in actual)
    assert consumed is (high_advice and not corrupt)
    captures.clear()
    subjects.clear()
    with monkeypatch.context() as ordinary:
        ordinary.setattr(owner, "_select_prefix_extension_8616", lambda *args: None)
        expected = sequence()
    for result, baseline in zip(actual, expected, strict=True):
        _assert_derived_equal(result, baseline)


@pytest.mark.parametrize('saved,visited_headers', [(608, 6), (1539, 18)])
def test_losing_capture_charges_headers_without_projecting_producers(monkeypatch, saved, visited_headers):
    """Header advice declines optional data while preserving the completed ledger."""
    blocks = tuple(IRBlock(i, tuple(IRInstr('NOP', None, (), addr=i*100+j) for j in range(80)))
                   for i in range(23))
    artifact = IRFunctionArtifact(0, blocks)
    boundary = ExactFunctionRangeBoundary8616(object(), 0, 3000, frozenset(range(23)), frozenset(), ())
    ctx = SimpleNamespace(prefix_consumed=False, prefix_capture_requested=True, prefix_terminal_call=object(),
                          prefix_simulation_work=saved, work_units=0, accounted_work_units=0,
                          work_limit=10000, deadline=monotonic()+10,
                          raw_facts={(0, 0)}, normalized_facts={(0, 0)}, classified_facts={(0, 0)},
                          materialized_facts={(0, 0)}, failures=0)
    monkeypatch.setattr(owner, '_prefix_execution_producers_8616', lambda: pytest.fail('losing capture projected producers'))
    before = owner._census_counts_8616(ctx)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert owner._retain_prefix_census_8616(ctx, None, artifact, boundary, None) is None
        # The initial lower bound is 141; each header adds 80 rows. Stop at
        # the first rejecting bound without projecting or visiting the suffix.
        assert ctx.work_units == traversal.census_work_units == visited_headers
    assert owner._census_counts_8616(ctx) == before == (1, 1, 1, 1, 0)


def test_optional_capture_preflight_never_exceeds_completed_request_budget():
    """Capture advice must not charge even its first header when allowance is absent."""
    blocks = (IRBlock(1, (IRInstr('NOP', None, (), addr=1),)),)
    artifact = IRFunctionArtifact(1, blocks)
    boundary = ExactFunctionRangeBoundary8616(object(), 1, 2, frozenset((1,)), frozenset(), ())
    ctx = SimpleNamespace(prefix_consumed=False, prefix_capture_requested=True, prefix_terminal_call=object(),
                          prefix_simulation_work=100000, work_units=0, accounted_work_units=0,
                          work_limit=0, deadline=monotonic()+10)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert owner._retain_prefix_census_8616(ctx, None, artifact, boundary, None) is None
        assert ctx.work_units == traversal.census_work_units == 0
