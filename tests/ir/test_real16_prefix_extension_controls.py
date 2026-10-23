"""Native prefix corruption must decline reuse and preserve ordinary census."""

from dataclasses import replace

import pytest

from inertia.ir import entry_domain_call_preservation as entry_owner
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_real16_prefix_capture_core import _extension_world
from tests.ir.test_real16_prefix_capture_core import high_capture_advice as high_capture_advice

pytestmark = pytest.mark.decompiler


def _corrupt_prefix(data, mutation, patch):
    """Alter only retained private data or an equivalent live producer."""
    if mutation == "facts":
        stages = (data.context.raw_facts, data.context.normalized_facts,
                  data.context.classified_facts, data.context.materialized_facts)
        row = min(stages[0])
        forged = (row[0], row[1] + 100000)
        before = owner._census_counts_8616(data.context)
        for stage in stages:
            stage.remove(row)
            stage.add(forged)
        assert owner._census_counts_8616(data.context) == before
    elif mutation == "seed":
        data.seed.registers["ax"] = data.seed.registers.get("ax", 0) ^ 1
    else:
        assert mutation == "producer"
        original = owner.DirectionTracker8616.step

        def equivalent_step(self, instruction, registers, tmps):
            return original(self, instruction, registers, tmps)

        patch.setattr(owner.DirectionTracker8616, "step", equivalent_step)


def _assert_derived_equal(actual, expected):
    assert actual.failure is expected.failure is None
    assert replace(expected.domain, callsite_artifact=actual.domain.callsite_artifact,
                   callsite_boundary=actual.domain.callsite_boundary) == actual.domain
    assert (actual.raw_fact_count, actual.normalized_fact_count, actual.classified_fact_count,
            actual.materialized_count, actual.failure_count, actual.entry_call_pool_consultation) == (
        expected.raw_fact_count, expected.normalized_fact_count, expected.classified_fact_count,
        expected.materialized_count, expected.failure_count, expected.entry_call_pool_consultation,
    )


@pytest.mark.parametrize("mutation", ("facts", "seed", "producer"))
def test_changed_native_prefix_falls_back_to_exact_ordinary_census(monkeypatch, mutation):
    """Same-cardinality facts, old seeds and changed producers cannot be reused."""
    project, source, sites = _extension_world(monkeypatch)
    boundary = entry_owner._exact_boundary_for_8616(project, 0x1000)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        artifact = owner.real16_native_census_import_8616(project, boundary)
        assert artifact is not None
        records = entry_owner.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda instruction:
            resolve_direct_call_target_from_instruction_8616(project, instruction),
        )
    assert len(records) == 3 and all(record.failure is None for record in records)
    results = []
    enroll = owner._enroll_prefix_census_data_8616

    def observe(subject, derived):
        # Test-only advice reaches independent authority/corruption guards.
        if derived.prefix_census is not None and derived.prefix_census.context.callsite_addr == sites[1]:
            object.__setattr__(derived.prefix_census, "simulation_work", 100000)
        enroll(subject, derived)
        if derived.prefix_census is not None:
            results.append(derived)

    monkeypatch.setattr(owner, "_enroll_prefix_census_data_8616", observe)

    def invoke(site):
        premise = entry_owner._declared_function_premise_8616(
            project, source, source.function_entries[0], artifact, boundary, site, records,
        )
        assert premise is not None and premise.complete

    with (monkeypatch.context() as changed, native_import_request_8616(),
          segment_call_dependency_traversal_scope_8616()):
        invoke(sites[0])
        invoke(sites[1])
        retained = results[-1].prefix_census
        assert retained is not None and retained.fact_ownership is not None
        assert retained.simulation_work > len(retained.context.raw_facts) + len(retained.producers)
        _corrupt_prefix(retained, mutation, changed)
        invoke(sites[2])
        actual = results[-1]
        assert not retained.context.prefix_consumed
    results.clear()
    with monkeypatch.context() as ordinary:
        ordinary.setattr(owner, "_select_prefix_extension_8616", lambda *args: None)
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
            for site in sites:
                invoke(site)
    _assert_derived_equal(actual, results[-1])
    state = dict(actual.domain.callsite_call_state)
    assert state["ax"] == 13 and state["sp"] == 0x7e


def test_native_extension_does_not_invoke_future_call_callback(monkeypatch):
    """Current stop excludes future CALLs while a later request actually resumes."""
    import sys

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
    enroll = owner._enroll_prefix_census_data_8616

    def observe(subject, derived):
        # Test-only advice reaches independent authority/corruption guards.
        if derived.prefix_census is not None and derived.prefix_census.context.callsite_addr == sites[1]:
            object.__setattr__(derived.prefix_census, "simulation_work", 100000)
        enroll(subject, derived)
        if derived.prefix_census is not None:
            captures.append(derived)

    monkeypatch.setattr(owner, "_enroll_prefix_census_data_8616", observe)
    calls = []

    def trace(frame, event, arg):
        if (event == "call" and frame.f_code is owner._cross_call_8616.__code__
            and frame.f_locals["artifact"] is artifact):
            calls.append(frame.f_locals["instruction"].addr)
        return None

    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        previous_trace = sys.gettrace()
        sys.settrace(trace)
        try:
            for site in sites[:2]:
                premise = entry_owner._declared_function_premise_8616(
                    project, source, source.function_entries[0], artifact, boundary, site, records,
                )
                assert premise is not None and premise.complete
            assert sites[2] not in calls
            prior = captures[-1].prefix_census
            assert prior is not None
            premise = entry_owner._declared_function_premise_8616(
                project, source, source.function_entries[0], artifact, boundary, sites[2], records,
            )
            assert premise is not None and premise.complete
            assert prior.context.prefix_consumed
        finally:
            sys.settrace(previous_trace)
