"""Only genuinely consumed native CALL identities constrain prefix pool reuse."""

from dataclasses import replace

import pytest

from inertia.ir import entry_domain_call_preservation as entry_owner
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_real16_prefix_capture_core import _extension_world
from tests.ir.test_real16_prefix_capture_core import high_capture_advice as high_capture_advice
from tests.ir.test_real16_prefix_extension_controls import _assert_derived_equal

pytestmark = pytest.mark.decompiler


def _changed_pool(records, change):
    if change == "unused_regenerated":
        return (records[0], replace(records[1]), records[2])
    if change == "reordered":
        return tuple(reversed(records))
    if change == "used_regenerated":
        return (replace(records[0]), *records[1:])
    if change == "used_missing":
        return records[1:]
    if change == "used_foreign":
        return (replace(records[0], block=replace(records[0].block)), *records[1:])
    return records


@pytest.mark.parametrize("change", (
    "unused_regenerated", "reordered", "used_regenerated", "used_missing", "used_foreign", "stale_source",
))
def test_native_prefix_binds_consumed_proof_identity_only(monkeypatch, change):
    """Fresh unused records/order are harmless; changed used authority refuses."""
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
    captured = []
    enroll = owner._enroll_prefix_census_data_8616

    def observe(subject, derived):
        # Test-only eligibility advice reaches proof-identity/source guards.
        if derived.prefix_census is not None and derived.prefix_census.context.callsite_addr == sites[1]:
            object.__setattr__(derived.prefix_census, "simulation_work", 100000)
        enroll(subject, derived)
        if derived.prefix_census is not None:
            captured.append(derived)

    monkeypatch.setattr(owner, "_enroll_prefix_census_data_8616", observe)

    def invoke(site, pool):
        return entry_owner._declared_function_premise_8616(
            project, source, source.function_entries[0], artifact, boundary, site, pool,
        )

    current = _changed_pool(records, change)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        for site in sites[:2]:
            premise = invoke(site, records)
            assert premise is not None and premise.complete
        retained = captured[-1].prefix_census
        assert retained is not None and retained.fact_ownership is not None
        assert retained.consumed_calls
        if change == "stale_source":
            project.loader.memory.store(0x1060, b"\x48")
        premise = invoke(sites[2], current)
        if change in ("used_missing", "used_foreign", "stale_source"):
            assert premise is None or not premise.complete
            assert not retained.context.prefix_consumed
            return
        assert premise is not None and premise.complete
        actual = captured[-1]
        assert retained.context.prefix_consumed is (change != "used_regenerated")
    captured.clear()
    with monkeypatch.context() as ordinary:
        ordinary.setattr(owner, "_select_prefix_extension_8616", lambda *args: None)
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
            for site in sites:
                premise = invoke(site, current)
                assert premise is not None and premise.complete
    _assert_derived_equal(actual, captured[-1])
