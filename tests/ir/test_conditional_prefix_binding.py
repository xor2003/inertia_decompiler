"""Conditional native helper evidence must survive only fresh scoped checks."""

from dataclasses import replace

import pytest

from inertia.ir import entry_domain_call_preservation as entry
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_real16_prefix_capture_core import _extension_world
from tests.ir.test_real16_prefix_capture_core import high_capture_advice as high_capture_advice
from tests.ir.test_real16_prefix_extension_controls import _assert_derived_equal

pytestmark = pytest.mark.decompiler


def _change_source(project, retained, change):
    """Mutate bytes or identity-only premise provenance after initial proof."""
    if change == "native":
        project.loader.memory.store(0x1061, b"\x48")
    elif change in ("premise", "late_premise"):
        if change == "late_premise":
            assert domain._prefix_after_callbacks_8616(retained.context, retained) is None
        continuation = retained.context.prefix_sources.bindings[0x1060].boundary.near_return_continuations
        assert continuation is not None and continuation.premise is not None
        frame = continuation.premise
        object.__setattr__(frame, "callsite", replace(frame.callsite))
        if change == "late_premise":
            assert domain._prefix_after_callbacks_8616(retained.context, retained) is (
                domain.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
            )
            assert not retained.context.prefix_consumed


@pytest.mark.parametrize("change", ["none", "native", "used_proof", "premise", "late_premise"])
def test_conditional_prefix_has_fresh_native_source_bindings(monkeypatch, change):
    """Real POP/JMP return semantics remain scoped while raw sources bind."""
    project, source, sites = _extension_world(
        monkeypatch, helper=bytes.fromhex("5940ffe1"), targets=(0x60, 0x70, 0x70),
    )
    boundary = entry._exact_boundary_for_8616(project, 0x1000)
    captures = []
    enroll = domain._enroll_prefix_census_data_8616

    def observe(subject, derived):
        if derived.prefix_census is not None and derived.prefix_census.context.callsite_addr == sites[1]:
            object.__setattr__(derived.prefix_census, "simulation_work", 100000)
        enroll(subject, derived)
        if derived.prefix_census is not None:
            captures.append(derived)

    monkeypatch.setattr(domain, "_enroll_prefix_census_data_8616", observe)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        artifact = domain.real16_native_census_import_8616(project, boundary)
        assert artifact is not None
        records = entry.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda instruction:
            resolve_direct_call_target_from_instruction_8616(project, instruction),
        )
        assert len(records) == 3 and all(record.failure is None for record in records), [
            record.failure for record in records
        ]
    captures.clear()
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        for site in sites[:2]:
            premise = entry._declared_function_premise_8616(
                project, source, source.function_entries[0], artifact, boundary, site, records,
            )
            assert premise is not None and premise.complete
        retained = captures[-1].prefix_census
        assert retained.consumed_calls
        assert retained.context.prefix_sources.complete
        assert 0x1060 in retained.context.prefix_sources.bindings
        current = records
        _change_source(project, retained, change)
        if change == "late_premise":
            return
        if change == "used_proof":
            current = (replace(records[0]), *records[1:])
        premise = entry._declared_function_premise_8616(
            project, source, source.function_entries[0], artifact, boundary, sites[2], current,
        )
        if change in ("native", "premise"):
            assert premise is None or not premise.complete
            assert not retained.context.prefix_consumed
            return
        assert premise is not None and premise.complete
        assert retained.context.prefix_consumed is (change == "none")
        actual = captures[-1]
    captures.clear()
    with monkeypatch.context() as ordinary:
        ordinary.setattr(domain, "_select_prefix_extension_8616", lambda *args: None)
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
            for site in sites:
                premise = entry._declared_function_premise_8616(
                    project, source, source.function_entries[0], artifact, boundary, site, current,
                )
                assert premise is not None and premise.complete
    _assert_derived_equal(actual, captures[-1])
