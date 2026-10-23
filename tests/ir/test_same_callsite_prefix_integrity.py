"""Retained-data corruption cannot authenticate a repeated invocation prefix."""

import pytest

from inertia.ir import entry_domain_call_preservation as entry_owner
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_real16_prefix_capture_core import _extension_world
from tests.ir.test_real16_prefix_capture_core import high_capture_advice as high_capture_advice

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('mutation', ['register', 'memory', 'counts', 'source'])
def test_forced_same_cut_replay_rejects_corrupted_retained_data(monkeypatch, mutation):
    project, source, sites = _extension_world(monkeypatch)
    boundary = entry_owner._exact_boundary_for_8616(project, 0x1000)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        artifact = owner.real16_native_census_import_8616(project, boundary)
        records = entry_owner.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda row:
            resolve_direct_call_target_from_instruction_8616(project, row),
        )
    assert records and all(record.failure is None for record in records)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        premise = entry_owner._declared_function_premise_8616(
            project, source, source.function_entries[0], artifact, boundary, sites[1], records,
        )
        assert premise is not None and premise.complete
        data = traversal.invocation_prefixes[id(premise)]
        # Advice opens the optimization gate, never its authority checks.
        object.__setattr__(data, 'simulation_work', 100000)
        if mutation == 'register':
            data.context.callsite_call_state['ax'] ^= 1
        elif mutation == 'memory':
            data.context.callsite_memory.apply_write(0x1290, 1, b'X')
        elif mutation == 'counts':
            data.context.checked_stores += 1
        else:
            project.loader.memory.store(0x1001, b'\x02')
        accepted = premise._consume_completion_8616(premise._replay_complete_8616, force_current=True)
        assert accepted is (mutation != 'source')
        assert not data.context.prefix_consumed
