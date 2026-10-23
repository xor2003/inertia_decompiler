"""Universal callee work is shared within one native preparation only."""
import sys

import pytest

from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import declared_selector_invariant as owner
from inertia.ir.core import IRInstr
from inertia.ir.segment_state import build_segment_state_with_native_survey_8616
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.real16_invocation_domain import real16_native_census_import_8616
from tests.ir.test_declared_function_entry_domain import _world

pytestmark = pytest.mark.decompiler


def test_repeated_universal_callee_builds_one_summary_and_retains_native_seal(monkeypatch):
    project, _boot, _link = _world()
    boundary = exact_function_range_boundary_8616(project, 0x1070, 0x1071)
    artifact = real16_native_census_import_8616(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert coverage.complete
    monkeypatch.setattr(owner, '_caller_premise_surface_8616', lambda *_: (artifact, boundary, coverage))
    visits = []
    code = build_segment_state_with_native_survey_8616.__code__
    sys.monitoring.use_tool_id(3, 'universal-callee-count')
    sys.monitoring.register_callback(3, sys.monitoring.events.PY_START, lambda *_: visits.append(True))
    sys.monitoring.set_local_events(3, code, sys.monitoring.events.PY_START)
    try:
        budget = owner._Budget(float('inf'), 20000)
        obligations, consumed, summaries, snapshots = [], {}, {}, {}
        results = []
        for callsite in (0x1023, 0x1026):
            encoded = b'\xe8' + (0x1070 - callsite - 3).to_bytes(2, 'little', signed=True)
            results.append(owner._resolve_callsite(
                project, 0x1020, IRInstr('CALL', None, (), addr=callsite), encoded,
                budget, obligations, consumed, universal=summaries, snapshots=snapshots))
        assert not obligations
        assert results[0] == results[1]
        assert len(visits) == 1
        assert consumed == {(id(boundary), id(artifact)): (boundary, artifact)}
        assert (id(boundary), id(artifact)) in snapshots
        # A reused summary must not bypass the final native-byte check.
        project.loader.memory.store(0x1070, b'\x90')
        owner._rebind_consumed_surfaces(project, consumed, 0x1020, budget, obligations, snapshots)
        assert any(row.kind is owner.ObligationKind.CONSUMED_SURFACE_STALE for row in obligations)
    finally:
        sys.monitoring.set_local_events(3, code, 0)
        sys.monitoring.free_tool_id(3)
