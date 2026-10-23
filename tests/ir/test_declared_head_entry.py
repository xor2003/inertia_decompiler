"""Declared HEAD admission requests bounded selector authority for body calls."""
import sys

import pytest

from inertia.ir import declared_entry_pipeline as owner
from inertia.ir.declared_selector_invariant import InvariantStatus
from inertia.ir.entry_domain_call_preservation import _invocation_premise_source_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.ir.test_declared_function_entry_intake import _install
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper

pytestmark = pytest.mark.decompiler


def _prepare(project, source, admission):
    counts = []
    def observe(code, offset):
        counts.append(1)
    sys.monitoring.use_tool_id(5, 'head-entry')
    sys.monitoring.register_callback(5, sys.monitoring.events.PY_START, observe)
    sys.monitoring.set_local_events(5, owner.prove_declared_selector_invariant_8616.__code__, sys.monitoring.events.PY_START)
    try:
        with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as ledger:
            result = owner._prepare_native_entry_8616(project, source, admission)
            work = ledger.census_work_units
    finally:
        sys.monitoring.free_tool_id(5)
    return result, counts, work


def test_native_call_body_head_runs_one_bounded_selector_survey(calls_with_pending_helper, record_property):
    """A CALL-bearing head gets one conditional survey, not unrelated proofs."""
    project, _boot, artifact, _boundary, _resolver, admission = calls_with_pending_helper
    source = _invocation_premise_source_8616(project)
    result, counts, work = _prepare(project, source, admission)
    record_property('work', work)
    record_property('selector_surveys', len(counts))
    assert isinstance(result, owner.DeclaredEntryPipeline8616)
    assert result.view.failure is None
    call_sites = sum(1 for block in artifact.blocks for row in block.instrs if row.op == 'CALL')
    assert call_sites > 0
    # One bounded survey for the whole body: conditional scope, one record per callsite.
    assert counts == [1]
    assert result.selector_scope is not None
    assert result.selector_scope.status is InvariantStatus.PROVEN_CONDITIONAL
    assert len(result.scope.entry_call_preservations) == call_sites
    assert result.scope.callsite_addr == admission.spec.range_start


def test_pending_selector_transform_keeps_body_survey(native_scope):
    project, link, scope, _proof = native_scope
    source = _install(project, scope.boot, link)
    result, counts, _work = _prepare(project, source, link.admission)
    assert counts and result.selector_scope is not None
    assert isinstance(result, owner.DeclaredEntryPipeline8616)
    assert result.view.failure is None
