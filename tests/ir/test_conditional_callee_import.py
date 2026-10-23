"""Premise-bound callees retain raw facts until independently scoped proof."""

import sys

import pytest

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import entry_domain_call_preservation as entry
from inertia.ir import vex_import
from inertia.ir.function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.real16_invocation_domain import real16_native_census_import_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_forward_declared_call_scope import _collect, _forward_world
from tests.ir.test_real16_prefix_capture_core import _extension_world

pytestmark = pytest.mark.decompiler


def test_conditional_callee_import_never_attempts_unscoped_discharge():
    """A native popped-return helper imports only under the census guard."""
    world = _forward_world(0x1234, guarded=True)
    project = world[0]
    guards = []
    code = vex_import.build_x86_16_ir_function_artifact.__code__

    def observe(current, offset):
        frame = sys._getframe(1)
        assert frame.f_code is current
        function = frame.f_locals["function"]
        if type(function) is ExactFunctionRangeBoundary8616:
            continuation = function.near_return_continuations
            if continuation is not None and continuation.premise is not None and continuation.proven_block_addrs:
                guards.append(vex_import._native_census_import_active_8616(frame.f_locals["project"]))

    sys.monitoring.use_tool_id(5, "conditional-import")
    sys.monitoring.register_callback(5, sys.monitoring.events.PY_START, observe)
    sys.monitoring.set_local_events(5, code, sys.monitoring.events.PY_START)
    try:
        records = _collect(world)
    finally:
        sys.monitoring.set_local_events(5, code, 0)
        sys.monitoring.register_callback(5, sys.monitoring.events.PY_START, None)
        sys.monitoring.free_tool_id(5)
    assert len(records) == 2 and all(record.failure is None for record in records)
    assert guards and all(guards), guards
    assert registered_function_ir_artifact_8616(project, 0x1050).verdict is FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE
    assert all(any(block.refusals for block in record.callee.coverage.artifact.blocks) for record in records)


def test_ordinary_near_return_callee_retains_universal_publication(monkeypatch):
    """A normal RET body keeps its ordinary complete artifact and registry route."""
    project, _source, _sites = _extension_world(monkeypatch)
    boundary = entry._exact_boundary_for_8616(project, 0x1000)
    with native_import_request_8616():
        artifact = real16_native_census_import_8616(project, boundary)
        assert artifact is not None
        records = entry.collect_entry_domain_call_preservations_8616(
            project, artifact, boundary, direct_target_resolver=lambda instruction:
            resolve_direct_call_target_from_instruction_8616(project, instruction),
        )
    assert len(records) == 3 and all(record.failure is None for record in records)
    registered = registered_function_ir_artifact_8616(project, 0x1060)
    assert registered.verdict is FunctionIRArtifactVerdict8616.PROVEN
    assert registered.artifact is not None and not registered.artifact.refusals
