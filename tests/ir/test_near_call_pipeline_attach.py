"""Ordinary callbacks consume native conditional control without declarations."""

from types import SimpleNamespace

import pytest

from inertia.ir.declared_entry_pipeline import prepare_declared_entry_pipeline_8616
from inertia.ir.entry_domain_call_preservation import install_real16_invocation_source_8616
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616
from inertia.ir.segment_state import apply_x86_16_segment_state_artifact
from tests.ir.test_declared_entry_pipeline_attach import _run_full_prefix, _run_initial_callbacks
from tests.ir.test_near_call_entry_pipeline import _installed

pytestmark = pytest.mark.decompiler


def test_ordinary_prepare_discovers_native_entry_without_declaration() -> None:
    """A pending native jump can use its indexed incoming CALL premise."""
    surface, _ = _installed()
    entry = prepare_declared_entry_pipeline_8616(
        surface.project, SimpleNamespace(), surface.boundary.addr,
    )
    assert type(entry) is NativeNearCallPipeline8616
    assert entry.view.near_call_scope is entry.scope
    assert not entry.view.complete


@pytest.mark.parametrize("full_prefix", [False, True])
def test_ordinary_callbacks_retain_raw_conditional_source_without_publication(full_prefix: bool) -> None:
    """Initial IR/state callbacks share the exact privately scoped input."""
    surface, _ = _installed()
    project, address = surface.project, surface.boundary.addr
    project.kb.functions.function(addr=address, create=True)
    before = registered_function_ir_artifact_8616(project, address)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=address))
    (_run_full_prefix if full_prefix else _run_initial_callbacks)(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    assert type(entry) is NativeNearCallPipeline8616
    state = codegen._inertia_segment_state_artifact
    assert state.near_call_scope is entry.scope
    assert state.scoped_view is entry.view
    assert state.source_artifact is entry.bundle.artifact
    if full_prefix:
        projection = codegen._inertia_call_semantic_projection_8616
        assert projection.source_ir is entry.bundle.artifact
        assert projection.scoped_input.scope is entry.scope
        assert projection.matches_codegen(codegen._inertia_vex_ir_artifact, codegen._inertia_vex_ir_function_ssa)
        apply_x86_16_segment_state_artifact(project, codegen)
        assert codegen._inertia_segment_state_artifact.near_call_scope is entry.scope
    else:
        assert codegen._inertia_vex_ir_artifact is entry.bundle.artifact
    assert registered_function_ir_artifact_8616(project, address) == before


def test_pending_native_control_demands_deferred_inventory() -> None:
    """Ordinary MZ demand can install its native index without proving startup."""
    surface, source = _installed()
    project = surface.project
    install_real16_invocation_source_8616(project, None)
    project._inertia_caller_function_ranges_8616 = (
        (surface.boundary.addr, surface.boundary.addr + surface.boundary.size),
    )
    calls = []

    def install(target):
        calls.append(target)
        install_real16_invocation_source_8616(target, source)

    project._inertia_mz_static_invocation_request_8616 = SimpleNamespace(install=install)
    entry = prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), surface.boundary.addr)
    assert type(entry) is NativeNearCallPipeline8616
    assert calls == [project]
