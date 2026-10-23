"""Clinic-retained conditional entry reaches the fresh structuring codegen.

The Clinic consumption route already proved and retained the typed declared
entry input. The fresh codegen's ordinary ``prepare_declared_entry_pipeline_8616``
only reads its own retained slot, so without a source-bound handoff it re-proves
the identical native surface. These tests pin the handoff contract: identical
envelope transported, fresh factory never invoked, and every stale/foreign or
copied binding refused before any effect.
"""

from dataclasses import replace
from types import SimpleNamespace

import networkx as nx
import pytest
from angr.codenode import BlockNode

import inertia.ir.declared_entry_pipeline as declared_entry_pipeline
import inertia.ir.near_call_entry_pipeline as near_call_entry_pipeline
from inertia.frontend.x86_16.clinic_scoped_control import (
    handoff_clinic_declared_entry_8616,
    prepare_clinic_scoped_partition_8616,
)
from inertia.ir.declared_entry_pipeline import (
    DeclaredEntryPipeline8616,
    prepare_declared_entry_pipeline_8616,
    retain_declared_entry_pipeline_8616,
)
from inertia.ir.entry_domain_call_preservation import install_real16_invocation_source_8616
from inertia.ir.near_call_entry_pipeline import prepare_near_call_entry_pipeline_8616
from inertia.pipeline.errors import PipelineHardError
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub
from tests.ir.test_declared_entry_pipeline_attach import installed_leaf  # noqa: F401
from tests.ir.test_near_call_entry_pipeline import _installed

pytestmark = pytest.mark.decompiler


def _partitioned_clinic(project, entry):
    """Retain a real source-bound Clinic partition before handoff."""
    boundary = entry.view.boundary
    nodes = {b.addr: BlockNode(b.addr, b.size) for b in boundary.blocks}
    graph = nx.DiGraph()
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[a], nodes[b]) for a, b in boundary.successor_edges)
    clinic = _clinic_stub(project)
    clinic.function = SimpleNamespace(addr=boundary.addr, graph=graph)
    clinic._func_graph = graph
    prepare_clinic_scoped_partition_8616(clinic, entry)
    return clinic


def _consumed_clinic() -> tuple[object, object, object, object, object]:
    """Build one Clinic that consumed and retained a native conditional entry."""
    surface, source = _installed()
    entry = prepare_near_call_entry_pipeline_8616(surface.project, surface.boundary).entry
    assert entry is not None
    clinic = _partitioned_clinic(surface.project, entry)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=surface.boundary.addr))
    codegen._clinic = clinic
    return surface, source, entry, clinic, codegen


def test_fresh_codegen_without_handoff_reproves_native_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured regression: a bare ``_clinic`` attach loses the consumed entry."""
    surface, _source, entry, _clinic, codegen = _consumed_clinic()
    calls = []
    real = near_call_entry_pipeline.prepare_near_call_entry_pipeline_8616

    def counting(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(
        near_call_entry_pipeline, "prepare_near_call_entry_pipeline_8616", counting
    )
    consumed = prepare_declared_entry_pipeline_8616(
        surface.project, codegen, surface.boundary.addr
    )
    assert calls and consumed is not entry


def test_handoff_reuses_clinic_entry_without_fresh_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    """The identical retained envelope authenticates; no factory rerun occurs."""
    surface, _source, entry, clinic, codegen = _consumed_clinic()
    monkeypatch.setattr(
        near_call_entry_pipeline,
        "prepare_near_call_entry_pipeline_8616",
        lambda *args, **kwargs: pytest.fail("fresh near-call proof ran"),
    )
    handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert codegen._inertia_declared_entry_pipeline_8616 is entry
    consumed = prepare_declared_entry_pipeline_8616(
        surface.project, codegen, surface.boundary.addr
    )
    assert consumed is entry


def test_handoff_does_not_authenticate_until_consumption(monkeypatch):
    """Pointer transport adds no full replay; the canonical consumer owns it."""
    surface, _, entry, clinic, codegen = _consumed_clinic()
    native = type(entry)
    original = native.authenticates
    calls = []

    def counted(self, project):
        calls.append(self)
        return original(self, project)

    monkeypatch.setattr(native, "authenticates", counted)
    handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert calls == []
    assert prepare_declared_entry_pipeline_8616(surface.project, codegen, surface.boundary.addr) is entry
    assert calls == [entry]


@pytest.mark.parametrize("damage", ["function_head", "body_bytes", "incoming_bytes"])
def test_retained_handoff_is_revalidated_at_consumption(damage):
    """Retaining the exact input never licenses stale native bytes or another head."""
    surface, _, entry, clinic, codegen = _consumed_clinic()
    handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert codegen._inertia_declared_entry_pipeline_8616 is entry
    function_addr = surface.boundary.addr
    if damage == "function_head":
        function_addr += 0x10
    else:
        address = surface.boundary.addr if damage == "body_bytes" else surface.context.callsite_addr
        surface.project.loader.memory.store(address, b"\x90")
    with pytest.raises(PipelineHardError):
        prepare_declared_entry_pipeline_8616(surface.project, codegen, function_addr)


@pytest.mark.parametrize("damage", ["copied_entry", "function_identity", "source_graph"])
def test_handoff_requires_original_clinic_partition(damage):
    """A same-coordinate envelope cannot replace Clinic's retained provenance."""
    surface, _, entry, clinic, codegen = _consumed_clinic()
    if damage == "copied_entry":
        retain_declared_entry_pipeline_8616(clinic, replace(entry))
    elif damage == "function_identity":
        clinic.function = SimpleNamespace(addr=clinic.function.addr, graph=clinic.function.graph)
    else:
        clinic.function.graph.clear()
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")


def test_handoff_without_clinic_entry_preserves_ordinary_route() -> None:
    """A Clinic that consumed nothing leaves the ordinary unscoped path alone."""
    surface, _source = _installed()
    clinic = _clinic_stub(surface.project)
    clinic.function = SimpleNamespace(addr=surface.boundary.addr)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=surface.boundary.addr))
    handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")


def test_structuring_hands_off_before_validation_baseline(monkeypatch):
    """Exercise the real structuring entry hook without running angr's core."""
    from inertia.structuring import decompiler_structuring_stage as stage

    surface, _, entry, clinic, codegen = _consumed_clinic()
    driver = SimpleNamespace(project=surface.project, clinic=clinic, codegen=codegen)
    monkeypatch.setattr(stage, "_run_angr_core_decompile_8616", lambda _: 0.0)
    monkeypatch.setattr(stage, "install_materialized_return_chain_integrity_guard_8616", lambda _: None)
    monkeypatch.setattr(stage, "_bind_structuring_callsite_consumers_8616", lambda _: None)

    def baseline(*args):
        assert codegen._inertia_declared_entry_pipeline_8616 is entry
        assert codegen._clinic is clinic
        raise RuntimeError("baseline reached after handoff")

    monkeypatch.setattr(stage, "_structuring_validation_baseline_8616", baseline)
    with pytest.raises(RuntimeError, match="baseline reached after handoff"):
        stage._decompile_structuring_8616(driver)


def test_handoff_refuses_foreign_project() -> None:
    """An entry proved against a different project boundary refuses."""
    _surface, _source, _entry, clinic, codegen = _consumed_clinic()
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, SimpleNamespace())


def test_handoff_refuses_foreign_clinic_function() -> None:
    """A Clinic consuming a different function cannot donate its entry."""
    surface, _source, _entry, clinic, codegen = _consumed_clinic()
    clinic.function = SimpleNamespace(addr=surface.boundary.addr + 0x10)
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")


def test_handoff_refuses_foreign_destination_function() -> None:
    """The exact destination function must equal the retained source function."""
    surface, _source, _entry, clinic, codegen = _consumed_clinic()
    codegen.cfunc.addr = surface.boundary.addr + 0x10
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")


@pytest.mark.parametrize("stale", ["removed", "replaced"])
def test_handoff_refuses_stale_or_foreign_source(stale: str) -> None:
    """Uninstalled or replaced invocation authority is not transported."""
    surface, source, _entry, clinic, codegen = _consumed_clinic()
    install_real16_invocation_source_8616(
        surface.project, None if stale == "removed" else replace(source)
    )
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")


def test_handoff_refuses_copied_scope() -> None:
    """A copied native scope no longer authenticates against its view."""
    surface, _source, entry, clinic, codegen = _consumed_clinic()
    retain_declared_entry_pipeline_8616(
        clinic, replace(entry, scope=replace(entry.scope))
    )
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")


def test_handoff_refuses_conflicting_codegen_entry() -> None:
    """A fresh codegen already retaining a different object refuses overwrite."""
    surface, _source, entry, clinic, codegen = _consumed_clinic()
    retain_declared_entry_pipeline_8616(codegen, replace(entry))
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert codegen._inertia_declared_entry_pipeline_8616 is not entry


def test_declared_entry_handoff_reuses_clinic_consumption(
    installed_leaf: object, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """A proven declared leaf also transports without a fresh entry proof."""
    project, codegen, _installed_source = installed_leaf
    clinic = SimpleNamespace(project=project, function=SimpleNamespace(addr=0x1020))
    entry = prepare_declared_entry_pipeline_8616(project, clinic, 0x1020)
    assert type(entry) is DeclaredEntryPipeline8616
    clinic = _partitioned_clinic(project, entry)
    monkeypatch.setattr(
        declared_entry_pipeline,
        "_prepare_native_entry_8616",
        lambda *args, **kwargs: pytest.fail("fresh declared proof ran"),
    )
    handoff_clinic_declared_entry_8616(clinic, codegen, project)
    assert codegen._inertia_declared_entry_pipeline_8616 is entry
    assert prepare_declared_entry_pipeline_8616(project, codegen, 0x1020) is entry


def test_declared_handoff_refuses_copied_scope(installed_leaf: object) -> None:  # noqa: F811
    """A copied invocation scope breaks the retained view's scope identity."""
    project, codegen, _installed_source = installed_leaf
    clinic = SimpleNamespace(project=project, function=SimpleNamespace(addr=0x1020))
    entry = prepare_declared_entry_pipeline_8616(project, clinic, 0x1020)
    assert type(entry) is DeclaredEntryPipeline8616
    retain_declared_entry_pipeline_8616(
        clinic, replace(entry, scope=replace(entry.scope))
    )
    with pytest.raises(PipelineHardError):
        handoff_clinic_declared_entry_8616(clinic, codegen, project)
    assert not hasattr(codegen, "_inertia_declared_entry_pipeline_8616")
