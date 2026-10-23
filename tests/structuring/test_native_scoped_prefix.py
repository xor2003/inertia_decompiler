"""Retained native entry: defer the redundant preparation replay.

The Clinic handoff already retained the identical conditional native entry
on the fresh codegen. The prefix's VEX stage must not re-run
``NativeNearCallPipeline8616.authenticates`` — the canonical final
full-scope consume inside ``call_stack_effects`` owns that replay, and it
must still run after the mutating ``indexed_address_ir`` owner. Source
membership and retained-entry identity are re-checked around the consume;
stale bytes, changed membership, replaced retained entries and early
consumer returns all refuse.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

import inertia.ir.function_ir_registry as ir_registry
import inertia.ir.function_ssa_registry as ssa_registry
import inertia.ir.indexed_address_pipeline as indexed_ir
import inertia.semantics.call_stack_effect_pipeline as effects_pipeline
import inertia.semantics.scoped_call_projection as semantic
from inertia.frontend.x86_16.clinic_scoped_control import (
    handoff_clinic_declared_entry_8616,
)
from inertia.ir.declared_entry_pipeline import (
    prepare_declared_entry_pipeline_8616,
    retain_declared_entry_pipeline_8616,
)
from inertia.ir.entry_domain_call_preservation import (
    install_real16_invocation_source_8616,
)
from inertia.ir.near_call_entry_pipeline import prepare_near_call_entry_pipeline_8616
from inertia.ir.vex_import import apply_x86_16_vex_ir_artifact
from inertia.pipeline.errors import PipelineHardError
from inertia.structuring import decompiler_structuring_stage as stage
from inertia.structuring.decompiler_structuring_stage import (
    _prepare_structuring_stack_semantics_8616,
)
from tests.frontend.test_x86_16_clinic_entry_handoff import _consumed_clinic
from tests.ir.test_near_call_entry_pipeline import _installed

pytestmark = pytest.mark.decompiler


def _prepared_codegen() -> tuple[object, object, object, object]:
    """Build the fresh codegen holding the Clinic-retained native entry."""
    surface, source, entry, clinic, codegen = _consumed_clinic()
    handoff_clinic_declared_entry_8616(clinic, codegen, surface.project)
    assert codegen._inertia_declared_entry_pipeline_8616 is entry
    function = surface.project.kb.functions.function(
        addr=surface.boundary.addr, create=True
    )
    codegen._func = function
    return surface, source, entry, codegen


def _stub_downstream_alias_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub only the unrelated downstream alias owners, never native proof."""
    monkeypatch.setattr(
        stage._indexed_address_aliases,
        "apply_x86_16_indexed_address_aliases_8616",
        lambda project, codegen: True,
    )
    monkeypatch.setattr(
        stage._stack_memory_ssa,
        "apply_x86_16_stack_memory_ssa_alias_artifact",
        lambda project, codegen: True,
    )


def test_prefix_defers_preparation_replay_until_after_indexed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No pre-replay; the final consume still runs after the middle owner."""
    surface, _source, entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    entry_type = type(entry)
    real_auth = entry_type.authenticates
    real_indexed = indexed_ir.apply_x86_16_indexed_address_evidence_8616
    real_consume = semantic.consume_scoped_ir_boundary_projection_8616
    order: list[str] = []

    def counted_auth(self: object, project: object) -> object:
        order.append("authenticates")
        return real_auth(self, project)

    def counted_indexed(project: object, cg: object) -> object:
        order.append("indexed")
        return real_indexed(project, cg)

    def counted_consume(*args: object, **kwargs: object) -> object:
        order.append("consume")
        return real_consume(*args, **kwargs)

    monkeypatch.setattr(entry_type, "authenticates", counted_auth)
    monkeypatch.setattr(
        indexed_ir,
        "apply_x86_16_indexed_address_evidence_8616",
        counted_indexed,
    )
    monkeypatch.setattr(
        semantic, "consume_scoped_ir_boundary_projection_8616", counted_consume
    )
    _prepare_structuring_stack_semantics_8616(surface.project, codegen)
    assert order.count("authenticates") == 0
    # Construction and output validation retain their separate full consumes.
    assert order == ["indexed", "consume", "consume"]
    assert codegen._inertia_declared_entry_pipeline_8616 is entry
    assert codegen._inertia_raw_vex_ir_artifact_8616 is entry.bundle.artifact


def test_prefix_accepts_freshly_authenticated_retained_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real repeat restores checked outputs rather than requiring new identity."""
    surface, _source, entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    _prepare_structuring_stack_semantics_8616(surface.project, codegen)
    projection = codegen._inertia_call_semantic_projection_8616
    _prepare_structuring_stack_semantics_8616(surface.project, codegen)
    assert codegen._inertia_call_semantic_projection_8616 is projection
    assert projection.scoped_input.scope is entry.scope
    assert projection.matches_codegen(
        codegen._inertia_vex_ir_artifact, codegen._inertia_vex_ir_function_ssa,
    )


@pytest.mark.parametrize("damage", ["body_bytes", "ssa_attachment"])
def test_retained_projection_rechecks_after_authentication_callback(
    monkeypatch: pytest.MonkeyPatch, damage: str,
) -> None:
    """A successful retained proof cannot conceal subsequent callback drift."""
    surface, _source, entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    _prepare_structuring_stack_semantics_8616(surface.project, codegen)
    projection = codegen._inertia_call_semantic_projection_8616
    original = semantic.ScopedCallSemanticInput8616.authenticates_outputs

    def drifting(self: object, *args: object) -> bool:
        assert original(self, *args)
        if damage == "body_bytes":
            surface.project.loader.memory.store(surface.boundary.addr, b"\xcc")
        else:
            codegen._inertia_vex_ir_function_ssa = replace(projection.function_ssa)
        return True

    monkeypatch.setattr(semantic.ScopedCallSemanticInput8616, "authenticates_outputs", drifting)
    assert not stage._fresh_native_projection_bound_8616(
        surface.project, codegen, entry, projection, codegen._func,
    )


@pytest.mark.parametrize("damage", ["incoming_bytes", "body_bytes"])
def test_stale_native_bytes_refuse(
    monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    """Selector membership is not proof: stale bytes fail the consume."""
    surface, _source, _entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    if damage == "incoming_bytes":
        surface.project.loader.memory.store(surface.call.addr, b"\x90")
    else:
        surface.project.loader.memory.store(0x1008, b"\xcc")
    with pytest.raises(PipelineHardError):
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)


def test_removed_installed_source_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changed source/index membership refuses at the selector stage."""
    surface, _source, _entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    install_real16_invocation_source_8616(surface.project, None)
    with pytest.raises(PipelineHardError):
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)


def test_retained_entry_replaced_during_indexed_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained-entry replacement inside the middle callback refuses."""
    surface, _source, entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    real_indexed = indexed_ir.apply_x86_16_indexed_address_evidence_8616

    def swapping(project: object, cg: object) -> object:
        result = real_indexed(project, cg)
        cg._inertia_declared_entry_pipeline_8616 = replace(
            entry, scope=replace(entry.scope)
        )
        return result

    monkeypatch.setattr(
        indexed_ir,
        "apply_x86_16_indexed_address_evidence_8616",
        swapping,
    )
    with pytest.raises(PipelineHardError):
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)


@pytest.mark.parametrize("prior", [False, True])
def test_consumer_early_return_refuses(
    monkeypatch: pytest.MonkeyPatch, prior: bool,
) -> None:
    """No accepted prefix when the semantic consumer returns no new projection."""
    surface, _source, _entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    if prior:
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)
        assert isinstance(codegen._inertia_call_semantic_projection_8616, stage.CallSemanticProjection8616)
    monkeypatch.setattr(
        stage,
        "apply_x86_16_call_stack_effects_8616",
        lambda project, cg: False,
    )
    with pytest.raises(PipelineHardError):
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)


@pytest.mark.parametrize("route", ["prepare", "apply"])
def test_standalone_prepare_and_apply_keep_full_auth(
    monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """The public standalone routes keep the full authentication replay."""
    surface, _source, entry, codegen = _prepared_codegen()
    entry_type = type(entry)
    real_auth = entry_type.authenticates
    calls: list[object] = []

    def counted(self: object, project: object) -> object:
        calls.append(self)
        return real_auth(self, project)

    monkeypatch.setattr(entry_type, "authenticates", counted)
    if route == "prepare":
        consumed = prepare_declared_entry_pipeline_8616(
            surface.project, codegen, surface.boundary.addr
        )
        assert consumed is entry
    else:
        apply_x86_16_vex_ir_artifact(surface.project, codegen)
    assert len(calls) == 1


def test_no_universal_raw_or_ssa_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retained raw bundle never reaches the universal registries."""
    surface, _source, _entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    published: list[str] = []
    for module, name, label in (
        (ir_registry, "publish_function_ir_artifact_8616", "raw"),
        (ssa_registry, "publish_function_ssa_artifact_8616", "ssa"),
        (effects_pipeline, "publish_function_ir_artifact_8616", "raw"),
        (effects_pipeline, "publish_function_ssa_artifact_8616", "ssa"),
    ):
        real = getattr(module, name, None)
        if real is None:
            continue

        def counting(*args: object, __real: object = real, __label: str = label, **kwargs: object) -> object:
            published.append(__label)
            return __real(*args, **kwargs)

        monkeypatch.setattr(module, name, counting)
    _prepare_structuring_stack_semantics_8616(surface.project, codegen)
    assert published == []


@pytest.mark.parametrize("damage", ["source", "entry"])
def test_late_semantic_build_mutation_refuses(monkeypatch, damage):
    """A callback after input consumption cannot replace the installed authority."""
    surface, _source, entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    build = effects_pipeline.build_semantic_function_ssa_8616

    def altered_build(*args, **kwargs):
        result = build(*args, **kwargs)
        if damage == "source":
            install_real16_invocation_source_8616(surface.project, None)
        else:
            codegen._inertia_declared_entry_pipeline_8616 = replace(entry)
        return result

    monkeypatch.setattr(effects_pipeline, "build_semantic_function_ssa_8616", altered_build)
    with pytest.raises(PipelineHardError):
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)


def test_indexed_callback_cannot_replace_original_function(monkeypatch):
    """A same-head function from another KB is not the original consuming function."""
    from angr.knowledge_base import KnowledgeBase

    surface, _source, _entry, codegen = _prepared_codegen()
    _stub_downstream_alias_owners(monkeypatch)
    original = indexed_ir.apply_x86_16_indexed_address_evidence_8616
    other_kb = KnowledgeBase(surface.project)
    other = other_kb.functions.function(addr=surface.boundary.addr, create=True)
    assert other is not codegen._func

    def altered_indexed(project, cg):
        result = original(project, cg)
        cg._func = other
        return result

    monkeypatch.setattr(indexed_ir, "apply_x86_16_indexed_address_evidence_8616", altered_indexed)
    with pytest.raises(PipelineHardError):
        _prepare_structuring_stack_semantics_8616(surface.project, codegen)


@pytest.mark.parametrize("damage", ["none", "remove_source", "replace_source", "replace_entry"])
def test_semantic_consume_pins_source_and_entry(monkeypatch, damage):
    surface, source = _installed()
    entry = prepare_near_call_entry_pipeline_8616(surface.project, surface.boundary).entry
    assert entry is not None
    codegen = SimpleNamespace()
    retain_declared_entry_pipeline_8616(codegen, entry)
    consume = semantic.consume_scoped_ir_boundary_projection_8616
    observed = []

    def altered_consume(*args, **kwargs):
        result = consume(*args, **kwargs)
        observed.append(result.coverage.failure)
        if damage == "remove_source":
            install_real16_invocation_source_8616(surface.project, None)
        elif damage == "replace_source":
            install_real16_invocation_source_8616(surface.project, replace(source))
        elif damage == "replace_entry":
            retain_declared_entry_pipeline_8616(codegen, replace(entry))
        return result

    monkeypatch.setattr(semantic, "consume_scoped_ir_boundary_projection_8616", altered_consume)
    arguments = (surface.project, codegen, surface.boundary, entry.bundle.artifact)
    if damage == "none":
        result = semantic.scoped_call_semantic_input_8616(*arguments)
        assert result is not None
        assert result.source_ir is entry.bundle.artifact
    else:
        with pytest.raises(PipelineHardError):
            semantic.scoped_call_semantic_input_8616(*arguments)
    assert observed == [None]
