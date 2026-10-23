"""Native indexed entry production; no whole-function validation claim."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.entry_domain_call_preservation import (
    Real16InvocationSource8616,
    install_real16_invocation_source_8616,
)
from inertia.ir.near_call_entry_pipeline import (
    NativeNearCallPipeline8616,
    NearCallEntryPipelineStatus8616,
    prepare_near_call_entry_pipeline_8616,
)
from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616
from inertia.pipeline.errors import PipelineHardError
from tests.ir.test_declared_entry_pipeline_attach import _run_full_prefix
from tests.ir.test_near_call_scoped_view import _native_pending_view_surface

pytestmark = pytest.mark.decompiler


def _installed():
    surface, _ = _native_pending_view_surface()
    # Boot is inventory provenance only: this producer grants no boot theorem.
    source = Real16InvocationSource8616(object(), None, surface.context.callsite_index)
    install_real16_invocation_source_8616(surface.project, source)
    return surface, source


@pytest.mark.parametrize("reuse_raw", [False, True])
def test_indexed_native_calls_build_conditional_private_entry(reuse_raw):
    surface, source = _installed()
    bundle = (raw_x86_16_import_bundle_for_artifact_8616(
        surface.project, surface.boundary, surface.artifact,
    ) if reuse_raw else None)
    result = prepare_near_call_entry_pipeline_8616(surface.project, surface.boundary, bundle=bundle)
    assert result.status is NearCallEntryPipelineStatus8616.CONDITIONAL, result.to_dict()
    assert result.entry is not None
    entry = result.entry
    assert entry.source is source
    if reuse_raw:
        assert entry.bundle.artifact is surface.artifact
    assert entry.bundle.artifact is entry.scope.artifact
    assert entry.view.source_artifact is entry.bundle.artifact
    assert entry.view.near_call_scope is entry.scope
    assert not entry.view.complete
    assert entry.view.complete_for(entry.scope)
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert entry.authenticates(surface.project)
    install_real16_invocation_source_8616(surface.project, None)
    assert not entry.authenticates(surface.project)


@pytest.mark.parametrize("corruption", ["missing", "ambiguous", "native_bytes"])
def test_indexed_entry_refuses_missing_ambiguous_or_stale_source(corruption):
    surface, source = _installed()
    if corruption == "missing":
        install_real16_invocation_source_8616(surface.project, None)
    elif corruption == "ambiguous":
        index = source.callsite_index
        rows = index.for_target(surface.boundary.addr)
        changed = replace(index, _entries_by_normalized_target={surface.boundary.addr: rows * 2})
        install_real16_invocation_source_8616(surface.project, replace(source, callsite_index=changed))
    else:
        surface.project.loader.memory.store(surface.context.callsite_addr + 1, b"\x00")
    result = prepare_near_call_entry_pipeline_8616(surface.project, surface.boundary)
    assert result.status is NearCallEntryPipelineStatus8616.REFUSED
    assert result.entry is None
    assert result.failure is not None
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def _semantics_attached_native():
    """Attach conditional call Semantics to a native entry through the prefix."""
    surface, source = _installed()
    project, address = surface.project, surface.boundary.addr
    project.kb.functions.function(addr=address, create=True)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=address))
    _run_full_prefix(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    assert type(entry) is NativeNearCallPipeline8616
    projection = codegen._inertia_call_semantic_projection_8616
    assert projection.scoped_input is not None
    assert projection.scoped_input.scope is entry.scope
    assert projection.scoped_input.view is entry.view
    return surface, source, codegen, entry, projection


def test_repeat_skips_constructor_but_authenticates_outputs_for_native(monkeypatch):
    """An unchanged native second pass reuses only after output authentication."""
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616

    surface, _source, codegen, _entry, _projection = _semantics_attached_native()
    counts = {"constructor": 0, "outputs": 0}
    construct = owner.scoped_call_semantic_input_8616
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs

    def counted_constructor(*args):
        counts["constructor"] += 1
        return construct(*args)

    def counted_outputs(*args):
        counts["outputs"] += 1
        return authenticate(*args)

    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", counted_constructor)
    monkeypatch.setattr(ScopedCallSemanticInput8616, "authenticates_outputs", counted_outputs)
    assert owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen) is False
    assert counts == {"constructor": 0, "outputs": 1}
    surface.project.loader.memory.store(surface.boundary.addr + 1, b"\x00")
    with pytest.raises(PipelineHardError):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)
    assert counts == {"constructor": 0, "outputs": 2}


@pytest.mark.parametrize(
    "mutation",
    ["revoked", "project", "function", "source", "view", "scope", "bundle", "universal"],
)
def test_native_changed_context_cannot_reuse_scoped_projection(monkeypatch, mutation):
    """Changed native context must rebuild rather than consume the old proof."""
    from inertia.semantics import call_stack_effect_pipeline as owner

    surface, _source, codegen, entry, projection = _semantics_attached_native()
    scoped = projection.scoped_input
    if mutation == "revoked":
        del codegen._inertia_declared_entry_pipeline_8616
    elif mutation == "project":
        projection = replace(projection, scoped_input=replace(scoped, project=object()))
    elif mutation == "function":
        projection = replace(projection, scoped_input=replace(scoped, function=object()))
    elif mutation == "source":
        projection = replace(
            projection, scoped_input=replace(scoped, source_ir=replace(scoped.source_ir)))
    elif mutation == "view":
        codegen._inertia_declared_entry_pipeline_8616 = replace(entry, view=replace(entry.view))
    elif mutation == "scope":
        codegen._inertia_declared_entry_pipeline_8616 = replace(entry, scope=replace(entry.scope))
    elif mutation == "bundle":
        codegen._inertia_declared_entry_pipeline_8616 = replace(
            entry, bundle=replace(entry.bundle, artifact=replace(entry.bundle.artifact)))
    else:
        projection = replace(projection, scoped_input=None)
    codegen._inertia_call_semantic_projection_8616 = projection

    def rebuilding(*args):
        raise LookupError("normal constructor reached")

    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", rebuilding)
    with pytest.raises(LookupError, match="normal constructor reached"):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)


@pytest.mark.parametrize("mutation", ["current_ir", "current_ssa"])
def test_native_mutated_codegen_slots_rebuild_instead_of_reuse(monkeypatch, mutation):
    """Changed attached codegen artifacts enter ordinary rebuilding, never reuse."""
    from inertia.semantics import call_stack_effect_pipeline as owner

    surface, _source, codegen, _entry, projection = _semantics_attached_native()
    if mutation == "current_ir":
        codegen._inertia_vex_ir_artifact = replace(projection.outputs.function)
    else:
        codegen._inertia_vex_ir_function_ssa = replace(projection.function_ssa)

    def rebuilding(*args):
        raise LookupError("normal constructor reached")

    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", rebuilding)
    with pytest.raises(LookupError, match="normal constructor reached"):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)


@pytest.mark.parametrize("mutation", ["forged_output", "forged_ssa"])
def test_native_forged_projection_refuses_reuse(mutation):
    """Content drift inside the retained projection fails output authentication."""
    from inertia.semantics import call_stack_effect_pipeline as owner

    surface, _source, codegen, _entry, projection = _semantics_attached_native()
    if mutation == "forged_output":
        changed = replace(projection.outputs.function, blocks=())
        codegen._inertia_vex_ir_artifact = changed
        codegen._inertia_call_semantic_projection_8616 = replace(
            projection, outputs=replace(projection.outputs, function=changed))
    else:
        changed = replace(
            projection.function_ssa, function_addr=projection.function_ssa.function_addr + 1)
        codegen._inertia_vex_ir_function_ssa = changed
        codegen._inertia_call_semantic_projection_8616 = replace(
            projection, function_ssa=changed)
    with pytest.raises(PipelineHardError):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)


@pytest.mark.parametrize(
    "slot",
    ["ir", "ssa", "projection", "stage", "source", "delete_ir", "delete_source"],
)
def test_native_attachment_change_after_real_authentication_refuses(monkeypatch, slot):
    """A post-proof attachment swap or deletion can never launder a reuse."""
    from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616

    surface, _source, codegen, _entry, projection = _semantics_attached_native()
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs

    def replace_after_real_proof(*args):
        assert authenticate(*args)
        if slot == "ir":
            codegen._inertia_vex_ir_artifact = replace(projection.outputs.function)
        elif slot == "ssa":
            codegen._inertia_vex_ir_function_ssa = replace(projection.function_ssa)
        elif slot == "projection":
            codegen._inertia_call_semantic_projection_8616 = replace(projection)
        elif slot == "stage":
            codegen._inertia_vex_ir_function_ssa_stage_8616 = FunctionSSAArtifactStage8616.IR
        elif slot == "source":
            codegen._inertia_raw_vex_ir_artifact_8616 = replace(projection.source_ir)
        elif slot == "delete_ir":
            del codegen._inertia_vex_ir_artifact
        else:
            del codegen._inertia_raw_vex_ir_artifact_8616
        return True

    monkeypatch.setattr(
        ScopedCallSemanticInput8616, "authenticates_outputs", replace_after_real_proof)
    with pytest.raises(PipelineHardError):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)


def _semantics_reattached_native():
    """Attach Semantics, then reattach the raw bundle like the public IR pass."""
    from inertia.ir.vex_import import apply_x86_16_vex_ir_artifact

    surface, source, codegen, entry, projection = _semantics_attached_native()
    apply_x86_16_vex_ir_artifact(surface.project, codegen)
    assert codegen._inertia_vex_ir_artifact is entry.bundle.artifact
    assert codegen._inertia_call_semantic_projection_8616 is projection
    return surface, source, codegen, entry, projection


def test_raw_reattach_restores_authenticated_semantics(monkeypatch):
    """IR -> Semantics restores the same projection after one fresh proof."""
    from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616

    surface, _source, codegen, _entry, projection = _semantics_reattached_native()
    counts = {"constructor": 0, "outputs": 0}
    construct = owner.scoped_call_semantic_input_8616
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs

    def counted_constructor(*args):
        counts["constructor"] += 1
        return construct(*args)

    def counted_outputs(*args):
        counts["outputs"] += 1
        return authenticate(*args)

    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", counted_constructor)
    monkeypatch.setattr(ScopedCallSemanticInput8616, "authenticates_outputs", counted_outputs)
    function = surface.project.kb.functions.function(
        addr=projection.source_ir.function_addr, create=False)
    assert owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen) is False
    assert counts == {"constructor": 0, "outputs": 1}
    assert codegen._inertia_vex_ir_artifact is projection.outputs.function
    assert codegen._inertia_vex_ir_function_ssa is projection.function_ssa
    assert codegen._inertia_call_stack_effect_artifact_8616 is projection.effects
    assert codegen._inertia_call_output_artifact_8616 is projection.outputs
    assert codegen._inertia_call_semantic_projection_8616 is projection
    assert (codegen._inertia_vex_ir_function_ssa_stage_8616
            is FunctionSSAArtifactStage8616.SEMANTIC)
    info = function.info
    assert info["x86_16_vex_ir_function_ssa_stage"] == (
        FunctionSSAArtifactStage8616.SEMANTIC.value)
    assert info["x86_16_vex_ir_artifact"] == projection.outputs.function.to_dict()


@pytest.mark.parametrize(
    "mutation",
    ["current_ir", "current_ssa", "raw_ssa", "raw_source", "source_function"],
)
def test_raw_reattach_changed_surface_rebuilds(monkeypatch, mutation):
    """A raw surface that is not the exact retained bundle takes the constructor."""
    from inertia.semantics import call_stack_effect_pipeline as owner

    surface, _source, codegen, _entry, projection = _semantics_reattached_native()
    if mutation == "current_ir":
        codegen._inertia_vex_ir_artifact = replace(codegen._inertia_vex_ir_artifact)
    elif mutation == "current_ssa":
        codegen._inertia_vex_ir_function_ssa = replace(codegen._inertia_vex_ir_function_ssa)
    elif mutation == "raw_ssa":
        codegen._inertia_raw_vex_ir_function_ssa_8616 = replace(
            codegen._inertia_raw_vex_ir_function_ssa_8616)
    elif mutation == "raw_source":
        codegen._inertia_raw_vex_ir_artifact_8616 = replace(projection.source_ir)
    else:
        codegen._inertia_vex_ir_source_function_8616 = object()

    def rebuilding(*args):
        raise LookupError("normal constructor reached")

    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", rebuilding)
    with pytest.raises(LookupError, match="normal constructor reached"):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)


@pytest.mark.parametrize("drift", ["native_bytes", "forged_outputs", "attachment_swap"])
def test_raw_reattach_proof_or_drift_refuses(monkeypatch, drift):
    """Mutated bytes, forged retained outputs or mid-proof swaps never restore."""
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616

    surface, _source, codegen, _entry, projection = _semantics_reattached_native()
    if drift == "native_bytes":
        surface.project.loader.memory.store(surface.boundary.addr + 1, b"\x00")
    elif drift == "forged_outputs":
        changed = replace(projection.outputs.function, blocks=())
        codegen._inertia_call_semantic_projection_8616 = replace(
            projection, outputs=replace(projection.outputs, function=changed))
        projection = codegen._inertia_call_semantic_projection_8616
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs

    def swap_after_real_proof(*args):
        assert authenticate(*args)
        codegen._inertia_vex_ir_artifact = replace(projection.outputs.function)
        return True

    if drift == "attachment_swap":
        monkeypatch.setattr(
            ScopedCallSemanticInput8616, "authenticates_outputs", swap_after_real_proof)
    with pytest.raises(PipelineHardError):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)


def test_native_attachment_seal_unchanged_reuses(monkeypatch):
    """The real proof runs once and an unchanged seal still skips the constructor."""
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616

    surface, _source, codegen, _entry, _projection = _semantics_attached_native()
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs
    calls = {"outputs": 0}

    def real(*args):
        calls["outputs"] += 1
        assert authenticate(*args)
        return True

    def rebuilding(*args):
        raise LookupError("normal constructor reached")

    monkeypatch.setattr(ScopedCallSemanticInput8616, "authenticates_outputs", real)
    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", rebuilding)
    assert owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen) is False
    assert calls["outputs"] == 1


@pytest.mark.parametrize(
    "swap", ["installed_source", "replaced_source", "retained_entry", "installed_bytes"],
)
def test_native_source_replacement_during_authentication_refuses(monkeypatch, swap):
    """Mid-authentication source or entry drift can never launder a reuse."""
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616

    surface, source, codegen, entry, _projection = _semantics_attached_native()
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs

    def drifting(*args):
        if swap == "installed_source":
            install_real16_invocation_source_8616(surface.project, None)
            return True
        if swap == "replaced_source":
            install_real16_invocation_source_8616(surface.project, replace(source))
            return True
        if swap == "retained_entry":
            codegen._inertia_declared_entry_pipeline_8616 = replace(entry)
            return True
        surface.project.loader.memory.store(surface.boundary.addr + 1, b"\x00")
        return authenticate(*args)

    monkeypatch.setattr(ScopedCallSemanticInput8616, "authenticates_outputs", drifting)
    with pytest.raises(PipelineHardError):
        owner.apply_x86_16_call_stack_effects_8616(surface.project, codegen)
