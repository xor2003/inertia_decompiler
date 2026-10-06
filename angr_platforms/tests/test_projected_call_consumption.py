"""Native regression for consuming declarations after semantic projection."""

import io
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.declared_external_call_evidence import admit_declared_external_call_files_8616
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir.core import IRInstr
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactStage8616,
    publish_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.segment_contract import apply_x86_16_segment_function_contract
from angr_platforms.X86_16.ir.segment_state import (
    apply_x86_16_segment_state_artifact,
    republish_declared_call_consumptions_8616,
)
from angr_platforms.X86_16.ir.segment_state_transfer import declared_call_effect_at_instruction_8616
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.segment_function_summary import apply_x86_16_segment_function_summary
from angr_platforms.X86_16.semantics.call_outputs import materialize_call_outputs_8616
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    CallSemanticProjection8616,
    _publish_semantic_artifacts_8616,
    build_semantic_function_ssa_8616,
)
from angr_platforms.X86_16.semantics.call_stack_effects import materialize_call_stack_effects_8616
from angr_platforms.X86_16.semantics.call_target_evidence_8616 import publish_call_semantic_projection_8616
from angr_platforms.X86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616
from x86_16_declared_call_fixture import NativeConsumption, world

from inertia_decompiler.segment_program_layout_reporting import segment_program_function_evidence_for_project_8616


def loadprogram_world() -> NativeConsumption:
    """Lift the exact retained LoadProgram CALL block with its bound declaration."""
    folder = Path(__file__).parent / "fixtures" / "declared_calls"
    image = (folder / "loadprogram-image.bin").read_bytes()
    project = angr.Project(io.BytesIO(image), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False, simos="DOS")
    record_synthetic_call_stubs_8616(project, frozenset({0x103D}))
    registry = admit_declared_external_call_files_8616(
        project, image_code=image, image_base=0x1000,
        paths=(folder / "loadprogram-declarations.json",),
    )
    assert registry is not None and registry.closes_evidence
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x103D)
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    block = next(item for item in artifact.blocks if any(instruction.op == "CALL" for instruction in item.instrs))
    call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact
    return project, block, call, artifact, registry.admissions[0], image


@pytest.fixture(params=[False, True])
def native_world(request: pytest.FixtureRequest, tmp_path: Path) -> NativeConsumption:
    """Exercise the minimal witness and the retained application bytes."""
    return loadprogram_world() if request.param else world(tmp_path)


def test_loadprogram_semantic_pipeline_publishes_consumption() -> None:
    """Real summary construction and segment-state application retain the receipt."""
    project, _block, _call, raw, admission, _image = loadprogram_world()
    boundary = exact_function_range_boundary_8616(project, admission.caller_addr, admission.caller_end)
    assert boundary is not None
    effects, outputs, ssa = build_semantic_function_ssa_8616(project, boundary, ir_artifact=raw)
    assert publish_function_ssa_artifact_8616(
        project, ssa, stage=FunctionSSAArtifactStage8616.SEMANTIC
    ).artifact is ssa
    codegen = SimpleNamespace()
    _publish_semantic_artifacts_8616(project, codegen, raw, effects, outputs, ssa)
    apply_x86_16_segment_state_artifact(project, codegen)
    receipts = codegen._inertia_segment_state_artifact.declared_call_consumptions
    assert len(receipts) == 1
    assert receipts[0].callsite_addr == admission.callsite_addr

    project._inertia_active_structuring_function_8616 = boundary
    apply_x86_16_segment_function_contract(project, codegen)
    apply_x86_16_segment_function_summary(project, codegen)
    evidence = segment_program_function_evidence_for_project_8616(project, admission.caller_addr)
    assert evidence is not None and evidence.declared_call_consumptions == receipts
    # Re-publication cannot grant a receipt that this state never consumed.
    state = codegen._inertia_segment_state_artifact
    codegen._inertia_segment_state_artifact = replace(state, declared_call_consumptions=())
    republish_declared_call_consumptions_8616(project, codegen, admission.caller_addr)
    assert codegen._inertia_segment_function_summary_8616.declared_call_consumptions == ()
    codegen._inertia_segment_state_artifact = state
    republish_declared_call_consumptions_8616(project, codegen, admission.caller_addr)
    assert codegen._inertia_segment_function_summary_8616.declared_call_consumptions == receipts
    # A foreign function cannot rewrite this function's retained receipt.
    republish_declared_call_consumptions_8616(project, codegen, admission.caller_addr + 1)
    assert codegen._inertia_segment_function_summary_8616.declared_call_consumptions == receipts
    project._inertia_declared_external_call_registry_8616 = None
    republish_declared_call_consumptions_8616(project, codegen, admission.caller_addr)
    assert codegen._inertia_segment_function_summary_8616.declared_call_consumptions == ()
    evidence = segment_program_function_evidence_for_project_8616(project, admission.caller_addr)
    assert evidence is not None and evidence.declared_call_consumptions == ()


@pytest.mark.parametrize("mutation", [
    "raw_registry", "ssa_registry", "missing_projection", "call_args",
    "output_suffix", "output_edge", "image", "extra_prefix", "call_origin",
])
def test_native_projected_declaration_consumption(native_world: NativeConsumption, mutation: str) -> None:
    """Authentic projection consumes; each corrupted source or overlay refuses."""
    project, _block, _call, raw, admission, _image = native_world
    effects = materialize_call_stack_effects_8616(raw, {}, project=project)
    outputs = materialize_call_outputs_8616(effects.function, {})
    ssa = build_x86_16_function_ssa(outputs.function)
    registered = publish_function_ssa_artifact_8616(
        project, ssa, stage=FunctionSSAArtifactStage8616.SEMANTIC
    )
    assert registered.artifact is ssa
    projection = CallSemanticProjection8616(raw, effects, outputs, ssa)
    assert publish_call_semantic_projection_8616(project, projection).complete
    projected = outputs.function
    assert projected is not raw
    block = projected.blocks[0]
    call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
    assert declared_call_effect_at_instruction_8616(projected, block, call, (admission,)) is admission
    if mutation == "raw_registry":
        vars(project)["_inertia_function_ir_artifacts_8616"].pop(raw.function_addr)
    elif mutation == "ssa_registry":
        vars(project)["_inertia_function_ssa_artifacts_8616"].pop(raw.function_addr)
    elif mutation == "missing_projection":
        vars(project)["_inertia_call_target_projections_8616"].pop(raw.function_addr)
    elif mutation == "call_args":
        # Equal IRValue comparison must not conceal a different temporary source.
        object.__setattr__(call, "args", (replace(call.args[0], source_tmp=999999),))
    elif mutation == "output_suffix":
        object.__setattr__(block, "instrs", (replace(block.instrs[0]), *block.instrs[1:]))
    elif mutation == "output_edge":
        object.__setattr__(block, "successor_addrs", (0xBAD,))
    elif mutation == "image":
        project.loader.memory.store(raw.function_addr, b"\x90")
    elif mutation == "extra_prefix":
        object.__setattr__(block, "instrs", (IRInstr("NOP", None, ()), *block.instrs))
    elif mutation == "call_origin":
        object.__setattr__(call, "origin", None)
    assert declared_call_effect_at_instruction_8616(projected, block, call, (admission,)) is None
