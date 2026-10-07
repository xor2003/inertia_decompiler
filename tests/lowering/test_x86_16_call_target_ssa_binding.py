"""Binary controls for the shared input/output CALL-target evidence gate."""

from __future__ import annotations

import io
from dataclasses import dataclass, replace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsitePushSourceKind8616, CallsiteSummary8616
from inertia.ir import IRFunctionArtifact, IRValue, MemSpace
from inertia.ir.core import IRActiveUnary8616
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactStage8616,
    publish_function_ssa_artifact_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.lowering.call_target_projection_integrity import (
    CallProducerIntegrityFailure8616,
    call_operand_producer_integrity_8616,
    ssa_value_modulo_version_8616,
)
from inertia.lowering.call_target_ssa_binder import (
    CallTargetBindStage8616,
    bind_ssa_call_target_8616,
)
from inertia.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
)
from inertia.lowering.interprocedural_storage_reaching_defs import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionVerdict8616,
    resolve_call_argument_reaching_definition_8616,
)
from inertia.lowering.interprocedural_storage_return_defs import (
    resolve_storage_call_output_definitions_8616,
)

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_boundary_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from inertia.semantics.call_stack_effect_pipeline import (
    CallSemanticProjection8616,
    build_semantic_function_ssa_8616,
)


@dataclass(frozen=True)
class _Evidence:
    project: angr.Project
    raw: IRFunctionArtifact
    ssa: SSAFunctionArtifact
    index: DecodedDirectCallsiteIndex8616
    projection: CallSemanticProjection8616 | None


def _evidence(semantic: bool, code: bytes | None = None) -> _Evidence:
    """Retain both native callees and the prefix-shifted second CALL."""
    if code is None:
        code = bytes.fromhex("e80d00 89c3 e80a00 c3")
    image = code + bytes(0x10 - len(code)) + bytes.fromhex("c3 90 c3")
    project = angr.Project(
        io.BytesIO(image),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
        simos="DOS",
    )
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    assert not raw.refusals
    publish_function_ir_artifact_8616(project, raw)
    if semantic:
        effects, outputs, ssa = build_semantic_function_ssa_8616(project, boundary, ir_artifact=raw)
        projection = CallSemanticProjection8616(raw, effects, outputs, ssa)
        stage = FunctionSSAArtifactStage8616.SEMANTIC
    else:
        ssa = build_x86_16_function_ssa(raw)
        projection = None
        stage = FunctionSSAArtifactStage8616.IR
    publish_function_ssa_artifact_8616(project, ssa, stage)
    index = build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    return _Evidence(project, raw, ssa, index, projection)


@pytest.mark.parametrize("semantic", [False, True])
@pytest.mark.parametrize(("callsite", "target"), [(0x1000, 0x1010), (0x1005, 0x1012)])
def test_shared_target_and_output_gate_accept_native_evidence(semantic: bool, callsite: int, target: int) -> None:
    evidence = _evidence(semantic)
    binding = bind_ssa_call_target_8616(
        evidence.ssa, 0x1000, callsite, (target,),
        project=evidence.project, callsite_index=evidence.index, projection=evidence.projection,
    )
    assert binding.complete and binding.target_addr == target
    result = resolve_storage_call_output_definitions_8616(
        evidence.ssa, 0x1000, callsite, target, (target,),
        (StorageIdentity8616(kind=StorageIdentityKind8616.REGISTER, width=2, register="ax"),),
        project=evidence.project, callsite_index=evidence.index, projection=evidence.projection,
    )
    assert result.complete and len(result.definitions) == 1
    assert result.definitions[0].instr_addr == callsite
    assert result.definitions[0].value.name == "ax"


@pytest.mark.parametrize("semantic", [False, True])
def test_rebound_target_version_corruption_refuses(semantic: bool) -> None:
    evidence = _evidence(semantic)
    blocks = []
    for block in evidence.ssa.blocks:
        instructions = []
        for instruction in block.instrs:
            if instruction.op == "CALL" and instruction.addr == 0x1005:
                target = instruction.args[0]
                assert isinstance(target, IRValue)
                instruction = replace(instruction, args=(replace(target, version=7),))
            instructions.append(instruction)
        blocks.append(replace(block, instrs=tuple(instructions)))
    mutant = replace(evidence.ssa, blocks=tuple(blocks))
    # Deliberately corrupt the dynamic third-party registry and retained
    # projection together: registry identity alone must not prove integrity.
    vars(evidence.project)["_inertia_function_ssa_artifacts_8616"][0x1000] = mutant
    projection = None if evidence.projection is None else replace(evidence.projection, function_ssa=mutant)
    binding = bind_ssa_call_target_8616(
        mutant, 0x1000, 0x1005, (0x1012,),
        project=evidence.project, callsite_index=evidence.index, projection=projection,
    )
    assert not binding.complete
    assert binding.stage is CallTargetBindStage8616.PRODUCER_MISMATCH


def test_rebuilt_ssa_does_not_authenticate_forged_output_prefix() -> None:
    evidence = _evidence(True)
    assert evidence.projection is not None
    blocks = []
    changed = 0
    for block in evidence.projection.outputs.function.blocks:
        instructions = []
        for instruction in block.instrs:
            if instruction.op == "CALL_OUTPUT":
                instruction = replace(instruction, addr=0xDEAD)
                changed += 1
            instructions.append(instruction)
        blocks.append(replace(block, instrs=tuple(instructions)))
    assert changed == 1
    enriched = replace(evidence.projection.outputs.function, blocks=tuple(blocks))
    mutant = build_x86_16_function_ssa(enriched)
    projection = replace(
        evidence.projection,
        outputs=replace(evidence.projection.outputs, function=enriched),
        function_ssa=mutant,
    )
    vars(evidence.project)["_inertia_function_ssa_artifacts_8616"][0x1000] = mutant
    binding = bind_ssa_call_target_8616(
        mutant, 0x1000, 0x1005, (0x1012,),
        project=evidence.project, callsite_index=evidence.index, projection=projection,
    )
    assert not binding.complete
    assert binding.stage is CallTargetBindStage8616.OUTPUTS_PREFIX_MISMATCH


@pytest.mark.parametrize("semantic", [False, True])
def test_admitted_image_relative_target_keeps_native_proof(semantic: bool) -> None:
    evidence = _evidence(semantic)
    binding = bind_ssa_call_target_8616(
        evidence.ssa, 0x1000, 0x1000, (0x10,),
        project=evidence.project, callsite_index=evidence.index, projection=evidence.projection,
    )
    assert binding.complete
    assert binding.target_addr == 0x1010


@pytest.mark.parametrize("target", [0x11010, 0x12, 0xDEAD])
def test_target_lookup_expansion_does_not_admit_other_targets(target: int) -> None:
    evidence = _evidence(True)
    binding = bind_ssa_call_target_8616(
        evidence.ssa, 0x1000, 0x1000, (target,),
        project=evidence.project, callsite_index=evidence.index, projection=evidence.projection,
    )
    assert not binding.complete
    assert binding.target_addr is None


@pytest.mark.parametrize("semantic", [False, True])
@pytest.mark.parametrize("admitted_target", [0x1010, 0x10])
def test_shared_input_gate_preserves_the_pushed_argument(semantic: bool, admitted_target: int) -> None:
    evidence = _evidence(semantic, bytes.fromhex("6a05 e80b00 c3"))
    summary = CallsiteSummary8616(
        callsite_addr=0x1002, target_addr=0x1010, return_addr=0x1005,
        kind="near", arg_count=1, arg_widths=(2,), stack_cleanup=None,
        return_register=None, return_used=False,
        push_arg_sources=((CallsitePushSourceKind8616.IMMEDIATE.value, 5),),
        push_arg_instruction_addrs=(0x1000,),
    )
    result = resolve_call_argument_reaching_definition_8616(
        evidence.ssa, summary, 0, project=evidence.project,
        expected_target_addr=admitted_target,
        callsite_index=evidence.index, projection=evidence.projection,
    )
    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.stats.complete
    assert result.use is not None and result.use.callsite_addr == 0x1002
    assert len(result.definitions) == 2
    assert all(definition.is_complete and definition.instr_addr == 0x1000 for definition in result.definitions)
    assert result.definitions[0].value.const == 5
    refused = resolve_call_argument_reaching_definition_8616(
        evidence.ssa, summary, 0, project=evidence.project,
        expected_target_addr=0x1012,
        callsite_index=evidence.index, projection=evidence.projection,
    )
    assert refused.verdict is CallArgumentDefinitionVerdict8616.CONFLICT
    assert refused.failure is CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT
    assert not refused.definitions and not refused.stats.complete


@pytest.mark.parametrize("index", [-1, 0, False, 999])
def test_public_producer_integrity_rejects_invalid_call_index(index: int) -> None:
    evidence = _evidence(False)
    failure = call_operand_producer_integrity_8616(evidence.ssa.blocks[0], evidence.raw.blocks[0], index)
    assert failure is CallProducerIntegrityFailure8616.PROJECTION_MISMATCH


def test_public_producer_integrity_accepts_actual_call_index() -> None:
    evidence = _evidence(False)
    source = evidence.raw.blocks[0]
    index = next(i for i, instruction in enumerate(source.instrs) if instruction.op == "CALL")
    assert call_operand_producer_integrity_8616(evidence.ssa.blocks[0], source, index) is None


@pytest.mark.parametrize("field", ["source_tmp", "memory_access_insn"])
def test_pending_operand_provenance_is_checked_beneath_unary(field: str) -> None:
    """Compare-exempt nested provenance cannot authorize a different producer."""
    operand = IRValue(MemSpace.TMP, size=2, source_tmp=7, memory_access_insn=0x1000)
    unary = IRActiveUnary8616("Iop_16Uto32", operand, 32)
    source = IRValue(MemSpace.TMP, size=4, active_unary=unary)
    projected = replace(source, version=1)
    assert ssa_value_modulo_version_8616(projected, source)
    changed = replace(operand, **{field: 123})
    corrupted = replace(projected, active_unary=replace(unary, operand=changed))
    assert not ssa_value_modulo_version_8616(corrupted, source)
