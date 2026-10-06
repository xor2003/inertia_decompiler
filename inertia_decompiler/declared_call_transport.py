"""Revalidate declared-call result dependencies against their live authority.

Layer: CLI/fallback/reporting.
Responsibility: retain exact assumption receipts without upgrading validation
verdicts, and refuse transport when the current semantic owner cannot replay
its admission. Declaration files and cache fingerprints are not proof.
"""
from __future__ import annotations

from angr_platforms.X86_16.declared_external_call_evidence import (
    DeclaredCallAdmission8616,
    DeclaredCallEffectConsumption8616,
    declared_external_call_registry_8616,
)
from angr_platforms.X86_16.ir.core import IRFunctionArtifact
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.segment_state_transfer import declared_call_effect_at_instruction_8616


def declared_call_receipts_current_8616(
    project: object,
    function_addr: int,
    receipts: tuple[DeclaredCallEffectConsumption8616, ...],
    *, require_registry: bool = False,
) -> bool:
    """Require exact receipts and replay every admission under current source."""
    if type(function_addr) is not int or type(receipts) is not tuple:
        return False
    if any(type(receipt) is not DeclaredCallEffectConsumption8616 for receipt in receipts):
        return False
    registry = declared_external_call_registry_8616(project)
    if registry is None:
        return not require_registry and not receipts
    if not registry.closes_evidence:
        return False
    admissions = registry.admissions_for_function_8616(function_addr)
    expected = tuple(DeclaredCallEffectConsumption8616.from_admission_8616(item) for item in admissions)
    if len({item.callsite_addr for item in admissions}) != len(admissions):
        return False
    if len(receipts) != len(expected) or set(receipts) != set(expected):
        return False
    if not admissions:
        return True
    resolution = registered_function_ir_artifact_8616(project, function_addr)
    artifact = resolution.artifact
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN or artifact is None:
        return False
    return _admissions_replay_8616(project, artifact, admissions)


def _admissions_replay_8616(
    project: object, artifact: IRFunctionArtifact,
    admissions: tuple[DeclaredCallAdmission8616, ...],
) -> bool:
    """Reconsume exact current admissions on unique registered CALL objects."""
    for admission in admissions:
        if admission.project is not project:
            return False
        matches = tuple(
            (block, instruction)
            for block in artifact.blocks for instruction in block.instrs
            if instruction.op == "CALL" and instruction.addr == admission.callsite_addr
        )
        if len(matches) != 1:
            return False
        block, instruction = matches[0]
        if declared_call_effect_at_instruction_8616(artifact, block, instruction, admissions) is not admission:
            return False
    return True


def declared_call_diagnostic_lines_8616(
    receipts: tuple[DeclaredCallEffectConsumption8616, ...],
) -> tuple[str, ...]:
    """Report conditional dependencies without making any validation claim."""
    return tuple(
        "[dbg] declared external-call effect: "
        f"assumption={receipt.assumption.value} "
        f"caller={receipt.caller_addr:#x} callsite={receipt.callsite_addr:#x} "
        f"target={receipt.target_addr:#x} distance={"far" if receipt.is_far else "near"} "
        f"retained={",".join(receipt.retained_registers)} "
        f"declaration={receipt.declaration_sha256} assumption_consumed=true"
        for receipt in receipts
    )
