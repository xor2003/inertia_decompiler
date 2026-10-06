"""Shared evidence guards for both CALL-target binder routes.

Layer: Types/Lowering (staged candidate under
``.cache/comparator-implementation/call-target-consolidation/``; intended
production home ``lowering/call_target_bind_common.py``).
Responsibility: the route-independent obligations — the unique well-formed
SSA CALL candidate at a callsite, unique typed blocks, the
registry-published raw artifact, and the producer-integrity closure that
binds an ``SSABlock`` to the owned ``build_x86_16_block_local_ssa``
projection of whichever source block the route selected.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr_platforms.X86_16.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact

from .call_target_projection_integrity import (
    CallProducerIntegrityFailure8616,
    call_operand_producer_integrity_8616,
)
from .call_target_ssa_contracts import (
    CallTargetBindResult8616,
    CallTargetBindStage8616,
    CallTargetBindVerdict8616,
    _refuse_8616,
)


def _unique_ssa_call_8616(
    artifact: SSAFunctionArtifact,
    caller_addr: int,
    callsite_addr: int,
) -> tuple[int, int, IRInstr] | CallTargetBindResult8616:
    """Return the unique well-formed SSA CALL candidate at the callsite."""
    if artifact.function_addr != caller_addr:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_CALLER_MISMATCH,
        )
    candidates = tuple(
        (block.addr, instr_index, instruction)
        for block in artifact.blocks
        for instr_index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL" and instruction.addr == callsite_addr
    )
    if not candidates:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.SSA_CALL_NOT_FOUND,
        )
    if len(candidates) != 1:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_CALL_AMBIGUOUS,
        )
    block_addr, instr_index, instruction = candidates[0]
    if (
        instruction.dst is not None
        or len(instruction.args) != 1
        or not isinstance(instruction.args[0], IRValue)
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.SSA_CALL_MALFORMED,
        )
    return block_addr, instr_index, instruction


def _registered_raw_artifact_8616(
    project: object,
    caller_addr: int,
    callsite_addr: int,
    *,
    not_registered: CallTargetBindStage8616,
    conflict: CallTargetBindStage8616,
) -> IRFunctionArtifact | CallTargetBindResult8616:
    """Return the registry-published raw artifact for this exact caller."""
    resolution = registered_function_ir_artifact_8616(project, caller_addr)
    if (
        resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN
        or resolution.artifact is None
    ):
        is_conflict = (
            resolution.failure is FunctionIRArtifactFailure8616.ARTIFACT_CONFLICT
        )
        return _refuse_8616(
            callsite_addr,
            (
                CallTargetBindVerdict8616.CONFLICT
                if is_conflict
                else CallTargetBindVerdict8616.UNKNOWN_REFUSE
            ),
            conflict if is_conflict else not_registered,
            normalized=True,
        )
    return resolution.artifact


def _integrity_failure_stage_8616(
    failure: CallProducerIntegrityFailure8616,
) -> CallTargetBindStage8616:
    """Map the owned producer-integrity refusal onto binder stages."""
    return {
        CallProducerIntegrityFailure8616.PROJECTION_MISMATCH: (
            CallTargetBindStage8616.PRODUCER_PROJECTION_MISMATCH
        ),
        CallProducerIntegrityFailure8616.PRODUCER_AMBIGUOUS: (
            CallTargetBindStage8616.PRODUCER_AMBIGUOUS
        ),
        CallProducerIntegrityFailure8616.PRODUCER_UNBOUND: (
            CallTargetBindStage8616.PRODUCER_UNBOUND
        ),
        CallProducerIntegrityFailure8616.PRODUCER_MISMATCH: (
            CallTargetBindStage8616.PRODUCER_MISMATCH
        ),
    }[failure]


def _closure_or_refusal_8616(
    artifact: SSAFunctionArtifact,
    ssa_block_addr: int,
    source_block: IRBlock,
    ssa_instr_index: int,
    callsite_addr: int,
) -> SSABlock | CallTargetBindResult8616:
    """Bind the artifact block's producer closure or return the refusal."""
    ssa_blocks = tuple(
        block for block in artifact.blocks if block.addr == ssa_block_addr
    )
    if len(ssa_blocks) != 1:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.PRODUCER_PROJECTION_MISMATCH,
            normalized=True,
        )
    failure = call_operand_producer_integrity_8616(
        ssa_blocks[0], source_block, ssa_instr_index
    )
    if failure is None:
        return ssa_blocks[0]
    stage = _integrity_failure_stage_8616(failure)
    return _refuse_8616(
        callsite_addr,
        (
            CallTargetBindVerdict8616.UNKNOWN_REFUSE
            if stage is CallTargetBindStage8616.PRODUCER_UNBOUND
            else CallTargetBindVerdict8616.CONFLICT
        ),
        stage,
        normalized=True,
        classified=stage is not CallTargetBindStage8616.PRODUCER_PROJECTION_MISMATCH,
    )


def _unique_block_8616(
    artifact: IRFunctionArtifact, block_addr: int
) -> IRBlock | None:
    """Return the unique typed block at one address, or ``None``."""
    blocks = tuple(block for block in artifact.blocks if block.addr == block_addr)
    return blocks[0] if len(blocks) == 1 else None
