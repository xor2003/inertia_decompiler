"""Raw-stage route of the shared SSA CALL-target binder.

Layer: Types/Lowering (staged candidate under
``.cache/comparator-implementation/call-target-consolidation/``; intended
production home ``lowering/call_target_raw_route.py``).
Responsibility: bind a raw-stage SSA CALL — no Semantics enrichment — to
the project-registered raw ``IRFunctionArtifact`` producer by shared
position, retained origin, and operand projection, then close the owned
producer-integrity closure against that raw block.
"""

from __future__ import annotations

from angr_platforms.X86_16.ir import IRInstr, IRValue
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact

from .call_target_bind_common import (
    _closure_or_refusal_8616,
    _registered_raw_artifact_8616,
)
from .call_target_projection_integrity import ssa_value_modulo_version_8616
from .call_target_ssa_contracts import (
    CallTargetBindResult8616,
    CallTargetBindStage8616,
    CallTargetBindVerdict8616,
    _BoundProducer8616,
    _refuse_8616,
)


def _raw_route_producer_8616(
    project: object,
    artifact: SSAFunctionArtifact,
    caller_addr: int,
    callsite_addr: int,
    ssa_block_addr: int,
    ssa_instr_index: int,
    ssa_instr: IRInstr,
) -> _BoundProducer8616 | CallTargetBindResult8616:
    """Bind a raw-stage SSA CALL to the registered raw producer.

    Positional binding plus retained-origin and operand-projection checks,
    then the owned producer-integrity closure against the registered raw
    block. Requires the SSA artifact to carry no Semantics enrichment: the
    raw producer and the SSA candidate share instruction positions.
    """
    raw_artifact = _registered_raw_artifact_8616(
        project,
        caller_addr,
        callsite_addr,
        not_registered=CallTargetBindStage8616.RAW_IR_NOT_REGISTERED,
        conflict=CallTargetBindStage8616.RAW_IR_CONFLICT,
    )
    if isinstance(raw_artifact, CallTargetBindResult8616):
        return raw_artifact
    raw_blocks = tuple(
        block for block in raw_artifact.blocks if block.addr == ssa_block_addr
    )
    if len(raw_blocks) != 1 or not 0 <= ssa_instr_index < len(
        raw_blocks[0].instrs
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_RAW_BLOCK_MISMATCH,
            normalized=True,
        )
    raw_block = raw_blocks[0]
    raw_instr = raw_block.instrs[ssa_instr_index]
    if raw_instr.op != "CALL" or raw_instr.addr != callsite_addr:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_RAW_INDEX_MISMATCH,
            normalized=True,
        )
    raw_candidates = tuple(
        instruction
        for block in raw_artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL" and instruction.addr == callsite_addr
    )
    if len(raw_candidates) != 1 or raw_candidates[0] is not raw_instr:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_RAW_CALL_AMBIGUOUS,
            normalized=True,
        )
    provenance = _raw_provenance_failure_8616(ssa_instr, raw_instr)
    if provenance is not None:
        return _refuse_8616(
            callsite_addr,
            (
                CallTargetBindVerdict8616.UNKNOWN_REFUSE
                if provenance is CallTargetBindStage8616.SSA_ORIGIN_MISSING
                else CallTargetBindVerdict8616.CONFLICT
            ),
            provenance,
            normalized=True,
        )
    bound_block = _closure_or_refusal_8616(
        artifact, ssa_block_addr, raw_block, ssa_instr_index, callsite_addr
    )
    if isinstance(bound_block, CallTargetBindResult8616):
        return bound_block
    return _BoundProducer8616(raw_block, raw_instr, None)


def _raw_provenance_failure_8616(
    ssa_instr: IRInstr,
    raw_instr: IRInstr,
) -> CallTargetBindStage8616 | None:
    """Return the first broken SSA-to-raw provenance obligation, or none."""
    if (
        ssa_instr.op != raw_instr.op
        or ssa_instr.addr != raw_instr.addr
        or ssa_instr.size != raw_instr.size
        or ssa_instr.call_stack_effect != raw_instr.call_stack_effect
    ):
        return CallTargetBindStage8616.SSA_RAW_OPERAND_MISMATCH
    if ssa_instr.origin is None or raw_instr.origin is None:
        return CallTargetBindStage8616.SSA_ORIGIN_MISSING
    if ssa_instr.origin != raw_instr.origin:
        return CallTargetBindStage8616.SSA_RAW_ORIGIN_MISMATCH
    dst_bound = (ssa_instr.dst is None and raw_instr.dst is None) or (
        ssa_instr.dst is not None
        and raw_instr.dst is not None
        and ssa_value_modulo_version_8616(ssa_instr.dst, raw_instr.dst)
    )
    if not dst_bound or len(ssa_instr.args) != len(raw_instr.args):
        return CallTargetBindStage8616.SSA_RAW_OPERAND_MISMATCH
    operands_bound = all(
        isinstance(ssa_arg, IRValue)
        and isinstance(raw_arg, IRValue)
        and ssa_value_modulo_version_8616(ssa_arg, raw_arg)
        for ssa_arg, raw_arg in zip(ssa_instr.args, raw_instr.args, strict=True)
    )
    if not operands_bound:
        return CallTargetBindStage8616.SSA_RAW_OPERAND_MISMATCH
    return None
