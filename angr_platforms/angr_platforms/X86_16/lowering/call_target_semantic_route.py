"""Semantics-enriched route of the shared SSA CALL-target binder.

Layer: Types/Lowering (staged candidate under
``.cache/comparator-implementation/call-target-consolidation/``; intended
production home ``lowering/call_target_semantic_route.py``).
Responsibility: verify the retained ``CallSemanticProjection8616`` chain —
``source_ir`` registered, effects a typed overlay, ``CALL_OUTPUT`` prefixes
reconstructed from retained ``CallOutputFact8616`` records, suffix
object-identical, semantic SSA the exact registered artifact — then bind
the CALL at its prefix-shifted position and close the producer-integrity
closure against the *enriched* block.
"""

from __future__ import annotations

from dataclasses import replace

from angr_platforms.X86_16.ir import (
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.semantics.call_output_contracts import (
    CallOutputVerdict8616,
)
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import (
    CallStackEffectFact8616,
)
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    CallSemanticProjection8616,
)

from .call_target_bind_common import (
    _closure_or_refusal_8616,
    _registered_raw_artifact_8616,
    _unique_block_8616,
)
from .call_target_ssa_contracts import (
    CallTargetBindResult8616,
    CallTargetBindStage8616,
    CallTargetBindVerdict8616,
    _BoundProducer8616,
    _refuse_8616,
)


def _expected_output_prefix_8616(
    projection: CallSemanticProjection8616, block_addr: int
) -> tuple[IRInstr, ...] | None:
    """Reconstruct one block's CALL_OUTPUT prefix from retained typed facts.

    ``materialize_call_outputs_8616`` assigns ``injections[return_block]``
    per proven fact in fact order, so replaying the retained records
    reproduces the exact injected prefix. A fact claiming outputs without
    complete coordinates is retained-artifact corruption, not a projection:
    the caller refuses on ``None``.
    """
    expected: tuple[IRInstr, ...] = ()
    for fact in projection.outputs.facts:
        if fact.return_block_addr != block_addr or not fact.outputs:
            continue
        if (
            fact.verdict is not CallOutputVerdict8616.PROVEN
            or fact.callsite_addr is None
            or fact.target_addr is None
            or fact.shape is None
        ):
            return None
        expected = tuple(
            IRInstr(
                "CALL_OUTPUT",
                output,
                (IRValue(MemSpace.CONST, const=fact.target_addr, size=4),),
                size=output.size,
                addr=fact.callsite_addr,
            )
            for output in fact.outputs
        )
    return expected


def _injected_instr_accounted_8616(actual: IRInstr, expected: IRInstr) -> bool:
    """Return whether one injected instr equals its fact-derived reconstruction.

    ``IRInstr`` equality compares ``op``/``dst``/``args``/``size``/``addr``/
    ``call_stack_effect``/``origin``, including the embedded
    ``IRCallOutputProvenance8616``; the compare-exempt value fields are
    checked explicitly so a smuggled temporary identity cannot hide inside a
    prefix.
    """
    if actual != expected:
        return False
    pending: list[object] = [actual.dst, *actual.args]
    while pending:
        node = pending.pop()
        if isinstance(node, IRValue):
            if node.source_tmp is not None or node.memory_access_insn is not None:
                return False
            if node.index is not None:
                pending.append(node.index)
        elif isinstance(node, IRBinaryValue):
            pending.extend((node.lhs, node.rhs))
        elif isinstance(node, IRAddress):
            pending.extend(node.base_values)
        elif isinstance(node, IRCondition):
            pending.extend(node.args)
    return True


def _semantic_route_producer_8616(
    project: object,
    projection: CallSemanticProjection8616,
    artifact: SSAFunctionArtifact,
    caller_addr: int,
    callsite_addr: int,
    ssa_block_addr: int,
    ssa_instr_index: int,
    ssa_instr: IRInstr,
) -> _BoundProducer8616 | CallTargetBindResult8616:
    """Bind a semantic-stage SSA CALL to its retained raw producer.

    Verifies projection identity, registry registration, and the bound
    block's retained chain links (outputs prefix accounted to output facts,
    suffix object-identical to the effects overlay of source), then binds
    the raw CALL through prefix-shifted position plus retained origin, and
    finally requires the owned producer closure against the *enriched*
    block — the exact projection ``build_x86_16_function_ssa`` consumed.
    """
    if projection.function_ssa is not artifact:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SEMANTIC_PROJECTION_SSA_MISMATCH,
            normalized=True,
        )
    if not projection.complete:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.SEMANTIC_PROJECTION_INCOMPLETE,
            normalized=True,
        )
    registered_ssa = registered_function_ssa_artifact_8616(project, caller_addr)
    if (
        registered_ssa.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        or registered_ssa.artifact is not artifact
        or registered_ssa.stage is not FunctionSSAArtifactStage8616.SEMANTIC
    ):
        conflict = (
            registered_ssa.failure
            is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT
        )
        return _refuse_8616(
            callsite_addr,
            (
                CallTargetBindVerdict8616.CONFLICT
                if conflict
                else CallTargetBindVerdict8616.UNKNOWN_REFUSE
            ),
            (
                CallTargetBindStage8616.SEMANTIC_SSA_CONFLICT
                if conflict
                else CallTargetBindStage8616.SEMANTIC_SSA_NOT_REGISTERED
            ),
            normalized=True,
        )
    source_ir = projection.source_ir
    registered_raw = _registered_raw_artifact_8616(
        project,
        caller_addr,
        callsite_addr,
        not_registered=CallTargetBindStage8616.SOURCE_IR_NOT_REGISTERED,
        conflict=CallTargetBindStage8616.SOURCE_IR_CONFLICT,
    )
    if isinstance(registered_raw, CallTargetBindResult8616):
        return registered_raw
    if registered_raw is not source_ir and registered_raw != source_ir:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SOURCE_IR_CONFLICT,
            normalized=True,
        )
    return _semantic_bound_block_8616(
        projection,
        artifact,
        callsite_addr,
        ssa_block_addr,
        ssa_instr_index,
        ssa_instr,
        source_ir,
    )


def _block_facts_8616(
    projection: CallSemanticProjection8616, block_addr: int
) -> dict[int, CallStackEffectFact8616] | None:
    """Index the retained effect facts for one block by instruction index."""
    facts_by_index: dict[int, CallStackEffectFact8616] = {}
    for fact in projection.effects.facts:
        if fact.block_addr != block_addr:
            continue
        if fact.instr_index in facts_by_index:
            return None
        facts_by_index[fact.instr_index] = fact
    return facts_by_index


def _effects_overlay_holds_8616(
    source_block: IRBlock,
    effects_block: IRBlock,
    facts_by_index: dict[int, CallStackEffectFact8616],
) -> bool:
    """Return whether the effects block is the typed overlay of the source.

    Non-CALL instructions must be the identical retained object; every CALL
    must be exactly ``replace(source, call_stack_effect=fact.effect)`` for
    the unique retained fact at ``(block_addr, instr_index)``, and no fact
    may claim a non-CALL or out-of-range index — the annotation is
    accounted to the Semantics owner, never erased for comparison.
    """
    if (
        source_block.addr != effects_block.addr
        or source_block.refusals != effects_block.refusals
        or source_block.successor_addrs != effects_block.successor_addrs
        or len(source_block.instrs) != len(effects_block.instrs)
    ):
        return False
    for index, (source_instr, effects_instr) in enumerate(
        zip(source_block.instrs, effects_block.instrs, strict=True)
    ):
        if source_instr.op != "CALL":
            if effects_instr is not source_instr:
                return False
            continue
        fact = facts_by_index.get(index)
        if (
            fact is None
            or fact.callsite_addr != source_instr.addr
            or replace(source_instr, call_stack_effect=fact.effect)
            != effects_instr
        ):
            return False
    return all(
        0 <= fact.instr_index < len(source_block.instrs)
        and source_block.instrs[fact.instr_index].op == "CALL"
        for fact in facts_by_index.values()
    )


def _outputs_block_prefix_8616(
    projection: CallSemanticProjection8616,
    outputs_block: IRBlock,
    effects_block: IRBlock,
    callsite_addr: int,
) -> int | CallTargetBindResult8616:
    """Return the accounted CALL_OUTPUT prefix length, or a typed refusal.

    The prefix is reconstructed exactly from the retained
    ``CallOutputFact8616`` records and compared instruction-for-instruction;
    the suffix must be the object-identical effects tail. Anything else is
    ``OUTPUTS_PREFIX_MISMATCH``/``OUTPUTS_SUFFIX_MISMATCH``, never a guess at
    the shift.
    """
    prefix = _expected_output_prefix_8616(projection, outputs_block.addr)
    if (
        prefix is None
        or len(outputs_block.instrs) != len(prefix) + len(effects_block.instrs)
        or outputs_block.refusals != effects_block.refusals
        or outputs_block.successor_addrs != effects_block.successor_addrs
        or not all(
            _injected_instr_accounted_8616(actual, expected)
            for actual, expected in zip(
                outputs_block.instrs[: len(prefix)], prefix, strict=True
            )
        )
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.OUTPUTS_PREFIX_MISMATCH,
            normalized=True,
        )
    if not all(
        outputs_block.instrs[len(prefix) + index] is effects_block.instrs[index]
        for index in range(len(effects_block.instrs))
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.OUTPUTS_SUFFIX_MISMATCH,
            normalized=True,
        )
    return len(prefix)


def _semantic_bound_block_8616(
    projection: CallSemanticProjection8616,
    artifact: SSAFunctionArtifact,
    callsite_addr: int,
    ssa_block_addr: int,
    ssa_instr_index: int,
    ssa_instr: IRInstr,
    source_ir: IRFunctionArtifact,
) -> _BoundProducer8616 | CallTargetBindResult8616:
    """Verify the bound block's retained chain and return the raw producer."""
    source_block = _unique_block_8616(source_ir, ssa_block_addr)
    effects_block = _unique_block_8616(projection.effects.function, ssa_block_addr)
    outputs_block = _unique_block_8616(projection.outputs.function, ssa_block_addr)
    if source_block is None or effects_block is None or outputs_block is None:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SOURCE_IR_BLOCK_MISMATCH,
            normalized=True,
        )
    facts_by_index = _block_facts_8616(projection, ssa_block_addr)
    if facts_by_index is None:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.EFFECTS_FACT_AMBIGUOUS,
            normalized=True,
        )
    if not _effects_overlay_holds_8616(
        source_block, effects_block, facts_by_index
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.EFFECTS_BLOCK_MISMATCH,
            normalized=True,
        )
    prefix_len = _outputs_block_prefix_8616(
        projection, outputs_block, effects_block, callsite_addr
    )
    if isinstance(prefix_len, CallTargetBindResult8616):
        return prefix_len
    bound = _semantic_raw_call_8616(
        source_block,
        facts_by_index,
        prefix_len,
        ssa_instr_index,
        ssa_instr,
        callsite_addr,
    )
    if isinstance(bound, CallTargetBindResult8616):
        return bound
    bound_block = _closure_or_refusal_8616(
        artifact, ssa_block_addr, outputs_block, ssa_instr_index, callsite_addr
    )
    if isinstance(bound_block, CallTargetBindResult8616):
        return bound_block
    return bound


def _semantic_raw_call_8616(
    source_block: IRBlock,
    facts_by_index: dict[int, CallStackEffectFact8616],
    prefix_len: int,
    ssa_instr_index: int,
    ssa_instr: IRInstr,
    callsite_addr: int,
) -> _BoundProducer8616 | CallTargetBindResult8616:
    """Bind the raw CALL at the prefix-shifted position plus origin."""
    raw_index = ssa_instr_index - prefix_len
    if not 0 <= raw_index < len(source_block.instrs):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_ENRICHED_INDEX_MISMATCH,
            normalized=True,
        )
    raw_instr = source_block.instrs[raw_index]
    fact = facts_by_index.get(raw_index)
    if fact is None:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.EFFECTS_FACT_MISSING,
            normalized=True,
        )
    if ssa_instr.origin is None or raw_instr.origin is None:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.UNKNOWN_REFUSE,
            CallTargetBindStage8616.SSA_ORIGIN_MISSING,
            normalized=True,
        )
    if ssa_instr.origin != raw_instr.origin:
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_ENRICHED_ORIGIN_MISMATCH,
            normalized=True,
        )
    if (
        raw_instr.op != "CALL"
        or raw_instr.addr != callsite_addr
        or fact.callsite_addr != callsite_addr
        or fact.effect != ssa_instr.call_stack_effect
    ):
        return _refuse_8616(
            callsite_addr,
            CallTargetBindVerdict8616.CONFLICT,
            CallTargetBindStage8616.SSA_ENRICHED_CALL_MISMATCH,
            normalized=True,
        )
    return _BoundProducer8616(source_block, raw_instr, fact)
