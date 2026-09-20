"""Materialize exact caller-frame effects before function memory SSA.

Layer: Semantics.
Responsibility: consume typed callsite summaries and exact IR CALL/storage facts
to prove which stable ``SS:BP`` ranges survive each call. Unknown interfaces,
pointer escape, cleanup disagreement, duplicate calls, and conflicting existing
effects are retained as typed refusals.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, replace

from ..callsite_summary import (
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from ..ir import (
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
)
from ..ir.frame_memory_accesses import stable_bp_memory_ranges_8616
from ..ir.stack_range_overlap import stack_ranges_may_overlap_8616
from .call_register_effects import (
    SyntheticCallRegisterEffectVerdict8616,
    classify_synthetic_call_register_effect_8616,
)
from .call_return_segment import ReturnSegmentFrame8616
from .call_stack_allocation import CallStackAllocationProof8616, resolve_call_stack_allocation_8616
from .call_stack_effect_contracts import (
    CallStackEffectFact8616,
    CallStackEffectFailure8616,
    CallStackEffectStats8616,
    CallStackEffectVerdict8616,
)
from .call_stack_provenance import stack_address_offset_8616


@dataclass(frozen=True, slots=True)
class CallStackEffectArtifact8616:
    """Semantics-enriched IR plus one outcome for every exact CALL."""

    function: IRFunctionArtifact
    facts: tuple[CallStackEffectFact8616, ...]
    stats: CallStackEffectStats8616

    @property
    def complete(self) -> bool:
        """Return whether every CALL has a positive preservation proof."""
        return bool(self.stats.complete)

    def to_dict(self) -> dict[str, object]:
        """Return deterministic diagnostics without duplicating the full IR."""
        return {
            "function_addr": self.function.function_addr,
            "facts": [
                {
                    "block_addr": fact.block_addr,
                    "instr_index": fact.instr_index,
                    "callsite_addr": fact.callsite_addr,
                    "target_addr": fact.target_addr,
                    "verdict": fact.verdict.value,
                    "effect": fact.effect.to_dict(),
                    "failure": None if fact.failure is None else fact.failure.value,
                }
                for fact in self.facts
            ],
            "stats": self.stats.to_dict(),
        }


def _stable_bp_ranges_8616(artifact: IRFunctionArtifact) -> tuple[IRAddress, ...]:
    """Consume both logical operands and exact execution cells from typed IR."""
    return stable_bp_memory_ranges_8616(artifact)


def _refused_effect_8616(
    ranges: tuple[IRAddress, ...],
    failure: CallStackEffectFailure8616,
) -> tuple[IRCallStackEffect8616, CallStackEffectFailure8616]:
    """Create one explicit non-preserving call effect."""
    escaped = ranges if failure is CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE else ()
    return IRCallStackEffect8616(escaped_ranges=escaped, complete=False), failure




def _stack_address_offsets_8616(
    summary: CallsiteSummary8616,
) -> tuple[tuple[int, ...], CallStackEffectFailure8616 | None]:
    """Classify all exact caller-frame addresses passed by physical PUSH provenance."""
    if len(summary.push_arg_sources) != summary.arg_count:
        return (), CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
    address_breaks = summary.push_arg_address_break_evidence
    if address_breaks and len(address_breaks) != summary.arg_count:
        return (), CallStackEffectFailure8616.ARGUMENT_ADDRESS_PROVENANCE_CONFLICT
    offsets: list[int] = []
    for index, source in enumerate(summary.push_arg_sources):
        address_break = address_breaks[index] if address_breaks else None
        if source is None and address_break is not None:
            if not address_break.complete or (
                len(summary.push_arg_instruction_addrs) != summary.arg_count
                or address_break.push_instruction_addr
                != summary.push_arg_instruction_addrs[index]
            ):
                return (), CallStackEffectFailure8616.ARGUMENT_ADDRESS_PROVENANCE_CONFLICT
            continue
        if address_break is not None:
            return (), CallStackEffectFailure8616.ARGUMENT_ADDRESS_PROVENANCE_CONFLICT
        offset, failure = stack_address_offset_8616(source)
        if failure is not None:
            return (), failure
        if offset is not None:
            offsets.append(offset)
    return tuple(dict.fromkeys(offsets)), None


def _range_contains_bp_offset_8616(address: IRAddress, offset: int) -> bool:
    """Compare a BP-derived argument against a range in the 16-bit coordinate."""
    pointed_byte = replace(address, offset=offset, size=1)
    return stack_ranges_may_overlap_8616(address, pointed_byte)


def _effect_from_summary_8616(
    summary: CallsiteSummary8616,
    ranges: tuple[IRAddress, ...],
    allocation: CallStackAllocationProof8616 | None = None,
) -> tuple[IRCallStackEffect8616, CallStackEffectFailure8616 | None]:
    """Classify caller-frame preservation from one authoritative summary."""
    allocation_effect = resolve_call_stack_allocation_8616(summary, ranges, allocation)
    if allocation_effect is not None:
        return allocation_effect
    if summary.target_addr is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.TARGET_UNRESOLVED)
    if callsite_machine_frame_kind_8616(summary) is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.FRAME_KIND_UNKNOWN)
    if summary.return_addr is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.RETURN_ADDRESS_UNKNOWN)
    if summary.arg_count is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.ARGUMENT_COUNT_UNKNOWN)
    if len(summary.arg_widths) != summary.arg_count or any(width <= 0 for width in summary.arg_widths):
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.ARGUMENT_WIDTHS_INCOMPLETE)
    argument_bytes = sum(summary.arg_widths)
    stack_cleanup = 0 if summary.arg_count == 0 and summary.stack_cleanup is None else summary.stack_cleanup
    if stack_cleanup is None:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.STACK_CLEANUP_UNKNOWN)
    if argument_bytes != stack_cleanup:
        return _refused_effect_8616(ranges, CallStackEffectFailure8616.STACK_CLEANUP_MISMATCH)
    stack_address_offsets, source_failure = _stack_address_offsets_8616(summary)
    if source_failure is not None:
        return _refused_effect_8616(ranges, source_failure)
    net_stack_delta = (
        stack_cleanup
        if stack_cleanup > 0 and summary.stack_cleanup_instruction_addr is None
        else 0
    )
    escaped_ranges = tuple(
        address
        for address in ranges
        if any(
            _range_contains_bp_offset_8616(address, offset)
            for offset in stack_address_offsets
        )
    )
    # A logical word may share independently executed byte ranges. Escape of
    # that operand forbids claiming preservation of any overlapping byte.
    escaped_ranges = tuple(address for address in ranges
                           if any(stack_ranges_may_overlap_8616(address, escaped) for escaped in escaped_ranges))
    escaped_identities = {
        (item.space, item.base, item.offset, item.size) for item in escaped_ranges
    }
    return (
        IRCallStackEffect8616(
            net_stack_delta=net_stack_delta,
            preserved_ranges=tuple(
                address
                for address in ranges
                if (address.space, address.base, address.offset, address.size)
                not in escaped_identities
            ),
            escaped_ranges=escaped_ranges,
            complete=True,
        ),
        None,
    )


def _with_synthetic_bp_proof_8616(
    effect: IRCallStackEffect8616,
    project: object | None,
    summary: CallsiteSummary8616,
    callsite_addr: int,
) -> IRCallStackEffect8616:
    """Keep frame-register preservation independent of stack cleanup evidence."""
    if not effect.complete or project is None or summary.callsite_addr != callsite_addr:
        return effect
    proof = classify_synthetic_call_register_effect_8616(
        project, callsite_addr=callsite_addr, target_addr=summary.target_addr, register="bp",
    )
    proven = proof.closes_evidence and proof.verdict is SyntheticCallRegisterEffectVerdict8616.PRESERVED
    return replace(effect, bp_preserved=True) if proven else effect


def materialize_call_stack_effects_8616(
    artifact: IRFunctionArtifact,
    summaries: Mapping[int, CallsiteSummary8616],
    *,
    project: object | None = None,
    allocation_proofs: Mapping[int, CallStackAllocationProof8616] | None = None,
    return_segment_frames: Mapping[int, ReturnSegmentFrame8616] | None = None,
) -> CallStackEffectArtifact8616:
    """Attach one summary-derived stack effect to every exact IR CALL."""
    ranges = _stable_bp_ranges_8616(artifact)
    call_addresses = tuple(
        instruction.addr
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    address_counts = Counter(address for address in call_addresses if address is not None)
    facts: list[CallStackEffectFact8616] = []
    rewritten_blocks: list[IRBlock] = []
    for block in artifact.blocks:
        rewritten: list[IRInstr] = []
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "CALL":
                rewritten.append(instruction)
                continue
            summary = summaries.get(instruction.addr) if instruction.addr is not None else None
            target_addr = None if summary is None else summary.target_addr
            failure: CallStackEffectFailure8616 | None
            if instruction.addr is None:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.CALL_ADDRESS_MISSING,
                )
            elif address_counts[instruction.addr] != 1:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.DUPLICATE_CALL_ADDRESS,
                )
            elif summary is None:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.SUMMARY_MISSING,
                )
            else:
                allocation = allocation_proofs.get(instruction.addr) if allocation_proofs is not None else None
                effect, failure = _effect_from_summary_8616(summary, ranges, allocation)
                effect = _with_synthetic_bp_proof_8616(effect, project, summary, instruction.addr)
                frame = return_segment_frames.get(instruction.addr) if return_segment_frames is not None else None
                if failure is None and frame is not None and frame.callsite_addr == instruction.addr:
                    adjustment = frame.additional_return_bytes
                    if adjustment is not None and effect.net_stack_delta is not None:
                        effect = replace(effect, net_stack_delta=effect.net_stack_delta + adjustment)
            if instruction.call_stack_effect is not None and instruction.call_stack_effect != effect:
                effect, failure = _refused_effect_8616(
                    ranges,
                    CallStackEffectFailure8616.EXISTING_EFFECT_CONFLICT,
                )
            verdict = (
                CallStackEffectVerdict8616.PROVEN
                if failure is None
                else CallStackEffectVerdict8616.UNKNOWN_REFUSE
            )
            facts.append(
                CallStackEffectFact8616(
                    block.addr,
                    instr_index,
                    instruction.addr,
                    target_addr,
                    verdict,
                    effect,
                    failure,
                )
            )
            rewritten.append(
                replace(instruction, call_stack_effect=effect)
            )
        rewritten_blocks.append(
            IRBlock(block.addr, tuple(rewritten), block.refusals, block.successor_addrs)
        )
    raw_count = len(call_addresses)
    failure_count = sum(fact.failure is not None for fact in facts)
    stats = CallStackEffectStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=len(facts),
        failure_count=failure_count,
    )
    artifact_summary = {
        **artifact.summary,
        "call_stack_effect_raw_fact_count": stats.raw_fact_count,
        "call_stack_effect_normalized_fact_count": stats.normalized_fact_count,
        "call_stack_effect_classified_fact_count": stats.classified_fact_count,
        "call_stack_effect_materialized_count": stats.materialized_count,
        "call_stack_effect_failure_count": stats.failure_count,
    }
    return CallStackEffectArtifact8616(
        replace(artifact, blocks=tuple(rewritten_blocks), summary=artifact_summary),
        tuple(facts),
        stats,
    )


__all__ = ["CallStackEffectArtifact8616", "materialize_call_stack_effects_8616"]
