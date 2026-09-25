"""Materialize exact used call returns as typed register definitions.

Layer: Semantics.
Responsibility: consume authoritative callsite summaries and exact IR return
edges, then insert ``CALL_OUTPUT`` definitions at an unambiguous continuation
block before SSA. Ambiguous call ownership, return edges, joins, uses, and
shapes remain typed refusals.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, replace

from ..callsite_summary import CallsiteSummary8616, callsite_machine_frame_kind_8616
from ..ir import (
    IRBlock,
    IRCallOutputProvenance8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from ..ir.logical_memory_rebase import rebase_logical_memory_prefix_insertions_8616
from .call_output_contracts import (
    CallOutputFact8616,
    CallOutputFailure8616,
    CallOutputShape8616,
    CallOutputStats8616,
    CallOutputVerdict8616,
)


@dataclass(frozen=True, slots=True)
class CallOutputArtifact8616:
    """Semantics-enriched IR plus one output outcome for every CALL."""

    function: IRFunctionArtifact
    facts: tuple[CallOutputFact8616, ...]
    stats: CallOutputStats8616

    @property
    def complete(self) -> bool:
        """Return whether every CALL output decision is positively proven."""
        return bool(self.stats.complete)

    def to_dict(self) -> dict[str, object]:
        """Return deterministic diagnostics without duplicating full IR."""
        return {
            "function_addr": self.function.function_addr,
            "facts": [
                {
                    "call_block_addr": fact.call_block_addr,
                    "call_instr_index": fact.call_instr_index,
                    "callsite_addr": fact.callsite_addr,
                    "target_addr": fact.target_addr,
                    "return_block_addr": fact.return_block_addr,
                    "shape": None if fact.shape is None else fact.shape.value,
                    "outputs": [output.to_dict() for output in fact.outputs],
                    "verdict": fact.verdict.value,
                    "failure": None if fact.failure is None else fact.failure.value,
                }
                for fact in self.facts
            ],
            "stats": self.stats.to_dict(),
        }


def _shape_8616(summary: CallsiteSummary8616) -> CallOutputShape8616 | None:
    """Normalize the authoritative summary shape without widening by name."""
    if summary.return_shape == CallOutputShape8616.AX.value:
        return CallOutputShape8616.AX
    if summary.return_shape == CallOutputShape8616.DX_AX.value:
        return CallOutputShape8616.DX_AX
    return None


def _output_values_8616(
    shape: CallOutputShape8616,
    callsite_addr: int,
    target_addr: int,
) -> tuple[IRValue, ...]:
    """Return exact register slices defined by one used call result."""
    names = ("ax",) if shape is CallOutputShape8616.AX else ("ax", "dx")
    return tuple(
        IRValue(
            MemSpace.REG,
            name=name,
            size=2,
            expr=("call_output", shape.value, f"{callsite_addr:#x}"),
            call_output=IRCallOutputProvenance8616(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                shape=shape,
            ),
        )
        for name in names
    )


def _refusal_8616(
    block_addr: int,
    instr_index: int,
    callsite_addr: int | None,
    summary: CallsiteSummary8616 | None,
    failure: CallOutputFailure8616,
) -> CallOutputFact8616:
    """Retain one conservative call-output refusal."""
    return CallOutputFact8616(
        block_addr,
        instr_index,
        callsite_addr,
        None if summary is None else summary.target_addr,
        None,
        None,
        (),
        CallOutputVerdict8616.UNKNOWN_REFUSE,
        failure,
    )


def _call_summary_gate_8616(
    block: IRBlock,
    instr_index: int,
    instruction: IRInstr,
    summaries: Mapping[int, CallsiteSummary8616],
    address_counts: Counter[int],
) -> CallsiteSummary8616 | CallOutputFact8616:
    """Return the proven callsite summary or its early refusal fact."""
    summary = summaries.get(instruction.addr) if instruction.addr is not None else None
    if instruction.addr is None:
        return _refusal_8616(
            block.addr,
            instr_index,
            None,
            summary,
            CallOutputFailure8616.CALL_ADDRESS_MISSING,
        )
    if address_counts[instruction.addr] != 1:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.DUPLICATE_CALL_ADDRESS,
        )
    if summary is None:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            None,
            CallOutputFailure8616.SUMMARY_MISSING,
        )
    if summary.target_addr is None:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.TARGET_UNRESOLVED,
        )
    if callsite_machine_frame_kind_8616(summary) is None:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.FRAME_KIND_UNKNOWN,
        )
    if summary.return_used is None:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.RETURN_USE_UNKNOWN,
        )
    return summary


def _call_shape_gate_8616(
    block: IRBlock,
    instr_index: int,
    instruction: IRInstr,
    summary: CallsiteSummary8616,
    blocks: Mapping[int, IRBlock],
    predecessors: Mapping[int, set[int]],
) -> CallOutputShape8616 | CallOutputFact8616:
    """Return the proven output shape, a no-output fact, or a refusal fact."""
    if summary.return_used is False:
        return CallOutputFact8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary.target_addr,
            summary.return_addr,
            None,
            (),
            CallOutputVerdict8616.PROVEN,
            None,
        )
    shape = _shape_8616(summary)
    if shape is None:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.RETURN_SHAPE_UNKNOWN,
        )
    if instr_index != len(block.instrs) - 1:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.CALL_NOT_TERMINAL,
        )
    if summary.return_addr is None or summary.return_addr not in blocks:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.RETURN_BLOCK_MISSING,
        )
    if block.successor_addrs != (summary.return_addr,):
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.RETURN_EDGE_MISMATCH,
        )
    if predecessors[summary.return_addr] != {block.addr}:
        return _refusal_8616(
            block.addr,
            instr_index,
            instruction.addr,
            summary,
            CallOutputFailure8616.RETURN_BLOCK_HAS_OTHER_PREDECESSOR,
        )
    return shape


def materialize_call_outputs_8616(
    artifact: IRFunctionArtifact,
    summaries: Mapping[int, CallsiteSummary8616],
) -> CallOutputArtifact8616:
    """Insert exact used call outputs at their uniquely dominated return blocks."""
    blocks = {block.addr: block for block in artifact.blocks}
    predecessors: dict[int, set[int]] = {address: set() for address in blocks}
    for block in artifact.blocks:
        for successor in block.successor_addrs:
            if successor in predecessors:
                predecessors[successor].add(block.addr)
    calls = tuple(
        (block, index, instruction)
        for block in artifact.blocks
        for index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL"
    )
    address_counts = Counter(
        instruction.addr for _block, _index, instruction in calls if instruction.addr is not None
    )
    injections: dict[int, tuple[IRInstr, ...]] = {}
    facts: list[CallOutputFact8616] = []
    for block, instr_index, instruction in calls:
        gated_summary = _call_summary_gate_8616(
            block,
            instr_index,
            instruction,
            summaries,
            address_counts,
        )
        if isinstance(gated_summary, CallOutputFact8616):
            facts.append(gated_summary)
            continue
        summary = gated_summary
        assert instruction.addr is not None
        gated_shape = _call_shape_gate_8616(
            block,
            instr_index,
            instruction,
            summary,
            blocks,
            predecessors,
        )
        if isinstance(gated_shape, CallOutputFact8616):
            facts.append(gated_shape)
            continue
        shape = gated_shape
        assert summary.return_addr is not None
        assert summary.target_addr is not None
        outputs = _output_values_8616(shape, instruction.addr, summary.target_addr)
        injections[summary.return_addr] = tuple(
            IRInstr(
                "CALL_OUTPUT",
                output,
                (IRValue(MemSpace.CONST, const=summary.target_addr, size=4),),
                size=output.size,
                addr=instruction.addr,
            )
            for output in outputs
        )
        facts.append(
            CallOutputFact8616(
                block.addr,
                instr_index,
                instruction.addr,
                summary.target_addr,
                summary.return_addr,
                shape,
                outputs,
                CallOutputVerdict8616.PROVEN,
                None,
            )
        )
    rewritten_blocks = tuple(
        IRBlock(
            block.addr,
            (*injections.get(block.addr, ()), *block.instrs),
            block.refusals,
            block.successor_addrs,
        )
        for block in artifact.blocks
    )
    logical_memory = rebase_logical_memory_prefix_insertions_8616(
        artifact.logical_memory,
        prefix_lengths={address: len(items) for address, items in injections.items()},
        rewritten_blocks=rewritten_blocks,
    )
    failure_count = sum(fact.failure is not None for fact in facts)
    stats = CallOutputStats8616(
        raw_fact_count=len(calls),
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=len(facts),
        failure_count=failure_count,
    )
    function_summary = {
        **artifact.summary,
        "call_output_raw_fact_count": stats.raw_fact_count,
        "call_output_normalized_fact_count": stats.normalized_fact_count,
        "call_output_classified_fact_count": stats.classified_fact_count,
        "call_output_materialized_count": stats.materialized_count,
        "call_output_failure_count": stats.failure_count,
    }
    return CallOutputArtifact8616(
        replace(
            artifact,
            blocks=rewritten_blocks,
            summary=function_summary,
            logical_memory=logical_memory,
        ),
        tuple(facts),
        stats,
    )


__all__ = [
    "CallOutputArtifact8616",
    "materialize_call_outputs_8616",
]
