"""Authenticate retained CALL semantic block overlays.

Layer: Semantics.
Responsibility: verify that enriched IR contains exactly the typed call-effect
annotations and output prefixes published by Semantics, retaining native source
instruction identity. Shared by declaration consumption and the SSA target binder.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
from typing import TYPE_CHECKING

from ..ir.core import IRAddress, IRBinaryValue, IRBlock, IRCondition, IRInstr, IRValue, MemSpace
from .call_output_contracts import CallOutputVerdict8616
from .call_stack_effect_contracts import CallStackEffectFact8616

if TYPE_CHECKING:
    from .call_stack_effect_pipeline import CallSemanticProjection8616


class OutputPrefixFailure8616(StrEnum):
    """Typed failure of a fact-derived output prefix or retained suffix."""

    PREFIX = "prefix"
    SUFFIX = "suffix"


def output_prefix_length_8616(
    projection: CallSemanticProjection8616,
    outputs_block: IRBlock,
    effects_block: IRBlock,
) -> int | OutputPrefixFailure8616:
    """Return the exact accounted prefix length, preserving every suffix object."""
    prefix = _expected_output_prefix_8616(projection, outputs_block.addr)
    if (
        prefix is None
        or len(outputs_block.instrs) != len(prefix) + len(effects_block.instrs)
        or outputs_block.refusals != effects_block.refusals
        or outputs_block.successor_addrs != effects_block.successor_addrs
        or not all(
            _injected_instr_accounted_8616(actual, expected)
            for actual, expected in zip(outputs_block.instrs[:len(prefix)], prefix, strict=True)
        )
    ):
        return OutputPrefixFailure8616.PREFIX
    if not all(
        outputs_block.instrs[len(prefix) + index] is instruction
        for index, instruction in enumerate(effects_block.instrs)
    ):
        return OutputPrefixFailure8616.SUFFIX
    return len(prefix)


def projected_call_source_8616(
    projection: CallSemanticProjection8616, block: IRBlock, instruction: IRInstr
) -> tuple[IRBlock, IRInstr] | None:
    """Resolve an output CALL to its exact raw producer through accounted overlays.

    The caller must authenticate this projection against project registries.
    Equal coordinates alone never authorize a foreign block or CALL object.
    """
    raw = tuple(item for item in projection.source_ir.blocks if item.addr == block.addr)
    effects = tuple(item for item in projection.effects.function.blocks if item.addr == block.addr)
    outputs = tuple(item for item in projection.outputs.function.blocks if item.addr == block.addr)
    if len(raw) != 1 or len(effects) != 1 or len(outputs) != 1 or outputs[0] is not block:
        return None
    facts = _block_facts_8616(projection, block.addr)
    if facts is None or not _effects_overlay_holds_8616(raw[0], effects[0], facts):
        return None
    prefix = output_prefix_length_8616(projection, block, effects[0])
    if isinstance(prefix, OutputPrefixFailure8616):
        return None
    positions = tuple(index for index, item in enumerate(block.instrs) if item is instruction)
    if len(positions) != 1:
        return None
    index = positions[0] - prefix
    if not 0 <= index < len(raw[0].instrs):
        return None
    source = raw[0].instrs[index]
    if (
        source.op != "CALL" or instruction.op != "CALL"
        or source.addr != instruction.addr or source.origin is None
        or source.origin != instruction.origin
    ):
        return None
    return raw[0], source

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
            or effects_instr.args is not source_instr.args
            or effects_instr.dst is not source_instr.dst
            or replace(source_instr, call_stack_effect=fact.effect)
            != effects_instr
        ):
            return False
    return all(
        0 <= fact.instr_index < len(source_block.instrs)
        and source_block.instrs[fact.instr_index].op == "CALL"
        for fact in facts_by_index.values()
    )
