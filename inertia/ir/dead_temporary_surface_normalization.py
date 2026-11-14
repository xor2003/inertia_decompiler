# cython: language_level=3, infer_types=True
"""Normalize dead scalar temporaries without losing imported byte coverage.

Layer: IR.
Responsibility: join retained capture roots and instruction-address anchors with
the authoritative block-local deletion proof before publishing a lift surface.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import cython

from collections.abc import Mapping
from dataclasses import dataclass

from .canonical_patterns import CanonicalPatternConfig8616, canonical_pattern_census_8616
from .condition_lift_capture import ConditionLiftCaptureSession8616
from .core import IRBlock, IRValue, MemSpace
from .dead_temporary_capture_inputs import (
    DeadTemporaryBlockCaptureInputs8616,
    DeadTemporaryCaptureStatus8616,
    select_dead_temporary_capture_inputs_8616,
)
from .dead_temporary_normalization import (
    DeadTemporaryNormalizationResult8616,
    dead_temporary_normalization_producers_8616,
    normalize_dead_temporaries_8616,
    refuse_dead_temporary_normalization_8616,
)
from .logical_memory_capture import IRLogicalMemoryCaptureRecord8616
from .select_normalization import (
    SelectNormalizationResult8616,
    normalize_selects_8616,
    select_normalization_producers_8616,
)
from .vex_terminal_jump import TerminalJumpEvidence8616
import dataclasses
import builtins


@dataclasses.dataclass(frozen=True, )
class DeadTemporarySurfaceNormalizationResult8616:
    """Retain each block's deletion decisions and closed evidence counts."""

    results: object
    selection_results: tuple[SelectNormalizationResult8616, ...] = ()

    @property
    def blocks(self) -> tuple[IRBlock, ...]:
        """Return the exact normalized or conservatively retained block tuple."""
        return tuple(result.block for result in iter(self.results))

    def to_summary(self) -> object:
        """Publish the five aggregate counts without claiming function proof."""
        summary = {
            "dead_temporary_raw_fact_count": sum(r.evidence.raw_fact_count for r in iter(self.results)),
            "dead_temporary_normalized_fact_count": sum(r.evidence.normalized_fact_count for r in iter(self.results)),
            "dead_temporary_classified_fact_count": sum(r.evidence.classified_fact_count for r in iter(self.results)),
            "dead_temporary_materialized_count": sum(r.evidence.materialized_count for r in iter(self.results)),
            "dead_temporary_failure_count": sum(r.evidence.failure_count for r in iter(self.results)),
        }
        if any(r.evidence.raw_fact_count for r in iter(self.selection_results)):
            summary.update({
                "select_raw_fact_count": sum(r.evidence.raw_fact_count for r in iter(self.selection_results)),
                "select_normalized_fact_count": sum(r.evidence.normalized_fact_count for r in iter(self.selection_results)),
                "select_classified_fact_count": sum(r.evidence.classified_fact_count for r in iter(self.selection_results)),
                "select_materialized_count": sum(r.evidence.materialized_count for r in iter(self.selection_results)),
                "select_failure_count": sum(r.evidence.failure_count for r in iter(self.selection_results)),
            })
        pattern_steps = [step for r in iter(self.selection_results) for step in iter(r.pattern_steps)]
        if pattern_steps:
            summary.update({
                f"canonical_pattern_{key}_count": count
                for key, count in builtins.iter(canonical_pattern_census_8616(pattern_steps).items())
            })
        return summary


@cython.ccall
def _instruction_anchor_roots_8616(block: IRBlock) -> object:
    """Keep the first original row at every instruction address and its inputs.

    The native byte census depends on retained instruction coordinates. A TMP
    definition at the first row therefore remains live even if its value has
    no semantic consumer. Unknown coordinates cannot authorize normalization.
    """
    instruction: object
    addresses: set[cython.longlong] = set()
    roots: set[cython.longlong] = set()
    for instruction in block.instrs:
        if type(instruction.addr) is not int or instruction.addr < 0:
            return None
        if instruction.addr in addresses:
            continue
        addresses.add(instruction.addr)
        destination = instruction.dst
        if type(destination) is IRValue and destination.space is MemSpace.TMP:
            if type(destination.source_tmp) is not int or destination.source_tmp < 0:
                return None
            roots.add(destination.source_tmp)
    return frozenset(roots)


def _normalize_captured_block_8616(
    block: IRBlock, capture: DeadTemporaryBlockCaptureInputs8616,
) -> DeadTemporaryNormalizationResult8616:
    """Require complete capture ownership and preserve instruction coverage."""
    anchors: object
    if capture.status is DeadTemporaryCaptureStatus8616.UNKNOWN_REFUSE:
        return refuse_dead_temporary_normalization_8616(block)
    anchors = _instruction_anchor_roots_8616(block)
    if anchors is None:
        return refuse_dead_temporary_normalization_8616(block)
    result = normalize_dead_temporaries_8616(
        block, external_payloads=capture.payloads, external_live_tmp_ids=anchors,
    )
    original_addresses = frozenset(instruction.addr for instruction in iter(block.instrs))
    normalized_addresses = frozenset(instruction.addr for instruction in iter(result.block.instrs))
    if original_addresses != normalized_addresses:
        return refuse_dead_temporary_normalization_8616(block)
    return result


@cython.ccall
def normalize_dead_temporary_surface_8616(
    blocks: object,
    condition_capture: ConditionLiftCaptureSession8616,
    captured_accesses: object,
    terminal_evidence: Mapping[cython.longlong, TerminalJumpEvidence8616],
    *,
    pattern_config: CanonicalPatternConfig8616 | None = None,
) -> DeadTemporarySurfaceNormalizationResult8616:
    """Normalize once after whole-function capture and before ownership finish.

    ``pattern_config`` is forwarded unchanged to the named canonical pattern
    table; ``None`` resolves the typed environment policy per block replay.
    """
    block: object
    capture: object
    captures = select_dead_temporary_capture_inputs_8616(
        blocks, condition_capture, captured_accesses, terminal_evidence,
    )
    results: list[DeadTemporaryNormalizationResult8616] = []
    selections: list[SelectNormalizationResult8616] = []
    for block, capture in zip(blocks, captures.blocks, strict=True):
        if (capture.status is not DeadTemporaryCaptureStatus8616.UNKNOWN_REFUSE
                and _instruction_anchor_roots_8616(block) is not None):
            selection = normalize_selects_8616(block, config=pattern_config)
            selections.append(selection)
            block = selection.block
        results.append(_normalize_captured_block_8616(block, capture))
    return DeadTemporarySurfaceNormalizationResult8616(tuple(results), tuple(selections))


@cython.ccall
def dead_temporary_surface_producers_8616() -> tuple[object, ...]:
    """Bind every normalization authority used by raw/canonical lift caching."""
    return (
        normalize_dead_temporary_surface_8616,
        _normalize_captured_block_8616,
        _instruction_anchor_roots_8616,
        select_dead_temporary_capture_inputs_8616,
        *dead_temporary_normalization_producers_8616(),
        *select_normalization_producers_8616(),
    )
