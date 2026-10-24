"""Coordinate the named canonical pattern replay over an unknown-entry prefix.

Layer: IR.
Responsibility: replay straight-line prefix state, offer each candidate row to
the registered canonical pattern specs, and preserve all instruction
identities and external capture pins. Typed match/proof/action, per-pattern
policy and audited per-row decisions live in ``canonical_patterns``; the
known-bits owner supplies numeric semantics. No entry register, memory or
environment assumptions are introduced, and no instruction is deleted here.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from . import canonical_patterns
from . import real16_edge_feasibility8616 as kb
from . import scalar_instruction_effects as scalar
from .canonical_patterns import (
    CanonicalPatternConfig8616,
    CanonicalPatternOutcome8616,
    CanonicalPatternSpec8616,
    CanonicalPatternStep8616,
)
from .core import IRBlock, IRInstr
from .dead_temporary_normalization import _collect_block_facts, dead_temporary_normalization_producers_8616
from .real16_path_memory8616 import PathMemory8616


class SelectNormalizationStatus8616(StrEnum):
    """Admission completeness, never emitted-C validation or equivalence status."""

    COMPLETE = "complete"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SelectNormalizationStats8616:
    """SELECT ledger: raw candidates, admitted shapes, replacements and refusals."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class SelectNormalizationResult8616:
    """Original or equivalently rewritten block with its complete evidence ledger.

    ``pattern_steps`` retains the audited per-row decisions of the named
    pattern table; the five admission counters stay commensurable with them.
    """

    block: IRBlock
    status: SelectNormalizationStatus8616
    evidence: SelectNormalizationStats8616
    pattern_steps: tuple[CanonicalPatternStep8616, ...] = ()


def _candidate_8616(row: IRInstr) -> bool:
    """Recognize only operation names registered by the scalar owner."""
    return scalar.frozen_dispatch_lookup(scalar._SELECT_BITS_8616, row.op) is not None


def _reject_service_8616(row: IRInstr, registers: dict[str, int], memory: PathMemory8616) -> bool:
    """Never provide environmental facts to the shared transfer machinery."""
    return False


def _rewrite_prefix_8616(
    block: IRBlock,
    specs: tuple[CanonicalPatternSpec8616, ...],
    config: CanonicalPatternConfig8616,
) -> tuple[IRBlock, int, int, tuple[CanonicalPatternStep8616, ...]]:
    """Replay an unknown-entry prefix, stopping at its first control transfer."""
    tmps: dict[int, tuple[int, int]] = {}
    registers: dict[str, tuple[int, int]] = {}
    instruction_entry: dict[str, tuple[int, int]] = {}
    dirty: set[str] = set()
    current_address: int | None = None
    memory = kb.path_memory_tainted_8616()
    rows: list[IRInstr] = []
    steps: list[CanonicalPatternStep8616] = []
    admitted = rewritten = 0
    for index, row in enumerate(block.instrs):
        if row.op in {"CJMP", "JMP", "RET"}:
            rows.extend(block.instrs[index:])
            break
        if row.addr != current_address:
            current_address = row.addr
            instruction_entry = dict(registers)
            dirty.clear()
        replacement = row
        for spec in specs:
            if not spec.candidate(row):
                continue
            step = canonical_patterns.run_canonical_pattern_8616(
                spec, row, canonical_patterns.CanonicalPatternState8616(registers, tmps), config,
            )
            steps.append(step)
            admitted += int(step.admitted)
            replacement = step.row
            if step.outcome is CanonicalPatternOutcome8616.MATCHED:
                rewritten += 1
            break
        rows.append(replacement)
        registers = kb._kb_transfer_effect_8616(
            replacement, registers, memory, tmps, dirty, instruction_entry, _reject_service_8616,
        )
    return (replace(block, instrs=tuple(rows)) if rewritten else block), admitted, rewritten, tuple(steps)


def normalize_selects_8616(
    block: IRBlock,
    config: CanonicalPatternConfig8616 | None = None,
) -> SelectNormalizationResult8616:
    """Normalize a proven SELECT prefix without deleting rows or changing captures.

    Blocks with no SELECT bypass dependency analysis, policy resolution and
    numeric replay. When every registered pattern is disabled, candidates are
    audited as skipped without claiming admission or refusal. All other
    blocks require complete unique temporary definitions before replay. An
    unknown guard is admitted but unchanged; malformed or unvisited shapes
    count as refused candidates. External-root liveness remains the caller's
    responsibility when performing subsequent dead-temporary deletion.
    """
    raw = sum(_candidate_8616(row) for row in block.instrs)
    if not raw:
        return SelectNormalizationResult8616(
            block, SelectNormalizationStatus8616.COMPLETE,
            SelectNormalizationStats8616(0, 0, 0, 0, 0),
        )
    policy = config if config is not None else canonical_patterns.canonical_pattern_config_8616()
    specs = canonical_patterns.CANONICAL_PATTERN_SPECS_8616
    active = tuple(spec for spec in specs if spec.name not in policy.disabled)
    if not active:
        empty_state = canonical_patterns.CanonicalPatternState8616({}, {})
        steps = tuple(
            canonical_patterns.run_canonical_pattern_8616(spec, row, empty_state, policy)
            for row in block.instrs if _candidate_8616(row)
            for spec in specs if spec.candidate(row)
        )
        return SelectNormalizationResult8616(
            block, SelectNormalizationStatus8616.COMPLETE,
            SelectNormalizationStats8616(raw, 0, 0, 0, 0), steps,
        )
    if _collect_block_facts(block) is None:
        return SelectNormalizationResult8616(
            block, SelectNormalizationStatus8616.UNKNOWN_REFUSE,
            SelectNormalizationStats8616(raw, 0, 0, 0, raw),
        )
    rewritten_block, admitted, rewritten, steps = _rewrite_prefix_8616(block, active, policy)
    failures = raw - admitted
    return SelectNormalizationResult8616(
        rewritten_block,
        SelectNormalizationStatus8616.UNKNOWN_REFUSE if failures else SelectNormalizationStatus8616.COMPLETE,
        SelectNormalizationStats8616(raw, admitted, rewritten, rewritten, failures),
        steps,
    )


def select_normalization_producers_8616() -> tuple[object, ...]:
    """Bind the shared numeric authority registry after module initialization.

    The invocation owner already authenticates the known-bits transfer graph;
    importing it only for this runtime query avoids a second semantic
    registry. The named pattern table and its match/action/config producers
    are part of the same authenticated closure.
    """
    from .real16_invocation_domain import _fused_callee_producers_8616

    return (
        normalize_selects_8616, _candidate_8616, _reject_service_8616,
        _rewrite_prefix_8616,
        canonical_patterns.canonical_pattern_producers_8616,
        *canonical_patterns.canonical_pattern_producers_8616(),
        scalar.scalar_select_result_bits_8616,
        *dead_temporary_normalization_producers_8616(),
        _fused_callee_producers_8616, *_fused_callee_producers_8616(),
        kb._kb_transfer_effect_8616, kb._kb_call_row_8616,
        kb._ordinary_call_target_8616, kb.interrupt_call_vector_8616,
        kb._kb_known_registers_8616, kb._kb_store_row_8616,
        kb._kb_store_span_8616, kb._kb_store_data_8616, kb._kb_eval_atom_8616,
        kb.path_memory_tainted_8616, PathMemory8616.__init__, PathMemory8616.taint,
    )
