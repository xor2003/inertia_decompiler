"""Retain guarded allocation identity and requests without effect authority.

Layer: Semantics.
Responsibility: retain binary helper identity and reaching allocation operands,
then refuse unproved guard continuations before Alias assigns storage identities.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Do not infer effects from names, requested sizes, rendered C, or source sidecars.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from inertia.ir.core import IRCallStackEffect8616, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.semantics.call_target_identity import (
    normalize_x86_16_call_target_addr_8616,
    x86_16_call_targets_equivalent_8616,
)
from inertia.semantics.callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
)
from inertia.semantics.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    identify_x86_16_compiler_helper_at_8616,
)

from .call_stack_effect_contracts import CallStackEffectFailure8616
from .register_value_preservation import register_value_family_8616

_WORD_BYTES = 2
_WORD_LIMIT = 1 << 16
_AX_FAMILY = register_value_family_8616("ax")


@dataclass(frozen=True, slots=True)
class CallStackAllocationCandidate8616:
    """A guarded probe call's known request provenance, frame and identity.

    STACK_PROBE pattern identity is labeling evidence only: the helper's carry
    and DS-limit guards are conditional failure exits that native executions
    reach, so identity alone never authorizes an unconditional allocation.
    Candidates exist so consumers refuse the call explicitly instead of
    falling through to the balanced zero-argument ABI. The request fields are
    None when no unclobbered constant AX write reaches the site.
    """

    callsite_addr: int
    target_addr: int
    value_instruction_addr: int | None
    allocation_size: int | None
    frame_kind: CallsiteMachineFrameKind8616


def resolve_call_stack_allocation_8616(
    summary: CallsiteSummary8616,
    candidate: CallStackAllocationCandidate8616 | None,
) -> tuple[IRCallStackEffect8616, CallStackEffectFailure8616 | None] | None:
    """Refuse guarded allocation candidates; ordinary calls keep normal handling.

    No authenticated owner discharges the probe's failure guards, so every
    binary-backed candidate resolves as STACK_ALLOCATION_UNPROVEN.
    """
    allocation_expected = (
        candidate is not None or summary.stack_probe_helper
        or summary.stack_probe_allocation_size is not None
    )
    if allocation_expected:
        return IRCallStackEffect8616(complete=False), CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN
    return None


def _constant_ax_write(instruction: IRInstr) -> int | None:
    """Accept a complete direct AX constant assignment, not partial arithmetic."""
    destination = instruction.dst
    source = instruction.args[0] if instruction.args else None
    exact_word = isinstance(destination, IRValue) and destination.name == "ax" and destination.size == _WORD_BYTES
    if instruction.op != "MOV" or not exact_word or not isinstance(source, IRValue):
        return None
    if source.space is not MemSpace.CONST or source.offset != 0 or source.size != _WORD_BYTES:
        return None
    value = source.const
    return value if isinstance(value, int) and 0 <= value < _WORD_LIMIT else None


def _binary_stack_allocation_target_frame_8616(
    project: object, instruction: IRInstr, summary: CallsiteSummary8616 | None = None,
) -> tuple[int, CallsiteMachineFrameKind8616] | None:
    """Identify the target and near/far frame; this does not prove effects."""
    target = instruction.args[0] if instruction.args else None
    if not isinstance(target, IRValue) or target.space is not MemSpace.CONST:
        return None
    if target.const is None or target.offset != 0:
        return None
    target_addr = (normalize_x86_16_call_target_addr_8616(project, target.const)
                   if summary is None else summary.target_addr)
    if target_addr is None:
        return None
    same_target = target.const == target_addr or x86_16_call_targets_equivalent_8616(
        project, target.const, target_addr,
    )
    if not same_target:
        return None
    evidence = identify_x86_16_compiler_helper_at_8616(project, target_addr)
    if evidence is None:
        return None
    if evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE:
        return target_addr, CallsiteMachineFrameKind8616.NEAR
    if evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR:
        return target_addr, CallsiteMachineFrameKind8616.FAR
    return None


def binary_stack_allocation_target_8616(
    project: object, instruction: IRInstr, summary: CallsiteSummary8616 | None = None,
) -> int | None:
    """Project the exact binary target for consumers that do not need its frame."""
    evidence = _binary_stack_allocation_target_frame_8616(project, instruction, summary)
    return None if evidence is None else evidence[0]


def collect_call_stack_allocation_candidates_8616(
    project: object,
    artifact: IRFunctionArtifact,
    summaries: Mapping[int, CallsiteSummary8616] | None = None,
) -> dict[int, CallStackAllocationCandidate8616]:
    """Collect guarded probe candidates; unknown paths retain normal refusal.

    The immediate is recovered from IR, never the summary's requested size.
    Any write to architectural AX storage or intervening CALL kills the value.
    Values are deliberately not propagated across unproven predecessor joins.
    Native pre-variable-recovery consumers can omit summaries: the binary and
    request provenance is retained when available, without relying on C metadata.
    Guarded identity candidates stay recorded even when the reaching request
    is unknown or the summary is unmarked, so the consumer refuses explicitly
    instead of falling through to the balanced zero-argument ABI.
    """
    candidates: dict[int, CallStackAllocationCandidate8616] = {}
    for block in artifact.blocks:
        allocation: int | None = None
        origin: int | None = None
        for instruction in block.instrs:
            destination = instruction.dst
            if isinstance(destination, IRValue) and destination.space is MemSpace.REG and destination.name in _AX_FAMILY:
                allocation = _constant_ax_write(instruction)
                origin = instruction.addr if allocation is not None else None
            if instruction.op != "CALL":
                continue
            site = instruction.addr
            summary = summaries.get(site) if summaries is not None and site is not None else None
            candidate_present = summaries is None or summary is not None
            if candidate_present and site is not None:
                target_frame = _binary_stack_allocation_target_frame_8616(project, instruction, summary)
                if target_frame is not None:
                    target, frame_kind = target_frame
                    # Keep guarded identity candidates so the consumer refuses
                    # the call instead of falling back to a zero-allocation ABI.
                    candidates[site] = CallStackAllocationCandidate8616(
                        site, target, origin, allocation, frame_kind,
                    )
            allocation = None
            origin = None
    return candidates
