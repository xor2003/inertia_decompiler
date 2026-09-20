"""Prove fixed call allocations from binary effects and reaching IR values.

Layer: Semantics.
Responsibility: combine frontend-proven stack allocation behavior with an exact
unclobbered allocation operand, before Alias assigns stack storage identities.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Do not infer effects from names, requested sizes, rendered C, or source sidecars.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..call_target_identity import normalize_x86_16_call_target_addr_8616, x86_16_call_targets_equivalent_8616
from ..callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from ..compiler_helpers import (
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_stack_probe_evidence_kind_8616,
)
from ..ir import IRAddress, IRCallStackEffect8616, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from .call_stack_effect_contracts import CallStackEffectFailure8616
from .register_value_preservation import register_value_family_8616

_WORD_BYTES = 2
_WORD_LIMIT = 1 << 16
_AX_FAMILY = register_value_family_8616("ax")


@dataclass(frozen=True, slots=True)
class CallStackAllocationProof8616:
    """A binary-backed returning call effect with its reaching operand origin."""

    callsite_addr: int
    target_addr: int
    value_instruction_addr: int
    allocation_size: int

    def matches(self, summary: CallsiteSummary8616) -> bool:
        """Reject conflicting call identity, argument frame or requested size."""
        same_site = self.callsite_addr == summary.callsite_addr and self.target_addr == summary.target_addr
        near_frame = callsite_machine_frame_kind_8616(summary) is CallsiteMachineFrameKind8616.NEAR
        no_arguments = (
            summary.arg_count == 0 and not summary.arg_widths
            and not summary.push_arg_sources and summary.stack_cleanup in {None, 0}
        )
        request_agrees = summary.stack_probe_allocation_size in {None, self.allocation_size}
        valid_allocation = 0 <= self.allocation_size < _WORD_LIMIT
        return bool(same_site and near_frame and no_arguments and request_agrees
                    and valid_allocation and summary.return_addr is not None)


def resolve_call_stack_allocation_8616(
    summary: CallsiteSummary8616,
    ranges: tuple[IRAddress, ...],
    proof: CallStackAllocationProof8616 | None,
) -> tuple[IRCallStackEffect8616, CallStackEffectFailure8616 | None] | None:
    """Resolve allocating calls without confusing requested and proven effects."""
    if proof is not None and proof.matches(summary):
        return IRCallStackEffect8616(
            net_stack_delta=-proof.allocation_size, preserved_ranges=ranges,
            complete=True, bp_preserved=True,
        ), None
    allocation_expected = proof is not None or summary.stack_probe_helper or summary.stack_probe_allocation_size is not None
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


def binary_stack_allocation_target_8616(
    project: object, instruction: IRInstr, summary: CallsiteSummary8616 | None = None,
) -> int | None:
    """Prove the binary target, requiring summary agreement when supplied."""
    target = instruction.args[0] if instruction.args else None
    if not isinstance(target, IRValue) or target.space is not MemSpace.CONST:
        return None
    if target.const is None or target.offset != 0:
        return None
    target_addr = (normalize_x86_16_call_target_addr_8616(project, target.const)
                   if summary is None else summary.target_addr)
    same_target = target.const == target_addr or x86_16_call_targets_equivalent_8616(
        project, target.const, target_addr,
    )
    if not same_target:
        return None
    evidence = identify_x86_16_compiler_helper_at_8616(project, target_addr)
    if evidence is None or not is_x86_16_stack_probe_evidence_kind_8616(evidence.kind):
        return None
    return target_addr


def collect_call_stack_allocation_proofs_8616(
    project: object,
    artifact: IRFunctionArtifact,
    summaries: Mapping[int, CallsiteSummary8616] | None = None,
) -> dict[int, CallStackAllocationProof8616]:
    """Prove block-local fixed allocations; unknown paths retain normal refusal.

    The immediate is recovered from IR, never the summary's requested size.
    Any write to architectural AX storage or intervening CALL kills the value.
    Values are deliberately not propagated across unproven predecessor joins.
    Native pre-variable-recovery consumers can omit summaries: the binary and
    reaching IR operand remain mandatory, without relying on C call metadata.
    """
    proofs: dict[int, CallStackAllocationProof8616] = {}
    for block in artifact.blocks:
        allocation: int | None = None
        origin: int | None = None
        for instruction in block.instrs:
            destination = instruction.dst
            if isinstance(destination, IRValue) and destination.space is MemSpace.REG and destination.name in _AX_FAMILY:
                allocation = _constant_ax_write(instruction)
                origin = instruction.addr
            if instruction.op != "CALL":
                continue
            site = instruction.addr
            summary = summaries.get(site) if summaries is not None and site is not None else None
            candidate_present = summaries is None or summary is not None
            if candidate_present and allocation is not None and origin is not None and site is not None:
                target = binary_stack_allocation_target_8616(project, instruction, summary)
                if target is not None:
                    proof = CallStackAllocationProof8616(site, target, origin, allocation)
                    if summary is None or proof.matches(summary):
                        proofs[site] = proof
            allocation = None
            origin = None
    return proofs
