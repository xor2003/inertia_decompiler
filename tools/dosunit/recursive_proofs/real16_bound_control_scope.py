"""Layer: dosunit source-bound native control-coordinate admission.

Responsibility: connect local architectural near16 target proofs to the exact
loaded manifest and derived entry domain. This prerequisite grants no dispatch,
frame, fault, environment or whole-binary equivalence theorem.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import Real16CodePrefixProof, _entry
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
from tools.dosunit.recursive_proofs.real16_fetched_code_intake import (
    FetchedPrefixIntake,
    PrefixIntakeReason,
    establish_prefix_intake,
)
from tools.dosunit.recursive_proofs.real16_native_control_scope import (
    ControlScopeReason,
    NativeControlScope,
    native_control_model_hash,
    prove_native_control_scope,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBlockRequest,
    _BindingRun,
    _block_bytes,
    _NativeRefusal,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem


class BoundControlReason(StrEnum):
    """Retain the precise connecting prerequisite that could not close."""

    PROVED = "bound_native_control_coordinates_discharged"
    SOURCE = "bound_native_control_source_refused"
    CONTROL = "bound_native_control_coordinates_unproved"
    MODEL = "bound_native_control_model_changed"
    DEADLINE = "bound_native_control_original_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class BoundControlBlock:
    """One immutable manifest coordinate and its local architectural proof."""

    side: int
    address: int
    size: int
    proof: NativeControlScope


@dataclass(frozen=True, slots=True)
class BoundReal16ControlScope:
    """Complete local scope with both current provenance consumptions retained."""

    status: ProofStatus
    reason: BoundControlReason
    blocks: tuple[BoundControlBlock, ...]
    intakes: tuple[FetchedPrefixIntake, ...]
    model_hash: str
    counters: FactCounters
    detail: str = ""

    @property
    def complete(self) -> bool:
        """Require every block and both complete source/domain consumptions."""
        count = len(self.blocks) + 3
        return (self.status is ProofStatus.PROVED and self.reason is BoundControlReason.PROVED
                and bool(self.blocks) and all(row.proof.complete for row in self.blocks)
                and len(self.intakes) == 2
                and all(row.reason is PrefixIntakeReason.CURRENT for row in self.intakes)
                and self.counters == FactCounters(count, count, count, count, 0))

    @property
    def binary_equivalence_proved(self) -> bool:
        """Local coordinate closure cannot establish program behavior."""
        return False


def bound_control_model_hash() -> str:
    """Seal the authoritative local proof and this manifest connector."""
    digest = hashlib.sha256(native_control_model_hash().encode("ascii"))
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()


def _collect_control_blocks(source: Real16CodePrefixProof,
    loads: tuple[BoundReal16Load, BoundReal16Load],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    scalar: Real16ScalarDomain, limits: LoadedRelationLimits, blocks: list[BoundControlBlock],
) -> tuple[BoundControlReason, str]:
    """Re-read every exact source block and retain each attempted local theorem."""
    for bound in source.blocks:
        limits.check_time()
        row = next(item for item in requests[bound.side]
                   if (item.address, item.size) == (bound.address, bound.size))
        data = _block_bytes(_BindingRun(loads[bound.side], requests[bound.side], limits), row)
        if hashlib.sha256(data).hexdigest() != bound.byte_hash:
            return BoundControlReason.SOURCE, "initialized block differs from prefix bytes"
        entry, domain = _entry(loads[bound.side], bound.address, scalar)
        proof = prove_native_control_scope(data, bound.address, entry, domain, deadline=limits.deadline)
        blocks.append(BoundControlBlock(bound.side, bound.address, bound.size, proof))
        if not proof.complete:
            reason = (BoundControlReason.DEADLINE if proof.reason is ControlScopeReason.DEADLINE
                      else BoundControlReason.CONTROL)
            return reason, proof.reason.value
    return BoundControlReason.PROVED, ""


def prove_bound_real16_control_scope(source: Real16CodePrefixProof, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, limits: LoadedRelationLimits,
) -> BoundReal16ControlScope:
    """Check all source-bound exits within the caller's unchanged deadline.

    The parent must separately consume initiation, dispatch and frame closure
    before using the local execution-cutpoint premise as a component theorem.
    """
    required = 3 + sum(len(rows) for rows in requests)
    blocks: list[BoundControlBlock] = []
    intakes: list[FetchedPrefixIntake] = []
    model, detail = "", ""
    fixed = 0
    reason = BoundControlReason.SOURCE
    try:
        limits.check_time()
        model = bound_control_model_hash()
        intake = establish_prefix_intake(source, system, loads, initialized, bootstrap, requests, limits=limits)
        intakes.append(intake)
        if intake.reason is PrefixIntakeReason.CURRENT and source.receipt is not None and source.receipt.domain is not None:
            fixed += 1
            scalar = source.receipt.domain.domain
            reason = BoundControlReason.PROVED
            reason, detail = _collect_control_blocks(source, loads, requests, scalar, limits, blocks)
            if reason is BoundControlReason.PROVED:
                final = establish_prefix_intake(source, system, loads, initialized, bootstrap, requests, limits=limits)
                intakes.append(final)
                if final.reason is not PrefixIntakeReason.CURRENT:
                    reason = (BoundControlReason.DEADLINE if final.reason is PrefixIntakeReason.DEADLINE
                              else BoundControlReason.SOURCE)
                    detail = final.detail
                else:
                    fixed += 1
                    if model != bound_control_model_hash():
                        reason = BoundControlReason.MODEL
                    else:
                        limits.check_time()
                        fixed += 1
        else:
            reason = (BoundControlReason.DEADLINE if intake.reason is PrefixIntakeReason.DEADLINE
                      else BoundControlReason.SOURCE)
            detail = intake.detail
    except LoadedRelationRefusal as refusal:
        reason = (BoundControlReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE
                  else BoundControlReason.SOURCE)
        detail = str(refusal)
    except TimeoutError as refusal:
        reason, detail = BoundControlReason.DEADLINE, str(refusal)
    except (ImageBindingRefusal, _NativeRefusal) as refusal:
        reason, detail = BoundControlReason.SOURCE, str(refusal)
    done = fixed + sum(row.proof.complete for row in blocks)
    status = ProofStatus.PROVED if reason is BoundControlReason.PROVED and done == required else ProofStatus.UNKNOWN
    if any(row.proof.status is ProofStatus.COUNTEREXAMPLE for row in blocks):
        status = ProofStatus.COUNTEREXAMPLE
    return BoundReal16ControlScope(status, reason, tuple(blocks), tuple(intakes), model,
        FactCounters(required, required, required, fixed + len(blocks), required - done), detail)
