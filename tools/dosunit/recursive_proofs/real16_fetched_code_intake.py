"""Layer: dosunit fetched-code provenance intake.

Responsibility: bind a reusable prefix theorem to the actual invocation using
the authoritative complete source/domain consumer. Byte equality alone cannot
transfer a theorem to different loader registers or scalar predicates.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    CodePrefixReason,
    Real16CodePrefixProof,
    code_prefix_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import BoundDomainReason
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockRequest
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash


class PrefixIntakeReason(StrEnum):
    """Typed intake result; no intake result establishes binary equivalence."""

    CURRENT = "fetched_prefix_current_source_domain"
    SOURCE = "fetched_prefix_source_or_manifest_refused"
    MODEL = "fetched_prefix_model_or_proposal_changed"
    DEADLINE = "fetched_prefix_source_original_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class FetchedPrefixIntake:
    """Retain partial identity and the complete consumer's attempted evidence."""

    reason: PrefixIntakeReason
    prefix_current: bool = False
    prefix_model: str = ""
    proposal_hash: str = ""
    consumption: BoundDomainConsumption | None = None
    detail: str = ""


def prefix_manifest_matches(source: Real16CodePrefixProof,
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
) -> bool:
    """Validate exact requests and ranges before any side indexes a manifest."""
    expected = tuple((side, row.address, row.size) for side, rows in enumerate(requests) for row in rows)
    actual = tuple((row.side, row.address, row.size) for row in source.blocks)
    count = 3 + len(expected)
    if (source.status is not ProofStatus.PROVED or source.reason is not CodePrefixReason.PRESERVED
            or len(source.consumers) != 2 or not all(row.complete for row in source.consumers)):
        return False
    if (actual != expected or len(set(actual)) != len(actual) or source.requests != requests
            or source.counters != FactCounters(count, count, count, count, 0)):
        return False
    return all(block.complete and block.protected_ranges == tuple((row.address, row.size) for row in requests[block.side])
               for block in source.blocks)


def establish_prefix_intake(source: Real16CodePrefixProof, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, limits: LoadedRelationLimits,
) -> FetchedPrefixIntake:
    """Reconsume producer provenance under current files, snapshots and domain.

    This uses the original absolute deadline. Consumer revalidation, rather
    than a competing local snapshot/schema check, owns the source relation.
    """
    limits.check_time()
    if source.receipt is None or not prefix_manifest_matches(source, requests):
        return FetchedPrefixIntake(PrefixIntakeReason.SOURCE, detail="prefix provenance or exact manifest is missing")
    model = code_prefix_model_hash()
    proposal = joint_proposal_hash(system, bootstrap)
    if source.model_hash != model or source.proposal_hash != proposal:
        return FetchedPrefixIntake(PrefixIntakeReason.MODEL, prefix_model=model,
            proposal_hash=proposal, detail="prefix source content or model changed")
    child = consume_image_bound_real16_domain(source.receipt, system, loads, initialized,
        bootstrap, requests, timeout_ms=2**31 - 1, limits=limits)
    if not child.complete:
        reason = PrefixIntakeReason.DEADLINE if child.reason is BoundDomainReason.DEADLINE else PrefixIntakeReason.SOURCE
        return FetchedPrefixIntake(reason, True, model, proposal, child, f"{child.reason.value}: {child.detail}")
    limits.check_time()
    return FetchedPrefixIntake(PrefixIntakeReason.CURRENT, True, model, proposal, child)
