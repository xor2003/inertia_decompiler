"""Layer: dosunit source-bound native operand scope (staging).

Responsibility: connect fresh logical operand proofs to consumed immutable MZ
requests and their established entry domains. Reuse the source/code-prefix owner;
physical permissions, fault outcomes and binary equivalence remain independent.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, replace
from enum import StrEnum

from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    Real16CodePrefixProof,
    _entry,
    code_prefix_model_hash,
    prove_real16_code_prefixes,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import BoundDomainReason, ImageBoundReal16Domain
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBlockRequest,
    _BindingRun,
    _block_bytes,
    _NativeRefusal,
)
from tools.dosunit.recursive_proofs.real16_operand_scope_proof import (
    NativeOperandScopeProof,
    OperandProofReason,
    operand_scope_model_hash,
    prove_native_operand_scope,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.register_state_relations import MachineState


class BoundOperandReason(StrEnum):
    """The exact local closure or the prerequisite still withholding admission."""

    PROVED = "bound_original_operand_scope_discharged"
    SOURCE = "bound_operand_source_or_code_prefix_refused"
    SCOPE = "bound_original_operand_scope_unproved"
    RECEIPT = "bound_operand_final_receipt_refused"
    MODEL = "bound_operand_model_changed"
    DEADLINE = "bound_operand_original_deadline_exhausted"
    RESOURCE = "bound_operand_resource_limit"


@dataclass(frozen=True, slots=True)
class BoundOperandBlock:
    """One immutable block's locally discharged coordinates and original widths."""

    side: int
    address: int
    size: int
    proof: NativeOperandScopeProof


@dataclass(frozen=True, slots=True)
class BoundReal16OperandScope:
    """Complete source/domain connection without allocation or fault closure."""

    status: ProofStatus
    reason: BoundOperandReason
    source: Real16CodePrefixProof
    blocks: tuple[BoundOperandBlock, ...]
    consumption: BoundDomainConsumption | None
    model_hash: str
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Operand scope leaves physical, fault, environment and relational proofs open."""
        return False


def bound_operand_model_hash() -> str:
    """Seal both authoritative producers and this connecting theorem."""
    from pathlib import Path

    digest = hashlib.sha256(code_prefix_model_hash().encode("ascii"))
    digest.update(operand_scope_model_hash().encode("ascii"))
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()


def _collect_blocks(receipt: ImageBoundReal16Domain,
                    loads: tuple[BoundReal16Load, BoundReal16Load],
                    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
                    source: Real16CodePrefixProof, limits: LoadedRelationLimits,
                    blocks: list[BoundOperandBlock]) -> BoundOperandReason:
    """Reuse consumed manifests and independently re-read/decode each operand block."""
    if source.status is not ProofStatus.PROVED or source.counters.failure_count or receipt.domain is None:
        return BoundOperandReason.SOURCE
    expected = tuple((side, row.address, row.size) for side, rows in enumerate(requests) for row in rows)
    actual = tuple((row.side, row.address, row.size) for row in source.blocks)
    if actual != expected or len(set(actual)) != len(actual) or not all(row.complete for row in source.blocks):
        return BoundOperandReason.SOURCE
    for bound in source.blocks:
        limits.check_time()
        row = next(item for item in requests[bound.side] if item.address == bound.address and item.size == bound.size)
        data = _block_bytes(_BindingRun(loads[bound.side], requests[bound.side], limits), row)
        if hashlib.sha256(data).hexdigest() != bound.byte_hash:
            return BoundOperandReason.SOURCE
        entry, domain = _entry(loads[bound.side], bound.address, receipt.domain.domain)
        proof = prove_native_operand_scope(data, bound.address, entry, domain,
                                           timeout_ms=2**31 - 1, deadline=limits.deadline)
        blocks.append(BoundOperandBlock(bound.side, bound.address, bound.size, proof))
        if proof.status is not ProofStatus.PROVED or proof.counters.failure_count:
            return BoundOperandReason.DEADLINE if proof.reason is OperandProofReason.DEADLINE else BoundOperandReason.SCOPE
    return BoundOperandReason.PROVED


def _status(reason: BoundOperandReason, done: int, required: int, source: Real16CodePrefixProof,
            blocks: list[BoundOperandBlock]) -> ProofStatus:
    """Preserve modeled counterexamples and require every mandatory obligation."""
    if source.status is ProofStatus.COUNTEREXAMPLE or any(row.proof.status is ProofStatus.COUNTEREXAMPLE for row in blocks):
        return ProofStatus.COUNTEREXAMPLE
    return ProofStatus.PROVED if reason is BoundOperandReason.PROVED and done == required else ProofStatus.UNKNOWN


def prove_bound_real16_operand_scope(receipt: ImageBoundReal16Domain, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 15000, limits: LoadedRelationLimits | None = None) -> BoundReal16OperandScope:
    """Prove native operand scope only after consumed complete immutable source evidence."""
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("bound operand scope requires a nonnegative finite millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    selected = replace(selected, deadline=deadline)
    source = prove_real16_code_prefixes(receipt, system, loads, initialized, bootstrap, requests,
                                       timeout_ms=2**31 - 1, limits=selected)
    count = 3 + 2 * (len(system.steps) + 1)
    fixed = int(source.status is ProofStatus.PROVED and source.counters.failure_count == 0)
    blocks: list[BoundOperandBlock] = []
    consumption: BoundDomainConsumption | None = None
    model, detail = "", ""
    reason = BoundOperandReason.SOURCE
    try:
        selected.check_time()
        model = bound_operand_model_hash()
        reason = _collect_blocks(receipt, loads, requests, source, selected, blocks)
        if reason is BoundOperandReason.PROVED:
            consumption = consume_image_bound_real16_domain(receipt, system, loads, initialized,
                bootstrap, requests, timeout_ms=2**31 - 1, limits=selected)
            if consumption.status is not ProofStatus.PROVED or consumption.counters.failure_count:
                reason = (BoundOperandReason.DEADLINE if consumption.reason is BoundDomainReason.DEADLINE
                          else BoundOperandReason.RECEIPT)
                detail = consumption.detail
            else:
                fixed += 1
                if model != bound_operand_model_hash():
                    reason = BoundOperandReason.MODEL
                else:
                    selected.check_time()
                    fixed += 1
    except TimeoutError as refusal:
        reason, detail = BoundOperandReason.DEADLINE, str(refusal)
    except LoadedRelationRefusal as refusal:
        reason = (BoundOperandReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE
                  else BoundOperandReason.RESOURCE)
        detail = str(refusal)
    except (ImageBindingRefusal, _NativeRefusal) as refusal:
        reason, detail = BoundOperandReason.SOURCE, str(refusal)
    done = fixed + sum(row.proof.status is ProofStatus.PROVED and row.proof.counters.failure_count == 0 for row in blocks)
    status = _status(reason, done, count, source, blocks)
    if not detail and blocks:
        detail = blocks[-1].proof.detail
    return BoundReal16OperandScope(status, reason, source, tuple(blocks), consumption, model,
        FactCounters(count, count, count, fixed + len(blocks), count - done), detail or source.detail)
