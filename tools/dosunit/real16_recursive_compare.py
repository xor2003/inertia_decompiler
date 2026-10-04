"""Layer: dosunit public real16 recursive joint-proof adapter.

Responsibility: bridge the ordinary ``compare_binary16`` report path to the
reviewed image-bound recursive joint checker. Proposals are derived only from
the supplied sealed SSA documents, executable bytes and public load metadata —
never from caller-supplied machine states or pre-proved receipts. One absolute
deadline covers admission, proposal construction, binding and both proof
stages; every delegated stage is additionally capped at its own established
budget and never granted the whole remaining allowance. A typed refusal
replaces rows for no obligation and leaves every requested function in the
original denominator. A discharged joint covers component members only and
retains its declared environment scope, open model requirements and proved
initialized-image entry domain separately. It never replaces the public
obligation's wider arbitrary-entry evidence.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import capstone

from tools.dosunit import straightline_ssa as S
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import Real16CallRefusal, initial_state
from tools.dosunit.real16_call_evidence import group_functions
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import (
    BoundReal16Load,
    ImageBindingRefusal,
    bind_real16_mz,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
    propose_loaded_byte_relation,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import prove_loaded_byte_relation
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16DomainProof, Real16ScalarDomain, native_effect_hash
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    ImageBoundReal16Domain,
    prove_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_joint_proof import (
    ImageBoundReal16JointProof,
    check_image_bound_real16_joint,
)
from tools.dosunit.recursive_proofs.real16_joint_construction import build_real16_joint_system
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockRequest
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    EnvironmentScopeMember,
    JointReason,
    JointSystem,
    Real16EnvironmentScope,
)
from tools.dosunit.register_state_relations import MachineState

REPORT_SCHEMA: str = "dosunit.binary16_compare.recursive_joint.v1"
_CONTROL_GROUPS = frozenset((capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET))

# Each delegated owner keeps its own established millisecond budget. The
# request's total deadline is shared absolutely and never enlarges a child:
# every child call receives ``min(remaining, owner default)``.
_CONSTRUCTION_BUDGET_MS: int = 20_000  # build_real16_joint_system default
_LOADED_RELATION_BUDGET_MS: int = 10_000  # prove_loaded_byte_relation default
_DOMAIN_BUDGET_MS: int = 30_000  # prove_image_bound_real16_domain default
_JOINT_BUDGET_MS: int = 120_000  # check_image_bound_real16_joint default


class RecursiveCompareReason(StrEnum):
    """Exact boundary where the public recursive attempt refused."""

    ADMISSION = "recursive_admission_incomplete"
    LOAD = "recursive_load_binding_refused"
    STALE = "recursive_executable_bytes_stale"
    ENTRY = "recursive_entry_block_unavailable"
    REQUEST = "recursive_block_request_refused"
    DOMAIN = "recursive_domain_receipt_refused"
    JOINT = "recursive_joint_proof_refused"
    DEADLINE = "recursive_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class Real16RecursiveRequest:
    """Typed opt-in for the image-bound recursive joint path.

    ``closed_machine`` declares the complete asynchronous-machine exclusion
    premise; the adapter binds it to both actual executable hashes, so a
    declaration is always a visible assumption, never an unconditional pass.
    ``declared_scope`` may instead carry a caller-built premise; a premise
    bound to different executable content cannot close ENVIRONMENT and simply
    leaves it open. Both fields set is a malformed request.
    """

    timeout_ms: int = 240_000
    max_roots: int = 16
    closed_machine: bool = False
    declared_scope: Real16EnvironmentScope | None = None
    provenance: str = ""

    def __post_init__(self) -> None:
        """Reject budgets and premise shapes the adapter cannot honor."""
        if type(self.timeout_ms) is not int or self.timeout_ms < 0:
            raise ValueError("recursive request requires a nonnegative millisecond budget")
        if type(self.max_roots) is not int or not 0 < self.max_roots <= 64:
            raise ValueError("recursive request requires one through 64 attempted roots")
        if type(self.closed_machine) is not bool:
            raise ValueError("closed_machine must be a typed boolean declaration")
        if self.declared_scope is not None:
            if not isinstance(self.declared_scope, Real16EnvironmentScope):
                raise ValueError("declared_scope must be a typed environment premise")
            if self.closed_machine:
                raise ValueError("closed_machine and an explicit declared_scope cannot both be supplied")
        if type(self.provenance) is not str:
            raise ValueError("recursive provenance must be a text tag")


@dataclass(frozen=True, slots=True)
class RecursiveAttempt:
    """One refused root retained for the public report."""

    root: str
    reason: JointReason  # owned enum; serialized via ``.value`` only
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RecursiveDomainScope:
    """Immutable metadata from a consumed domain receipt, not a new theorem.

    Model/proposal/snapshot identities retain the exact receipt and remain
    visible in the public JSON projection for dependency auditing.
    """

    original_sha256: str
    candidate_sha256: str
    entry_linear: tuple[int, int]
    root_linear: int
    scalars: Real16ScalarDomain
    snapshot_hashes: tuple[str, str]
    domain_model_hash: str
    scalar_model_hash: str
    proposal_hash: str

    def __post_init__(self) -> None:
        """Require immutable scalar identities, not mutable nested payloads."""
        if not isinstance(self.scalars, Real16ScalarDomain):
            raise ValueError("recursive scope requires a typed scalar domain")
        if type(self.entry_linear) is not tuple or len(self.entry_linear) != 2:
            raise ValueError("recursive scope requires two immutable entries")
        if any(type(value) is not int or not 0 <= value < 0x100000
               for value in (*self.entry_linear, self.root_linear)):
            raise ValueError("recursive scope requires real-mode linear entries")
        if type(self.snapshot_hashes) is not tuple or len(self.snapshot_hashes) != 2:
            raise ValueError("recursive scope requires two immutable snapshot identities")
        identities = (self.original_sha256, self.candidate_sha256, *self.snapshot_hashes,
                      self.domain_model_hash, self.scalar_model_hash, self.proposal_hash)
        if any(type(value) is not str or not value for value in identities):
            raise ValueError("recursive scope requires nonempty receipt identities")

    def to_document(self) -> dict[str, Any]:
        """Create a fresh JSON projection without exposing mutable owned state."""
        return {
            "kind": "initialized_mz_image",
            "entry_linear": list(self.entry_linear),
            "root_linear": self.root_linear,
            "ss": self.scalars.ss,
            "cs": self.scalars.cs,
            "sp_alignment": self.scalars.alignment,
            "initialized_loaded_relation": True,
            "arbitrary_entry_states_proved": False,
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "snapshot_hashes": list(self.snapshot_hashes),
            "domain_model_hash": self.domain_model_hash,
            "scalar_model_hash": self.scalar_model_hash,
            "proposal_hash": self.proposal_hash,
        }


@dataclass(frozen=True, slots=True)
class RecursiveCompareOutcome:
    """Complete recursive attempt state for the public report; never a boolean."""

    attempted: bool
    status: ProofStatus
    reason: RecursiveCompareReason | JointReason  # owned enum; .value at serialization
    nested_reason: StrEnum | None = None  # delegated child's typed reason, if any
    member_ids: tuple[str, ...] = ()
    domain_scope: RecursiveDomainScope | None = None
    assumptions: tuple[str, ...] = ()
    counters: FactCounters = field(default_factory=FactCounters)
    root: str = ""
    proposal_hash: str = ""
    model_hash: str = ""
    remaining: tuple[str, ...] = ()
    attempts: tuple[RecursiveAttempt, ...] = ()
    detail: str = ""
    proof: ImageBoundReal16JointProof | None = None

    def __post_init__(self) -> None:
        """Reject mutable dictionaries at the owned scope boundary."""
        if self.domain_scope is not None and not isinstance(self.domain_scope, RecursiveDomainScope):
            raise ValueError("recursive domain scope requires immutable typed metadata")

    def to_document(self) -> dict[str, Any]:
        """Serialize the retained state; assumptions stay visible downstream."""
        return {
            "schema": REPORT_SCHEMA,
            "attempted": self.attempted,
            "status": self.status.value,
            "reason": self.reason.value,
            "nested_reason": self.nested_reason.value if self.nested_reason is not None else None,
            "root": self.root or None,
            "members": list(self.member_ids),
            "assumptions": list(self.assumptions),
            "remaining_requirements": list(self.remaining),
            "proposal_hash": self.proposal_hash,
            "model_hash": self.model_hash,
            "counters": {
                "raw_fact_count": self.counters.raw_fact_count,
                "normalized_fact_count": self.counters.normalized_fact_count,
                "classified_fact_count": self.counters.classified_fact_count,
                "materialized_count": self.counters.materialized_count,
                "failure_count": self.counters.failure_count,
            },
            "attempts": [
                {"root": attempt.root, "reason": attempt.reason.value, "detail": attempt.detail}
                for attempt in self.attempts
            ],
            "domain_scope": self.domain_scope.to_document() if self.domain_scope is not None else None,
            "joint": (
                None
                if self.proof is None
                else {
                    "status": self.proof.status.value,
                    "reason": self.proof.reason.value,
                    "detail": self.proof.detail,
                    "binary_equivalence_proved": self.proof.binary_equivalence_proved,
                }
            ),
            "detail": self.detail,
        }


class _AdapterRefusal(Exception):
    """Internal typed boundary; never leaves this module as an exception."""

    def __init__(self, reason: RecursiveCompareReason, detail: str,
                 nested: StrEnum | None = None) -> None:
        """Retain the typed reason, its detail and any delegated child reason."""
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.nested = nested


def _load_segment(image: dict[str, Any]) -> int:
    """Derive the MZ load paragraph from the actual lifter load coordinate."""
    base = image.get("mapped_base")
    if type(base) is not int or base % 16 or not 0 <= base <= 0xF0000:
        raise _AdapterRefusal(
            RecursiveCompareReason.LOAD,
            "lifter mapped base does not provide a paragraph-aligned MZ load segment",
        )
    return base >> 4


def _bind_load(document: dict[str, Any], image: dict[str, Any], expected_hash: str,
               limits: LoadedRelationLimits) -> BoundReal16Load:
    """Bind fresh executable bytes and require them to equal the sealed digest."""
    path = document.get("exe")
    if not isinstance(path, str):
        raise _AdapterRefusal(RecursiveCompareReason.LOAD, "document lacks its executable identity")
    load = bind_real16_mz(Path(path).read_bytes(), load_segment=_load_segment(image), limits=limits)
    if load.binding.file_sha256 != expected_hash:
        raise _AdapterRefusal(RecursiveCompareReason.STALE, "bound executable differs from the report digest")
    return load


def _entry_bootstrap(document: dict[str, Any], load: BoundReal16Load,
                     limits: LoadedRelationLimits) -> MachineState:
    """Compose the actual effect of the unique lowered block at the MZ entry."""
    entry = load.binding.entry
    found: dict[str, Any] | None = None
    for ctx in group_functions(document).values():
        block = ctx.blocks.get(entry - ctx.entry_linear)
        if block is None:
            continue
        if found is not None:
            raise _AdapterRefusal(RecursiveCompareReason.ENTRY, "multiple lowered blocks claim the entry")
        found = block
    if found is None:
        raise _AdapterRefusal(
            RecursiveCompareReason.ENTRY,
            "no lowered block covers the loaded entry; catalog/selection must include it",
        )
    outputs = found.get("outputs")
    if not isinstance(outputs, dict):
        raise _AdapterRefusal(RecursiveCompareReason.ENTRY, "entry block lacks full-state outputs")
    return S._compose_block_outputs(found, outputs, initial_state(),
                                    compose_stats={"deadline": limits.deadline})


def _block_request(load: BoundReal16Load, address: int, state: MachineState) -> NativeBlockRequest:
    """Propose one native extent from actual loaded control bytes; binder rechecks."""
    match = next(
        (chunk for chunk in load.binding.snapshot.chunks if chunk[0] <= address < chunk[0] + len(chunk[1])),
        None,
    )
    if match is None:
        raise _AdapterRefusal(RecursiveCompareReason.REQUEST, f"no loaded bytes cover 0x{address:x}")
    start, data = match
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    extent = 0
    for instruction in decoder.disasm(data[address - start:], address):
        extent += instruction.size
        if _CONTROL_GROUPS.intersection(instruction.groups):
            if address + extent > 0x100000:
                raise _AdapterRefusal(RecursiveCompareReason.REQUEST, "block extent exceeds physical domain")
            try:
                return NativeBlockRequest(address, extent, native_effect_hash(state),
                                          canonical_json_bytes(state))
            except ValueError as exc:
                raise _AdapterRefusal(
                    RecursiveCompareReason.REQUEST, f"block proposal intake refused: {exc}"
                ) from exc
    raise _AdapterRefusal(
        RecursiveCompareReason.REQUEST, f"loaded bytes at 0x{address:x} contain no control transfer"
    )


def _side_requests(load: BoundReal16Load, system: JointSystem, side: int,
                   bootstrap: MachineState) -> tuple[NativeBlockRequest, ...]:
    """Bind every joint node plus the entry effect to actual loaded bytes."""
    rows = [
        _block_request(
            load,
            step.original_address if side == 0 else step.candidate_address,
            step.original if side == 0 else step.candidate,
        )
        for step in system.steps
    ]
    rows.append(_block_request(load, load.binding.entry, bootstrap))
    return tuple(rows)


def _environment_scope(request: Real16RecursiveRequest, digests: dict[str, str]) -> Real16EnvironmentScope | None:
    """Bind the declared machine premise to both actual executable identities."""
    if request.closed_machine:
        return Real16EnvironmentScope(
            members=tuple(EnvironmentScopeMember),
            original_hash=digests["oracle"],
            candidate_hash=digests["candidate"],
            provenance=request.provenance,
        )
    return request.declared_scope


def _refuse(reason: RecursiveCompareReason, detail: str,
            attempts: tuple[RecursiveAttempt, ...],
            nested: StrEnum | None = None) -> RecursiveCompareOutcome:
    """Assemble one refused outcome while retaining every attempted root."""
    return RecursiveCompareOutcome(
        attempted=True, status=ProofStatus.UNKNOWN, reason=reason,
        nested_reason=nested,
        counters=FactCounters(1, 1, 1, 1, 1), attempts=attempts, detail=detail,
    )


def _domain_scope(receipt: ImageBoundReal16Domain,
                  loads: tuple[BoundReal16Load, BoundReal16Load]) -> RecursiveDomainScope:
    """Copy only proved, consistently bound receipt metadata; never prove a bridge."""
    proof = receipt.domain
    if receipt.status is not ProofStatus.PROVED or not isinstance(proof, Real16DomainProof):
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain receipt is not proved")
    if proof.status is not ProofStatus.PROVED:
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain receipt is not proved")
    ledgers = (receipt.counters, proof.counters)
    if any(not row.closed() or row.failure_count or not row.materialized_count for row in ledgers):
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain ledger is incomplete")
    identities = (receipt.model_hash, proof.model_hash, receipt.proposal_hash)
    if any(not isinstance(value, str) or not value for value in identities):
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain identity is missing")
    original, candidate = (load.binding.file_sha256 for load in loads)
    snapshots = (loads[0].binding.snapshot.sparse_byte_sha256, loads[1].binding.snapshot.sparse_byte_sha256)
    if (proof.original_file_hash, proof.candidate_file_hash) != (original, candidate):
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain image identity differs")
    if proof.snapshot_hashes != snapshots:
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain snapshot identity differs")
    contract = receipt.system.contract
    if (contract.original_hash, contract.candidate_hash) != (original, candidate):
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized component image identity differs")
    roots = tuple(step for step in receipt.system.steps if step.node == receipt.system.root)
    if len(roots) != 1 or (roots[0].original_address, roots[0].candidate_address) != (proof.root_address,) * 2:
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "initialized domain root identity differs")
    return RecursiveDomainScope(original, candidate, (loads[0].binding.entry, loads[1].binding.entry),
                                proof.root_address, proof.domain, snapshots, receipt.model_hash,
                                proof.model_hash, receipt.proposal_hash)


def _domain_bridge(receipt: ImageBoundReal16Domain,
                   loads: tuple[BoundReal16Load, BoundReal16Load],
                   ) -> tuple[tuple[str, ...], RecursiveDomainScope]:
    """Describe the initialized component domain without asserting member implication."""
    scope = _domain_scope(receipt, loads)
    bound = f"original={scope.original_sha256},candidate={scope.candidate_sha256}"
    scalars = scope.scalars
    assumptions = (
        f"supported_entry_domain:initialized_mz_image({bound})",
        f"entry_scalars_proved(ss=0x{scalars.ss:04x},cs=0x{scalars.cs:04x},"
        f"sp_alignment={scalars.alignment},{bound})",
        f"mz_entry_execution(entry=0x{scope.entry_linear[0]:x},"
        f"candidate_entry=0x{scope.entry_linear[1]:x})",
        f"initialized_loaded_byte_relation({bound})",
        f"arbitrary_entry_states_not_proved({bound})",
    )
    return assumptions, scope


def _outcome_from_proof(proof: ImageBoundReal16JointProof,
                        receipt: ImageBoundReal16Domain,
                        loads: tuple[BoundReal16Load, BoundReal16Load],
                        member_ids: tuple[str, ...],
                        attempts: tuple[RecursiveAttempt, ...], root: str) -> RecursiveCompareOutcome:
    """Project the sealed joint result; conditional scope stays explicit."""
    remaining = tuple(item.value for item in proof.remaining)
    declared = proof.outcomes.declared_scope_assumptions if proof.outcomes is not None else ()
    domain_assumptions, domain_scope = _domain_bridge(receipt, loads)
    if proof.proposal_hash != domain_scope.proposal_hash:
        raise _AdapterRefusal(RecursiveCompareReason.DOMAIN, "joint/domain proposal identity differs")
    assumptions = remaining + declared + domain_assumptions
    discharged = proof.status is ProofStatus.PROVED
    status = ProofStatus.PROVED if discharged else (
        ProofStatus.CONDITIONAL if proof.status is ProofStatus.CONDITIONAL else ProofStatus.UNKNOWN
    )
    return RecursiveCompareOutcome(
        attempted=True, status=status, reason=proof.reason,
        member_ids=member_ids if status is not ProofStatus.UNKNOWN else (),
        domain_scope=domain_scope if status is not ProofStatus.UNKNOWN else None,
        assumptions=assumptions if status is not ProofStatus.UNKNOWN else (),
        counters=proof.proof.counters, root=root,
        proposal_hash=proof.proposal_hash, model_hash=proof.model_hash,
        remaining=remaining, attempts=attempts, detail=proof.detail, proof=proof,
    )


def prove_recursive_compare(
    *,
    documents: dict[str, dict[str, Any]],
    digests: dict[str, str],
    images: dict[str, dict[str, Any]],
    roots: Sequence[str],
    request: Real16RecursiveRequest,
) -> RecursiveCompareOutcome:
    """Attempt the image-bound recursive joint proof for requested roots.

    ``documents``/``images`` are the comparator's own sealed lowering products;
    ``roots`` are the requested oracle function keys tried in order until one
    admits a closed same-coordinate near16 recursive component. The shared
    ``request.timeout_ms`` deadline covers admission, MZ binding, relation,
    domain and joint proof stages without replenishment. Every refusal returns
    a typed outcome with all attempted roots retained; only a PROVED or
    CONDITIONAL joint exposes component ``member_ids``/``assumptions`` only.
    """
    if not isinstance(request, Real16RecursiveRequest):
        raise ValueError("recursive compare requires a typed request")
    limits = LoadedRelationLimits(deadline=time.monotonic() + request.timeout_ms / 1000)
    attempts: list[RecursiveAttempt] = []

    def remaining_ms() -> int:
        limits.check_time()
        return max(0, int((limits.deadline - time.monotonic()) * 1000))

    try:
        system = _construct_system(
            documents["oracle"], documents["candidate"], roots, request, digests,
            limits, attempts, remaining_ms,
        )
        loads = (
            _bind_load(documents["oracle"], images["oracle"], digests["oracle"], limits),
            _bind_load(documents["candidate"], images["candidate"], digests["candidate"], limits),
        )
        initialized = prove_loaded_byte_relation(
            propose_loaded_byte_relation(
                loads[0].binding.snapshot, loads[1].binding.snapshot, limits=limits
            ),
            timeout_ms=min(remaining_ms(), _LOADED_RELATION_BUDGET_MS), limits=limits,
        )
        bootstrap = (
            _entry_bootstrap(documents["oracle"], loads[0], limits),
            _entry_bootstrap(documents["candidate"], loads[1], limits),
        )
        requests = (
            _side_requests(loads[0], system, 0, bootstrap[0]),
            _side_requests(loads[1], system, 1, bootstrap[1]),
        )
        receipt = prove_image_bound_real16_domain(
            system, loads, initialized, bootstrap, requests,
            timeout_ms=min(remaining_ms(), _DOMAIN_BUDGET_MS), limits=limits,
        )
        if receipt.status is not ProofStatus.PROVED:
            raise _AdapterRefusal(
                RecursiveCompareReason.DOMAIN, f"{receipt.reason.value}: {receipt.detail}",
                nested=receipt.reason,
            )
        proof = check_image_bound_real16_joint(
            receipt, system, loads, initialized, bootstrap, requests,
            timeout_ms=min(remaining_ms(), _JOINT_BUDGET_MS), limits=limits,
        )
        member_ids = tuple(str(member.value) for member in system.members)
        return _outcome_from_proof(
            proof, receipt, loads, member_ids, tuple(attempts),
            str(system.root.function.value),
        )
    except _AdapterRefusal as exc:
        return _refuse(exc.reason, exc.detail, tuple(attempts), nested=exc.nested)
    except JointRefusal as exc:
        reason = (RecursiveCompareReason.DEADLINE if exc.reason is JointReason.DEADLINE
                  else RecursiveCompareReason.JOINT)
        return _refuse(reason, f"{exc.reason.value}: {exc.detail}", tuple(attempts),
                       nested=exc.reason)
    except LoadedRelationRefusal as exc:
        reason = (RecursiveCompareReason.DEADLINE if exc.reason is LoadedRelationReason.DEADLINE
                  else RecursiveCompareReason.LOAD)
        return _refuse(reason, f"{exc.reason.value}: {exc.detail}", tuple(attempts),
                       nested=exc.reason)
    except ImageBindingRefusal as exc:
        return _refuse(RecursiveCompareReason.LOAD, f"{exc.reason.value}: {exc.detail}",
                       tuple(attempts), nested=exc.reason)
    except Real16CallRefusal as exc:
        return _refuse(RecursiveCompareReason.ADMISSION, f"{exc.reason}: {exc.detail}", tuple(attempts))
    except S.LowerFailure as exc:
        return _refuse(RecursiveCompareReason.ADMISSION, f"{exc.reason}: {exc.message}", tuple(attempts))


def _construct_system(
    original: dict[str, Any],
    candidate: dict[str, Any],
    roots: Sequence[str],
    request: Real16RecursiveRequest,
    digests: dict[str, str],
    limits: LoadedRelationLimits,
    attempts: list[RecursiveAttempt],
    remaining_ms: Callable[[], int],
) -> JointSystem:
    """Try each requested root until one yields a complete admitted proposal."""
    scope = _environment_scope(request, digests)
    seen: set[str] = set()
    for root in (str(key) for key in roots):
        if not root or root in seen:
            continue
        seen.add(root)
        if len(attempts) >= request.max_roots:
            raise _AdapterRefusal(
                RecursiveCompareReason.ADMISSION,
                f"root budget exhausted after {request.max_roots} attempts",
            )
        try:
            return build_real16_joint_system(
                original, candidate, root,
                timeout_ms=min(remaining_ms(), _CONSTRUCTION_BUDGET_MS),
                environment_scope=scope,
            )
        except JointRefusal as exc:
            attempts.append(RecursiveAttempt(root, exc.reason, exc.detail))
    detail = "; ".join(f"{item.root}: {item.reason.value}" for item in attempts) or "no requested roots"
    raise _AdapterRefusal(RecursiveCompareReason.ADMISSION, detail)
