"""Typed proof obligations and evidence for binary behavior equivalence.

Layer: dosunit proof contracts.
Responsibility: own conservative verdict evaluation for semantic proof
obligations shared by the real-mode and flat32 comparators. Proof status
stays independent of concrete execution evidence; PROVED requires complete
contract-identical acyclic evidence with closed fact counters. Missing,
duplicate, stale, assumed or cyclically self-bootstrapping evidence never
produces a pass, and classified-but-unmaterialized facts fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import astuple, dataclass, field
from enum import StrEnum
from typing import Any

from tools.dosunit.contracts.model import stable_id

REPORT_SCHEMA: str = "dosunit.proof_report.v1"


class Architecture(StrEnum):
    """Machine model an obligation was discharged under."""

    REAL16 = "real16"
    FLAT32 = "flat32"


class ProofStatus(StrEnum):
    """Semantic proof verdict; CONDITIONAL never satisfies a proof obligation."""

    PROVED = "proved"
    CONDITIONAL = "conditional"
    COUNTEREXAMPLE = "counterexample"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    UNMAPPED = "unmapped"


class ProofReason(StrEnum):
    """Typed explanation for an evaluated obligation verdict or report problem."""

    DISCHARGED = "discharged"
    BACKEND_VERDICT = "backend_verdict"
    UNPROVED_ASSUMPTIONS = "unproved_assumptions"
    EMPTY_OBLIGATIONS = "empty_obligations"
    DUPLICATE_OBLIGATION = "duplicate_obligation"
    MISSING_EVIDENCE = "missing_evidence"
    DUPLICATE_EVIDENCE = "duplicate_evidence"
    UNEXPECTED_EVIDENCE = "unexpected_evidence"
    CONTRACT_MISMATCH = "contract_mismatch"
    UNMATERIALIZED_FACTS = "unmaterialized_facts"
    FAILED_FACTS = "failed_facts"
    DEPENDENCY_MISSING = "dependency_missing"
    DEPENDENCY_UNPROVED = "dependency_unproved"
    DEPENDENCY_CONDITIONAL = "dependency_conditional"
    DEPENDENCY_CYCLE = "dependency_cycle"


class ExecutionStatus(StrEnum):
    """Concrete replay outcome; recorded independently of symbolic proof."""

    AGREEMENT = "agreement"
    MISMATCH = "mismatch"
    FAULT = "fault"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, order=True)
class ObligationId:
    """Stable binary-derived identity of one proof obligation."""

    kind: str
    key: str


@dataclass(frozen=True)
class ContractIdentity:
    """Binds proof validity to both binaries and all semantic contract versions."""

    architecture: Architecture
    original_hash: str
    candidate_hash: str
    semantic_hash: str
    model_hash: str
    abi_hash: str

    def __post_init__(self) -> None:
        """Reject identities that are not bound to concrete content hashes."""
        if any(not value for value in astuple(self)[1:]):
            raise ValueError("contract identity requires non-empty content hashes")

    def key(self) -> str:
        """Return the deterministic content key for proof-cache invalidation."""
        identity: str = stable_id("contract", self.to_document())
        return identity

    def to_document(self) -> dict[str, str]:
        """Publish the authoritative fields that define this proof domain."""
        return {
            "architecture": self.architecture.value, "original_hash": self.original_hash,
            "candidate_hash": self.candidate_hash, "semantic_hash": self.semantic_hash,
            "model_hash": self.model_hash, "abi_hash": self.abi_hash,
        }


@dataclass(frozen=True)
class FactCounters:
    """Closed evidence-pipeline counters; classified work must materialize."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def __post_init__(self) -> None:
        """Reject counters that cannot describe a real evidence pipeline."""
        if any(type(count) is not int or count < 0 for count in astuple(self)):
            raise ValueError("fact counters must be non-negative integers")

    def closed(self) -> bool:
        """Return False when classified facts vanished instead of materializing."""
        return self.classified_fact_count == 0 or self.materialized_count > 0


@dataclass(frozen=True)
class Obligation:
    """One required proof obligation and its declared dependencies."""

    id: ObligationId
    dependencies: tuple[ObligationId, ...] = ()


@dataclass(frozen=True)
class ObligationEvidence:
    """Backend evidence offered for one obligation under a specific contract."""

    id: ObligationId
    contract: ContractIdentity
    status: ProofStatus
    reason: str = ""
    method: str = ""
    dependencies: tuple[ObligationId, ...] = ()
    assumptions: tuple[str, ...] = ()
    counters: FactCounters = field(default_factory=FactCounters)


@dataclass(frozen=True)
class ExecutionEvidence:
    """Concrete differential-execution observation, separate from proof state."""

    id: ObligationId
    status: ExecutionStatus
    detail: str = ""


@dataclass(frozen=True)
class ObligationVerdict:
    """Evaluated verdict for one required obligation."""

    id: ObligationId
    status: ProofStatus
    reason: ProofReason
    detail: str = ""
    method: str = ""
    counters: FactCounters = field(default_factory=FactCounters)
    dependencies: tuple[ObligationId, ...] = ()
    assumptions: tuple[str, ...] = ()
    evidence_contract_key: str = ""
    attempted: bool = False


@dataclass(frozen=True)
class ObligationReport:
    """Complete evaluated report; the aggregate status can only under-claim."""

    contract: ContractIdentity
    status: ProofStatus
    verdicts: tuple[ObligationVerdict, ...]
    counters: FactCounters
    problem: ProofReason | None = None
    unexpected_evidence: tuple[ObligationId, ...] = ()
    executions: tuple[ExecutionEvidence, ...] = ()


LEGACY_PROOF_STATUSES: Mapping[str, ProofStatus] = {
    "passed": ProofStatus.PROVED,
    "failed": ProofStatus.COUNTEREXAMPLE,
    "refused": ProofStatus.UNKNOWN,
    "conditional": ProofStatus.CONDITIONAL,
}


def proof_status_from_legacy(value: object) -> ProofStatus | None:
    """Map a legacy verdict string; never inspect reason text; unknown values return None."""
    if isinstance(value, str):
        return LEGACY_PROOF_STATUSES.get(value)
    return None


def legacy_status_for(status: ProofStatus) -> str:
    """Project a proof status back onto the legacy passed/failed/refused vocabulary."""
    if status is ProofStatus.PROVED:
        return "passed"
    if status is ProofStatus.CONDITIONAL:
        return "conditional"
    if status is ProofStatus.COUNTEREXAMPLE:
        return "failed"
    return "refused"

def evaluate_obligations(
    contract: ContractIdentity, required: Sequence[Obligation], evidence: Sequence[ObligationEvidence],
    *, executions: Sequence[ExecutionEvidence] = (),
) -> ObligationReport:
    """Evaluate required evidence through the shared conservative proof owner."""
    from tools.dosunit.contracts.proof_obligations import evaluate_obligations as evaluate

    return evaluate(contract, required, evidence, executions=executions)


def report_to_document(report: ObligationReport) -> dict[str, Any]:
    """Serialize a proof report while retaining its assumptions and dependencies."""
    from tools.dosunit.reporting.proof_serialization import report_to_document as serialize

    return serialize(report)


def report_json_bytes(report: ObligationReport) -> bytes:
    """Return the canonical JSON encoding of a fully identified proof report."""
    from tools.dosunit.reporting.proof_serialization import report_json_bytes as serialize

    return serialize(report)
