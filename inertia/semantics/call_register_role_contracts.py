"""Typed contracts for the four distinct register roles of one exact CALL.

Layer: Semantics.
Responsibility: own immutable per-call register-role evidence — incoming
input/pass bits, possible-clobber (spoiled) bits, caller-dead bits and proven
result registers — with explicit complete/partial/unknown coverage over the
canonical Alias register domains. Each role is independently evidenced; sets
may overlap and unknown coverage is always distinct from an empty mask.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.domains import REGISTER_VIEWS as _ALIAS_REGISTER_VIEWS
from inertia.ir.core import IRFunctionArtifact

from .call_output_contracts import CallOutputFact8616, CallOutputShape8616

__all__ = [
    "CALL_REGISTER_ROLE_KINDS_8616",
    "FULL_DOMAIN_MASK_8616",
    "TRACKED_REGISTER_DOMAIN_NAMES_8616",
    "CallRegisterDomainBits8616",
    "CallRegisterRoleCoverage8616",
    "CallRegisterRoleEvidence8616",
    "CallRegisterRoleFailure8616",
    "CallRegisterRoleKind8616",
    "CallRegisterRoleResult8616",
    "CallRegisterRoleStats8616",
    "CallRegisterRolesArtifact8616",
    "CallRegisterRolesFact8616",
]

# Canonical 16-bit Alias register domains shared by every role. Reusing the
# DomainKey names keeps semantic masks keyed by the same storage identity the
# Alias consumer resolves; wider 80386 parents project into these low views.
TRACKED_REGISTER_DOMAIN_NAMES_8616: tuple[str, ...] = tuple(
    sorted({key.name for key, _view in _ALIAS_REGISTER_VIEWS.values()})
)

FULL_DOMAIN_MASK_8616: int = (1 << 16) - 1


class CallRegisterRoleKind8616(StrEnum):
    """The four independently evidenced roles of one exact CALL."""

    INPUT = "input"
    MAY_CLOBBER = "may_clobber"
    CALLER_DEAD = "caller_dead"
    RESULT = "result"


CALL_REGISTER_ROLE_KINDS_8616: tuple[CallRegisterRoleKind8616, ...] = tuple(
    CallRegisterRoleKind8616
)


class CallRegisterRoleCoverage8616(StrEnum):
    """Evidence coverage for one register-role decision."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallRegisterRoleFailure8616(StrEnum):
    """Typed reasons one register role could not be fully proven."""

    CALL_IDENTITY_INCOMPLETE = "call_identity_incomplete"
    CALLEE_EVIDENCE_MISSING = "callee_evidence_missing"
    CALLEE_COVERAGE_PARTIAL = "callee_coverage_partial"
    CALLEE_TRANSFER_UNSUPPORTED = "callee_transfer_unsupported"
    CALLER_EVIDENCE_MISSING = "caller_evidence_missing"
    CALLER_CONTINUATION_MISSING = "caller_continuation_missing"
    CALLER_COVERAGE_PARTIAL = "caller_coverage_partial"
    OUTPUT_FACT_MISMATCH = "output_fact_mismatch"
    OUTPUT_FACT_MISSING = "output_fact_missing"
    OUTPUT_FACT_REFUSED = "output_fact_refused"
    OUTPUT_VIEW_UNSUPPORTED = "output_view_unsupported"


@dataclass(frozen=True, slots=True)
class CallRegisterDomainBits8616:
    """Role evidence for one canonical 16-bit register domain.

    ``known_bits`` marks the bit positions whose role membership is decided;
    ``role_bits`` marks the decided positions that carry the role. Positive
    observations stay known under partial coverage while their complement
    remains undecided.
    """

    domain: str
    known_bits: int
    role_bits: int

    def __post_init__(self) -> None:
        """Reject role bits that outrun their decided mask or domain."""
        if self.domain not in TRACKED_REGISTER_DOMAIN_NAMES_8616:
            raise ValueError(f"untracked register domain {self.domain!r}")
        for mask in (self.known_bits, self.role_bits):
            if (
                not isinstance(mask, int)
                or isinstance(mask, bool)
                or not 0 <= mask <= FULL_DOMAIN_MASK_8616
            ):
                raise ValueError(f"domain {self.domain} mask out of range")
        if self.role_bits & ~self.known_bits:
            raise ValueError(
                f"domain {self.domain} carries the role on undecided bits"
            )


@dataclass(frozen=True, slots=True)
class CallRegisterRoleEvidence8616:
    """One role decision over the tracked register domains.

    Counters are closed per-domain decisions: ``classified`` and
    ``materialized`` count domains whose published evidence decides at least
    one bit; ``failure_count`` counts domains with no decided evidence. An
    all-refused decision keeps ``classified`` and ``materialized`` at zero.
    """

    kind: CallRegisterRoleKind8616
    coverage: CallRegisterRoleCoverage8616
    domains: tuple[CallRegisterDomainBits8616, ...]
    witnesses: tuple[int, ...]
    failures: tuple[CallRegisterRoleFailure8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def __post_init__(self) -> None:
        """Reject unsorted evidence, bad witnesses and incoherent counters."""
        names = tuple(entry.domain for entry in self.domains)
        if names != tuple(sorted(names)) or len(set(names)) != len(names):
            raise ValueError("domain evidence must be sorted and unique")
        if self.witnesses != tuple(sorted(set(self.witnesses))):
            raise ValueError("witnesses must be sorted and unique")
        for witness in self.witnesses:
            if not isinstance(witness, int) or isinstance(witness, bool) or witness < 0:
                raise ValueError("witnesses must be non-negative addresses")
        if self.coverage is CallRegisterRoleCoverage8616.UNKNOWN_REFUSE:
            _refusal_role_invariants_8616(self)
        else:
            _decided_role_invariants_8616(self)

    def domain_bits(self, domain: str) -> CallRegisterDomainBits8616 | None:
        """Return the decided evidence for one canonical domain name."""
        for entry in self.domains:
            if entry.domain == domain:
                return entry
        return None


def _refusal_role_invariants_8616(evidence: CallRegisterRoleEvidence8616) -> None:
    """Require a refusal to publish no decided bits or positive census."""
    if (
        evidence.classified_fact_count != 0
        or evidence.materialized_count != 0
        or evidence.failure_count < 1
        or not evidence.failures
        or any(entry.known_bits != 0 for entry in evidence.domains)
    ):
        raise ValueError("refused role evidence cannot publish decided bits")


def _decided_role_invariants_8616(evidence: CallRegisterRoleEvidence8616) -> None:
    """Require decided evidence to close per-domain and match coverage."""
    if (
        evidence.raw_fact_count != len(TRACKED_REGISTER_DOMAIN_NAMES_8616)
        or evidence.normalized_fact_count != evidence.raw_fact_count
        or evidence.classified_fact_count != evidence.materialized_count
        or evidence.classified_fact_count + evidence.failure_count
        != evidence.normalized_fact_count
    ):
        raise ValueError("role evidence counters must close per domain")
    decided = sum(entry.known_bits != 0 for entry in evidence.domains)
    if evidence.classified_fact_count != decided:
        raise ValueError("classified domains must publish decided bits")
    if evidence.coverage is CallRegisterRoleCoverage8616.COMPLETE:
        expected = dict.fromkeys(
            TRACKED_REGISTER_DOMAIN_NAMES_8616, FULL_DOMAIN_MASK_8616
        )
        actual = {entry.domain: entry.known_bits for entry in evidence.domains}
        if (
            evidence.failure_count != 0
            or evidence.failures
            or actual != expected
        ):
            raise ValueError("complete coverage cannot retain failures")
    if (
        evidence.coverage is CallRegisterRoleCoverage8616.PARTIAL
        and not evidence.failures
    ):
        raise ValueError("partial coverage must retain typed failure reasons")


@dataclass(frozen=True, slots=True)
class CallRegisterRoleResult8616:
    """One proven output register bound to an exact call identity."""

    register: str
    domain: str
    bit_mask: int
    callsite_addr: int
    target_addr: int
    return_block_addr: int
    shape: CallOutputShape8616 | None

    def __post_init__(self) -> None:
        """Reject empty or out-of-range result masks."""
        if (
            not isinstance(self.bit_mask, int)
            or isinstance(self.bit_mask, bool)
            or not 0 < self.bit_mask <= FULL_DOMAIN_MASK_8616
        ):
            raise ValueError("result bit mask must cover a 16-bit domain view")


@dataclass(frozen=True, slots=True)
class CallRegisterRolesFact8616:
    """All four register roles bound to one exact CALL identity.

    The same call may simultaneously prove a register is an input, may be
    clobbered, is caller-dead, and is a result — the roles are independent
    evidence, never derived from each other.
    """

    call_block_addr: int | None
    call_instr_index: int | None
    callsite_addr: int | None
    target_addr: int | None
    return_block_addr: int | None
    roles: tuple[CallRegisterRoleEvidence8616, ...]
    results: tuple[CallRegisterRoleResult8616, ...]

    def __post_init__(self) -> None:
        """Require the four role evidences and identity-bound results."""
        kinds = tuple(role.kind for role in self.roles)
        if kinds != CALL_REGISTER_ROLE_KINDS_8616:
            raise ValueError("exactly one evidence per role kind is required")
        for result in self.results:
            if not self._result_binds_identity(result):
                raise ValueError("results must carry the exact call identity")

    def _result_binds_identity(self, result: CallRegisterRoleResult8616) -> bool:
        """Return whether one result carries this call's exact identity."""
        return (
            self.callsite_addr is not None
            and self.target_addr is not None
            and self.return_block_addr is not None
            and result.callsite_addr == self.callsite_addr
            and result.target_addr == self.target_addr
            and result.return_block_addr == self.return_block_addr
        )

    def role(self, kind: CallRegisterRoleKind8616) -> CallRegisterRoleEvidence8616:
        """Return the evidence for one role kind."""
        for evidence in self.roles:
            if evidence.kind is kind:
                return evidence
        raise ValueError(f"missing role evidence for {kind}")


@dataclass(frozen=True, slots=True)
class CallRegisterRoleStats8616:
    """Closed aggregate accounting for every role decision in one function."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every role decision has a retained typed outcome."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.classified_fact_count == self.materialized_count
            and self.classified_fact_count + self.failure_count
            == self.normalized_fact_count
        )

    @property
    def complete(self) -> bool:
        """Return whether every role decision was positively proven."""
        return self.closed and self.failure_count == 0

    def to_dict(self) -> dict[str, int]:
        """Return deterministic closed-loop counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class CallRegisterRolesArtifact8616:
    """Per-function register-role evidence bound to exact CALL identities.

    ``output_facts`` retains the canonical ``CallOutputFact8616`` census the
    producer consumed; ``source_function`` and ``output_function`` retain the
    pre/post-materialization IR snapshots those fact indexes name. Together
    they authenticate which exact output snapshot this artifact belongs to —
    a function address alone is not identity.
    """

    function_addr: int
    facts: tuple[CallRegisterRolesFact8616, ...]
    stats: CallRegisterRoleStats8616
    output_facts: tuple[CallOutputFact8616, ...] = ()
    source_function: IRFunctionArtifact | None = None
    output_function: IRFunctionArtifact | None = None

    def __post_init__(self) -> None:
        """Reconcile retained stats with the actual retained fact census."""
        expected = CallRegisterRoleStats8616(
            raw_fact_count=sum(
                role.raw_fact_count for fact in self.facts for role in fact.roles
            ),
            normalized_fact_count=sum(
                role.normalized_fact_count
                for fact in self.facts
                for role in fact.roles
            ),
            classified_fact_count=sum(
                role.classified_fact_count
                for fact in self.facts
                for role in fact.roles
            ),
            materialized_count=sum(
                role.materialized_count for fact in self.facts for role in fact.roles
            ),
            failure_count=sum(
                role.failure_count for fact in self.facts for role in fact.roles
            ),
        )
        if self.stats != expected:
            raise ValueError(
                "role artifact stats must equal the retained fact census"
            )

    @property
    def complete(self) -> bool:
        """Return whether every call's role decisions are fully proven.

        Closed counters are necessary but not sufficient: a coherent partial
        role still leaves bits undecided, so completeness also requires every
        retained role evidence to carry COMPLETE coverage.
        """
        return self.stats.complete and all(
            role.coverage is CallRegisterRoleCoverage8616.COMPLETE
            for fact in self.facts
            for role in fact.roles
        )

    def authenticates_output_facts(
        self,
        output_facts: tuple[CallOutputFact8616, ...],
    ) -> bool:
        """Return whether this artifact consumed that exact fact census."""
        return self.output_facts == output_facts

    def to_dict(self) -> dict[str, object]:
        """Return deterministic diagnostics without duplicating decoded IR."""
        return {
            "function_addr": self.function_addr,
            "facts": [
                {
                    "call_block_addr": fact.call_block_addr,
                    "call_instr_index": fact.call_instr_index,
                    "callsite_addr": fact.callsite_addr,
                    "target_addr": fact.target_addr,
                    "return_block_addr": fact.return_block_addr,
                    "roles": {
                        evidence.kind.value: {
                            "coverage": evidence.coverage.value,
                            "domains": {
                                entry.domain: {
                                    "known_bits": entry.known_bits,
                                    "role_bits": entry.role_bits,
                                }
                                for entry in evidence.domains
                            },
                            "witnesses": list(evidence.witnesses),
                            "failures": [failure.value for failure in evidence.failures],
                        }
                        for evidence in fact.roles
                    },
                    "results": [
                        {
                            "register": result.register,
                            "domain": result.domain,
                            "bit_mask": result.bit_mask,
                            "shape": (
                                None if result.shape is None else result.shape.value
                            ),
                        }
                        for result in fact.results
                    ],
                }
                for fact in self.facts
            ],
            "stats": self.stats.to_dict(),
        }
