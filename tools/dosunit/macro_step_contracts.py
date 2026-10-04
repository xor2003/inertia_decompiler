"""Typed contracts for bounded unequal-step (macro-step) frontier pairing.

Layer: dosunit relational control-flow proposal.
Responsibility: own the typed surface shared by the staged macro-step pairing
search and both width adapters. A macro-cut is a synchronized cutpoint head; a
frontier path is a finite region sequence ending at the first macro-cut visit
or a real return. A macro-transition pairs a concatenation of 1..K frontier
paths on each side; every accepted transition must still discharge its path
guards, full masked machine state and endpoint consistency through the
existing SSA/Z3 machinery. Nothing in this module is a proof result.

Corrections applied from the parent contract review (all mandatory):

* Search status, proposal direction and endpoint kind are owned enums, never
  strings.
* Endpoint normalization is restricted to explicitly paired continuing PC
  identities. Unpaired/unknown heads never collapse into a common token; an
  unclosed endpoint is refused or checked per side with its actual identity.
* Feasible-path coverage and non-overlap are solver-discharged obligations on
  both sides; UNKNOWN guard verdicts cannot prune.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.paired_region_graph import CollapsedRegion, RegionGraphReason
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.proof_scope import ProofScope


class MacroStepReason(StrEnum):
    """Exact missing macro-step obligation, never an execution counterexample."""

    MACRO_DEPTH = "macro_frontier_depth_exceeded"
    MACRO_PATH_LIMIT = "macro_path_limit_exceeded"
    MACRO_STATE_LIMIT = "macro_state_limit_exceeded"
    MACRO_TRANSITION_LIMIT = "macro_transition_limit_exceeded"
    MACRO_TERM_LIMIT = "macro_term_nodes_exceeded"
    MACRO_GUARD_UNRESOLVED = "macro_path_guard_unresolved"
    MACRO_PATH_UNPAIRED = "macro_frontier_path_unpaired"
    MACRO_ENDPOINT = "macro_endpoint_mismatch"
    MACRO_UNSUPPORTED_BOUNDARY = "macro_unsupported_boundary"
    MACRO_COVERAGE = "macro_coverage_unproved"
    MACRO_PROGRESS = "macro_progress_missing"
    MACRO_DEADLINE = "macro_search_deadline"
    MACRO_ADMISSION = "macro_admission_refused"


class MacroProofReason(StrEnum):
    """Final discharged or unproved unequal-step proof obligation."""

    PROVED = "paired_macro_step_transitions_proved"
    UNPROVED = "paired_macro_step_unproved"


class MacroSearchStatus(StrEnum):
    """Whether bounded proposal enumeration covered the whole search space."""

    EXHAUSTED = "exhausted"
    LIMIT = "limit_reached"


class MacroDirection(StrEnum):
    """Which side takes the deeper frontier concatenation per macro-transition."""

    ORACLE_SLOWER = "oracle_slower"
    CANDIDATE_SLOWER = "candidate_slower"


class MacroEndpointKind(StrEnum):
    """How a frontier path or macro-transition terminates."""

    CONTINUING = "continuing_paired_cut"
    RETURN = "return_physical"


class MacroObligation(StrEnum):
    """Solver-discharged proof obligations carried by a macro-step attempt."""

    PATH_GUARD_EQUALITY = "path_guard_equality"
    MASKED_STATE_EQUALITY = "masked_state_equality"
    ENDPOINT_CONSISTENCY = "endpoint_consistency"
    COVERAGE_COMPLETENESS = "coverage_completeness"
    COVERAGE_DISJOINTNESS = "coverage_disjointness"
    POSITIVE_PROGRESS = "positive_progress"


@dataclass(frozen=True, slots=True)
class MacroStepLimits:
    """Total bounded-search budget for one macro-step proposal and discharge."""

    max_paths_per_cut: int = 32
    max_concat_segments: int = 2
    max_states: int = 4096
    max_transitions: int = 64
    max_term_nodes: int = 12000
    max_frontier_regions: int = 16


@dataclass(frozen=True, slots=True)
class FrontierPath:
    """Regions traversed from one macro-cut until the next cut or a return.

    ``regions`` is nonempty: it starts at the region headed by ``start_cut``
    and ends at a RETURN region or at a region whose taken exit lands on a
    macro-cut head (``end_head``). Continuing endpoints carry only explicitly
    paired macro-cut identities; an exit to an unpaired head is refused during
    expansion, never normalized into a shared token.
    """

    regions: tuple[CollapsedRegion, ...]
    start_cut: int
    end_head: int
    end_kind: MacroEndpointKind

    @property
    def block_steps(self) -> int:
        """Positive binary-block progress across the whole path."""
        return sum(len(region.members) for region in self.regions)


@dataclass(frozen=True, slots=True)
class MacroTransitionSpec:
    """One proposed macro-transition before solver discharge.

    ``oracle_paths`` and ``candidate_paths`` are concatenations of 1..K
    frontier paths on each side between paired endpoints. ``end_pair`` is the
    index into ``macro_pairs`` for continuing endpoints; ``end_kind`` is
    RETURN only when both sides terminate at RETURN-kind regions.
    """

    oracle_paths: tuple[FrontierPath, ...]
    candidate_paths: tuple[FrontierPath, ...]
    end_kind: MacroEndpointKind
    end_pair: int
    fast_side: MacroDirection


@dataclass(frozen=True, slots=True)
class PairingCandidate:
    """Endpoint-compatible slow-side concatenations offered for one fast path."""

    fast_path: FrontierPath
    slow_concats: tuple[tuple[FrontierPath, ...], ...]


@dataclass(frozen=True, slots=True)
class MacroStepProposal:
    """Unproved entry-cut correspondence plus all pairing candidates."""

    direction: MacroDirection
    macro_pairs: tuple[tuple[int, int], ...]
    pairings: tuple[PairingCandidate, ...]
    oracle_paths: tuple[FrontierPath, ...]
    candidate_paths: tuple[FrontierPath, ...]


@dataclass(frozen=True, slots=True)
class MacroStepCounters:
    """Work counters recording exactly what the bounded search did."""

    frontier_paths_oracle: int
    frontier_paths_candidate: int
    concats_oracle: int
    concats_candidate: int
    pairing_candidates: int
    dead_ends: int


@dataclass(frozen=True, slots=True)
class MacroStepSearch:
    """Bounded proposal result; LIMIT status is never read as absence."""

    status: MacroSearchStatus
    proposals: tuple[MacroStepProposal, ...]
    counters: MacroStepCounters
    refusal: MacroStepReason | None = None


@dataclass(frozen=True, slots=True)
class MacroTransitionProof:
    """One discharged or refused macro-transition with row-level evidence."""

    index: int
    oracle_members: tuple[int, ...]
    candidate_members: tuple[int, ...]
    oracle_segments: int
    candidate_segments: int
    end_kind: MacroEndpointKind
    end_pair: int
    status: ProofStatus
    guard_status: ProofStatus
    obligations: tuple[MacroObligation, ...]
    diagnostics: dict[str, object]


@dataclass(frozen=True, slots=True)
class MacroCoverageProof:
    """Per-side completeness and non-overlap discharge over one macro-cut."""

    side: str
    completeness: ProofStatus
    disjoint_pairs: int
    disjoint_failures: int
    diagnostics: dict[str, object]


@dataclass(frozen=True, slots=True)
class MacroStepAttempt:
    """One proposal direction and every checked transition, including refusals."""

    direction: MacroDirection
    status: ProofStatus
    transitions: tuple[MacroTransitionProof, ...]
    coverage: tuple[MacroCoverageProof, ...]
    counters: FactCounters
    refusal: MacroStepReason | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class MacroStepProof:
    """Complete staged macro-step verdict with retained failed attempts."""

    status: ProofStatus
    reason: MacroProofReason | MacroStepReason | RegionGraphReason
    direction: MacroDirection | None
    transitions: tuple[MacroTransitionProof, ...]
    counters: FactCounters
    attempts: tuple[MacroStepAttempt, ...]
    search_status: MacroSearchStatus | None
    search_refusal: MacroStepReason | None
    proof_scope: ProofScope
    detail: str = ""
    graph_evidence: dict[str, object] | None = None


class MacroStepRefusal(Exception):
    """Fail-closed staged refusal carrying the typed missing obligation."""

    def __init__(self, reason: MacroStepReason, detail: dict[str, object] | None = None) -> None:
        """Retain the exact obligation that refused."""
        super().__init__(reason.value)
        self.reason = reason
        self.detail = dict(detail or {})
