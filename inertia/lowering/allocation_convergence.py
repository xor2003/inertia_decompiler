"""Typed convergence contracts and policy for restartable native variable allocation.

Layer: Types/Lowering.
Responsibility: own immutable fingerprints, verdicts, census accounting and the
bounded deterministic convergence policy for local-variable allocation
restarts. Only primitive structural keys live here; the frontend adapter lowers
native manager/AIL state into these contracts, and the CLI runtime drives the
policy at the native stage boundary. No rendered text participates in
comparisons.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

type AllocationStructuralKey = tuple[object, ...]
type AllocationGraphNodes = tuple[tuple[int, object, tuple[AllocationStructuralKey, ...]], ...]
type AllocationGraphEdges = tuple[tuple[tuple[int, object], tuple[int, object], AllocationStructuralKey], ...]


class AllocationFingerprintRefusal(Exception):
    """A native input form cannot be fingerprinted structurally."""


class AllocationConvergenceRefusal(Exception):
    """Causal typed refusal raised before a stale/unverified publication can be consumed.

    Carries the verdict, function and cause so the CLI attempt/fallback records
    a typed non-result instead of downstream codegen silently consuming stale
    bindings.
    """

    def __init__(self, verdict: AllocationRestartVerdict, function_addr: int, detail: str) -> None:
        """Create a typed refusal carrying the verdict, function and cause."""
        self.verdict = verdict
        self.function_addr = function_addr
        self.detail = detail
        super().__init__(f"{verdict.value}: allocation convergence for {function_addr:#x}: {detail}")


class AllocationRestartVerdict(enum.Enum):
    """Typed outcome of one allocation-restart decision."""

    UNCHANGED = "unchanged"
    RESTARTED = "restarted"
    EXHAUSTED = "exhausted"
    CYCLE = "cycle"
    REFUSED = "refused"


class AllocationDecisionKind(enum.Enum):
    """What the controller asks the boundary to do at a recovery entry."""

    RUN = "run"
    SKIP = "skip"
    EXHAUSTED = "exhausted"
    CYCLE = "cycle"


@dataclass(frozen=True, slots=True)
class NativeVariableKey:
    """Structural identity of one native decompilation variable."""

    kind: str
    ident: str | None
    location: object  # int offset/reg, tuple for combo regs, None otherwise
    size: int | None
    name: str | None


@dataclass(frozen=True, slots=True)
class AllocationInputFingerprint:
    """Typed structural inputs the native allocator consumes for one function.

    Binds real CFG edges, per-statement kinds and full expression operand trees,
    argument locations/identities, type layout including signedness, stack-item
    bounds, calling-convention fields, and the entry node. Any field change is
    an allocator input revision.
    """

    function_addr: int
    argument_variables: tuple[NativeVariableKey, ...]
    argument_vvars: tuple[tuple[int, NativeVariableKey, object, object], ...]
    vvar_to_vvar: tuple[tuple[int, int], ...]
    type_hints: tuple[tuple[str, str], ...]
    manual_types: tuple[tuple[NativeVariableKey, AllocationStructuralKey], ...]
    stack_items: tuple[tuple[int, str, int, str], ...]
    prototype: AllocationStructuralKey | None
    calling_convention: AllocationStructuralKey | None
    entry_node: object
    graph_nodes: AllocationGraphNodes
    graph_edges: AllocationGraphEdges

    def evidence_only(self) -> AllocationInputFingerprint:
        """The authoritative non-graph allocator inputs (types/args/hints/cc).

        The AIL graph is consumed and rewritten by the native stage, so the
        published (post-run) graph is output, not input. Mid-run input
        revisions are detected by comparing this evidence-only projection.
        """
        return AllocationInputFingerprint(
            function_addr=self.function_addr,
            argument_variables=self.argument_variables,
            argument_vvars=self.argument_vvars,
            vvar_to_vvar=self.vvar_to_vvar,
            type_hints=self.type_hints,
            manual_types=self.manual_types,
            stack_items=self.stack_items,
            prototype=self.prototype,
            calling_convention=self.calling_convention,
            entry_node=self.entry_node,
            graph_nodes=(),
            graph_edges=(),
        )


@dataclass(frozen=True, slots=True)
class AllocationCensus:
    """One commensurable attempt/publication ledger for a session.

    All four counters count stage-level decisions in the same unit.
    """

    attempts: int = 0
    published: int = 0
    skipped: int = 0
    refused: int = 0
    failures: int = 0

    @property
    def raw_fact_count(self) -> int:
        """Count completed stage decisions, including reuse and refusal."""
        return self.attempts + self.skipped + self.refused

    @property
    def normalized_fact_count(self) -> int:
        """Every completed decision has one normalized typed outcome."""
        return self.raw_fact_count

    @property
    def classified_fact_count(self) -> int:
        """Every normalized decision is classified exactly once."""
        return self.normalized_fact_count

    @property
    def materialized_count(self) -> int:
        """Count accepted publications and authenticated publication reuse."""
        return self.published + self.skipped

    @property
    def failure_count(self) -> int:
        """Count unsuccessful native attempts and explicit typed refusals."""
        return self.failures + self.refused

    def validate(self) -> tuple[str, ...]:
        """Typed invariant checks on the census."""
        problems = []
        if self.classified_fact_count != self.materialized_count + self.failure_count:
            problems.append("completed decisions are not fully materialized or refused")
        if self.published > self.attempts:
            problems.append("published exceeds attempts")
        if self.failures > self.attempts:
            problems.append("failures exceed attempts")
        if min(self.attempts, self.published, self.skipped, self.refused, self.failures) < 0:
            problems.append("negative counter")
        return tuple(problems)


@dataclass(frozen=True, slots=True)
class AllocationDiagnostics:
    """Native surface sizes observed at one decision (diagnostic, not proof)."""

    input_variables: int = 0
    output_variables: int = 0
    input_links: int = 0
    output_links: int = 0
    preserved_manual_types: int = 0
    dropped_stale_facts: int = 0


@dataclass(frozen=True, slots=True)
class AllocationRestartResult:
    """Typed outcome of an allocation restart decision."""

    verdict: AllocationRestartVerdict
    function_addr: int
    fingerprint: AllocationInputFingerprint | None
    census: AllocationCensus
    diagnostics: AllocationDiagnostics
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AllocationDecision:
    """Controller decision handed to the native boundary."""

    kind: AllocationDecisionKind
    validate_accepted: bool
    detail: str


class AllocationConvergenceSession:
    """Bounded deterministic convergence policy for one function's allocation.

    One transaction = one entry into the recovery stage plus any rounds needed
    while authoritative input evidence is revised during the run. The budget
    and cycle detection are scoped to the current transaction; a later
    completed revision (A -> B -> A) is a legitimate new transaction, not an
    oscillating fixpoint. The session never invokes native code; the CLI
    runtime injects the boundary operations.
    """

    __slots__ = (
        "_accepted_fingerprint",
        "_accepted_handle",
        "_accepted_output_fingerprint",
        "_attempts",
        "_failures",
        "_max_rounds",
        "_published",
        "_refused",
        "_round_fps",
        "_rounds",
        "_skipped",
        "last_detail",
        "last_result",
        "last_verdict",
    )

    def __init__(self, *, max_rounds: int = 2) -> None:
        """Create a session bounding rounds within one convergence transaction."""
        self._max_rounds = max_rounds
        self._accepted_fingerprint: AllocationInputFingerprint | None = None
        self._accepted_output_fingerprint: AllocationInputFingerprint | None = None
        self._accepted_handle: object | None = None
        self._round_fps: set[AllocationInputFingerprint] = set()
        self._rounds = 0
        self._attempts = 0
        self._published = 0
        self._skipped = 0
        self._refused = 0
        self._failures = 0
        self.last_verdict: AllocationRestartVerdict | None = None
        self.last_detail = ""
        self.last_result: AllocationRestartResult | None = None

    @property
    def accepted_fingerprint(self) -> AllocationInputFingerprint | None:
        """The raw entry fingerprint that produced the accepted publication."""
        return self._accepted_fingerprint

    @property
    def accepted_output_fingerprint(self) -> AllocationInputFingerprint | None:
        """The post-run surface fingerprint recorded at publication time."""
        return self._accepted_output_fingerprint

    @property
    def accepted_handle(self) -> object | None:
        """Opaque native handle identifying the accepted publication."""
        return self._accepted_handle

    @property
    def rounds_used(self) -> int:
        """Extra rounds consumed inside the current/finished transaction."""
        return self._rounds

    def decide(self, fingerprint: AllocationInputFingerprint, bound: bool) -> AllocationDecision:
        """Decide what to do when the recovery stage is entered.

        ``bound`` reports whether the clinic's live manager/link-map/graph are
        the objects the accepted publication was written into. SKIP is only
        valid when reuse is bound to these actual surfaces AND the presented
        inputs equal either the accepted raw input or the accepted published
        output (a same-clinic re-entry presents the already-rewritten graph).
        Anything else starts a fresh transaction with a fresh round budget.
        """
        if self._accepted_fingerprint is None or not bound:
            return AllocationDecision(AllocationDecisionKind.RUN, False, "recovery must execute")
        if fingerprint in (self._accepted_fingerprint, self._accepted_output_fingerprint):
            return AllocationDecision(
                AllocationDecisionKind.SKIP, True, "inputs identical to accepted publication"
            )
        return AllocationDecision(AllocationDecisionKind.RUN, False, "allocator inputs revised")

    def begin_transaction(self, fingerprint: AllocationInputFingerprint) -> None:
        """Open a transaction for an entry-time input fingerprint."""
        self._round_fps = {fingerprint.evidence_only()}
        self._rounds = 0

    def record_revision_round(
        self, revised_evidence: AllocationInputFingerprint
    ) -> AllocationDecision:
        """Record that inputs were revised mid-run; decide whether to iterate.

        Returns RUN to attempt another round, CYCLE if this evidence was
        already attempted in this transaction, EXHAUSTED when the per-
        transaction round budget is spent.
        """
        if revised_evidence in self._round_fps:
            return AllocationDecision(
                AllocationDecisionKind.CYCLE, False, "input evidence oscillates within transaction"
            )
        if self._rounds >= self._max_rounds:
            return AllocationDecision(
                AllocationDecisionKind.EXHAUSTED, False, "convergence round budget exhausted"
            )
        self._round_fps.add(revised_evidence)
        self._rounds += 1
        return AllocationDecision(AllocationDecisionKind.RUN, False, "input revised during recovery")

    def record_published(
        self,
        attempted_fingerprint: AllocationInputFingerprint,
        published_fingerprint: AllocationInputFingerprint,
        handle: object,
    ) -> None:
        """Record a converged publication.

        ``attempted_fingerprint`` is the raw entry input that the successful
        run provably consumed (evidence verified stable post-run);
        ``published_fingerprint`` is the post-run surface a same-clinic
        re-entry will present.
        """
        self._attempts += 1
        self._published += 1
        self._accepted_fingerprint = attempted_fingerprint
        self._accepted_output_fingerprint = published_fingerprint
        self._accepted_handle = handle
        self._round_fps = set()
        self.last_verdict = AllocationRestartVerdict.RESTARTED
        self.last_detail = "native recovery published under converged input fingerprint"

    def record_skip(self) -> None:
        """Record an unchanged-input reuse; the accepted publication stands."""
        self._skipped += 1
        self.last_verdict = AllocationRestartVerdict.UNCHANGED
        self.last_detail = "allocator inputs unchanged; bound accepted publication reused"

    def record_failure(self, fingerprint: AllocationInputFingerprint) -> None:
        """Record a failed attempt; nothing was published for this input."""
        self._attempts += 1
        self._failures += 1
        self.last_result = None
        self._round_fps = set()
        self.last_verdict = AllocationRestartVerdict.REFUSED
        self.last_detail = "native recovery raised; checkpoint restored, cause propagated"

    def record_refusal(self, verdict: AllocationRestartVerdict, detail: str) -> None:
        """Record a typed non-decision refusal (exhaustion, cycle, unsupported)."""
        self._refused += 1
        self.last_result = None
        self._round_fps = set()
        self.last_verdict = verdict
        self.last_detail = detail

    def census(self) -> AllocationCensus:
        """Snapshot the attempt/publication ledger."""
        return AllocationCensus(
            attempts=self._attempts,
            published=self._published,
            skipped=self._skipped,
            refused=self._refused,
            failures=self._failures,
        )
