"""Conditional near-CALL CS-preservation step under an authenticated entry interval.

Layer: IR.
Responsibility: combine one authenticated conditional outgoing-CALL target
theorem (``ConditionalNearCallTargetTheorem8616``) with a complete UNIVERSAL
callee segment-effect closure at the theorem's exact encoded target. The
resulting record asserts only: if the retained outgoing-callsite selector
obligation holds, and the callee bound at ``callee_addr`` returns, CS is
preserved across this CALL. The obligation is retained verbatim and is never
discharged here; nothing claims callsite reachability, callee termination,
an entry-to-callsite CS premise, or a context-free preserved-register
surface, and nothing is published into any registry.

The coordinates factory consumes its synchronously derived target without
an initial replay; it retains the same final native seals. The arbitrary
retained-theorem producer replays the target at entry, then reauthenticates
its native surfaces after callee callbacks. The retained-step consumer
instead defers its full target replay to the final seal, after its census
and callee checks. All routes reconcile the snapshot's owned caller facts
before downstream gates and run the one fresh whole-graph reconciliation
after the last callback; a refusal re-runs the full reconciliation once on
the refusal path so persistent drift keeps its SEAL_SOURCE_CHANGED
diagnostic. The private staged census-step operation keeps that same check
order for a census that already owns the caller's complete pre-callback
snapshot and owes a fresh final whole-graph seal; it defers only the
detached-graph comparison, never a scalar, identity, native, callee, or
deadline check. Composition
reuses canonical owners only: the outgoing
callsite's
decoded census row and the canonical NOP-padding candidate window come from
the caller-boundary callsite index through ``_decoded_entry_for_callsite_8616``
and ``_callsite_window_8616``; the bounded universal closure is resolved by
``_callee_closure_8616`` under the owner's resolution session; and
completeness, the nested-call dependency census, and entry/return CS
identity revalidate through ``SegmentEffectClosureResult8616.complete``,
``_callee_dependency_failure_8616`` and ``_callee_preserved_registers_8616``.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar, cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DirectCallTargetResolver8616,
    decoded_callsite_index_for_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.near_call_entry_context import (
    NativeNearCallEntry8616,
)
from inertia.semantics.conditional_near_call_target import (
    ConditionalCallsiteSelectorObligation8616,
    ConditionalNearCallTargetTheorem8616,
    ConditionalNearCallTargetVerdict8616,
    _ScopedTargetStage8616,
    _staged_scoped_theorem_8616,
    consume_conditional_near_call_target_8616,
    prove_conditional_near_call_target_8616,
    reauthenticate_conditional_near_call_target_8616,
)
from inertia.semantics.direct_near_call_target_binding import DirectNearCallCoordinates8616

from .core import IRBlock, IRFunctionArtifact, IRInstr
from .direct_evidence_deadline import (
    direct_evidence_deadline_expired_8616,
)
from .entry_domain_call_preservation import (
    EntryDomainCallPreservationFailure8616,
    _active_direct_evidence_deadline_8616,
    _active_resolution_8616,
    _callee_closure_8616,
    _callee_dependency_failure_8616,
    _callee_preserved_registers_8616,
    _CalleeResolution8616,
    _CalleeResolutionSurface8616,
    _callsite_window_8616,
    _decoded_entry_for_callsite_8616,
    _decoded_instruction_map_8616,
)
from .ir_boundary_cfg import IRBoundaryCoverageResult8616
from .segment_call_preservation import (
    segment_call_dependency_traversal_scope_8616,
)
from .segment_effect_closure import SegmentEffectClosureResult8616
from .segment_state import SegmentStateArtifact
from .source_graph_binding import (
    ImmutableSourceGraphFacts8616,
    SourceGraphSerializationError8616,
    capture_immutable_source_graph_facts_8616,
)

__all__ = [
    "ConditionalNearCallPreservation8616",
    "ConditionalNearCallPreservationFailure8616",
    "ConditionalNearCallPreservationStats8616",
    "ConditionalNearCallPreservationVerdict8616",
    "consume_conditional_near_call_preservation_8616",
    "prove_conditional_near_call_preservation_8616",
    "prove_near_call_preservation_from_coordinates_8616",
]

_CS_REGISTER_8616 = "cs"


class ConditionalNearCallPreservationVerdict8616(StrEnum):
    """Evidence result for one conditional near-CALL preservation step.

    CONDITIONAL is deliberately distinct from any universal completeness:
    the step holds only relative to its retained selector obligation.
    REFUSED retains a typed failure, never a silent absence.
    """

    CONDITIONAL = "conditional"
    REFUSED = "refused"


class ConditionalNearCallPreservationFailure8616(StrEnum):
    """Typed reasons a conditional call step cannot materialize."""

    REQUEST_EXPIRED = "near_call_preservation_request_expired"
    THEOREM_ABSENT = "near_call_preservation_theorem_absent"
    CALLER_MISMATCH = "near_call_preservation_caller_mismatch"
    THEOREM_NOT_AUTHENTICATED = "near_call_preservation_theorem_not_authenticated"
    CALLSITE_UNPROVEN = "near_call_preservation_callsite_unproven"
    TARGET_MISMATCH = "near_call_preservation_target_mismatch"
    CALLEE_UNRESOLVED = "near_call_preservation_callee_unresolved"
    CALLEE_FOREIGN_CONTEXT = "near_call_preservation_callee_foreign_context"
    CALLEE_INCOMPLETE = "near_call_preservation_callee_incomplete"
    DEPENDENCY_UNPROVEN = "near_call_preservation_dependency_unproven"
    CS_NOT_PRESERVED = "near_call_preservation_cs_not_preserved"
    SEAL_SOURCE_CHANGED = "near_call_preservation_seal_source_changed"


@dataclass(frozen=True, slots=True)
class ConditionalNearCallPreservationStats8616:
    """Closed five-stage accounting for one conditional step evaluation."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether the candidate resolved to one step or refusal."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if not all(type(count) is int and count >= 0 for count in counts):
            return False
        return bool(
            self.raw_fact_count == self.normalized_fact_count == 1
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_dict(self) -> dict[str, int]:
        """Serialize the evidence ledger for diagnostics."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class ConditionalNearCallPreservation8616:
    """Conditional CS-preservation step (or typed refusal) for one near CALL.

    A CONDITIONAL verdict asserts only the interval-relative claim: if the
    retained ``obligation`` — the identical obligation the theorem proved —
    holds at ``callsite_addr``, and the callee bound at ``callee_addr``
    returns, CS is preserved across this CALL. The record deliberately has
    no ``complete`` property, no context-free ``preserved_registers``
    surface and no entry-to-callsite CS-preservation or termination claim —
    conditionality is the claim, not a stepping stone to a public proof.
    ``theorem``, ``obligation`` and ``callee`` are retained identities the
    consumer revalidates end to end; the scalar fields are the reconciled
    coordinates.
    """

    conditional_only: ClassVar[bool] = True
    cs_preservation_required: ClassVar[bool] = True
    callee_termination_unproved: ClassVar[bool] = True
    reachability_unproved: ClassVar[bool] = True

    verdict: ConditionalNearCallPreservationVerdict8616
    failure: ConditionalNearCallPreservationFailure8616 | None
    callee_failure: EntryDomainCallPreservationFailure8616 | None
    stats: ConditionalNearCallPreservationStats8616
    theorem: ConditionalNearCallTargetTheorem8616 | None = field(
        default=None, compare=False, repr=False,
    )
    callee: SegmentEffectClosureResult8616 | None = field(
        default=None, compare=False, repr=False,
    )
    obligation: ConditionalCallsiteSelectorObligation8616 | None = field(
        default=None, compare=False, repr=False,
    )
    callsite_addr: int | None = None
    next_addr: int | None = None
    target_addr: int | None = None
    callee_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the conditional step result for diagnostics."""
        return {
            "verdict": self.verdict.value,
            "failure": None if self.failure is None else self.failure.value,
            "callee_failure": (
                None
                if self.callee_failure is None
                else self.callee_failure.value
            ),
            "stats": self.stats.to_dict(),
            "callsite_addr": self.callsite_addr,
            "next_addr": self.next_addr,
            "target_addr": self.target_addr,
            "callee_addr": self.callee_addr,
            "statement": (
                "cs_preserved_across_call_if_obligation_holds"
                "_and_callee_returns"
            ),
            "obligation": (
                None if self.obligation is None else self.obligation.to_dict()
            ),
            "conditional_only": self.conditional_only,
            "cs_preservation_required": self.cs_preservation_required,
            "callee_termination_unproved": self.callee_termination_unproved,
        }


def _refuse_8616(
    callsite_addr: int | None,
    target_addr: int | None,
    failure: ConditionalNearCallPreservationFailure8616,
    *,
    normalized: bool = False,
    classified: bool = False,
    callee: SegmentEffectClosureResult8616 | None = None,
    callee_addr: int | None = None,
    callee_failure: EntryDomainCallPreservationFailure8616 | None = None,
) -> ConditionalNearCallPreservation8616:
    """Retain one refused conditional step in the five-stage evidence count."""
    return ConditionalNearCallPreservation8616(
        verdict=ConditionalNearCallPreservationVerdict8616.REFUSED,
        failure=failure,
        callee_failure=callee_failure,
        stats=ConditionalNearCallPreservationStats8616(
            1, int(normalized), int(classified), 0, 1
        ),
        callee=callee,
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        callee_addr=callee_addr,
    )


def _theorem_facts_valid_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
) -> bool:
    """Require the CONDITIONAL theorem and its retained obligation facts."""
    if not all((
        theorem.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL,
        theorem.failure is None,
        theorem.preflight_failure is None,
        theorem.stats.closed,
        theorem.stats.materialized_count == 1,
        theorem.stats.failure_count == 0,
    )):
        return False
    context, obligation = theorem.context, theorem.obligation
    if type(context) is not NativeNearCallEntry8616:
        return False
    if not all((
        type(theorem.artifact) is IRFunctionArtifact,
        type(theorem.block) is IRBlock,
        type(theorem.instruction) is IRInstr,
    )):
        return False
    if type(obligation) is not ConditionalCallsiteSelectorObligation8616:
        return False
    if obligation.context is not context:
        return False
    scalars = (
        theorem.callsite_addr,
        theorem.next_addr,
        theorem.target_addr,
        theorem.selector_low,
        theorem.selector_high,
        obligation.callsite_addr,
        obligation.selector_low,
        obligation.selector_high,
    )
    if not all(type(value) is int for value in scalars):
        return False
    return bool(
        obligation.callsite_addr == theorem.callsite_addr
        and obligation.selector_low == theorem.selector_low
        and obligation.selector_high == theorem.selector_high
    )


def _caller_boundary_bound_8616(
    project: object,
    context: NativeNearCallEntry8616,
    artifact: IRFunctionArtifact,
    instruction: IRInstr,
    callsite_addr: int | None,
) -> bool:
    """Require the context's callee boundary to own the identical caller."""
    boundary = context.boundary
    if type(boundary) is not ExactFunctionRangeBoundary8616:
        return False
    return bool(
        context.project is project
        and boundary.project is project
        and boundary.addr == artifact.function_addr
        and instruction.op == "CALL"
        and instruction.addr == callsite_addr
    )


def _surface_failure_8616(
    project: object,
    theorem: object,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
) -> ConditionalNearCallPreservationFailure8616 | None:
    """Reject omitted, foreign, or mismatched surfaces before any native work.

    The supplied surfaces must be the identical objects the theorem proved:
    the theorem's retained ``artifact``/``block``/``instruction``/``context``
    (with its native callsite index) define the only raw caller and context
    this step may combine with callee evidence.
    """
    if type(theorem) is not ConditionalNearCallTargetTheorem8616:
        return ConditionalNearCallPreservationFailure8616.THEOREM_ABSENT
    bound = theorem
    if not _theorem_facts_valid_8616(bound):
        return ConditionalNearCallPreservationFailure8616.THEOREM_ABSENT
    retained_context = cast(NativeNearCallEntry8616, bound.context)
    if not all((
        artifact is bound.artifact,
        context is retained_context,
        block is bound.block,
        instruction is bound.instruction,
    )):
        return ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
    if not _caller_boundary_bound_8616(
        project,
        retained_context,
        cast(IRFunctionArtifact, bound.artifact),
        cast(IRInstr, bound.instruction),
        bound.callsite_addr,
    ):
        return ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
    return None


def _callsite_evidence_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    theorem: ConditionalNearCallTargetTheorem8616,
    resolver: DirectCallTargetResolver8616,
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    DecodedDirectCallsite8616 | None,
    tuple[int, ...],
]:
    """Rebind the decoded outgoing-callsite row and its candidate window.

    The caller-boundary index is the canonical inventory for the caller's
    decoded CALL census; the retained row for the theorem's exact callsite
    recomputes the canonical candidate window — the raw encoded target plus
    a canonical head only when the owner's NOP-padding proof admits it. The
    window's encoded coordinates must equal the theorem's proven
    ``next_addr``/``target_addr`` or the census disagrees with the theorem.
    """
    index = decoded_callsite_index_for_boundary_8616(
        project, boundary, direct_target_resolver=resolver,
    ).index
    if direct_evidence_deadline_expired_8616(project):
        return ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED, None, ()
    entry = _decoded_entry_for_callsite_8616(
        index,
        boundary,
        _decoded_instruction_map_8616(boundary),
        cast(int, theorem.callsite_addr),
        resolver,
    )
    if entry is None:
        return (
            ConditionalNearCallPreservationFailure8616.CALLSITE_UNPROVEN,
            None,
            (),
        )
    window = _callsite_window_8616(project, entry)
    if window is None:
        return (
            ConditionalNearCallPreservationFailure8616.CALLSITE_UNPROVEN,
            entry,
            (),
        )
    if window[0] != theorem.next_addr or window[1] != theorem.target_addr:
        return (
            ConditionalNearCallPreservationFailure8616.TARGET_MISMATCH,
            entry,
            (),
        )
    return None, entry, window[2]


@dataclass(frozen=True, slots=True)
class _DetachedCallerFacts8616:
    """Immutable caller/theorem/context facts detached before callbacks.

    ``graph`` detaches the entire caller block surface through the
    canonical interned encoder, so a later in-place field mutation on any
    owned IR node — including ``compare=False`` provenance — is observable
    without trusting live object state. The scalar/identity fields pin the
    entry-context fields, the theorem's coordinate and selector-interval
    facts, the retained obligation's interval, and the proven operand and
    origin objects exactly as the authenticated pass validated them.
    ``theorem_integrity`` pins the verdict/failure/stats/shape facts the
    theorem consumer's retained-versus-fresh reconciliation covers, and
    ``theorem_surfaces`` pins the retained record's surface identities, so
    the seal can substitute the bounded native re-authentication for a
    second full factory replay without losing drift coverage. Object
    fields are ``compare=False`` because they are reconciled by identity
    (``is``), not by value equality.
    """

    graph: ImmutableSourceGraphFacts8616
    context_scalars: tuple[int, int, int, int, int, int]
    theorem_scalars: tuple[int, int, int, int, int]
    obligation_scalars: tuple[int, int, int]
    theorem_integrity: tuple[object, ...]
    call_encoding: bytes
    context_project: object = field(compare=False)
    context_boundary: object = field(compare=False)
    context_premise: object = field(compare=False)
    context_callsite_index: object = field(compare=False)
    context_callee_witness: object = field(compare=False)
    theorem_surfaces: tuple[object, ...] = field(compare=False)
    operand: object = field(compare=False)
    origin: object = field(compare=False)


@dataclass(frozen=True, slots=True)
class _SharedCallerGraph8616:
    """One operation-local caller graph bound to its owning artifact.

    A multi-step caller census detaches the caller's immutable source
    graph once per operation phase instead of once per retained step.
    ``artifact`` is the only caller this graph may stand in for: the
    capture and staleness helpers validate identical object identity
    before reuse, so the shared graph can never be assigned to a
    theorem whose caller artifact is foreign. Nothing is cached across
    operations.
    """

    artifact: IRFunctionArtifact = field(compare=False)
    graph: ImmutableSourceGraphFacts8616


def _caller_graph_facts_8616(
    artifact: IRFunctionArtifact, shared: _SharedCallerGraph8616 | None,
) -> ImmutableSourceGraphFacts8616 | None:
    """Use the identical caller's detached graph or capture its own source."""
    if shared is not None and artifact is shared.artifact:
        return shared.graph
    try:
        return capture_immutable_source_graph_facts_8616(
            artifact.function_addr, artifact.blocks, artifact.refusals,
        )
    except SourceGraphSerializationError8616:
        return None


def _capture_caller_facts_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
    *,
    shared_graph: _SharedCallerGraph8616 | None = None,
) -> _DetachedCallerFacts8616 | None:
    """Freeze owned caller/theorem/context facts before native callbacks.

    The snapshot must be taken before the callbacks whose side effects it
    guards, not after. A surface the canonical encoder cannot validate is
    already evidence drift, so the typed serialization refusal returns
    ``None`` rather than a partial projection.

    ``shared_graph`` substitutes one operation-local detached graph for
    this theorem's own capture, but only when the graph's bound artifact
    is the theorem's identical caller artifact; a foreign theorem always
    recaptures its own graph exactly as the standalone helper did.
    """
    artifact = theorem.artifact
    context = theorem.context
    block = theorem.block
    instruction = theorem.instruction
    obligation = theorem.obligation
    if artifact is None or context is None or block is None or instruction is None or obligation is None:
        return None
    if not all((
        type(artifact) is IRFunctionArtifact,
        type(context) is NativeNearCallEntry8616,
        type(block) is IRBlock,
        type(instruction) is IRInstr,
        type(obligation) is ConditionalCallsiteSelectorObligation8616,
    )):
        return None
    scalars = (
        context.callsite_addr,
        context.next_addr,
        context.target_addr,
        context.callee_addr,
        context.selector_low,
        context.selector_high,
        theorem.callsite_addr,
        theorem.next_addr,
        theorem.target_addr,
        theorem.selector_low,
        theorem.selector_high,
        obligation.callsite_addr,
        obligation.selector_low,
        obligation.selector_high,
    )
    if (
        len(instruction.args) != 1
        or type(context.call_encoding) is not bytes
        or not all(type(value) is int for value in scalars)
    ):
        return None
    graph = _caller_graph_facts_8616(artifact, shared_graph)
    if graph is None:
        return None
    return _DetachedCallerFacts8616(
        graph=graph,
        context_scalars=(
            context.callsite_addr,
            context.next_addr,
            context.target_addr,
            context.callee_addr,
            context.selector_low,
            context.selector_high,
        ),
        theorem_scalars=cast(tuple[int, int, int, int, int], (
            theorem.callsite_addr,
            theorem.next_addr,
            theorem.target_addr,
            theorem.selector_low,
            theorem.selector_high,
        )),
        obligation_scalars=(
            obligation.callsite_addr,
            obligation.selector_low,
            obligation.selector_high,
        ),
        theorem_integrity=_theorem_integrity_facts_8616(theorem),
        call_encoding=context.call_encoding,
        context_project=context.project,
        context_boundary=context.boundary,
        context_premise=context.premise,
        context_callsite_index=context.callsite_index,
        context_callee_witness=context.callee_witness,
        theorem_surfaces=(context, artifact, block, instruction, obligation),
        operand=instruction.args[0],
        origin=instruction.origin,
    )


def _theorem_integrity_facts_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
) -> tuple[object, ...]:
    """Detach scalar evidence so in-place payload mutation cannot rewrite it."""
    stats, shape = theorem.stats, theorem.shape
    return (
        theorem.verdict, theorem.failure, theorem.preflight_failure,
        (stats.raw_fact_count, stats.normalized_fact_count,
         stats.classified_fact_count, stats.materialized_count, stats.failure_count),
        None if shape is None else (
            shape.segment_register, shape.next_linear_addr,
            shape.displacement, shape.control_bits,
        ),
    )


def _record_facts_equal_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
) -> bool:
    """Reconcile pinned theorem integrity and surface identities.

    The integrity tuple reproduces the retained-record facts a
    retained-versus-fresh reconciliation re-checks — verdict, failures,
    stats and recovered operand shape — and the surface tuple pins the
    identical context, artifact, block, instruction and obligation objects
    the snapshot validated, so a substituted bounded re-authentication
    loses no drift coverage the full consume provided.
    """
    if _theorem_integrity_facts_8616(theorem) != snapshot.theorem_integrity:
        return False
    surfaces = (
        theorem.context,
        theorem.artifact,
        theorem.block,
        theorem.instruction,
        theorem.obligation,
    )
    return all(
        surface is pinned
        for surface, pinned in zip(
            surfaces, snapshot.theorem_surfaces, strict=True
        )
    )


def _stale_owned_caller_facts_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
) -> bool:
    """Return whether any callback-free owned caller fact drifted.

    Pure owned reads with no native callback and no detached-graph
    recapture: root/context coordinate agreement, retained block
    membership, CALL identity, the proven operand and origin objects, the
    context scalar/identity projection, the theorem's integrity facts and
    retained surface identities, and the theorem and obligation
    coordinate/interval facts. A scoped census step reconciles these facts
    against the scope's pre-callback snapshot at the same positions the
    standalone consumer seals them; the fresh-graph comparison still runs
    only under the scope's final whole-census seal and under each
    standalone seal's final callee-and-caller reconciliation.
    """
    artifact = theorem.artifact
    context = theorem.context
    block = theorem.block
    instruction = theorem.instruction
    obligation = theorem.obligation
    if artifact is None or context is None or block is None or instruction is None or obligation is None:
        return True
    if not all((
        type(artifact) is IRFunctionArtifact,
        type(context) is NativeNearCallEntry8616,
        type(block) is IRBlock,
        type(instruction) is IRInstr,
        type(obligation) is ConditionalCallsiteSelectorObligation8616,
    )):
        return True
    boundary = context.boundary
    if type(boundary) is not ExactFunctionRangeBoundary8616:
        return True
    if not all((
        boundary.project is project,
        boundary.addr == artifact.function_addr,
        artifact.function_addr == context.target_addr,
        any(candidate is block for candidate in artifact.blocks),
    )):
        return True
    if not all((
        instruction.op == "CALL",
        instruction.addr == theorem.callsite_addr,
        len(instruction.args) == 1,
        instruction.origin is snapshot.origin,
        any(item is instruction for item in block.instrs),
    )):
        return True
    if instruction.args[0] is not snapshot.operand:
        return True
    if not all((
        context.project is snapshot.context_project,
        context.boundary is snapshot.context_boundary,
        context.premise is snapshot.context_premise,
        context.callsite_index is snapshot.context_callsite_index,
        context.callee_witness is snapshot.context_callee_witness,
    )):
        return True
    return not all((
        context.call_encoding == snapshot.call_encoding,
        _record_facts_equal_8616(theorem, snapshot),
        (
            context.callsite_addr,
            context.next_addr,
            context.target_addr,
            context.callee_addr,
            context.selector_low,
            context.selector_high,
        ) == snapshot.context_scalars,
        (
            theorem.callsite_addr,
            theorem.next_addr,
            theorem.target_addr,
            theorem.selector_low,
            theorem.selector_high,
        ) == snapshot.theorem_scalars,
        obligation.context is context,
        (
            obligation.callsite_addr,
            obligation.selector_low,
            obligation.selector_high,
        ) == snapshot.obligation_scalars,
    ))


def _stale_caller_facts_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    *,
    shared_fresh: _SharedCallerGraph8616 | None = None,
) -> bool:
    """Return whether any owned caller fact drifted from the snapshot.

    Every callback-free owned read ``_stale_owned_caller_facts_8616``
    performs, then the full recaptured source graph (which covers in-place
    field mutation an identity check cannot see) compared against the
    snapshot's detached graph.

    ``shared_fresh`` substitutes one operation-local post-callback
    recapture for this theorem's own fresh capture, but only when the
    graph's bound artifact is the theorem's identical caller artifact;
    a foreign theorem always recaptures its own graph exactly as the
    standalone helper did.
    """
    if _stale_owned_caller_facts_8616(project, theorem, snapshot):
        return True
    artifact = cast(IRFunctionArtifact, theorem.artifact)
    fresh = _caller_graph_facts_8616(artifact, shared_fresh)
    return fresh is None or not all((
        fresh == snapshot.graph,
        fresh.function_refusals == snapshot.graph.function_refusals,
        fresh.block_refusals == snapshot.graph.block_refusals,
    ))


@contextmanager
def _resolution_scope_8616(
    project: object,
    resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None,
) -> Iterator[_CalleeResolution8616]:
    """Join the owner's active callee session or mint one bounded session.

    A supplied session is installed for nested imports; an active project session
    is joined unchanged. Otherwise one session is minted and installed on the project
    slot for exactly this resolution so nested callee imports share the
    aggregate budget — the identical mechanism the collector uses. No new
    cache, registry, or scheduler is created.
    """
    active = _active_resolution_8616(project)
    if active is not None:
        if resolution is not None and resolution is not active:
            raise ValueError("Cannot replace an active callee resolution budget")
        yield active
        return
    surface = cast(_CalleeResolutionSurface8616, project)
    session = resolution if resolution is not None else _CalleeResolution8616(
        resolver=resolver,
        deadline=_active_direct_evidence_deadline_8616(project),
    )
    surface._inertia_entry_domain_call_resolution_8616 = session
    try:
        yield session
    finally:
        surface._inertia_entry_domain_call_resolution_8616 = None


def _resolve_universal_callee_8616(
    project: object,
    caller_head: int,
    entry: DecodedDirectCallsite8616,
    candidates: tuple[int, ...],
    session: _CalleeResolution8616,
) -> tuple[
    SegmentEffectClosureResult8616 | None,
    int | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Resolve the first bound universal closure across the candidate window.

    The caller's own head is held in-flight during resolution so a callee
    chain cycling back into it reports the owner's dependency refusal
    instead of resolving a second caller. ``entry`` is the identical decoded
    row the census bound, transported only into premise-bound imports; a
    premise-derived callee keeps the universal route refused, matching the
    owner contract.
    """
    callee: SegmentEffectClosureResult8616 | None = None
    callee_addr: int | None = None
    refusal: EntryDomainCallPreservationFailure8616 | None = None
    prior_in_flight = session.in_flight
    session.in_flight = prior_in_flight | {caller_head}
    try:
        for candidate in candidates:
            closure, refusal = _callee_closure_8616(
                project, candidate, session, callsite=entry,
            )
            if direct_evidence_deadline_expired_8616(project):
                return None, None, refusal
            if closure is not None:
                callee, callee_addr = closure, candidate
                break
    finally:
        session.in_flight = prior_in_flight
    return callee, callee_addr, None if callee is not None else refusal


def _callee_chain_failure_8616(
    project: object,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
    candidates: tuple[int, ...],
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Revalidate the bound universal closure through canonical owners only.

    The closure must bind the requested candidate head on the identical
    project, carry no scoped or entry-contextual state (a universal closure
    only), prove ``complete`` context-free, satisfy the canonical nested-call
    dependency census, and preserve the CS identity at entry and every
    return exit through the canonical preserved-register projection.
    """
    if type(callee) is not SegmentEffectClosureResult8616:
        return ConditionalNearCallPreservationFailure8616.CALLEE_UNRESOLVED, None
    bound_callee = callee
    coverage = bound_callee.coverage
    if type(coverage) is not IRBoundaryCoverageResult8616:
        return ConditionalNearCallPreservationFailure8616.CALLEE_UNRESOLVED, None
    boundary = coverage.boundary
    if (
        type(boundary) is not ExactFunctionRangeBoundary8616
        or boundary.project is not project
        or type(coverage.artifact) is not IRFunctionArtifact
    ):
        return ConditionalNearCallPreservationFailure8616.CALLEE_UNRESOLVED, None
    if coverage.artifact.function_addr != callee_addr or callee_addr not in candidates:
        return ConditionalNearCallPreservationFailure8616.TARGET_MISMATCH, None
    state = bound_callee.state
    if type(state) is not SegmentStateArtifact:
        return ConditionalNearCallPreservationFailure8616.CALLEE_UNRESOLVED, None
    if any(scope is not None for scope in (
        state.invocation_scope, state.entry_context, state.near_call_scope, state.scoped_view,
    )):
        return (
            ConditionalNearCallPreservationFailure8616.CALLEE_FOREIGN_CONTEXT,
            None,
        )
    with segment_call_dependency_traversal_scope_8616():
        if not bound_callee.complete:
            return (
                ConditionalNearCallPreservationFailure8616.CALLEE_INCOMPLETE,
                None,
            )
        dependency = _callee_dependency_failure_8616(callee)
        if dependency is not None:
            return (
                ConditionalNearCallPreservationFailure8616.DEPENDENCY_UNPROVEN,
                dependency,
            )
        if _CS_REGISTER_8616 not in _callee_preserved_registers_8616(callee):
            return ConditionalNearCallPreservationFailure8616.CS_NOT_PRESERVED, None
    return None, None


def _seal_refusal_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    failure: ConditionalNearCallPreservationFailure8616,
    owner_failure: EntryDomainCallPreservationFailure8616 | None = None,
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Prefer SEAL_SOURCE_CHANGED when post-callback facts still drift.

    Within the existing request budget, one failure-path-only whole-graph
    recapture reproduces the ordering a
    pre-authentication graph seal enforced: caller facts that still
    disagree with the detached snapshot at a refusal point outrank the
    downstream refusal, so persistent drift keeps its original typed
    diagnostic. Never runs on the success path; the final
    callee-and-caller seal remains the only success-path graph
    comparison.
    """
    if (
        failure
        is not ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED
        and not direct_evidence_deadline_expired_8616(project)
        and _stale_caller_facts_8616(project, theorem, snapshot)
    ):
        return ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED, None
    return failure, owner_failure


def _evidence_seal_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
    candidates: tuple[int, ...],
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Reauthenticate native facts and seal owned facts after callbacks.

    One bounded pass: reconcile the snapshot's callback-free owned caller
    facts, re-run the theorem's canonical native re-authentication —
    raw-root rebind, entry-context consumption and mapped-byte binding
    through the same owner surfaces the consume replays — then reconcile
    the retained callee through the canonical chain check so its facts
    survive the late native target checks, and run the one fresh
    whole-graph reconciliation against the detached snapshot after the
    last callback, so no callback can invalidate the earlier raw-IR or
    surface checks unnoticed. A downstream refusal re-runs the full
    reconciliation once on the refusal path so persistent drift keeps its
    SEAL_SOURCE_CHANGED diagnostic. The theorem's owned derivation is
    not replayed here: the upfront consume or synchronous
    canonical factory already established the record against live evidence, and the snapshot pinned at
    operation entry covers every post-callback owned-fact drift this
    seal guards, including the integrity and surface-identity facts a
    retained-versus-fresh comparison would re-check. No replay loop and
    no new registry or cache.
    """
    if _stale_owned_caller_facts_8616(project, theorem, snapshot):
        return ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED, None
    if not reauthenticate_conditional_near_call_target_8616(
        project,
        theorem,
        artifact=theorem.artifact,
        context=theorem.context,
        block=theorem.block,
        instruction=theorem.instruction,
    ):
        return _seal_refusal_8616(
            project,
            theorem,
            snapshot,
            ConditionalNearCallPreservationFailure8616.THEOREM_NOT_AUTHENTICATED,
        )
    if direct_evidence_deadline_expired_8616(project):
        return _seal_refusal_8616(
            project,
            theorem,
            snapshot,
            ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED,
        )
    failure, owner_failure = _final_callee_and_caller_seal_8616(
        project, theorem, snapshot, callee, callee_addr, candidates,
    )
    if failure is None:
        return None, None
    return _seal_refusal_8616(project, theorem, snapshot, failure, owner_failure)


def _final_callee_and_caller_seal_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
    candidates: tuple[int, ...],
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Reconcile the callee and caller after the last target authentication."""
    if callee is not None:
        failure, owner_failure = _callee_chain_failure_8616(
            project, callee, callee_addr, candidates
        )
        if failure is not None:
            return failure, owner_failure
        if direct_evidence_deadline_expired_8616(project):
            return ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED, None
    if _stale_caller_facts_8616(project, theorem, snapshot):
        return ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED, None
    return None, None



def _consume_evidence_seal_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
    candidates: tuple[int, ...],
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Fully replay retained target evidence after untrusted census callbacks.

    No intermediate census or callee check publishes authority. The initial
    detached snapshot brackets those callbacks and this full target replay;
    owned caller facts reconcile before it, the fresh whole-graph
    comparison defers to the final callee-and-caller seal, and a refusal
    re-runs the full reconciliation once on the refusal path so persistent
    drift keeps its SEAL_SOURCE_CHANGED diagnostic.
    """
    if _stale_owned_caller_facts_8616(project, theorem, snapshot):
        return ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED, None
    if not consume_conditional_near_call_target_8616(
        project, theorem, artifact=theorem.artifact, context=theorem.context,
        block=theorem.block, instruction=theorem.instruction,
    ):
        return _seal_refusal_8616(
            project,
            theorem,
            snapshot,
            ConditionalNearCallPreservationFailure8616.THEOREM_NOT_AUTHENTICATED,
        )
    if direct_evidence_deadline_expired_8616(project):
        return _seal_refusal_8616(
            project,
            theorem,
            snapshot,
            ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED,
        )
    failure, owner_failure = _final_callee_and_caller_seal_8616(
        project, theorem, snapshot, callee, callee_addr, candidates,
    )
    if failure is None:
        return None, None
    return _seal_refusal_8616(project, theorem, snapshot, failure, owner_failure)


def _scoped_evidence_seal_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
    candidates: tuple[int, ...],
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Replay retained target evidence inside a scoped census step.

    Identical order and deadlines as the consumer's evidence seal —
    caller reconciliation bracketing the theorem's staged canonical
    target gates, then the retained callee's canonical revalidation —
    except owned-fact reconciliation substitutes for the detached-graph
    capture, and the staged gates omit the raw-root rebind, context
    replay and theorem-level snapshots the enclosing scope runs once
    per census or once at its final seal. No retained graph substitutes
    for a fresh post-callback observation: the owning scope compares a
    fresh whole graph against this original pre-callback snapshot after
    the last callback, then re-derives every theorem callback-free.
    """
    if _stale_owned_caller_facts_8616(project, theorem, snapshot):
        return ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED, None
    staged_target = _staged_scoped_theorem_8616(
        project, theorem, artifact=theorem.artifact, context=theorem.context,
        block=theorem.block, instruction=theorem.instruction,
    )
    if staged_target is not _ScopedTargetStage8616.STAGED:
        return (
            ConditionalNearCallPreservationFailure8616.THEOREM_NOT_AUTHENTICATED,
            None,
        )
    if direct_evidence_deadline_expired_8616(project):
        return ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED, None
    if callee is not None:
        failure, owner_failure = _callee_chain_failure_8616(
            project, callee, callee_addr, candidates
        )
        if failure is not None:
            return failure, owner_failure
        if direct_evidence_deadline_expired_8616(project):
            return (
                ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED,
                None,
            )
    if _stale_owned_caller_facts_8616(project, theorem, snapshot):
        return ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED, None
    return None, None


def _bound_callee_evidence_8616(
    project: object,
    caller_head: int,
    entry: DecodedDirectCallsite8616,
    candidates: tuple[int, ...],
    resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None,
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    SegmentEffectClosureResult8616 | None,
    int | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Resolve and revalidate the bound universal callee closure.

    Returns ``(failure, callee, callee_addr, owner_failure)``: the joined
    or minted owner session resolves the candidate window under the
    caller's in-flight mark, and the bound closure then passes the
    canonical completeness, census and CS-identity chain unchanged.
    """
    with _resolution_scope_8616(project, resolver, resolution) as session:
        callee, callee_addr, callee_refusal = _resolve_universal_callee_8616(
            project, caller_head, entry, candidates, session
        )
    if direct_evidence_deadline_expired_8616(project):
        return (
            ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED,
            callee,
            callee_addr,
            callee_refusal,
        )
    if callee is None:
        return (
            ConditionalNearCallPreservationFailure8616.CALLEE_UNRESOLVED,
            None,
            None,
            callee_refusal,
        )
    failure, owner_failure = _callee_chain_failure_8616(
        project, callee, callee_addr, candidates
    )
    if failure is not None:
        return failure, callee, callee_addr, owner_failure
    return None, callee, callee_addr, None


def _resolve_and_seal_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    entry: DecodedDirectCallsite8616,
    candidates: tuple[int, ...],
    resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None,
) -> tuple[
    ConditionalNearCallPreservationFailure8616 | None,
    SegmentEffectClosureResult8616 | None,
    int | None,
    EntryDomainCallPreservationFailure8616 | None,
]:
    """Resolve the universal callee then seal all retained evidence.

    Returns ``(failure, callee, callee_addr, owner_failure)`` so the caller
    can retain the bound evidence on either kind of refusal; the seal runs
    only when a closure was bound and revalidated first.
    """
    artifact = cast(IRFunctionArtifact, theorem.artifact)
    failure, callee, callee_addr, owner_failure = _bound_callee_evidence_8616(
        project, artifact.function_addr, entry, candidates, resolver,
        resolution,
    )
    if failure is not None:
        return failure, callee, callee_addr, owner_failure
    failure, owner_failure = _evidence_seal_8616(
        project, theorem, snapshot, callee, callee_addr, candidates
    )
    return failure, callee, callee_addr, owner_failure


def prove_conditional_near_call_preservation_8616(
    project: object,
    theorem: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    direct_target_resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None = None,
) -> ConditionalNearCallPreservation8616:
    """Prove the conditional CS-preservation step for one outgoing CALL.

    Identical ``artifact``/``block``/``instruction``/``context`` objects to
    the theorem's retained surfaces are required — a copied or foreign
    caller refuses. The theorem is re-authenticated end to end; the
    outgoing callsite's decoded row and canonical candidate window come
    from the caller-boundary census; a bounded universal callee closure is
    resolved per candidate (canonical head first only when the owner's
    NOP-padding window admits it); and the bound closure is revalidated for
    universal completeness, the dependency census and entry/return CS
    identity. A detached caller snapshot captured before the first native
    callback is reconciled again after the last, bracketing one bounded
    theorem re-authentication and one callee revalidation, so no callback
    can revoke the already-authenticated caller root or callee facts
    unnoticed. The identical selector obligation is retained unproved. The
    request deadline is enforced across every native callback.
    """
    callsite = (
        theorem.callsite_addr
        if type(theorem) is ConditionalNearCallTargetTheorem8616
        else None
    )
    target = (
        theorem.target_addr
        if type(theorem) is ConditionalNearCallTargetTheorem8616
        else None
    )
    if resolution is not None and type(resolution) is not _CalleeResolution8616:
        raise TypeError("resolution must be a typed callee resolution session")
    expired = ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED
    if direct_evidence_deadline_expired_8616(project):
        return _refuse_8616(callsite, target, expired)
    failure = _surface_failure_8616(
        project, theorem, artifact, context, block, instruction
    )
    if failure is not None:
        return _refuse_8616(callsite, target, failure)
    bound = cast(ConditionalNearCallTargetTheorem8616, theorem)
    snapshot = _capture_caller_facts_8616(bound)
    if snapshot is None:
        return _refuse_8616(
            callsite,
            target,
            ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED,
            normalized=True,
        )
    if not consume_conditional_near_call_target_8616(
        project,
        bound,
        artifact=artifact,
        context=context,
        block=block,
        instruction=instruction,
    ):
        return _refuse_8616(
            callsite,
            target,
            ConditionalNearCallPreservationFailure8616.THEOREM_NOT_AUTHENTICATED,
            normalized=True,
        )
    return _finish_conditional_preservation_8616(
        project, bound, snapshot, direct_target_resolver, resolution,
    )


def prove_near_call_preservation_from_coordinates_8616(
    project: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    coordinates: DirectNearCallCoordinates8616,
    direct_target_resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None = None,
) -> ConditionalNearCallPreservation8616:
    """Derive and consume fresh target evidence in one synchronous operation.

    The canonical target factory seals its native inputs before returning.
    Its result stays private until a detached caller snapshot is captured,
    with no intervening native callback. Callee composition then uses the
    same final native reauthentication and callback-free reconciliation as
    arbitrary-theorem composition. No reusable authentication token is
    produced; later consumers must replay the retained theorem normally.
    """
    if resolution is not None and type(resolution) is not _CalleeResolution8616:
        raise TypeError("resolution must be a typed callee resolution session")
    if direct_evidence_deadline_expired_8616(project):
        return _refuse_8616(
            coordinates.callsite_addr, coordinates.target_addr,
            ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED,
        )
    bound = prove_conditional_near_call_target_8616(
        project, artifact=artifact, context=context, block=block,
        instruction=instruction, coordinates=coordinates,
    )
    failure = _surface_failure_8616(
        project, bound, artifact, context, block, instruction,
    )
    if failure is not None:
        return _refuse_8616(bound.callsite_addr, bound.target_addr, failure)
    snapshot = _capture_caller_facts_8616(bound)
    if snapshot is None:
        return _refuse_8616(
            bound.callsite_addr, bound.target_addr,
            ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED,
            normalized=True,
        )
    return _finish_conditional_preservation_8616(
        project, bound, snapshot, direct_target_resolver, resolution,
    )


def _finish_conditional_preservation_8616(
    project: object,
    bound: ConditionalNearCallTargetTheorem8616,
    snapshot: _DetachedCallerFacts8616,
    direct_target_resolver: DirectCallTargetResolver8616,
    resolution: _CalleeResolution8616 | None,
) -> ConditionalNearCallPreservation8616:
    """Compose authenticated target evidence and retain every final native seal."""
    callsite, target = bound.callsite_addr, bound.target_addr
    expired = ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED
    if direct_evidence_deadline_expired_8616(project):
        return _refuse_8616(callsite, target, expired, normalized=True)
    boundary = cast(NativeNearCallEntry8616, bound.context).boundary
    failure, entry, candidates = _callsite_evidence_8616(
        project,
        boundary,
        bound,
        direct_target_resolver,
    )
    if failure is not None:
        return _refuse_8616(callsite, target, failure, normalized=True)
    failure, callee, callee_addr, owner_failure = _resolve_and_seal_8616(
        project,
        bound,
        snapshot,
        cast(DecodedDirectCallsite8616, entry),
        candidates,
        direct_target_resolver,
        resolution,
    )
    if failure is not None:
        return _refuse_8616(
            callsite,
            target,
            failure,
            normalized=True,
            classified=callee is not None,
            callee=callee,
            callee_addr=callee_addr,
            callee_failure=owner_failure,
        )
    if direct_evidence_deadline_expired_8616(project):
        return _refuse_8616(
            callsite,
            target,
            expired,
            normalized=True,
            classified=True,
            callee=callee,
            callee_addr=callee_addr,
        )
    return _conditional_preservation_record_8616(bound, callee, callee_addr)


def _conditional_preservation_record_8616(
    bound: ConditionalNearCallTargetTheorem8616,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
) -> ConditionalNearCallPreservation8616:
    """Materialize the canonical record only after caller and callee seals pass."""
    return ConditionalNearCallPreservation8616(
        verdict=ConditionalNearCallPreservationVerdict8616.CONDITIONAL,
        failure=None,
        callee_failure=None,
        stats=ConditionalNearCallPreservationStats8616(1, 1, 1, 1, 0),
        theorem=bound,
        callee=callee,
        obligation=bound.obligation,
        callsite_addr=bound.callsite_addr,
        next_addr=bound.next_addr,
        target_addr=bound.target_addr,
        callee_addr=callee_addr,
    )


def _step_integrity_8616(step: ConditionalNearCallPreservation8616) -> bool:
    """Require the retained CONDITIONAL step to carry its whole chain."""
    if not all((
        step.verdict is ConditionalNearCallPreservationVerdict8616.CONDITIONAL,
        step.failure is None,
        step.callee_failure is None,
        step.stats.closed,
        step.stats.materialized_count == 1,
        step.stats.failure_count == 0,
    )):
        return False
    theorem, obligation, callee = step.theorem, step.obligation, step.callee
    if type(theorem) is not ConditionalNearCallTargetTheorem8616:
        return False
    bound_theorem = theorem
    if type(obligation) is not ConditionalCallsiteSelectorObligation8616:
        return False
    if obligation is not bound_theorem.obligation:
        return False
    if type(callee) is not SegmentEffectClosureResult8616:
        return False
    return all((
        type(step.callee_addr) is int,
        step.callsite_addr == bound_theorem.callsite_addr,
        step.next_addr == bound_theorem.next_addr,
        step.target_addr == bound_theorem.target_addr,
        type(bound_theorem.callsite_addr) is int,
        type(bound_theorem.next_addr) is int,
        type(bound_theorem.target_addr) is int,
    ))


def _replay_evidence_8616(
    project: object,
    theorem: ConditionalNearCallTargetTheorem8616,
    boundary: ExactFunctionRangeBoundary8616,
    callee: SegmentEffectClosureResult8616 | None,
    callee_addr: int | None,
    resolver: DirectCallTargetResolver8616,
    snapshot: _DetachedCallerFacts8616,
) -> bool:
    """Replay census, callee and seal checks against live evidence.

    One bounded pass: recompute the decoded callsite row and canonical
    window, revalidate the retained callee through the canonical chain,
    then run the evidence seal — caller-fact reconciliation bracketing the
    full final theorem replay and callee revalidation — and require
    the request deadline to survive it all.
    """
    failure, _entry, candidates = _callsite_evidence_8616(
        project, boundary, theorem, resolver
    )
    if failure is not None:
        return False
    chain_failure, _owner = _callee_chain_failure_8616(
        project, callee, callee_addr, candidates
    )
    if chain_failure is not None:
        return False
    seal_failure, _seal_owner = _consume_evidence_seal_8616(
        project, theorem, snapshot, callee, callee_addr, candidates
    )
    if seal_failure is not None:
        return False
    return not direct_evidence_deadline_expired_8616(project)


class _ScopedCensusStepStatus8616(StrEnum):
    """Staged per-step outcome inside one scope-owned caller census.

    ``STAGED`` reports only that this step's staged checks passed; it is
    not proof and publishes nothing — the outer scope's fresh
    whole-census seal after the last callback remains the only admission
    authority. ``REFUSED`` retains typed failure evidence.
    """

    STAGED = "staged"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class _ScopedCensusStep8616:
    """Typed staged census-step result with retained refusal evidence."""

    status: _ScopedCensusStepStatus8616
    failure: ConditionalNearCallPreservationFailure8616 | None = None
    callee_failure: EntryDomainCallPreservationFailure8616 | None = None

    def __bool__(self) -> bool:
        """Reject accidental use of an unsealed staged result as proof."""
        raise TypeError("A staged census step requires the final whole-census seal")


def _staged_step_refusal_8616(
    failure: ConditionalNearCallPreservationFailure8616,
    callee_failure: EntryDomainCallPreservationFailure8616 | None = None,
) -> _ScopedCensusStep8616:
    """Retain one refused staged step with its typed failure evidence."""
    return _ScopedCensusStep8616(
        _ScopedCensusStepStatus8616.REFUSED, failure, callee_failure
    )


def _consume_scoped_census_step_8616(
    project: object,
    step: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    direct_target_resolver: DirectCallTargetResolver8616,
    snapshot: _DetachedCallerFacts8616,
) -> _ScopedCensusStep8616:
    """Run one census step's staged checks under the scope's owned seals.

    Every standalone consumer check is retained — step record integrity,
    the identical surface binding, the request deadline bracketing each
    native callback, the callsite native census, the retained callee's
    canonical chain validation, and the theorem's full target replay
    deferred to after the census and callee checks. ``snapshot`` must be
    the scope's complete pre-callback caller capture for this step's
    identical theorem: owned caller facts reconcile against it before the
    first native callback and again after the last one, but no caller
    source graph is captured or compared here — the scope owns the only
    fresh whole-graph seal after every callback; retained graphs never
    substitute for that fresh observation. ``STAGED`` is never proof: a partial
    staged result never licenses publication; only the scope's successful
    final whole-census authentication admits the step.
    """
    if type(step) is not ConditionalNearCallPreservation8616 or not _step_integrity_8616(
        step
    ):
        return _staged_step_refusal_8616(
            ConditionalNearCallPreservationFailure8616.THEOREM_ABSENT
        )
    theorem = cast(ConditionalNearCallTargetTheorem8616, step.theorem)
    retained_context = theorem.context
    if not all((
        type(retained_context) is NativeNearCallEntry8616,
        context is retained_context,
        artifact is theorem.artifact,
        block is theorem.block,
        instruction is theorem.instruction,
        type(snapshot) is _DetachedCallerFacts8616,
    )):
        return _staged_step_refusal_8616(
            ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
        )
    if direct_evidence_deadline_expired_8616(project):
        return _staged_step_refusal_8616(
            ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED
        )
    boundary = cast(NativeNearCallEntry8616, retained_context).boundary
    if (
        type(boundary) is not ExactFunctionRangeBoundary8616
        or boundary.project is not project
    ):
        return _staged_step_refusal_8616(
            ConditionalNearCallPreservationFailure8616.CALLER_MISMATCH
        )
    if _stale_owned_caller_facts_8616(project, theorem, snapshot):
        return _staged_step_refusal_8616(
            ConditionalNearCallPreservationFailure8616.SEAL_SOURCE_CHANGED
        )
    census_failure, _entry, candidates = _callsite_evidence_8616(
        project,
        boundary,
        theorem,
        direct_target_resolver,
    )
    if census_failure is not None:
        return _staged_step_refusal_8616(census_failure)
    callee = step.callee
    chain_failure, chain_owner = _callee_chain_failure_8616(
        project, callee, step.callee_addr, candidates
    )
    if chain_failure is not None:
        return _staged_step_refusal_8616(chain_failure, chain_owner)
    seal_failure, seal_owner = _scoped_evidence_seal_8616(
        project, theorem, snapshot, callee, step.callee_addr, candidates
    )
    if seal_failure is not None:
        return _staged_step_refusal_8616(seal_failure, seal_owner)
    if direct_evidence_deadline_expired_8616(project):
        return _staged_step_refusal_8616(
            ConditionalNearCallPreservationFailure8616.REQUEST_EXPIRED
        )
    return _ScopedCensusStep8616(_ScopedCensusStepStatus8616.STAGED)


def consume_conditional_near_call_preservation_8616(
    project: object,
    step: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    direct_target_resolver: DirectCallTargetResolver8616,
) -> bool:
    """Revalidate a retained conditional step against live evidence.

    The identical explicit surfaces the theorem retained are required — a
    copied or foreign caller returns ``False`` before any replay. The
    decoded outgoing-callsite row and canonical window are recomputed;
    and the bound callee revalidates universal completeness, the dependency
    census, and entry/return CS identity under one bounded traversal. A
    detached caller snapshot seals every retained caller, theorem and
    obligation fact after the last native callback — the theorem's native
    surfaces and retained facts are fully replayed once inside that final
    seal, then the callee is revalidated. The snapshot covers owned-fact
    drift across every callback; no intermediate result publishes proof.
    The retained selector obligation is never discharged here — a ``True``
    result asserts only that the conditional step remains bound exactly as
    recorded.
    """
    if type(step) is not ConditionalNearCallPreservation8616 or not _step_integrity_8616(
        step
    ):
        return False
    theorem = cast(ConditionalNearCallTargetTheorem8616, step.theorem)
    retained_context = theorem.context
    if not all((
        type(retained_context) is NativeNearCallEntry8616,
        context is retained_context,
        artifact is theorem.artifact,
        block is theorem.block,
        instruction is theorem.instruction,
    )):
        return False
    if direct_evidence_deadline_expired_8616(project):
        return False
    snapshot = _capture_caller_facts_8616(theorem)
    if snapshot is None:
        return False
    boundary = cast(NativeNearCallEntry8616, retained_context).boundary
    if (
        type(boundary) is not ExactFunctionRangeBoundary8616
        or boundary.project is not project
    ):
        return False
    return _replay_evidence_8616(
        project,
        theorem,
        boundary,
        step.callee,
        step.callee_addr,
        direct_target_resolver,
        snapshot,
    )
