"""Bind proved segment preservation to one exact near CALL, leaf or chained.

Layer: IR.
Responsibility: consume raw caller coverage, a decoded direct-call index and
closed callee state. Preserve only identities unchanged on every returning
exit. A CONST control operand binds by exact full-width callee equality only;
a symbolic operand must bind through the Semantics-owned direct-near target
proof against the decoded index entry's native instruction evidence. When
the all-fetch-selector window cannot discharge that binding, an optional
source-bound ``Real16InvocationDomain8616`` premise may be offered; the
consumed consumption record is then retained on the result and replayed on
every revalidation, so a conditional binding never escapes as a universal
claim. A
non-leaf callee is admitted only through a fully proved acyclic direct-callee
closure: every CALL site recorded in the admitted callee chain must carry
exactly one bound, still-complete proof, inside explicit traversal budgets.
This never proves whole-function equivalence, stack balance, or termination;
it only projects segment identities observed at the callee's admitted RET
exits. Never infer GP preservation, calling conventions, or pointer types.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, TypeGuard, cast

from ..frontend_direct_callsite_index import DecodedDirectCallsite8616, DecodedDirectCallsiteIndex8616
from .core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace, SegmentOrigin
from .ir_boundary_cfg import IRBoundaryCoverageResult8616
from .segment_state_transfer import SEGMENT_REGISTERS

if TYPE_CHECKING:
    from .real16_invocation_domain import (
        Real16CallInvocation8616,
        Real16InvocationDomain8616,
    )
    from .segment_effect_closure import SegmentEffectClosureResult8616


class _DecodedInstructionSurface8616(Protocol):
    """Third-party decoded instruction coordinate consumed from the frontend."""

    address: int


class SegmentCallPreservationFailure8616(StrEnum):
    """Stable reasons a call cannot retain segment identities.

    ``CALLEE_NOT_LEAF`` is retained for results produced before acyclic
    dependency-chain admission existed; new evaluations emit the precise
    ``DEPENDENCY_*`` reason instead.
    """

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    PROJECT_MISMATCH = "project_mismatch"
    CALLEE_NOT_LEAF = "callee_not_leaf"
    INDEX_INCOMPLETE = "index_incomplete"
    CALLSITE_UNPROVEN = "callsite_unproven"
    TARGET_MISMATCH = "target_mismatch"
    ACCOUNTING_INCOMPLETE = "accounting_incomplete"
    DEPENDENCY_MISSING = "dependency_missing"
    DEPENDENCY_AMBIGUOUS = "dependency_ambiguous"
    DEPENDENCY_STALE = "dependency_stale"
    DEPENDENCY_CYCLE = "dependency_cycle"
    DEPENDENCY_BUDGET_EXHAUSTED = "dependency_budget_exhausted"


_SEGMENT_CALL_DEPENDENCY_MAX_DEPTH_8616: int = 16
_SEGMENT_CALL_DEPENDENCY_MAX_CLOSURES_8616: int = 64
_SEGMENT_CALL_DEPENDENCY_MAX_PROOFS_8616: int = 256


@dataclass(slots=True)
class SegmentCallDependencyTraversal8616:
    """Bounded one-shot traversal state for dependency-closure evaluation.

    Keys are ``id()`` identities; every keyed object stays reachable from the
    root result for the whole traversal, so no identifier can be recycled
    while these maps live. ``active_*`` is the DFS stack used for cycle
    detection; ``*_verdicts`` memoizes completed nodes so shared callees in a
    DAG are revalidated once instead of exponentially.
    """

    active_domains: set[int] = field(default_factory=set)
    domain_verdicts: dict[int, bool] = field(default_factory=dict)
    retained_domains: dict[int, Real16InvocationDomain8616] = field(default_factory=dict)
    remaining_domains: int = _SEGMENT_CALL_DEPENDENCY_MAX_CLOSURES_8616
    census_work_units: int = 0
    census_deadline: float | None = None
    active_closures: set[int] = field(default_factory=set)
    active_proofs: set[int] = field(default_factory=set)
    closure_verdicts: dict[int, SegmentCallPreservationFailure8616 | None] = field(default_factory=dict)
    proof_verdicts: dict[
        int,
        tuple[
            SegmentCallPreservationFailure8616 | None,
            Real16CallInvocation8616 | None,
        ],
    ] = field(default_factory=dict)
    remaining_closures: int = _SEGMENT_CALL_DEPENDENCY_MAX_CLOSURES_8616
    remaining_proofs: int = _SEGMENT_CALL_DEPENDENCY_MAX_PROOFS_8616


_AMBIENT_DEPENDENCY_TRAVERSAL_8616: ContextVar[SegmentCallDependencyTraversal8616 | None] = ContextVar(
    "x86_16_segment_call_dependency_traversal_8616", default=None,
)


@contextmanager
def segment_call_dependency_traversal_scope_8616() -> Iterator[SegmentCallDependencyTraversal8616]:
    """Reuse the ambient bounded traversal, or open one fresh bounded scope.

    Sibling modules (``segment_effect_closure``) enter this scope so nested
    ``complete`` revalidation shares one memoized budget instead of opening a
    fresh dependency walk per supplied proof. This scope is internal to one
    synchronous validation snapshot: retained state mappings must not be
    mutated while it is active. Cached verdicts never survive that request.
    An in-progress revisit is cyclic evidence and the active-set refuses it.
    """
    ambient = _AMBIENT_DEPENDENCY_TRAVERSAL_8616.get()
    if ambient is not None:
        yield ambient
        return
    traversal = SegmentCallDependencyTraversal8616()
    token = _AMBIENT_DEPENDENCY_TRAVERSAL_8616.set(traversal)
    try:
        yield traversal
    finally:
        _AMBIENT_DEPENDENCY_TRAVERSAL_8616.reset(token)


@dataclass(frozen=True, slots=True)
class SegmentCallPreservationResult8616:
    """Exact retained evidence; preserved registers are derived, never guessed."""

    caller: IRBoundaryCoverageResult8616
    callee: SegmentEffectClosureResult8616
    index: DecodedDirectCallsiteIndex8616
    callsite_addr: int
    failure: SegmentCallPreservationFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    # The consumed source-bound invocation premise the Semantics-owned
    # target binding retained when the all-fetch-selector window could not
    # prove this call's target — bound to the exact caller block, project,
    # callsite and target it discharged. ``None`` when the unconditional
    # window bound sufficed, so a supplied-but-unused premise leaves no
    # residue. Every revalidation replays this premise under the current
    # source authority instead of trusting the stored verdict.
    invocation: Real16CallInvocation8616 | None = None
    invocation_scope: Real16InvocationDomain8616 | None = None

    @property
    def required_scope(self) -> Real16InvocationDomain8616 | None:
        """Return the entry scope a consumer must authenticate, or ``None``.

        Conditional evidence names exactly one required entry provenance:
        the explicitly retained ``invocation_scope`` wins; otherwise the
        source-bound premise the consumed target binding retained. A
        ``None`` result is universal evidence any scope may consume.
        """
        required = self.invocation_scope
        if required is None and self.invocation is not None:
            required = self.invocation.premise
        return required

    @property
    def complete(self) -> bool:
        """Require closed accounting and still-bound caller/callee evidence.

        Revalidation recomputes the same proof from retained inputs under one
        bounded traversal, so a retained result never acts as a mutable or
        incomplete certificate and cyclic evidence cannot recurse unchecked.
        When an enclosing evaluation is active the ambient traversal is
        reused, so nested ``complete`` revalidation shares its memoized
        verdicts and budgets instead of re-crawling the dependency graph.
        """
        return self.complete_for(None)

    def complete_for(self, invocation_scope: Real16InvocationDomain8616 | None) -> bool:
        """Revalidate only within the retained authenticated invocation domain."""
        with segment_call_dependency_traversal_scope_8616() as traversal:
            return _scoped_preservation_failure_8616(self, invocation_scope, traversal) is None

    @property
    def preserved_registers(self) -> tuple[str, ...]:
        """Project only exact identities shared by entry and every return exit.

        For an admitted non-leaf callee these exits already carry the
        identities the bound nested-call proofs retained, so the projection
        composes without claiming anything about non-returning paths.
        """
        return self.preserved_registers_for(None)

    def preserved_registers_for(
        self, invocation_scope: Real16InvocationDomain8616 | None,
    ) -> tuple[str, ...]:
        """Project identities only for an authenticated consuming scope."""
        if not self.complete_for(invocation_scope):
            return ()
        state = self.callee.state
        entry = state.entry_states[self.callee.coverage.artifact.function_addr]
        return tuple(
            register for register in SEGMENT_REGISTERS
            if entry[register].origin is SegmentOrigin.PROVEN
            and entry[register].source is not None
            and all(
                state.exit_states[block_addr][register].origin is SegmentOrigin.PROVEN
                and state.exit_states[block_addr][register].source == entry[register].source
                for block_addr in self.callee.return_block_addrs
            )
        )


def _census_surface_8616(
    closure: SegmentEffectClosureResult8616,
) -> IRFunctionArtifact | SegmentCallPreservationFailure8616:
    """Return the closure's caller artifact, or refuse malformed retained fields.

    Forged field types on a retained closure fail closed here instead of
    surfacing as attribute errors deeper in the census walk.
    """
    from .segment_state import SegmentStateArtifact

    if (
        type(closure.coverage) is not IRBoundaryCoverageResult8616
        or type(closure.state) is not SegmentStateArtifact
        or not isinstance(closure.coverage.artifact, IRFunctionArtifact)
    ):
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE
    census = closure.callsite_addrs
    supplied = closure.state.call_preservations
    if type(census) is not tuple or type(supplied) is not tuple:
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE
    if (len(census) > _SEGMENT_CALL_DEPENDENCY_MAX_PROOFS_8616
            or len(supplied) > _SEGMENT_CALL_DEPENDENCY_MAX_PROOFS_8616):
        return SegmentCallPreservationFailure8616.DEPENDENCY_BUDGET_EXHAUSTED
    if any(type(site) is not int for site in census):
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE
    return closure.coverage.artifact


def _supplied_proof_bound_8616(
    proof: object,
    artifact: IRFunctionArtifact,
    census_set: frozenset[int],
) -> TypeGuard[SegmentCallPreservationResult8616]:
    """Accept only a typed result bound to this artifact inside the census."""
    return (
        type(proof) is SegmentCallPreservationResult8616
        and type(proof.callsite_addr) is int
        and type(proof.caller) is IRBoundaryCoverageResult8616
        and type(proof.index) is DecodedDirectCallsiteIndex8616
        and proof.caller.artifact is artifact
        and proof.callsite_addr in census_set
    )


def _scoped_preservation_failure_8616(
    result: SegmentCallPreservationResult8616,
    invocation_scope: Real16InvocationDomain8616 | None,
    traversal: SegmentCallDependencyTraversal8616,
) -> SegmentCallPreservationFailure8616 | None:
    """Keep scope authentication and the precise bounded revalidation refusal.

    A boolean completeness projection loses cycle, budget and binding failures.
    Both public completeness and dependency traversal consume this typed result
    so authenticating a premise never collapses another refusal into staleness.
    """
    from .real16_invocation_domain import same_real16_entry_scope_8616

    required = result.required_scope
    if required is not None and not same_real16_entry_scope_8616(invocation_scope, required):
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE
    return _preservation_result_failure_8616(result, traversal)[0]


def _dependency_census_failure_8616(
    closure: SegmentEffectClosureResult8616,
    traversal: SegmentCallDependencyTraversal8616,
) -> SegmentCallPreservationFailure8616 | None:
    """Reconcile one callee's recorded call census with native-bound proofs.

    Every CALL site in the retained census must be covered by exactly one
    supplied proof bound to the identical caller artifact; supplied proofs at
    foreign artifacts, foreign types, or sites outside the census are stale.
    """
    artifact = _census_surface_8616(closure)
    if not isinstance(artifact, IRFunctionArtifact):
        return artifact
    census = closure.callsite_addrs
    census_set = frozenset(census)
    by_site: dict[int, list[SegmentCallPreservationResult8616]] = {}
    for proof in closure.state.call_preservations:
        if not _supplied_proof_bound_8616(proof, artifact, census_set):
            return SegmentCallPreservationFailure8616.DEPENDENCY_STALE
        by_site.setdefault(proof.callsite_addr, []).append(proof)
    for site in census:
        bound = by_site.get(site)
        if bound is None:
            return SegmentCallPreservationFailure8616.DEPENDENCY_MISSING
        if len(bound) != 1:
            return SegmentCallPreservationFailure8616.DEPENDENCY_AMBIGUOUS
    for site in census:
        verdict = _scoped_preservation_failure_8616(
            by_site[site][0], closure.state.invocation_scope, traversal,
        )
        if verdict is not None:
            return verdict
    return None


def _dependency_closure_failure_8616(
    closure: SegmentEffectClosureResult8616,
    traversal: SegmentCallDependencyTraversal8616,
) -> SegmentCallPreservationFailure8616 | None:
    """Prove one non-leaf callee's call census carries bound complete evidence.

    Cycles, missing coverage and exhausted budgets are typed refusals, never
    recursion errors or silent passes.
    """
    identity = id(closure)
    if identity in traversal.closure_verdicts:
        return traversal.closure_verdicts[identity]
    if identity in traversal.active_closures:
        return SegmentCallPreservationFailure8616.DEPENDENCY_CYCLE
    if (
        traversal.remaining_closures <= 0
        or len(traversal.active_closures) >= _SEGMENT_CALL_DEPENDENCY_MAX_DEPTH_8616
    ):
        return SegmentCallPreservationFailure8616.DEPENDENCY_BUDGET_EXHAUSTED
    traversal.remaining_closures -= 1
    traversal.active_closures.add(identity)
    try:
        verdict = _dependency_census_failure_8616(closure, traversal)
    finally:
        traversal.active_closures.discard(identity)
    traversal.closure_verdicts[identity] = verdict
    return verdict


def _preservation_result_verdict_8616(
    result: SegmentCallPreservationResult8616,
    traversal: SegmentCallDependencyTraversal8616,
    offered: Real16InvocationDomain8616 | None = None,
) -> tuple[
    SegmentCallPreservationFailure8616 | None,
    Real16CallInvocation8616 | None,
]:
    """Recompute one proof's retained accounting and evidence verdict.

    ``offered`` carries a source-bound invocation domain only on the initial
    evaluation, before the consumed consumption record exists; revalidation
    always re-offers the retained invocation's own premise, so a proof that
    discharged its selector window through a premise replays that premise
    under the current source authority on every read.
    """
    if result.failure is not None:
        if type(result.failure) is not SegmentCallPreservationFailure8616:
            return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
        return result.failure, None
    counts = (result.raw_fact_count, result.normalized_fact_count,
              result.classified_fact_count, result.materialized_count, result.failure_count)
    if counts != (1, 1, 1, 1, 0) or any(type(count) is not int for count in counts):
        return SegmentCallPreservationFailure8616.ACCOUNTING_INCOMPLETE, None
    expected = result.invocation
    if expected is not None:
        # Deferred for the same package initialization-order reason as the
        # binding owner: the invocation-domain module imports this module.
        from .real16_invocation_domain import Real16CallInvocation8616

        if type(expected) is not Real16CallInvocation8616:
            return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
    return _preservation_failure_8616(
        result.caller,
        result.callee,
        result.index,
        result.callsite_addr,
        traversal,
        invocation=result.invocation_scope or (expected.premise if expected is not None else offered),
        expected=expected,
    )


def _preservation_result_failure_8616(
    result: SegmentCallPreservationResult8616,
    traversal: SegmentCallDependencyTraversal8616,
    offered: Real16InvocationDomain8616 | None = None,
) -> tuple[
    SegmentCallPreservationFailure8616 | None,
    Real16CallInvocation8616 | None,
]:
    """Revalidate one bound dependency proof inside the bounded traversal.

    Returns the typed failure (``None`` on a bound verdict) plus the
    invocation consumption record the target binding retained this run.
    ``offered`` is only meaningful on the first evaluation of a fresh
    candidate, whose ``invocation`` field is still empty; once a consumed
    premise is retained it becomes the sole revalidation authority and any
    later divergence is a stale-evidence refusal, not an override.
    """
    if type(result) is not SegmentCallPreservationResult8616:
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
    from .segment_effect_closure import SegmentEffectClosureResult8616

    if type(result.callee) is not SegmentEffectClosureResult8616:
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
    identity = id(result)
    if identity in traversal.proof_verdicts:
        return traversal.proof_verdicts[identity]
    if identity in traversal.active_proofs:
        return SegmentCallPreservationFailure8616.DEPENDENCY_CYCLE, None
    if traversal.remaining_proofs <= 0:
        return SegmentCallPreservationFailure8616.DEPENDENCY_BUDGET_EXHAUSTED, None
    traversal.remaining_proofs -= 1
    traversal.active_proofs.add(identity)
    try:
        verdict = _preservation_result_verdict_8616(result, traversal, offered)
    finally:
        traversal.active_proofs.discard(identity)
    traversal.proof_verdicts[identity] = verdict
    return verdict


def _call_entry_8616(
    caller: IRBoundaryCoverageResult8616,
    callee: SegmentEffectClosureResult8616,
    index: DecodedDirectCallsiteIndex8616,
    site: int,
) -> DecodedDirectCallsite8616 | None:
    """Require one exact indexed near-call coordinate in the caller boundary."""
    target = callee.coverage.artifact.function_addr
    entries = tuple(
        entry for entry in index.for_target(target)
        if entry.caller_start == caller.artifact.function_addr
        and entry.callsite_addr == site and entry.target_addr == target
        and not entry.is_far
    )
    if len(entries) != 1:
        return None
    entry = entries[0]
    if type(entry.instruction_index) is not int or not 0 <= entry.instruction_index < len(entry.instructions):
        return None
    instruction = cast(_DecodedInstructionSurface8616, entry.instructions[entry.instruction_index])
    try:
        address = instruction.address
    except AttributeError:
        return None
    return entry if type(address) is int and address == site else None


def _caller_call_instruction_8616(
    caller: IRBoundaryCoverageResult8616,
    site: int,
) -> tuple[IRBlock, IRInstr] | None:
    """Return the unique CALL instruction and its owning block at ``site``."""
    calls = tuple(
        (block, instruction)
        for block in caller.artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL" and instruction.addr == site
    )
    return calls[0] if len(calls) == 1 else None


def _consumed_invocation_match_8616(
    fresh: Real16CallInvocation8616 | None,
    expected: Real16CallInvocation8616,
) -> bool:
    """Require the replayed consumption to bind the identical retained use.

    The premise, project, and block bind by object identity; the callsite
    and target bind by exact coordinate. Any divergence means the retained
    consumption record no longer describes what the current source
    authority can prove — a stale-evidence refusal, not a near miss.
    """
    from .real16_invocation_domain import Real16CallInvocation8616

    return (
        fresh is not None
        and type(fresh) is Real16CallInvocation8616
        and fresh.premise is expected.premise
        and fresh.callsite_addr == expected.callsite_addr
        and fresh.target_addr == expected.target_addr
        and fresh.project is expected.project
        and fresh.block is expected.block
    )


def _constant_call_target_failure_8616(
    target: IRValue,
    callee_addr: int,
    expected: Real16CallInvocation8616 | None,
) -> SegmentCallPreservationFailure8616 | None:
    """A constant target binds exactly and cannot consume invocation evidence."""
    if expected is not None:
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE
    if type(target.const) is not int or target.const != callee_addr:
        return SegmentCallPreservationFailure8616.TARGET_MISMATCH
    return None


def _call_target_failure_8616(
    caller: IRBoundaryCoverageResult8616,
    callee_addr: int,
    entry: DecodedDirectCallsite8616,
    site: int,
    *,
    invocation: Real16InvocationDomain8616 | None = None,
    expected: Real16CallInvocation8616 | None = None,
) -> tuple[
    SegmentCallPreservationFailure8616 | None,
    Real16CallInvocation8616 | None,
]:
    """Bind the exact IR call operand to the proven full-width callee address.

    A CONST operand binds only by exact full-width callee equality; any
    symbolic operand must complete the Semantics-owned direct-near binding
    against the decoded entry's native instruction evidence. ``invocation``
    is an optional source-bound premise the binding may consume only to
    discharge the selector-window obligation for this exact callsite;
    ``expected`` is the consumption record retained by a prior evaluation —
    when present it must bind this identical site, target, project and
    block, and the replayed binding must reproduce it exactly.
    Returns the typed failure plus the invocation consumption record the
    binding retained (``None`` when the unconditional window bound
    sufficed or a CONST operand needed no premise).
    """
    if expected is not None:
        from .real16_invocation_domain import Real16CallInvocation8616

        if (
            type(expected) is not Real16CallInvocation8616
            or expected.callsite_addr != site
            or expected.target_addr != callee_addr
            or expected.project is not caller.boundary.project
        ):
            return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
    call_pair = _caller_call_instruction_8616(caller, site)
    if call_pair is None:
        return SegmentCallPreservationFailure8616.CALLSITE_UNPROVEN, None
    block, call = call_pair
    if expected is not None and expected.block is not block:
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
    target = call.args[0] if call.args else None
    if not isinstance(target, IRValue):
        return SegmentCallPreservationFailure8616.TARGET_MISMATCH, None
    if target.space is MemSpace.CONST:
        return _constant_call_target_failure_8616(target, callee_addr, expected), None
    # Defer the Semantics binding owner until proof time: the ir package
    # imports this module through segment_state before the parent package
    # finishes initializing the semantics package, so a module-level edge
    # would make ir initialization depend on semantics import order.
    from ..semantics.direct_near_call_target_binding import (
        prove_direct_near_call_target_binding_from_decoded_8616,
    )

    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        caller.boundary.project,
        block=block,
        instruction=call,
        decoded=entry,
        invocation=invocation,
    )
    if (
        not binding.complete
        or binding.callsite_addr != site
        or binding.target_addr != callee_addr
    ):
        return SegmentCallPreservationFailure8616.TARGET_MISMATCH, None
    consumed = binding.invocation
    if expected is not None and not _consumed_invocation_match_8616(
        consumed, expected,
    ):
        return SegmentCallPreservationFailure8616.DEPENDENCY_STALE, None
    return None, consumed


def _callee_complete_in_scope_8616(
    caller: IRBoundaryCoverageResult8616,
    callee: SegmentEffectClosureResult8616,
    site: int,
    invocation: Real16InvocationDomain8616 | None,
) -> bool:
    """Require authenticated cross-call transport before using scoped effects."""
    from .real16_invocation_domain import real16_scope_crosses_call_8616

    scope = callee.state.invocation_scope
    if scope is not None and not real16_scope_crosses_call_8616(invocation, scope, caller, site):
        return False
    return callee.complete_for(scope)


def _preservation_failure_8616(
    caller: IRBoundaryCoverageResult8616,
    callee: SegmentEffectClosureResult8616,
    index: DecodedDirectCallsiteIndex8616,
    site: int,
    traversal: SegmentCallDependencyTraversal8616,
    *,
    invocation: Real16InvocationDomain8616 | None = None,
    expected: Real16CallInvocation8616 | None = None,
) -> tuple[
    SegmentCallPreservationFailure8616 | None,
    Real16CallInvocation8616 | None,
]:
    """Validate caller coverage, dependency closure and exact target binding.

    The callee's local closure evidence is consulted only after its recorded
    call census is reconciled, so dependency violations report their precise
    reason instead of a generic coverage refusal. The stored census is never
    trusted alone: admission still requires ``callee.complete``, which
    recomputes the real call census from the artifact, so a shrunken or
    invented ``callsite_addrs`` cannot bypass dependency validation.
    ``invocation`` is an optional source-bound premise offered to the
    target-binding stage; ``expected`` is the consumption record a retained
    proof must reproduce. Returns the typed failure plus the consumed
    invocation record so the caller can retain it as bound evidence.
    """
    if not caller.complete_for(invocation):
        return SegmentCallPreservationFailure8616.COVERAGE_INCOMPLETE, None
    surface = _census_surface_8616(callee)
    if isinstance(surface, SegmentCallPreservationFailure8616):
        return surface, None
    if caller.boundary.project is not callee.coverage.boundary.project:
        return SegmentCallPreservationFailure8616.PROJECT_MISMATCH, None
    if callee.callsite_addrs:
        dependency_failure = _dependency_closure_failure_8616(callee, traversal)
        if dependency_failure is not None:
            return dependency_failure, None
    if not _callee_complete_in_scope_8616(caller, callee, site, invocation):
        return SegmentCallPreservationFailure8616.COVERAGE_INCOMPLETE, None
    if not index.stats.closed or index.stats.failure_count:
        return SegmentCallPreservationFailure8616.INDEX_INCOMPLETE, None
    if type(site) is not int:
        return SegmentCallPreservationFailure8616.CALLSITE_UNPROVEN, None
    entry = _call_entry_8616(caller, callee, index, site)
    if entry is None:
        return SegmentCallPreservationFailure8616.CALLSITE_UNPROVEN, None
    callee_addr = callee.coverage.artifact.function_addr
    return _call_target_failure_8616(
        caller, callee_addr, entry, site,
        invocation=invocation, expected=expected,
    )


def prove_segment_call_preservation_8616(
    caller: IRBoundaryCoverageResult8616,
    callee: SegmentEffectClosureResult8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite_addr: int,
    *,
    invocation: Real16InvocationDomain8616 | None = None,
) -> SegmentCallPreservationResult8616:
    """Produce a typed exact-call preservation proof or atomic refusal.

    The callee may itself make calls only when every recorded callsite in its
    acyclic dependency closure carries one bound complete proof; retained
    counts stay request-scoped and never claim unexamined callees.
    ``invocation`` is an optional source-bound caller-domain premise that the
    Semantics-owned target binding may consume only to discharge the
    selector-window obligation for this exact callsite; when consumed, the
    bound consumption record is retained on the result and replayed on every
    revalidation, so a conditional binding never escapes as an unconditional
    claim. An unused premise leaves no residue.
    """
    candidate = SegmentCallPreservationResult8616(
        caller, callee, index, callsite_addr, None, 1, 1, 1, 1, 0,
    )
    traversal = SegmentCallDependencyTraversal8616()
    token = _AMBIENT_DEPENDENCY_TRAVERSAL_8616.set(traversal)
    try:
        # Charge the root exactly as subsequent complete revalidation does.
        failure, consumed = _preservation_result_failure_8616(
            candidate, traversal, invocation,
        )
    finally:
        _AMBIENT_DEPENDENCY_TRAVERSAL_8616.reset(token)
    accepted = int(failure is None)
    return replace(
        candidate, failure=failure, classified_fact_count=accepted,
        materialized_count=accepted, failure_count=1 - accepted,
        invocation=consumed if failure is None else None,
        invocation_scope=(invocation if failure is None and (
            consumed is not None or callee.state.invocation_scope is not None
            or caller.scoped_view is not None
        ) else None),
    )
