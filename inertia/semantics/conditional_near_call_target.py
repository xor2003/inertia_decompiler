"""Conditional direct near-CALL target theorem under an authenticated entry interval.

Layer: Semantics.
Responsibility: under one explicit, re-authenticated incoming near-CALL
selector interval (``NativeNearCallEntry8616``), prove only the narrow
theorem that *if* CS at this outgoing CALL still lies inside that interval,
*then* the CALL's bound CS-relative control operand denotes
``coordinates.target_addr``. The incoming context certifies a conditional
entry only; CS preservation from the bound callee entry to this callsite is
retained as an explicit typed obligation and is never discharged here.

Every gate is reused from its canonical owner: the identical raw root
``IRFunctionArtifact`` is re-bound through
``raw_x86_16_import_bundle_for_artifact_8616`` so a stale or foreign raw
surface refuses; the incoming context is re-authenticated through
``consume_native_near_call_entry_8616`` with its own retained
``callsite_index``; the outgoing CALL's operand DAG, block-``next``
provenance, native terminal identity, shape and coordinate gates run through
``prove_direct_near_call_target_binding_at_coordinates_8616``; and the
exact mapped E8 target bytes are checked through
``direct_near_call_target_is_bound_8616`` because the ordinary route
refuses ``SELECTOR_WINDOW_UNPROVED`` before its own byte binding runs.
Because every native callback can in principle leave the live surface
stale, a detached immutable snapshot of the raw-root source graph and of
the context/coordinate projection is captured before the byte-binding
callback and reconciled callback-free after the final context replay.
Incoming instruction bytes and the canonical root native key are likewise
pinned before callbacks and re-read before that final owned-fact check.
Consumers that already bracket a consumption site with their own
operation-local detached source-fact reconciliation may call
``reauthenticate_conditional_near_call_target_8616`` — the identical
retained-record and surface gates plus only the canonical native
surfaces (raw-root rebind, entry-context consumption, mapped E8 byte
binding) — so the seal does not repeat the full-IR serialization and
preflight replay that the bracketing snapshot already covers.
The only new arithmetic is closed-interval membership on the retained
selector bounds plus the sub-1 MiB physical limit. This theorem proves no
CS preservation, reachability, ABI, stack/memory or callee preservation,
and publishes nothing to any registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar, cast

from inertia.frontend.x86_16.frontend_boundary_transport import (
    FunctionBoundaryWitness8616,
    capture_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from inertia.frontend.x86_16.near_call_entry_context import (
    NativeNearCallEntry8616,
    _live_call_encoding_8616,
    consume_native_near_call_entry_8616,
)
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.direct_evidence_deadline import (
    direct_evidence_deadline_expired_8616,
)
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.source_graph_binding import (
    ImmutableSourceGraphFacts8616,
    SourceGraphSerializationError8616,
    capture_immutable_source_graph_facts_8616,
)

from .callsite_summary import CallsiteMachineFrameKind8616
from .direct_near_call_target_binding import (
    DirectNearCallCoordinates8616,
    DirectNearCallTargetBinding8616,
    DirectNearCallTargetBindingFailure8616,
    DirectNearCallTargetBindingVerdict8616,
    DirectNearCallTargetShape8616,
    _control_operand_8616,
    _operand_shape_outcome_8616,
    _owned_origin_provenance_8616,
    _retained_coordinate_facts_8616,
    prove_direct_near_call_target_binding_at_coordinates_8616,
)
from .direct_ret_call_effect import direct_near_call_target_is_bound_8616

__all__ = [
    "ConditionalCallsiteSelectorObligation8616",
    "ConditionalNearCallTargetFailure8616",
    "ConditionalNearCallTargetStats8616",
    "ConditionalNearCallTargetTheorem8616",
    "ConditionalNearCallTargetVerdict8616",
    "consume_conditional_near_call_target_8616",
    "prove_conditional_near_call_target_8616",
    "reauthenticate_conditional_near_call_target_8616",
]

_SELECTOR_SHIFT_8616 = 4
_SELECTOR_MAX_8616 = 0xFFFF
_WORD_SPAN_8616 = 0x10000
_PHYSICAL_LIMIT_8616 = 0x100000


class ConditionalNearCallTargetVerdict8616(StrEnum):
    """Evidence result for one conditional outgoing-CALL target theorem.

    CONDITIONAL is deliberately distinct from the unconditional binding's
    PROVEN: the theorem holds only relative to its retained selector
    obligation. REFUSED retains a typed failure, never a silent absence.
    """

    CONDITIONAL = "conditional"
    REFUSED = "refused"


class ConditionalNearCallTargetFailure8616(StrEnum):
    """Typed reasons the conditional target theorem cannot materialize."""

    REQUEST_EXPIRED = "conditional_near_call_request_expired"
    FOREIGN_COORDINATES = "conditional_near_call_foreign_coordinates"
    FOREIGN_CONTEXT = "conditional_near_call_foreign_context"
    FOREIGN_ROOT = "conditional_near_call_foreign_root"
    FOREIGN_BLOCK = "conditional_near_call_foreign_block"
    FOREIGN_INSTRUCTION = "conditional_near_call_foreign_instruction"
    ROOT_REIMPORT_MISMATCH = "conditional_near_call_root_reimport_mismatch"
    CONTEXT_NOT_AUTHENTICATED = "conditional_near_call_context_not_authenticated"
    SEAL_SOURCE_CHANGED = "conditional_near_call_seal_source_changed"
    PREFLIGHT_REFUSED = "conditional_near_call_preflight_refused"
    TARGET_BYTES_UNBOUND = "conditional_near_call_target_bytes_unbound"
    INTERVAL_MALFORMED = "conditional_near_call_interval_malformed"
    TARGET_A20_AMBIGUOUS = "conditional_near_call_target_a20_ambiguous"
    TARGET_OUTSIDE_INTERVAL = "conditional_near_call_target_outside_interval"


@dataclass(frozen=True, slots=True)
class ConditionalNearCallTargetStats8616:
    """Closed five-stage accounting for one conditional theorem evaluation."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether the candidate resolved to one theorem or refusal."""
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
class ConditionalCallsiteSelectorObligation8616:
    """Explicit unproved CS-preservation condition for one outgoing CALL.

    The retained theorem asserts: if CS at ``callsite_addr`` remains inside
    ``[selector_low, selector_high]`` — the interval authenticated by
    ``context`` — then the bound CS-relative target equals the theorem's
    retained ``target_addr``. Nothing here proves CS is preserved from the
    bound callee entry to this callsite; a caller must discharge this exact
    obligation separately before relying on the conditional equality.
    """

    context: NativeNearCallEntry8616 = field(compare=False, repr=False)
    callsite_addr: int = 0
    selector_low: int = 0
    selector_high: int = 0

    def admits_selector(self, selector: int) -> bool:
        """Return whether ``selector`` lies in the retained interval."""
        return bool(
            type(selector) is int
            and self.selector_low <= selector <= self.selector_high
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the outstanding condition for diagnostics."""
        return {
            "condition": "cs_at_callsite_in_interval",
            "callsite_addr": self.callsite_addr,
            "selector_low": self.selector_low,
            "selector_high": self.selector_high,
            "cs_preservation_unproved": True,
        }


@dataclass(frozen=True, slots=True)
class ConditionalNearCallTargetTheorem8616:
    """Conditional target theorem (or typed refusal) for one outgoing CALL.

    A CONDITIONAL verdict asserts only the interval-relative target
    equality; the record deliberately has no ``complete`` property and no
    unconditional verdict — conditionality is the claim, not a stepping
    stone to a public proof. ``context``, ``artifact``, ``block`` and
    ``instruction`` are retained identities for consumer reconciliation;
    the scalar coordinate and interval fields are the reconciled facts.
    """

    conditional_only: ClassVar[bool] = True
    cs_preservation_required: ClassVar[bool] = True
    reachability_unproved: ClassVar[bool] = True
    callee_preservation_unproved: ClassVar[bool] = True

    verdict: ConditionalNearCallTargetVerdict8616
    failure: ConditionalNearCallTargetFailure8616 | None
    preflight_failure: DirectNearCallTargetBindingFailure8616 | None
    stats: ConditionalNearCallTargetStats8616
    context: NativeNearCallEntry8616 | None = field(
        default=None, compare=False, repr=False,
    )
    artifact: IRFunctionArtifact | None = field(
        default=None, compare=False, repr=False,
    )
    block: IRBlock | None = field(default=None, compare=False, repr=False)
    instruction: IRInstr | None = field(default=None, compare=False, repr=False)
    obligation: ConditionalCallsiteSelectorObligation8616 | None = None
    callsite_addr: int | None = None
    next_addr: int | None = None
    target_addr: int | None = None
    selector_low: int | None = None
    selector_high: int | None = None
    shape: DirectNearCallTargetShape8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the theorem result for diagnostics and workers."""
        return {
            "verdict": self.verdict.value,
            "failure": None if self.failure is None else self.failure.value,
            "preflight_failure": (
                None
                if self.preflight_failure is None
                else self.preflight_failure.value
            ),
            "stats": self.stats.to_dict(),
            "callsite_addr": self.callsite_addr,
            "next_addr": self.next_addr,
            "target_addr": self.target_addr,
            "selector_low": self.selector_low,
            "selector_high": self.selector_high,
            "obligation": (
                None if self.obligation is None else self.obligation.to_dict()
            ),
            "shape": None if self.shape is None else self.shape.to_dict(),
            "conditional_only": self.conditional_only,
            "cs_preservation_required": self.cs_preservation_required,
        }


def _refuse_8616(
    callsite_addr: int | None,
    target_addr: int | None,
    failure: ConditionalNearCallTargetFailure8616,
    *,
    normalized: bool = False,
    classified: bool = False,
    preflight_failure: DirectNearCallTargetBindingFailure8616 | None = None,
    shape: DirectNearCallTargetShape8616 | None = None,
) -> ConditionalNearCallTargetTheorem8616:
    """Retain one refused theorem obligation in the five-stage evidence count."""
    return ConditionalNearCallTargetTheorem8616(
        verdict=ConditionalNearCallTargetVerdict8616.REFUSED,
        failure=failure,
        preflight_failure=preflight_failure,
        stats=ConditionalNearCallTargetStats8616(
            1, int(normalized), int(classified), 0, 1
        ),
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        shape=shape,
    )


def _rebind_raw_root_8616(
    project: object,
    context: NativeNearCallEntry8616,
    artifact: IRFunctionArtifact,
) -> bool:
    """Re-bind the identical raw root artifact against a fresh native import.

    The IR-side bundle owner is imported lazily: IR callers may reach this
    owner while ``inertia.ir.vex_import`` itself is mid-import, so a
    top-level dependency could close an import cycle. The returned bundle
    must be anchored on the identical supplied artifact object.
    """
    from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616

    bundle = raw_x86_16_import_bundle_for_artifact_8616(
        project, context.boundary, artifact
    )
    return bundle is not None and bundle.artifact is artifact


def _surface_identity_failure_8616(
    project: object,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    coordinates: object,
) -> ConditionalNearCallTargetFailure8616 | None:
    """Reject omitted, copied, or foreign surfaces before any native work.

    Block and instruction identities are bound by object identity: an
    equal-but-rebuilt block or instruction is foreign evidence even when
    its fields match, matching the raw-artifact rebind contract.
    """
    if type(coordinates) is not DirectNearCallCoordinates8616:
        return ConditionalNearCallTargetFailure8616.FOREIGN_COORDINATES
    if type(context) is not NativeNearCallEntry8616:
        return ConditionalNearCallTargetFailure8616.FOREIGN_CONTEXT
    bound_context = context
    if (
        bound_context.project is not project
        or type(bound_context.boundary) is not ExactFunctionRangeBoundary8616
        or bound_context.boundary.project is not project
    ):
        return ConditionalNearCallTargetFailure8616.FOREIGN_CONTEXT
    if type(artifact) is not IRFunctionArtifact:
        return ConditionalNearCallTargetFailure8616.FOREIGN_ROOT
    bound_artifact = artifact
    if (bound_artifact.function_addr != bound_context.target_addr
            or bound_context.boundary.addr != bound_artifact.function_addr):
        return ConditionalNearCallTargetFailure8616.FOREIGN_ROOT
    if type(block) is not IRBlock or not any(
        candidate is block for candidate in bound_artifact.blocks
    ):
        return ConditionalNearCallTargetFailure8616.FOREIGN_BLOCK
    if type(instruction) is not IRInstr or not any(
        item is instruction for item in block.instrs
    ):
        return ConditionalNearCallTargetFailure8616.FOREIGN_INSTRUCTION
    return None


@dataclass(frozen=True, slots=True)
class _DetachedSourceFacts8616:
    """Immutable pre-callback projection of the theorem's owned facts.

    ``graph`` detaches the entire raw-root block surface through the
    canonical interned encoder, so a later in-place field mutation on any
    owned IR node — including ``compare=False`` provenance such as
    ``source_tmp`` — is observable without trusting live object state. The
    scalar/identity fields pin the entry-context fields, the coordinate
    triple, and the proven operand/origin/shape objects exactly as the
    preflight validated them. Object fields are ``compare=False`` because
    they are reconciled by identity (``is``) in the stale check, not by
    value equality.
    """

    graph: ImmutableSourceGraphFacts8616
    context_scalars: tuple[int, int, int, int, int, int]
    call_encoding: bytes
    coordinate_facts: tuple[int, int, int]
    shape: DirectNearCallTargetShape8616 | None
    context_project: object = field(compare=False)
    context_boundary: object = field(compare=False)
    context_premise: object = field(compare=False)
    context_callsite_index: object = field(compare=False)
    context_callee_witness: object = field(compare=False)
    operand: object = field(compare=False)
    origin: object = field(compare=False)


@dataclass(frozen=True, slots=True)
class _DetachedNativeFacts8616:
    """Live instruction evidence with native authorities pinned across callbacks."""

    incoming: bytes
    witness: FunctionBoundaryWitness8616
    root_key: tuple[object, ...] | None
    authorities: tuple[object, ...] = field(compare=False, repr=False)


def _capture_native_facts_8616(
    project: object, context: NativeNearCallEntry8616,
) -> _DetachedNativeFacts8616 | None:
    """Capture canonical native freshness evidence without VEX relifting.

    The raw import owner is lazy for the same import-cycle reason as the
    ordinary root rebind. The canonical byte witness supports every admitted
    boundary; the native import key adds freshness facts when available.
    An absent key is never an authority to skip the ordinary proof gates.
    Witness capture uses the existing boundary restoration owner and may
    decode reachability; it is not merely a byte read.
    """
    from inertia.ir.raw_boot_native_surface_cache import _native_surface_key_8616
    from inertia.ir.vex_import import build_x86_16_ir_function_artifact

    witness = capture_function_boundary_8616(project, context.boundary)
    if witness is None:
        return None
    native = _native_surface_key_8616(
        project, context.boundary, build_x86_16_ir_function_artifact,
    )
    incoming = _live_call_encoding_8616(project, context.premise)
    if incoming is None:
        return None
    key, authorities = (None, ()) if native is None else native
    return _DetachedNativeFacts8616(incoming, witness, key, authorities)


def _capture_source_facts_8616(
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    shape: DirectNearCallTargetShape8616 | None,
) -> _DetachedSourceFacts8616 | None:
    """Freeze owned source/context/coordinate facts before native callbacks.

    The snapshot must be taken before the callbacks whose side effects it
    guards, not after. A surface the canonical encoder cannot validate is
    already evidence drift, so the typed serialization refusal returns
    ``None`` rather than a partial projection.
    """
    if len(instruction.args) != 1:
        return None
    if not all(
        type(value) is int
        for value in (
            context.callsite_addr,
            context.next_addr,
            context.target_addr,
            context.callee_addr,
            context.selector_low,
            context.selector_high,
        )
    ):
        return None
    try:
        graph = capture_immutable_source_graph_facts_8616(
            artifact.function_addr, artifact.blocks, artifact.refusals
        )
    except SourceGraphSerializationError8616:
        return None
    return _DetachedSourceFacts8616(
        graph=graph,
        context_scalars=(
            context.callsite_addr,
            context.next_addr,
            context.target_addr,
            context.callee_addr,
            context.selector_low,
            context.selector_high,
        ),
        call_encoding=context.call_encoding,
        coordinate_facts=(
            coordinates.callsite_addr,
            coordinates.next_addr,
            coordinates.target_addr,
        ),
        shape=shape,
        context_project=context.project,
        context_boundary=context.boundary,
        context_premise=context.premise,
        context_callsite_index=context.callsite_index,
        context_callee_witness=context.callee_witness,
        operand=instruction.args[0],
        origin=instruction.origin,
    )


def _graph_facts_equal_8616(
    artifact: IRFunctionArtifact,
    snapshot: ImmutableSourceGraphFacts8616,
) -> bool:
    """Recapture the detached source graph and reconcile it callback-free.

    The ``compare=False`` refusal arrays are orthogonal census evidence,
    so they are reconciled explicitly alongside the structural ``==``.
    """
    try:
        fresh = capture_immutable_source_graph_facts_8616(
            artifact.function_addr, artifact.blocks, artifact.refusals
        )
    except SourceGraphSerializationError8616:
        return False
    return bool(
        fresh == snapshot
        and fresh.function_refusals == snapshot.function_refusals
        and fresh.block_refusals == snapshot.block_refusals
    )


def _context_projection_equal_8616(
    context: NativeNearCallEntry8616,
    snapshot: _DetachedSourceFacts8616,
) -> bool:
    """Reconcile context identities, scalars and encoding callback-free."""
    if not all((
        context.project is snapshot.context_project,
        context.boundary is snapshot.context_boundary,
        context.premise is snapshot.context_premise,
        context.callsite_index is snapshot.context_callsite_index,
        context.callee_witness is snapshot.context_callee_witness,
    )):
        return False
    return bool(
        context.call_encoding == snapshot.call_encoding
        and (
            context.callsite_addr,
            context.next_addr,
            context.target_addr,
            context.callee_addr,
            context.selector_low,
            context.selector_high,
        ) == snapshot.context_scalars
    )


def _stale_source_projection_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    snapshot: _DetachedSourceFacts8616,
) -> bool:
    """Return whether owned facts drifted, without graph recapture.

    Pure owned reads with no native callback: root/context coordinate
    agreement, retained block membership, CALL identity, the proven
    operand and origin objects, the context scalar/identity projection,
    callsite agreement, coordinate facts, and the recovered shape facts.
    In-place graph field mutation is deliberately not covered here —
    ``_stale_source_facts_8616`` owns that recapture.
    """
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
        instruction.addr == coordinates.callsite_addr,
        len(instruction.args) == 1,
        instruction.origin is snapshot.origin,
        any(item is instruction for item in block.instrs),
    )):
        return True
    if instruction.args[0] is not snapshot.operand:
        return True
    if not _context_projection_equal_8616(context, snapshot):
        return True
    shape = snapshot.shape
    if type(shape) is not DirectNearCallTargetShape8616:
        return True
    bound_shape = shape
    return not all((
        bound_shape.next_linear_addr == coordinates.next_addr,
        _retained_coordinate_facts_8616(
            coordinates.callsite_addr, coordinates.target_addr, bound_shape
        ),
        (
            coordinates.callsite_addr,
            coordinates.next_addr,
            coordinates.target_addr,
        ) == snapshot.coordinate_facts,
    ))


def _stale_source_facts_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    snapshot: _DetachedSourceFacts8616,
) -> bool:
    """Return whether any owned fact drifted from the detached snapshot.

    The cheap reconciliation plus one full recaptured source graph —
    the graph covers in-place field mutation an identity check cannot
    see. This is the expensive seal check; callers that only need
    callback-free identity/scalar agreement use
    ``_stale_source_projection_8616``.
    """
    if _stale_source_projection_8616(
        project, artifact, context, block, instruction, coordinates,
        snapshot,
    ):
        return True
    return not _graph_facts_equal_8616(artifact, snapshot.graph)


def _final_seal_source_changed_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    snapshot: _DetachedSourceFacts8616,
    native_snapshot: _DetachedNativeFacts8616,
) -> bool:
    """Read native evidence before the final callback-free owned reconciliation."""
    if _stale_source_projection_8616(
        project, artifact, context, block, instruction, coordinates, snapshot,
    ):
        return True
    if _capture_native_facts_8616(project, context) != native_snapshot:
        return True
    return _stale_source_facts_8616(
        project, artifact, context, block, instruction, coordinates, snapshot,
    )


def _conditional_seal_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    snapshot: _DetachedSourceFacts8616,
    native_snapshot: _DetachedNativeFacts8616,
) -> ConditionalNearCallTargetFailure8616 | None:
    """Reauthenticate native facts and seal owned facts after callbacks.

    One bounded pass: reconcile the detached snapshot's identity and
    scalar facts cheaply, re-run the canonical raw-root rebind and the
    context consumption — the same owner methods the initial pass used,
    no second proof model — then reconcile the pinned incoming bytes and
    canonical root native key and run the one full source recapture after
    the last callback, so a replay cannot invalidate the earlier raw-IR
    or surface checks unnoticed. When a native callback itself refuses,
    one failure-path reconciliation keeps SEAL_SOURCE_CHANGED preferred
    over the native refusal rather than suppressing a real staleness
    verdict. No replay loop and no new registry or cache.
    """
    if _stale_source_projection_8616(
        project, artifact, context, block, instruction, coordinates,
        snapshot,
    ):
        return ConditionalNearCallTargetFailure8616.SEAL_SOURCE_CHANGED
    if not _rebind_raw_root_8616(project, context, artifact):
        if _stale_source_facts_8616(
            project, artifact, context, block, instruction, coordinates,
            snapshot,
        ):
            return ConditionalNearCallTargetFailure8616.SEAL_SOURCE_CHANGED
        return ConditionalNearCallTargetFailure8616.ROOT_REIMPORT_MISMATCH
    if direct_evidence_deadline_expired_8616(project):
        return ConditionalNearCallTargetFailure8616.REQUEST_EXPIRED
    if not consume_native_near_call_entry_8616(
        project, context, callsite_index=context.callsite_index
    ):
        if _stale_source_facts_8616(
            project, artifact, context, block, instruction, coordinates,
            snapshot,
        ):
            return ConditionalNearCallTargetFailure8616.SEAL_SOURCE_CHANGED
        return ConditionalNearCallTargetFailure8616.CONTEXT_NOT_AUTHENTICATED
    if direct_evidence_deadline_expired_8616(project):
        return ConditionalNearCallTargetFailure8616.REQUEST_EXPIRED
    if _final_seal_source_changed_8616(
        project, artifact, context, block, instruction, coordinates,
        snapshot, native_snapshot,
    ):
        return ConditionalNearCallTargetFailure8616.SEAL_SOURCE_CHANGED
    return None


def _interval_failure_8616(
    context: NativeNearCallEntry8616,
    target_addr: int,
) -> ConditionalNearCallTargetFailure8616 | None:
    """Check the conditional theorem's own arithmetic on retained bounds.

    For each selector ``s`` in ``[selector_low, selector_high]`` the proven
    operand composition computes
    ``(s << 4) + ((next_linear - (s << 4) + disp) & 0xFFFF)``; with
    ``target == next_linear + disp`` that equals ``target`` exactly while
    ``0 <= target - (s << 4) <= 0xFFFF`` for every admitted ``s``, i.e.
    ``(high << 4) <= target <= (low << 4) + 0xFFFF``. The 1 MiB physical
    limit keeps the linear interpretation honest; a target outside any
    single admitted window refuses rather than approximating.
    """
    low, high = context.selector_low, context.selector_high
    if (
        type(low) is not int
        or type(high) is not int
        or not 0 <= low <= high <= _SELECTOR_MAX_8616
    ):
        return ConditionalNearCallTargetFailure8616.INTERVAL_MALFORMED
    if not 0 <= target_addr < _PHYSICAL_LIMIT_8616:
        return ConditionalNearCallTargetFailure8616.TARGET_A20_AMBIGUOUS
    admitted = (
        (high << _SELECTOR_SHIFT_8616) <= target_addr
        <= (low << _SELECTOR_SHIFT_8616) + _WORD_SPAN_8616 - 1
    )
    if not admitted:
        return ConditionalNearCallTargetFailure8616.TARGET_OUTSIDE_INTERVAL
    return None


def _byte_and_seal_gates_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    shape: DirectNearCallTargetShape8616 | None,
) -> ConditionalNearCallTargetFailure8616 | None:
    """Snapshot owned facts, bind target bytes, then run the bounded seal.

    The detached snapshot is captured after the preflight validated the
    operand/provenance/shape and *before* the mapped-byte callback — a
    snapshot taken later could not observe drift this callback leaves.
    The ordinary route refuses the selector window before binding target
    bytes, so the owning helper must check the mapped E8 encoding here.
    """
    snapshot = _capture_source_facts_8616(
        artifact, context, instruction, coordinates, shape
    )
    if snapshot is None:
        return ConditionalNearCallTargetFailure8616.SEAL_SOURCE_CHANGED
    native_snapshot = _capture_native_facts_8616(project, context)
    if native_snapshot is None:
        return ConditionalNearCallTargetFailure8616.SEAL_SOURCE_CHANGED
    if not direct_near_call_target_is_bound_8616(
        project,
        coordinates.callsite_addr,
        coordinates.next_addr,
        coordinates.target_addr,
        CallsiteMachineFrameKind8616.NEAR,
    ):
        return ConditionalNearCallTargetFailure8616.TARGET_BYTES_UNBOUND
    return _conditional_seal_8616(
        project, artifact, context, block, instruction, coordinates,
        snapshot, native_snapshot,
    )


def _post_auth_gates_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
) -> tuple[
    ConditionalNearCallTargetFailure8616 | None,
    DirectNearCallTargetBindingFailure8616 | None,
    DirectNearCallTargetShape8616 | None,
]:
    """Run the outgoing-CALL preflight, byte, seal and interval gates.

    Returns ``(failure, preflight_failure, shape)``. The canonical binding
    is the shared operand/provenance/shape preflight; its only accepted
    gap is ``SELECTOR_WINDOW_UNPROVED``, exactly what this theorem narrows.
    The mapped E8 bytes are then checked through the owning helper because
    that refusal precedes the ordinary byte binding. The bounded seal
    re-authenticates the raw root and context and reconciles the detached
    source snapshot that ends the gate chain.
    """
    expired = ConditionalNearCallTargetFailure8616.REQUEST_EXPIRED
    binding = prove_direct_near_call_target_binding_at_coordinates_8616(
        project, block=block, instruction=instruction, coordinates=coordinates
    )
    if direct_evidence_deadline_expired_8616(project):
        return expired, None, None
    selector_unproved = (
        binding.failure
        is DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED
    )
    if (
        binding.verdict is not DirectNearCallTargetBindingVerdict8616.PROVEN
        and not selector_unproved
    ):
        return (
            ConditionalNearCallTargetFailure8616.PREFLIGHT_REFUSED,
            binding.failure,
            binding.shape,
        )
    failure = _byte_and_seal_gates_8616(
        project, artifact, context, block, instruction, coordinates,
        binding.shape,
    )
    if failure is not None:
        return failure, None, binding.shape
    failure = _interval_failure_8616(context, coordinates.target_addr)
    if failure is not None:
        return failure, None, binding.shape
    if direct_evidence_deadline_expired_8616(project):
        return expired, None, binding.shape
    return None, None, binding.shape


def _conditional_evidence_8616(
    project: object,
    artifact: IRFunctionArtifact,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
) -> tuple[
    ConditionalNearCallTargetFailure8616 | None,
    DirectNearCallTargetBindingFailure8616 | None,
    DirectNearCallTargetShape8616 | None,
]:
    """Run the raw-root rebind and context authentication, then the gates.

    Returns ``(failure, preflight_failure, shape)``: a non-``None`` failure
    is the typed refusal reason with the retained inner preflight failure
    and recovered operand shape when classification already ran. Every
    native callback is followed by a deadline check.
    """
    expired = ConditionalNearCallTargetFailure8616.REQUEST_EXPIRED
    if not _rebind_raw_root_8616(project, context, artifact):
        return (
            ConditionalNearCallTargetFailure8616.ROOT_REIMPORT_MISMATCH,
            None,
            None,
        )
    if direct_evidence_deadline_expired_8616(project):
        return expired, None, None
    if not consume_native_near_call_entry_8616(
        project, context, callsite_index=context.callsite_index
    ):
        return (
            ConditionalNearCallTargetFailure8616.CONTEXT_NOT_AUTHENTICATED,
            None,
            None,
        )
    if direct_evidence_deadline_expired_8616(project):
        return expired, None, None
    return _post_auth_gates_8616(
        project, artifact, context, block, instruction, coordinates
    )


def prove_conditional_near_call_target_8616(
    project: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    coordinates: object,
) -> ConditionalNearCallTargetTheorem8616:
    """Prove the conditional CS-interval target theorem for one outgoing CALL.

    The theorem is conditional on the authenticated incoming near-CALL
    ``context``: if CS at this outgoing callsite remains inside the
    context's selector interval, the bound CS-relative target equals
    ``coordinates.target_addr``. Identity gates reject foreign roots,
    blocks and instructions; the identical raw artifact is re-bound against
    a fresh native import; the context is re-authenticated with its own
    retained ``callsite_index``; the canonical direct-near binding runs as
    the operand/provenance/shape preflight (a
    ``SELECTOR_WINDOW_UNPROVED`` refusal is the only expected gap, since
    the universal selector bound is exactly what this theorem narrows);
    the mapped E8 target bytes are then checked explicitly; a bounded
    post-callback seal re-authenticates the raw root and context and
    reconciles a detached immutable snapshot of the source graph, context
    and coordinate facts; and the closed-interval membership plus sub-1
    MiB limit completes the theorem.
    The request deadline is enforced before and after every native
    callback. CS preservation from the callee entry to this callsite is
    retained as the explicit ``obligation`` and remains unproved.
    """
    callsite = (
        coordinates.callsite_addr
        if type(coordinates) is DirectNearCallCoordinates8616
        else None
    )
    target = (
        coordinates.target_addr
        if type(coordinates) is DirectNearCallCoordinates8616
        else None
    )
    expired = ConditionalNearCallTargetFailure8616.REQUEST_EXPIRED
    if direct_evidence_deadline_expired_8616(project):
        return _refuse_8616(callsite, target, expired)
    failure = _surface_identity_failure_8616(
        project, artifact, context, block, instruction, coordinates
    )
    if failure is not None:
        return _refuse_8616(callsite, target, failure)
    bound_context = cast(NativeNearCallEntry8616, context)
    bound_artifact = cast(IRFunctionArtifact, artifact)
    bound_block = cast(IRBlock, block)
    bound_instruction = cast(IRInstr, instruction)
    bound_coordinates = cast(DirectNearCallCoordinates8616, coordinates)
    failure, preflight_failure, shape = _conditional_evidence_8616(
        project,
        bound_artifact,
        bound_context,
        bound_block,
        bound_instruction,
        bound_coordinates,
    )
    if failure is not None:
        return _refuse_8616(
            callsite,
            target,
            failure,
            normalized=True,
            classified=shape is not None,
            preflight_failure=preflight_failure,
            shape=shape,
        )
    return _conditional_theorem_8616(
        bound_context, bound_artifact, bound_block, bound_instruction,
        bound_coordinates, shape,
    )


def _conditional_theorem_8616(
    context: NativeNearCallEntry8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
    shape: DirectNearCallTargetShape8616 | None,
) -> ConditionalNearCallTargetTheorem8616:
    """Assemble the CONDITIONAL theorem record for one bound callsite.

    Shared by the public factory and the scope-owned final derivation so
    identical surfaces always produce a structurally identical record —
    retained scalars, selector obligation and stats never diverge between
    the two construction paths.
    """
    return ConditionalNearCallTargetTheorem8616(
        verdict=ConditionalNearCallTargetVerdict8616.CONDITIONAL,
        failure=None,
        preflight_failure=None,
        stats=ConditionalNearCallTargetStats8616(1, 1, 1, 1, 0),
        context=context,
        artifact=artifact,
        block=block,
        instruction=instruction,
        obligation=ConditionalCallsiteSelectorObligation8616(
            context=context,
            callsite_addr=coordinates.callsite_addr,
            selector_low=context.selector_low,
            selector_high=context.selector_high,
        ),
        callsite_addr=coordinates.callsite_addr,
        next_addr=coordinates.next_addr,
        target_addr=coordinates.target_addr,
        selector_low=context.selector_low,
        selector_high=context.selector_high,
        shape=shape,
    )


class _ScopedTargetStage8616(StrEnum):
    """Non-proof outcome awaiting the scope's final rooted derivation."""

    STAGED = "staged"
    REFUSED = "refused"

    def __bool__(self) -> bool:
        """Prevent staged evidence from acting as an admitted proof."""
        raise TypeError("staged target requires the final whole-census seal")


@dataclass(frozen=True, slots=True)
class _ScopedFreshTheorem8616:
    """Staged fresh-theorem result; never admission authority.

    ``STAGED`` reports only that the staged canonical gates passed; the
    enclosing census still owes its final whole-census native/graph/dependency
    seals and the callback-free final derivation before the retained theorem
    may promote into a conditional preservation step.
    """

    status: _ScopedTargetStage8616
    theorem: ConditionalNearCallTargetTheorem8616 | None = field(
        default=None, compare=False, repr=False,
    )

    def __bool__(self) -> bool:
        """Reject staged evidence used as an admitted proof."""
        raise TypeError(
            "staged fresh theorem requires the final whole-census seal"
        )


def _staged_target_binding_8616(
    project: object,
    context: NativeNearCallEntry8616,
    block: IRBlock,
    instruction: IRInstr,
    coordinates: DirectNearCallCoordinates8616,
) -> DirectNearCallTargetBinding8616 | None:
    """Check canonical operand, native E8 binding and interval within a census.

    Both fresh and retained staging use these gates. The result remains
    provisional until the caller seals the complete native and owned census.
    """
    binding = prove_direct_near_call_target_binding_at_coordinates_8616(
        project,
        block=block,
        instruction=instruction,
        coordinates=coordinates,
    )
    if direct_evidence_deadline_expired_8616(project):
        return None
    if (
        binding.verdict is not DirectNearCallTargetBindingVerdict8616.PROVEN
        and binding.failure
        is not DirectNearCallTargetBindingFailure8616.SELECTOR_WINDOW_UNPROVED
    ):
        return None
    if not direct_near_call_target_is_bound_8616(
        project,
        coordinates.callsite_addr,
        coordinates.next_addr,
        coordinates.target_addr,
        CallsiteMachineFrameKind8616.NEAR,
    ):
        return None
    if _interval_failure_8616(context, coordinates.target_addr) is not None:
        return None
    return None if direct_evidence_deadline_expired_8616(project) else binding


def _staged_fresh_theorem_8616(
    project: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
    coordinates: object,
) -> _ScopedFreshTheorem8616:
    """Stage one fresh conditional theorem inside an owned census.

    The identical surface-identity gate and staged canonical gates the
    standalone factory runs after its one-time root rebind and context
    authentication — which the owning census performs once up front. A
    CONDITIONAL record is assembled only through the canonical
    ``_conditional_theorem_8616`` builder and only after every staged gate
    passes; refused input can never mint a theorem.
    """
    refused = _ScopedFreshTheorem8616(_ScopedTargetStage8616.REFUSED)
    if _surface_identity_failure_8616(
        project, artifact, context, block, instruction, coordinates,
    ) is not None:
        return refused
    bound_context = cast(NativeNearCallEntry8616, context)
    bound_coordinates = cast(DirectNearCallCoordinates8616, coordinates)
    binding = _staged_target_binding_8616(
        project, bound_context, cast(IRBlock, block),
        cast(IRInstr, instruction), bound_coordinates,
    )
    if binding is None:
        return refused
    return _ScopedFreshTheorem8616(
        _ScopedTargetStage8616.STAGED,
        _conditional_theorem_8616(
            bound_context,
            cast(IRFunctionArtifact, artifact),
            cast(IRBlock, block),
            cast(IRInstr, instruction),
            bound_coordinates,
            binding.shape,
        ),
    )


def _staged_scoped_theorem_8616(
    project: object,
    theorem: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
) -> _ScopedTargetStage8616:
    """Run the per-call canonical target gates inside one owned census.

    Staged non-proof evidence for the scope's census: the retained-record
    and surface gates, the shared operand/provenance/shape preflight with
    its native terminal check, the mapped E8 byte binding and the selector
    interval — identical to the standalone consumer's own gates, minus
    the raw-root rebind, context replay and detached snapshots that the
    enclosing scope now runs once per census and once at the final seal.
    ``STAGED`` is never admission: the scope's callback-free final
    derivation still re-compares every retained fact against the rooted
    IR.
    """
    facts = _retained_theorem_facts_8616(
        project, theorem, artifact, context, block, instruction
    )
    if facts is None:
        return _ScopedTargetStage8616.REFUSED
    bound_context = cast(NativeNearCallEntry8616, context)
    coordinates = DirectNearCallCoordinates8616(*facts)
    if _surface_identity_failure_8616(
        project, artifact, context, block, instruction, coordinates,
    ) is not None:
        return _ScopedTargetStage8616.REFUSED
    binding = _staged_target_binding_8616(
        project, bound_context, cast(IRBlock, block), cast(IRInstr, instruction), coordinates,
    )
    return _ScopedTargetStage8616.STAGED if binding is not None else _ScopedTargetStage8616.REFUSED


def _derive_final_scoped_theorem_8616(
    project: object,
    theorem: object,
    *,
    artifact: object,
    context: object,
) -> bool:
    """Re-derive one retained theorem callback-free from the final IR.

    The scope's final whole-census pass: reconcile the retained record,
    then recompute the control operand, owned origin prefix, canonical
    operand shape and selector interval from the retained (already
    seal-verified identical) block/instruction of the rooted caller IR.
    A fresh theorem assembled from those derived facts must equal the
    retained record exactly — forged shape, obligation, stats or
    coordinate facts refuse. No native callback runs here; every
    mutation a transient callback could hide is observed against the
    final rooted state.
    """
    bound = theorem if type(theorem) is ConditionalNearCallTargetTheorem8616 else None
    if bound is None:
        return False
    facts = _retained_theorem_facts_8616(
        project, theorem, artifact, context, bound.block, bound.instruction
    )
    if facts is None:
        return False
    coordinates = DirectNearCallCoordinates8616(*facts)
    if _surface_identity_failure_8616(
        project, artifact, context, bound.block, bound.instruction, coordinates,
    ) is not None:
        return False
    bound_context = cast(NativeNearCallEntry8616, bound.context)
    bound_block = cast(IRBlock, bound.block)
    bound_instruction = cast(IRInstr, bound.instruction)
    bound_artifact = cast(IRFunctionArtifact, bound.artifact)
    operand = _control_operand_8616(
        coordinates.callsite_addr, coordinates.target_addr, bound_instruction,
    )
    if isinstance(operand, DirectNearCallTargetBinding8616):
        return False
    origin = _owned_origin_provenance_8616(
        bound_block, bound_instruction, operand, coordinates,
    )
    if isinstance(origin, DirectNearCallTargetBinding8616):
        return False
    shape = _operand_shape_outcome_8616(bound_block, operand, coordinates)
    if isinstance(shape, DirectNearCallTargetBinding8616):
        return False
    if _interval_failure_8616(bound_context, coordinates.target_addr) is not None:
        return False
    fresh = _conditional_theorem_8616(
        bound_context, bound_artifact, bound_block, bound_instruction,
        coordinates, shape,
    )
    return _conditional_facts_equal_8616(bound, fresh)


def _theorem_coordinate_facts_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
    context: NativeNearCallEntry8616,
) -> tuple[int, int, int] | None:
    """Reconcile the theorem's retained scalars against its own obligation."""
    obligation = theorem.obligation
    callsite = theorem.callsite_addr
    next_addr = theorem.next_addr
    target = theorem.target_addr
    low = theorem.selector_low
    high = theorem.selector_high
    if obligation is None or not all(
        type(value) is int
        for value in (callsite, next_addr, target, low, high)
    ):
        return None
    if not all((
        obligation.context is context,
        obligation.callsite_addr == callsite,
        obligation.selector_low == low,
        obligation.selector_high == high,
        low == context.selector_low,
        high == context.selector_high,
    )):
        return None
    if not (
        type(callsite) is int
        and type(next_addr) is int
        and type(target) is int
    ):
        return None
    if next_addr <= callsite or callsite < 0 or target < 0:
        return None
    return callsite, next_addr, target


def _conditional_facts_equal_8616(
    theorem: ConditionalNearCallTargetTheorem8616,
    fresh: ConditionalNearCallTargetTheorem8616,
) -> bool:
    """Reconcile a re-evaluated theorem against the retained record."""
    if not all((
        type(fresh) is ConditionalNearCallTargetTheorem8616,
        fresh.verdict is ConditionalNearCallTargetVerdict8616.CONDITIONAL,
        fresh.failure is None,
        fresh.preflight_failure is None,
    )):
        return False
    return all((
        fresh.context is theorem.context,
        fresh.artifact is theorem.artifact,
        fresh.block is theorem.block,
        fresh.instruction is theorem.instruction,
        (
            fresh.callsite_addr,
            fresh.next_addr,
            fresh.target_addr,
            fresh.selector_low,
            fresh.selector_high,
        )
        == (
            theorem.callsite_addr,
            theorem.next_addr,
            theorem.target_addr,
            theorem.selector_low,
            theorem.selector_high,
        ),
        fresh.obligation == theorem.obligation,
        fresh.shape == theorem.shape,
        fresh.stats == theorem.stats,
        fresh.stats.closed,
    ))


def _retained_theorem_facts_8616(
    project: object,
    theorem: object,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
) -> tuple[int, int, int] | None:
    """Reconcile a retained theorem record against the supplied surfaces.

    Shared structural gate for both consumption paths: the record must be
    an intact CONDITIONAL theorem bound to the identical supplied context
    and caller ``artifact``/``block``/``instruction``, and its retained
    coordinates must agree with its own obligation and the context's
    selector interval. Returns the validated ``(callsite, next, target)``
    coordinate facts, or ``None`` for any omitted, copied, or foreign
    surface.
    """
    if (
        type(theorem) is not ConditionalNearCallTargetTheorem8616
        or not all((
            theorem.verdict
            is ConditionalNearCallTargetVerdict8616.CONDITIONAL,
            theorem.failure is None,
            theorem.preflight_failure is None,
            theorem.stats.materialized_count == 1,
            theorem.stats.failure_count == 0,
        ))
    ):
        return None
    retained = theorem.context
    if (
        retained is None or type(retained) is not NativeNearCallEntry8616
        or not all((
            context is retained,
            retained.project is project,
            type(artifact) is IRFunctionArtifact,
            artifact is theorem.artifact,
            block is theorem.block,
            instruction is theorem.instruction,
        ))
    ):
        return None
    return _theorem_coordinate_facts_8616(theorem, retained)


def consume_conditional_near_call_target_8616(
    project: object,
    theorem: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
) -> bool:
    """Re-prove a retained conditional theorem against live evidence.

    The identical explicit ``context`` and the exact retained
    ``artifact``/``block``/``instruction`` objects are required — a copied
    or foreign surface refuses before any replay. The full factory then
    re-binds the raw root, re-authenticates the context, and re-runs every
    outgoing-CALL gate; every retained coordinate, interval, obligation and
    shape fact must reconcile with the fresh result. An omitted, copied,
    foreign, expired, or mutated context, CALL, target, or raw IR surface
    returns ``False``; the context alone can never license a modified or
    forged artifact.
    """
    facts = _retained_theorem_facts_8616(
        project, theorem, artifact, context, block, instruction
    )
    if facts is None:
        return False
    coordinates = DirectNearCallCoordinates8616(*facts)
    fresh = prove_conditional_near_call_target_8616(
        project,
        artifact=artifact,
        context=context,
        block=block,
        instruction=instruction,
        coordinates=coordinates,
    )
    return _conditional_facts_equal_8616(cast(ConditionalNearCallTargetTheorem8616, theorem), fresh)


def reauthenticate_conditional_near_call_target_8616(
    project: object,
    theorem: object,
    *,
    artifact: object,
    context: object,
    block: object,
    instruction: object,
) -> bool:
    """Re-run only the canonical native surfaces of a retained theorem.

    One bounded pass for consumers that already bracket this call with
    their own operation-local detached source-fact reconciliation: the
    retained-record and surface gates are identical to
    ``consume_conditional_near_call_target_8616``, then the same owner
    callbacks re-authenticate — the raw-root rebind, the entry-context
    consumption with its retained ``callsite_index``, and the mapped E8
    byte binding — each followed by the request deadline check. The
    theorem's pure-owned derivation (operand DAG, coordinate and interval
    arithmetic) is deliberately not replayed: drift in those facts must be
    caught by the caller's snapshot reconciliation before and after this
    call, so no redundant full-IR serialization or second proof model is
    introduced, and no cache or registry is consulted.
    """
    facts = _retained_theorem_facts_8616(
        project, theorem, artifact, context, block, instruction
    )
    if facts is None:
        return False
    bound = cast(ConditionalNearCallTargetTheorem8616, theorem)
    bound_context = cast(NativeNearCallEntry8616, bound.context)
    bound_artifact = cast(IRFunctionArtifact, artifact)
    callsite, next_addr, target = facts
    if direct_evidence_deadline_expired_8616(project):
        return False
    if not _rebind_raw_root_8616(project, bound_context, bound_artifact):
        return False
    if direct_evidence_deadline_expired_8616(project):
        return False
    if not consume_native_near_call_entry_8616(
        project, bound_context, callsite_index=bound_context.callsite_index
    ):
        return False
    if direct_evidence_deadline_expired_8616(project):
        return False
    if not direct_near_call_target_is_bound_8616(
        project, callsite, next_addr, target,
        CallsiteMachineFrameKind8616.NEAR,
    ):
        return False
    return not direct_evidence_deadline_expired_8616(project)
