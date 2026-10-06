"""Track proven segment-register state across IR blocks.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from ..declared_external_call_evidence import (
        DeclaredCallAdmission8616,
        DeclaredCallEffectConsumption8616,
    )
    from .direct_call_segment_context import SegmentEntryContext8616
    from .near_return_continuation_view import (
        ScopedNearReturnContinuationView8616,
    )
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import ScopedFunctionIRView8616

from .core import IRFunctionArtifact, IRValue, MemSpace, SegmentOrigin
from .segment_call_preservation import SegmentCallPreservationResult8616
from .segment_state_solver import solve_segment_state_8616
from .segment_state_transfer import (
    SEGMENT_REGISTERS,
    InstructionStateKey,
    SegmentRegisterState,
    SegmentRestoreSource,
    SegmentValueKind8616,
    call_preservation_at_instruction_8616,
    declared_call_effect_at_instruction_8616,
    join_register_states,
)
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "SegmentRegisterState",
    "SegmentRestoreSource",
    "SegmentStateArtifact",
    "SegmentValueKind8616",
    "apply_x86_16_segment_state_artifact",
    "build_x86_16_segment_state_artifact",
    "republish_declared_call_consumptions_8616",
]

class _SegmentStateCodegenBoundary(Protocol):
    """Dynamic codegen attributes consumed and produced by this IR attachment."""

    _inertia_vex_ir_artifact: object
    _inertia_vex_ir_function_ssa: object
    _inertia_segment_stack_restore_artifact: object
    _inertia_segment_state_artifact: SegmentStateArtifact
    _inertia_segment_call_preservations_8616: tuple[SegmentCallPreservationResult8616, ...]
    _inertia_segment_function_summary_8616: object


class _SegmentStateProjectBoundary(Protocol):
    """Project registry field the apply path refreshes for receipts."""

    _inertia_segment_function_summaries_8616: dict[int, object]


class _SegmentRestoreEvidenceSurface(Protocol):
    """Alias-owned restore evidence consumed through a typed IR relation."""

    restore_sources: tuple[SegmentRestoreSource, ...]


@dataclass(frozen=True, slots=True)
class SegmentStateArtifact:
    """Entry/exit state retaining the identical analyzed IR artifact.

    An absent source is unbound legacy/test evidence. Serialized source address
    is diagnostic only and cannot reconstruct in-process artifact identity.

    ``scoped_view`` retains the exact conditional CFG view the predecessor
    relation was taken from — a retained application view or a
    premise-derived near-return continuation view — alongside the
    still-raw ``source_artifact`` and the supplied ``invocation_scope``
    consuming entry. Its presence marks the state as scoped evidence for
    that entry only — never universal function proof — and the default
    builder/codegen paths never attach one.
    """

    entry_states: dict[int, dict[str, SegmentRegisterState]]
    exit_states: dict[int, dict[str, SegmentRegisterState]]
    summary: dict[str, object]
    instruction_entry_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = field(default_factory=dict)
    instruction_exit_states: dict[InstructionStateKey, dict[str, SegmentRegisterState]] = field(default_factory=dict)
    source_artifact: IRFunctionArtifact | None = field(default=None, repr=False, compare=False)
    call_preservations: tuple[SegmentCallPreservationResult8616, ...] = ()
    declared_call_consumptions: tuple[DeclaredCallEffectConsumption8616, ...] = ()
    entry_context: SegmentEntryContext8616 | None = field(default=None, repr=False, compare=False)
    invocation_scope: Real16InvocationDomain8616 | None = field(default=None, repr=False, compare=False)
    scoped_view: (
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None
    ) = field(default=None, repr=False, compare=False)

    def state_for_register(self, register: str) -> SegmentRegisterState | None:
        """Return the one proven identity held throughout the function."""
        observed = tuple(
            state
            for state_map in (
                *self.entry_states.values(),
                *self.exit_states.values(),
                *self.instruction_entry_states.values(),
                *self.instruction_exit_states.values(),
            )
            if (state := state_map.get(register)) is not None
        )
        joined = join_register_states(observed, register)
        return joined if joined.origin is SegmentOrigin.PROVEN else None

    def state_at_block_entry(self, block_addr: int, register: str) -> SegmentRegisterState | None:
        """Return the exact state before one IR block when available."""
        return self.entry_states.get(block_addr, {}).get(register)

    def state_at_block_exit(self, block_addr: int, register: str) -> SegmentRegisterState | None:
        """Return the exact state after one IR block when available."""
        return self.exit_states.get(block_addr, {}).get(register)

    def state_before_instruction(
        self,
        instruction_addr: int,
        register: str,
    ) -> SegmentRegisterState | None:
        """Return the exact state immediately before one typed IR instruction."""
        return self.instruction_entry_states.get(instruction_addr, {}).get(register)

    def state_after_instruction(
        self,
        instruction_addr: int,
        register: str,
    ) -> SegmentRegisterState | None:
        """Return the exact state immediately after one typed IR instruction."""
        return self.instruction_exit_states.get(instruction_addr, {}).get(register)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "invocation_scope": None if self.invocation_scope is None else self.invocation_scope.to_dict(),
            "scoped_view": None if self.scoped_view is None else self.scoped_view.to_dict(),
            "entry_context_callsite": None if self.entry_context is None else self.entry_context.candidate.callsite_addr,
            "entry_context_complete": None if self.entry_context is None else self.entry_context.complete,
            "source_function_addr": None if self.source_artifact is None else self.source_artifact.function_addr,
            "call_preservation_sites": [proof.callsite_addr for proof in self.call_preservations],
            "declared_call_consumptions": [
                consumption.to_record() for consumption in self.declared_call_consumptions
            ],
            "entry_states": {
                hex(addr): {name: state.to_dict() for name, state in sorted(states.items())}
                for addr, states in sorted(self.entry_states.items())
            },
            "exit_states": {
                hex(addr): {name: state.to_dict() for name, state in sorted(states.items())}
                for addr, states in sorted(self.exit_states.items())
            },
            "instruction_entry_states": {
                _instruction_state_key_text(key): {name: state.to_dict() for name, state in sorted(states.items())}
                for key, states in sorted(self.instruction_entry_states.items(), key=lambda item: str(item[0]))
            },
            "instruction_exit_states": {
                _instruction_state_key_text(key): {name: state.to_dict() for name, state in sorted(states.items())}
                for key, states in sorted(self.instruction_exit_states.items(), key=lambda item: str(item[0]))
            },
            "summary": dict(self.summary),
        }


def _instruction_state_key_text(key: InstructionStateKey) -> str:
    """Format an exact instruction coordinate for diagnostic serialization."""
    return hex(key) if isinstance(key, int) else f"{key[0]:#x}:{key[1]}"


def build_x86_16_segment_state_artifact(
    artifact: IRFunctionArtifact,
    function_ssa: SSAFunctionArtifact | None = None,
    restore_sources: tuple[SegmentRestoreSource, ...] = (),
    *,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...] = (),
    entry_context: SegmentEntryContext8616 | None = None,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    scoped_view: (
        ScopedFunctionIRView8616 | ScopedNearReturnContinuationView8616 | None
    ) = None,
    declared_call_effects: tuple[DeclaredCallAdmission8616, ...] = (),
) -> SegmentStateArtifact:
    """Build forward segment-register state from typed IR and SSA predecessors.

    Closed evidence accounting counts one raw fact per explicit segment write
    and one raw fact per CALL boundary. A write is classified when its exit
    state is proven. A CALL is classified only by one complete, bound leaf
    preservation proof; unsupported and ambiguous calls remain counted
    refusals. GP proxy identities never survive on that segment evidence.
    An optional entry context remains callsite-local and contributes one
    retained proof fact; it must never become a universal callee summary.

    A supplied ``scoped_view`` routes the solve through the view's
    authenticated effective CFG while keeping ``artifact`` — the identical
    raw source — as the call/write accounting and instruction-identity
    surface; the solver owns the binding checks and refuses unbound
    combinations. The default codegen apply path never supplies a view, so
    state it publishes stays universal.

    ``declared_call_effects`` carries only already-admitted frontend
    declarations bound to this identical artifact's function address; each
    consumed declaration contributes one classified CALL-boundary fact and
    one retained immutable consumption receipt, never a universal callee
    summary.
    """
    declared_consumptions: list[DeclaredCallEffectConsumption8616] = []
    if declared_call_effects:
        from ..declared_external_call_evidence import DeclaredCallEffectConsumption8616

        for block in artifact.blocks:
            for instruction in block.instrs:
                if instruction.op != "CALL":
                    continue
                admission = declared_call_effect_at_instruction_8616(
                    artifact, block, instruction, declared_call_effects
                )
                if admission is not None:
                    declared_consumptions.append(
                        DeclaredCallEffectConsumption8616.from_admission_8616(admission)
                    )
    solution = solve_segment_state_8616(
        artifact, function_ssa, restore_sources, call_preservations, entry_context=entry_context, invocation_scope=invocation_scope, scoped_view=scoped_view, declared_call_effects=declared_call_effects,
    )
    call_boundary_count = sum(
        1
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    explicit_write_count = sum(
        1
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op != "CALL"
        and isinstance(instruction.dst, IRValue)
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in SEGMENT_REGISTERS
    )
    classified_write_count = sum(
        1
        for block in artifact.blocks
        for instruction_index, instruction in enumerate(block.instrs)
        if instruction.op != "CALL"
        and isinstance(instruction.dst, IRValue)
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name in SEGMENT_REGISTERS
        and solution.instruction_exit_states[
            instruction.addr if isinstance(instruction.addr, int) else (block.addr, instruction_index)
        ][instruction.dst.name].origin
        is SegmentOrigin.PROVEN
    )
    entry_context_count = int(entry_context is not None)
    raw_fact_count = explicit_write_count + call_boundary_count + entry_context_count
    classified_call_count = sum(
        call_preservation_at_instruction_8616(artifact, block, instruction, call_preservations, invocation_scope) is not None
        or declared_call_effect_at_instruction_8616(artifact, block, instruction, declared_call_effects) is not None
        for block in artifact.blocks for instruction in block.instrs if instruction.op == "CALL"
    )
    scoped_projection = solution.scoped_projection
    summary: dict[str, object] = {
        "block_count": len(artifact.blocks),
        "scoped_view_bound": scoped_view is not None,
        "scoped_discharged_edge_count": (
            0 if scoped_projection is None else len(scoped_projection.applied)
        ),
        "scoped_pending_block_count": (
            0
            if scoped_projection is None
            else sum(
                1 for refusals in scoped_projection.pending.values() if refusals
            )
        ),
        "explicit_write_count": explicit_write_count,
        "call_boundary_count": call_boundary_count,
        "classified_call_count": classified_call_count,
        "declared_call_consumption_count": len(declared_consumptions),
        "entry_context_count": entry_context_count,
        "raw_fact_count": raw_fact_count,
        "normalized_fact_count": raw_fact_count,
        "classified_fact_count": classified_write_count + classified_call_count + entry_context_count,
        "materialized_count": classified_write_count + classified_call_count + entry_context_count,
        "failure_count": raw_fact_count - classified_write_count - classified_call_count - entry_context_count,
        "architectural_live_in_count": sum(
            state.value_kind is SegmentValueKind8616.ARCHITECTURAL_LIVE_IN
            for state in solution.entry_states.get(artifact.function_addr, {}).values()
        ),
        "proven_register_count": sum(
            state.origin is SegmentOrigin.PROVEN
            for states in solution.exit_states.values()
            for state in states.values()
        ),
        "unknown_register_count": sum(
            state.origin is SegmentOrigin.UNKNOWN
            for states in solution.exit_states.values()
            for state in states.values()
        ),
    }
    return SegmentStateArtifact(
        entry_states=solution.entry_states,
        exit_states=solution.exit_states,
        summary=summary,
        instruction_entry_states=solution.instruction_entry_states,
        instruction_exit_states=solution.instruction_exit_states,
        source_artifact=artifact,
        call_preservations=call_preservations,
        declared_call_consumptions=tuple(declared_consumptions),
        entry_context=entry_context, invocation_scope=invocation_scope,
        scoped_view=scoped_view,
    )


def apply_x86_16_segment_state_artifact(project: object, codegen: object) -> bool:
    """Attach the segment-state artifact to codegen for later IR consumers."""
    boundary = cast(_SegmentStateCodegenBoundary, codegen)
    try:
        artifact = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, IRFunctionArtifact):
        return False
    try:
        candidate_function_ssa = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        candidate_function_ssa = None
    function_ssa = candidate_function_ssa if isinstance(candidate_function_ssa, SSAFunctionArtifact) else None
    try:
        restore_evidence = cast(
            _SegmentRestoreEvidenceSurface,
            boundary._inertia_segment_stack_restore_artifact,
        )
        restore_sources = restore_evidence.restore_sources
    except AttributeError:
        restore_sources = ()
    try:
        call_preservations = boundary._inertia_segment_call_preservations_8616
    except AttributeError:
        call_preservations = ()
    if not isinstance(call_preservations, tuple):
        raise TypeError("segment call preservation evidence must be a tuple")
    from ..declared_external_call_evidence import (
        declared_external_call_registry_8616,
    )

    declared_registry = declared_external_call_registry_8616(project)
    declared_call_effects = (
        ()
        if declared_registry is None or not declared_registry.closes_evidence
        else declared_registry.admissions_for_function_8616(artifact.function_addr)
    )
    segment_artifact = build_x86_16_segment_state_artifact(
        artifact,
        function_ssa=function_ssa,
        restore_sources=restore_sources,
        call_preservations=call_preservations,
        declared_call_effects=declared_call_effects,
    )
    boundary._inertia_segment_state_artifact = segment_artifact
    _publish_declared_consumption_receipts_8616(
        project, boundary, artifact.function_addr, segment_artifact.declared_call_consumptions
    )
    return False


def republish_declared_call_consumptions_8616(
    project: object, codegen: object, function_addr: int,
) -> None:
    """Rebind consumed assumptions after the later function-summary stage.

    Summary construction replaces its project/codegen objects after segment
    state has run. Reauthenticate only receipts actually consumed by that
    state; an admission alone cannot manufacture a consumption receipt.
    """
    from ..declared_external_call_evidence import (
        DeclaredCallEffectConsumption8616,
        declared_external_call_registry_8616,
    )

    boundary = cast(_SegmentStateCodegenBoundary, codegen)
    try:
        state = boundary._inertia_segment_state_artifact
    except AttributeError:
        return
    if not isinstance(state, SegmentStateArtifact) or state.source_artifact is None:
        return
    source = state.source_artifact
    if source.function_addr != function_addr:
        return
    registry = declared_external_call_registry_8616(project)
    admissions = (
        registry.admissions_for_function_8616(source.function_addr)
        if registry is not None and registry.closes_evidence else ()
    )
    verified: list[DeclaredCallEffectConsumption8616] = []
    if state.declared_call_consumptions:
        for block in source.blocks:
            for instruction in block.instrs:
                admission = declared_call_effect_at_instruction_8616(source, block, instruction, admissions)
                if admission is None:
                    continue
                receipt = DeclaredCallEffectConsumption8616.from_admission_8616(admission)
                if receipt in state.declared_call_consumptions:
                    verified.append(receipt)
    _publish_declared_consumption_receipts_8616(project, boundary, source.function_addr, tuple(verified))


def _publish_declared_consumption_receipts_8616(
    project: object,
    boundary: _SegmentStateCodegenBoundary,
    function_addr: int,
    consumptions: tuple[DeclaredCallEffectConsumption8616, ...],
) -> None:
    """Attach immutable consumption receipts to the retained summary surfaces.

    Both segment-state refresh and the later summary stage publish through this
    owner. Empty current receipts clear prior consumption after revocation;
    summary reconstruction must not discard freshly consumed assumptions.
    """
    from dataclasses import replace

    from ..segment_function_summary import SegmentFunctionSummary8616

    try:
        summary = boundary._inertia_segment_function_summary_8616
    except AttributeError:
        summary = None
    if isinstance(summary, SegmentFunctionSummary8616) and summary.function_addr == function_addr:
        summary = replace(summary, declared_call_consumptions=consumptions)
        boundary._inertia_segment_function_summary_8616 = summary
    try:
        summaries = cast(
            _SegmentStateProjectBoundary, project
        )._inertia_segment_function_summaries_8616
    except AttributeError:
        return
    if not isinstance(summaries, dict):
        return
    prior = summaries.get(function_addr)
    if isinstance(prior, SegmentFunctionSummary8616) and prior.function_addr == function_addr:
        summaries[function_addr] = replace(
            prior, declared_call_consumptions=consumptions
        )
