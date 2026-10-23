"""Layer: Semantics.
Responsibility: authenticate conditional raw-IR to call-Semantics projections.

The original native source and its scoped control proof remain authoritative.
Projected IR/SSA belongs to one consuming codegen, never a universal registry.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from inertia.ir.core import IRBlock, IRFunctionArtifact, IRValue, MemSpace
from inertia.ir.declared_entry_pipeline import (
    DeclaredEntryPipeline8616,
    _retained_input_8616,
)
from inertia.ir.entry_projection_mode import EntryProjectionMode8616, entry_projection_mode_for_scope_8616
from inertia.ir.ir_boundary_cfg import consume_scoped_ir_boundary_projection_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616
from inertia.ir.scoped_function_ir_view import (
    EntryJumpConsumingScope8616,
    ScopedFunctionCFGProjection8616,
    ScopedFunctionIRView8616,
)
from inertia.ir.source_graph_binding import source_graphs_equal_8616
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.pipeline.errors import PipelineHardError

if TYPE_CHECKING:
    from .call_outputs import CallOutputArtifact8616
    from .call_stack_effects import CallStackEffectArtifact8616


def scoped_call_blocks_8616(
    projection: ScopedFunctionCFGProjection8616,
) -> tuple[IRBlock, ...]:
    """Derive private semantic CALL operands from one fresh authenticated census.

    This synchronous projection adds no authority; retained consumers must
    reauthenticate the owning view. Raw and CFG instructions remain unchanged.
    """
    targets = {(call.block.addr, call.instruction.addr): call
               for call in projection.call_targets}
    if len(targets) != len(projection.call_targets):
        raise PipelineHardError("ambiguous scoped CALL census", layer="semantics")
    result: list[IRBlock] = []
    for block in projection.blocks:
        instructions = []
        for instruction in block.instrs:
            call = targets.get((block.addr, instruction.addr)) if instruction.op == "CALL" else None
            if call is not None:
                if call.scope is not projection.scope:
                    raise PipelineHardError("scoped CALL premise differs", layer="semantics")
                instruction = replace(instruction, args=(IRValue(MemSpace.CONST, const=call.target, size=4),))
            instructions.append(instruction)
        result.append(block if all(a is b for a, b in zip(instructions, block.instrs, strict=True))
                      else replace(block, instrs=tuple(instructions)))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ScopedCallSemanticInput8616:
    """Exact native source, authenticated control projection and consuming entry."""

    project: object
    function: object
    source_ir: IRFunctionArtifact
    input_ir: IRFunctionArtifact
    scope: EntryJumpConsumingScope8616
    view: ScopedFunctionIRView8616

    @property
    def projection_mode(self) -> EntryProjectionMode8616:
        """Derive the request from retained typed authority on every consumption."""
        return entry_projection_mode_for_scope_8616(self.scope)

    def authenticate(self) -> bool:
        """Recheck the whole source/control census without universal publication."""
        if self.scope.project is not self.project or self.view.source_artifact is not self.source_ir:
            return False
        consumption = consume_scoped_ir_boundary_projection_8616(
            self.project, self.view.boundary, self.source_ir, self.view, self.scope,
            projection_mode=self.projection_mode,
        )
        if consumption.coverage.failure is not None:
            return False
        projection = consumption.projection
        if projection is None or self.input_ir.refusals:
            return False
        if self.input_ir.logical_memory is not self.source_ir.logical_memory:
            return False
        return (
            self.input_ir.summary is self.source_ir.summary
            and self.input_ir.condition_evidence is self.source_ir.condition_evidence
            and self.input_ir.function_addr == self.source_ir.function_addr
            and source_graphs_equal_8616(
                self.input_ir.function_addr, self.input_ir.blocks,
                self.source_ir.function_addr, scoped_call_blocks_8616(projection),
            )
        )

    def authenticates_outputs(
        self, effects: CallStackEffectArtifact8616, outputs: CallOutputArtifact8616,
        function_ssa: SSAFunctionArtifact,
    ) -> bool:
        """Recompute owned transforms, rejecting forged or changed output artifacts."""
        from .call_stack_effect_pipeline import build_semantic_function_ssa_8616

        with native_import_request_8616():
            if not self.authenticate():
                return False
            current_effects, current_outputs, current_ssa = build_semantic_function_ssa_8616(
                self.project, self.function, ir_artifact=self.input_ir,
            )
            if not self._proofs_bound(effects, current_effects):
                return False
            return bool(
                effects == current_effects
                and outputs == current_outputs
                and function_ssa == current_ssa
                and effects.function.condition_evidence is self.input_ir.condition_evidence
                and outputs.function.condition_evidence is self.input_ir.condition_evidence
                and function_ssa.condition_evidence is self.input_ir.condition_evidence
                and effects.to_dict() == current_effects.to_dict()
                and outputs.to_dict() == current_outputs.to_dict()
                and outputs.function.to_dict() == current_outputs.function.to_dict()
                and effects.function.to_dict() == current_effects.function.to_dict()
                and function_ssa.to_dict() == current_ssa.to_dict()
            )

    def _proofs_bound(
        self, effects: CallStackEffectArtifact8616, current: CallStackEffectArtifact8616,
    ) -> bool:
        """Authenticate retained proof identities omitted from diagnostics."""
        for retained, fresh in zip(effects.facts, current.facts, strict=False):
            bp, fresh_bp = retained.bp_preservation, fresh.bp_preservation
            if (bp is None) != (fresh_bp is None):
                return False
            if (bp is not None and fresh_bp is not None
                    and (bp.project is not self.project or bp != fresh_bp or bp.complete != fresh_bp.complete)):
                return False
            target, fresh_target = retained.target_binding, fresh.target_binding
            if (target is None) != (fresh_target is None):
                return False
            if target is not None and fresh_target is not None:
                if target != fresh_target or target.to_dict() != fresh_target.to_dict():
                    return False
                if target.complete != fresh_target.complete:
                    return False
                invocation = target.invocation
                if invocation is not None and (
                    invocation.project is not self.project
                    or not any(invocation.block is block for block in self.input_ir.blocks)
                ):
                    return False
        return True


def scoped_call_semantic_input_8616(
    project: object, codegen: object, function: object, source_ir: IRFunctionArtifact,
) -> ScopedCallSemanticInput8616 | None:
    """Consume an explicitly prepared entry at the earliest call-Semantics stage."""
    entry = _retained_input_8616(codegen)
    if entry is None:
        return None
    if type(entry) is not DeclaredEntryPipeline8616 and type(entry) is not NativeNearCallPipeline8616:
        # An unproved declared entry has no premise-derived projection: the
        # typed record stays retained while Semantics runs its ordinary
        # unscoped input over the identical raw artifact.
        return None
    if (entry.bundle.artifact is not source_ir or entry.scope.project is not project
            or entry.view.source_artifact is not source_ir):
        raise PipelineHardError("scoped call input lost its original native source", layer="semantics")
    if type(entry) is NativeNearCallPipeline8616 and (
        _retained_input_8616(codegen) is not entry
        or entry.scope.artifact is not entry.bundle.artifact
        or entry.view.near_call_scope is not entry.scope
        or not entry._source_current(project)
    ):
        raise PipelineHardError(
            "scoped call input lost its installed native source", layer="semantics")
    # This constructor owns the fresh consumption synchronously. Derive the
    # new input from that checked projection rather than replaying it again;
    # retained inputs still use the unchanged full authenticate() contract.
    consumption = consume_scoped_ir_boundary_projection_8616(
        project, entry.view.boundary, source_ir, entry.view, entry.scope,
        projection_mode=entry_projection_mode_for_scope_8616(entry.scope),
    )
    if type(entry) is NativeNearCallPipeline8616 and (
        _retained_input_8616(codegen) is not entry
        or entry.scope.artifact is not entry.bundle.artifact
        or entry.view.near_call_scope is not entry.scope
        or not entry._source_current(project)
    ):
        raise PipelineHardError(
            "native source changed during scoped call consumption", layer="semantics")
    if consumption.coverage.failure is not None:
        raise PipelineHardError("scoped call input has incomplete native coverage", layer="semantics")
    projection = consumption.projection
    if projection is None:
        raise PipelineHardError("scoped call input has no authenticated control projection", layer="semantics")
    # The native source remains retained separately. This exact control-only
    # projection is private input to the existing Semantics owners.
    input_ir = replace(source_ir, blocks=scoped_call_blocks_8616(projection), refusals=())
    result = ScopedCallSemanticInput8616(project, function, source_ir, input_ir, entry.scope, entry.view)
    if not source_graphs_equal_8616(
        input_ir.function_addr, input_ir.blocks,
        source_ir.function_addr, scoped_call_blocks_8616(projection),
    ):
        raise PipelineHardError("scoped call input has incomplete native coverage", layer="semantics")
    return result
