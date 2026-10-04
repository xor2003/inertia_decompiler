"""Preserve exact numeric 16-bit input values bound to one logical PUSH root.

Layer: Types/Lowering.
Responsibility: bind one ``LogicalInputRootBinding8616`` to its exact caller SSA
artifact, reaching definition, and CALL use, then retain the upstream modular
affine trace of the original pushed root taken before its physical push sites.
The result is numeric evidence only: it never claims a source segment, a native
pointer representation, a pointee, or an ``Address`` for the pushed value.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir import (
    IRValue,
    ScalarAffineExpression8616,
    ScalarAffineTrace8616,
    SSABlock,
    SSAFunctionArtifact,
)
from ..ir.scalar_affine_trace import trace_scalar_affine_expression_8616
from .interprocedural_storage_contracts import (
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_logical_input_contracts import (
    LogicalInputRootBinding8616,
)

__all__ = [
    "InputOffsetValue8616",
    "InputOffsetValueFailure8616",
    "InputOffsetValueStats8616",
    "collect_input_offset_value_8616",
]

_WORD_BYTES_8616 = 2


class InputOffsetValueFailure8616(StrEnum):
    """Stable reasons one bound input value cannot be preserved numerically."""

    MISSING_LOGICAL_ROOT = "missing_logical_root"
    BINDING_INCOMPLETE = "binding_incomplete"
    SPLIT_LOGICAL_ARGUMENT = "split_logical_argument"
    WIDTH_CONFLICT = "width_conflict"
    FOREIGN_CALLER_ARTIFACT = "foreign_caller_artifact"
    FOREIGN_PUSH_SITE = "foreign_push_site"
    DEFINITION_MISMATCH = "definition_mismatch"
    CALL_USE_MISMATCH = "call_use_mismatch"
    TRACE_REFUSED = "trace_refused"


@dataclass(frozen=True, slots=True)
class InputOffsetValueStats8616:
    """Count numeric facts; only complete affine traces classify/materialize."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether one input became one retained traced expression."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


def _covers_whole_word_8616(binding: LogicalInputRootBinding8616) -> bool:
    """Return whether the bound root alone covers the complete 16-bit input."""
    return bool(
        binding.covers_logical_argument
        and binding.width == _WORD_BYTES_8616
        and binding.argument_storage.size == _WORD_BYTES_8616
    )


def _push_block_8616(
    artifact: SSAFunctionArtifact,
    binding: LogicalInputRootBinding8616,
) -> SSABlock | None:
    """Return the one artifact block hosting every PUSH store site, or refuse.

    Slice sites must name this artifact's exact block and instruction objects;
    equal-shaped copies from another artifact are foreign evidence.
    """
    blocks = {block.addr: block for block in artifact.blocks}
    if len(blocks) != len(artifact.blocks):
        return None
    push_block: SSABlock | None = None
    for item in binding.slices:
        site = item.site
        block = blocks.get(site.block.addr)
        if block is None or block is not site.block or block.refusals:
            return None
        if not 0 <= site.instr_index < len(block.instrs):
            return None
        if block.instrs[site.instr_index] is not site.instr:
            return None
        if site.instr.addr != binding.push_addr:
            return None
        if push_block is None:
            push_block = block
        elif push_block is not block:
            return None
    return push_block


def _definition_matches_8616(
    binding: LogicalInputRootBinding8616,
    definition: StorageReachingDefinition8616 | None,
) -> bool:
    """Return whether the reaching definition is this root's exact slice."""
    return bool(
        definition is not None
        and definition.is_complete
        and binding.matches_definition(definition)
    )


def _use_in_artifact_8616(
    artifact: SSAFunctionArtifact,
    binding: LogicalInputRootBinding8616,
    use: StorageUseEvidence8616 | None,
) -> bool:
    """Return whether the bound CALL use is the exact artifact instruction."""
    if use is None or use != binding.call_use or not use.is_complete:
        return False
    block = next(
        (block for block in artifact.blocks if block.addr == use.block_addr),
        None,
    )
    if block is None or not 0 <= use.instr_index < len(block.instrs):
        return False
    instruction = block.instrs[use.instr_index]
    return bool(
        instruction.op == "CALL"
        and instruction.addr == use.instr_addr == use.callsite_addr == binding.callsite_addr
    )


def _trace_proves_root_8616(
    binding: LogicalInputRootBinding8616,
    trace: ScalarAffineTrace8616 | None,
) -> bool:
    """Return whether the retained upstream trace proves this exact root."""
    if trace is None or not trace.complete:
        return False
    expression = trace.expression
    return bool(
        expression is not None
        and expression.root is binding.root
        and expression.width == _WORD_BYTES_8616
    )


@dataclass(frozen=True, slots=True)
class InputOffsetValue8616:
    """One proven numeric caller input value or one atomic typed refusal.

    Completeness is recomputed from the retained binding, artifact, definition,
    use, and upstream trace — never from a cached verdict. The retained scalar
    expression is numeric evidence only; it does not prove a source segment,
    a native pointer representation, or a pointee.
    """

    binding: LogicalInputRootBinding8616 | None
    artifact: SSAFunctionArtifact | None
    definition: StorageReachingDefinition8616 | None
    use: StorageUseEvidence8616 | None
    trace: ScalarAffineTrace8616 | None
    failure: InputOffsetValueFailure8616 | None
    stats: InputOffsetValueStats8616

    @property
    def complete(self) -> bool:
        """Recheck owned scope, root, site, definition, use, and trace proof."""
        binding = self.binding
        artifact = self.artifact
        if self.failure is not None or not self.stats.complete:
            return False
        if binding is None or artifact is None or not binding.complete:
            return False
        scope_agrees = (
            _covers_whole_word_8616(binding)
            and artifact.function_addr == binding.caller_addr
        )
        evidence_agrees = (
            scope_agrees
            and _push_block_8616(artifact, binding) is not None
            and _definition_matches_8616(binding, self.definition)
            and _use_in_artifact_8616(artifact, binding, self.use)
        )
        if not evidence_agrees or not _trace_proves_root_8616(binding, self.trace):
            return False
        block = _push_block_8616(artifact, binding)
        assert block is not None
        current = trace_scalar_affine_expression_8616(
            artifact, binding.root, block_addr=block.addr,
            before_index=min(item.site.instr_index for item in binding.slices),
            allow_entry_registers=True,
        )
        return current.complete and current == self.trace

    @property
    def value(self) -> IRValue | None:
        """Return the exact original pushed 16-bit Value, never a projection."""
        if not self.complete or self.binding is None:
            return None
        return self.binding.root

    @property
    def expression(self) -> ScalarAffineExpression8616 | None:
        """Return the upstream affine expression only for a closed proof."""
        if not self.complete or self.trace is None:
            return None
        return self.trace.expression


def _refuse_8616(
    failure: InputOffsetValueFailure8616,
    *,
    binding: LogicalInputRootBinding8616 | None,
    artifact: SSAFunctionArtifact,
    definition: StorageReachingDefinition8616 | None,
    use: StorageUseEvidence8616 | None,
    trace: ScalarAffineTrace8616 | None = None,
    normalized: bool,
    classified: bool = False,
) -> InputOffsetValue8616:
    """Build one atomic refusal that retains every input for diagnosis."""
    return InputOffsetValue8616(
        binding=binding,
        artifact=artifact,
        definition=definition,
        use=use,
        trace=trace,
        failure=failure,
        stats=InputOffsetValueStats8616(
            raw_fact_count=1,
            normalized_fact_count=int(normalized),
            classified_fact_count=int(classified),
            materialized_count=0,
            failure_count=1,
        ),
    )


def collect_input_offset_value_8616(
    binding: LogicalInputRootBinding8616 | None,
    *,
    artifact: SSAFunctionArtifact,
    definition: StorageReachingDefinition8616 | None,
    use: StorageUseEvidence8616 | None,
) -> InputOffsetValue8616:
    """Preserve one caller's exact numeric PUSH value under closed evidence.

    The upstream affine trace runs at the original root before the physical
    push, with the entry-register opt-in so proven frame arithmetic stays
    numeric. Any malformed, split, foreign, mismatched, or untraceable input
    refuses atomically rather than degrading to a partial value.
    """
    if binding is None:
        return _refuse_8616(
            InputOffsetValueFailure8616.MISSING_LOGICAL_ROOT,
            binding=None,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=False,
        )
    if not binding.complete:
        return _refuse_8616(
            InputOffsetValueFailure8616.BINDING_INCOMPLETE,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=False,
        )
    if not binding.covers_logical_argument:
        return _refuse_8616(
            InputOffsetValueFailure8616.SPLIT_LOGICAL_ARGUMENT,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=True,
        )
    if binding.width != _WORD_BYTES_8616:
        return _refuse_8616(
            InputOffsetValueFailure8616.WIDTH_CONFLICT,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=True,
        )
    if artifact.function_addr != binding.caller_addr:
        return _refuse_8616(
            InputOffsetValueFailure8616.FOREIGN_CALLER_ARTIFACT,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=True,
        )
    push_block = _push_block_8616(artifact, binding)
    if push_block is None:
        return _refuse_8616(
            InputOffsetValueFailure8616.FOREIGN_PUSH_SITE,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=True,
        )
    if not _definition_matches_8616(binding, definition):
        return _refuse_8616(
            InputOffsetValueFailure8616.DEFINITION_MISMATCH,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=True,
        )
    if not _use_in_artifact_8616(artifact, binding, use):
        return _refuse_8616(
            InputOffsetValueFailure8616.CALL_USE_MISMATCH,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            normalized=True,
        )
    trace = trace_scalar_affine_expression_8616(
        artifact,
        binding.root,
        block_addr=push_block.addr,
        before_index=min(item.site.instr_index for item in binding.slices),
        allow_entry_registers=True,
    )
    if not _trace_proves_root_8616(binding, trace):
        return _refuse_8616(
            InputOffsetValueFailure8616.TRACE_REFUSED,
            binding=binding,
            artifact=artifact,
            definition=definition,
            use=use,
            trace=trace,
            normalized=True,
        )
    return InputOffsetValue8616(
        binding=binding,
        artifact=artifact,
        definition=definition,
        use=use,
        trace=trace,
        failure=None,
        stats=InputOffsetValueStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        ),
    )
