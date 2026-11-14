# cython: language_level=3, infer_types=True
"""Resolve call arguments to exact typed SSA reaching definitions.

Layer: Types/Lowering.
Responsibility: select one structured callsite argument, verify its exact CALL
use, normalize byte-executed logical pushes, and orchestrate source-definition
proof over ``SSAFunctionArtifact``. Ordinary source matching is owned by
``interprocedural_storage_source_defs``; durable outcomes are owned by
``interprocedural_storage_reaching_contracts``.
Consumes alias, widening, and typed facts.
This module does not classify C types or mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsiteIndex8616
from inertia.ir.core import IRValue
from inertia.ir.scalar_affine_contracts import ScalarAffineExpression8616
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.semantics.call_stack_effect_pipeline import CallSemanticProjection8616
from inertia.semantics.call_target_identity import x86_16_call_targets_equivalent_8616
from inertia.semantics.callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
    logical_argument_widths_from_callsite_8616,
)

from .call_target_ssa_binder import bind_ssa_call_target_8616
from .interprocedural_storage_contracts import (
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_expression_defs import (
    resolve_expression_argument_definitions_8616,
)
from .interprocedural_storage_physical_defs import (
    reaching_definition_width_8616,
    resolve_physical_store_definitions_8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionResolution8616,
    CallArgumentDefinitionStats8616,
    CallArgumentDefinitionVerdict8616,
    PhysicalCallArgument8616,
    PhysicalCallArgumentPiece8616,
    SSAInstructionSite8616,
)
from .interprocedural_storage_source_defs import (
    resolve_argument_source_definitions_8616,
)
from .interprocedural_storage_trial_types import (
    logical_source_definitions_failure_8616,
)
import operator
import builtins

__all__ = [
    "CallArgumentDefinitionFailure8616",
    "CallArgumentDefinitionResolution8616",
    "CallArgumentDefinitionStats8616",
    "CallArgumentDefinitionVerdict8616",
    "physical_call_argument_8616",
    "resolve_call_argument_reaching_definition_8616",
]


@cython.ccall
def _refusal_8616(
    failure: CallArgumentDefinitionFailure8616,
    *,
    normalized: cython.bint,
    conflict: cython.bint = False,
) -> CallArgumentDefinitionResolution8616:
    """Build one deterministic refusal with closed evidence counters."""
    verdict = (
        CallArgumentDefinitionVerdict8616.CONFLICT if conflict else CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    )
    return CallArgumentDefinitionResolution8616(
        verdict=verdict,
        definitions=(),
        use=None,
        failure=failure,
        stats=CallArgumentDefinitionStats8616(
            raw_fact_count=1,
            normalized_fact_count=int(normalized),
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        ),
    )


def _sites_8616(
    function_ssa: SSAFunctionArtifact,
) -> tuple[SSAInstructionSite8616, ...]:
    """Return all SSA instructions in deterministic block/index order."""
    return tuple(
        SSAInstructionSite8616(block, instr_index, instr)
        for block in builtins.iter(sorted(function_ssa.blocks, key=lambda item: item.addr))
        for instr_index, instr in builtins.iter(enumerate(block.instrs))
    )


@cython.ccall
def _symbolic_call_target_matches_8616(
    function_ssa: SSAFunctionArtifact,
    summary: CallsiteSummary8616,
    expected_target: cython.longlong,
    *,
    project: object,
    callsite_index: DecodedDirectCallsiteIndex8616 | None,
    projection: CallSemanticProjection8616 | None,
) -> cython.bint:
    """Prove a non-CONST CALL operand's target through the shared binder.

    The same typed proof the output gate consumes: producer integrity against
    the owned block-local SSA projection of the registered source block (raw
    or Semantics-enriched via the retained projection), then the
    Semantics-owned native binding restricted to the admitted target
    relation. Any refused or non-admitted proof leaves the operand unmatched.
    """
    binding = bind_ssa_call_target_8616(
        function_ssa,
        function_ssa.function_addr,
        summary.callsite_addr,
        (expected_target,),
        project=project,
        callsite_index=callsite_index,
        projection=projection,
    )
    if not binding.complete or binding.target_addr is None:
        return False
    if project is None:
        return operator.eq(binding.target_addr, expected_target)
    return x86_16_call_targets_equivalent_8616(
        project,
        binding.target_addr,
        expected_target,
    )


def _call_use_8616(
    sites: object,
    summary: CallsiteSummary8616,
    *,
    function_ssa: SSAFunctionArtifact,
    project: object,
    expected_target_addr: int | None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None = None,
    projection: CallSemanticProjection8616 | None = None,
) -> tuple[
    StorageUseEvidence8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Find one exact SSA CALL and verify its constant or proven target."""
    calls = tuple(site for site in iter(sites) if site.instr.op == "CALL" and operator.eq(site.instr.addr, summary.callsite_addr))
    if not calls:
        return None, CallArgumentDefinitionFailure8616.CALLSITE_NOT_FOUND
    if len(calls) != 1:
        return None, CallArgumentDefinitionFailure8616.CALLSITE_CONFLICT
    site = calls[0]
    target = site.instr.args[0] if site.instr.args else None
    expected_target = (
        expected_target_addr
        if isinstance(expected_target_addr, int)
        else summary.target_addr
    )
    if not isinstance(target, IRValue) or not isinstance(expected_target, int):
        return None, CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT
    if not isinstance(target.const, int):
        target_matches = _symbolic_call_target_matches_8616(
            function_ssa,
            summary,
            expected_target,
            project=project,
            callsite_index=callsite_index,
            projection=projection,
        )
    elif project is None:
        target_matches = operator.eq(target.const, expected_target)
    else:
        target_matches = x86_16_call_targets_equivalent_8616(
            project,
            target.const,
            expected_target,
        )
    if project is None:
        summary_matches = summary.target_addr in {None, expected_target}
    else:
        summary_matches = summary.target_addr is None or x86_16_call_targets_equivalent_8616(
            project,
            summary.target_addr,
            expected_target,
        )
    if not target_matches or not summary_matches:
        return None, CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT
    return (
        StorageUseEvidence8616(
            block_addr=site.block.addr,
            instr_index=site.instr_index,
            instr_addr=summary.callsite_addr,
            callsite_addr=summary.callsite_addr,
        ),
        None,
    )


@cython.ccall
def physical_call_argument_8616(
    summary: CallsiteSummary8616,
    logical_index: cython.longlong,
) -> tuple[
    PhysicalCallArgument8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Map one source-order argument to all of its exact physical pushes."""
    groups: object
    projected_widths: object
    source_order_pieces: object
    physical_count = summary.arg_count
    if not isinstance(physical_count, int) or physical_count <= 0:
        return None, CallArgumentDefinitionFailure8616.INVALID_ARGUMENT_INDEX
    physical_widths: object = summary.arg_widths
    logical_widths: object = summary.logical_arg_widths
    if not logical_widths:
        projected_widths = logical_argument_widths_from_callsite_8616(
            summary,
            expected_arg_count=physical_count,
        )
        if projected_widths is None:
            return None, CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT
        logical_widths = projected_widths
    if logical_index < 0 or logical_index >= len(logical_widths):
        return None, CallArgumentDefinitionFailure8616.INVALID_ARGUMENT_INDEX
    if _incomplete_widths_8616(
        summary, physical_widths, logical_widths, physical_count,
    ):
        return None, CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT
    source_order_pieces = _source_order_pieces_8616(summary, physical_widths)
    if source_order_pieces is None:
        return None, CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT
    groups = _grouped_arguments_8616(logical_widths, source_order_pieces)
    if groups is None:
        return None, CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT
    return groups[logical_index], None


def _incomplete_widths_8616(
    summary: CallsiteSummary8616,
    physical_widths: object,
    logical_widths: object,
    physical_count: cython.longlong,
) -> cython.bint:
    """Return whether the pushed widths/addr census is incomplete or unequal."""
    return bool(
        operator.ne(len(physical_widths), physical_count)
        or operator.ne(len(summary.push_arg_instruction_addrs), physical_count)
        or operator.ne(len(summary.push_arg_sources), physical_count)
        or any(width <= 0 for width in iter(physical_widths))
        or any(width <= 0 for width in iter(logical_widths))
        or operator.ne(sum(physical_widths), sum(logical_widths))
    )


@cython.ccall
def _source_order_pieces_8616(
    summary: CallsiteSummary8616,
    physical_widths: object,
) -> object:
    """Build source-order pieces or refuse incomplete push-site evidence."""
    push_addr: object
    source: object
    width: object
    source_order_pieces: list[PhysicalCallArgumentPiece8616] = []
    for width, source, push_addr in reversed(
        tuple(
            zip(
                physical_widths,
                summary.push_arg_sources,
                summary.push_arg_instruction_addrs,
                strict=True,
            )
        )
    ):
        if not isinstance(source, tuple) or not isinstance(push_addr, int):
            return None
        source_order_pieces.append(
            PhysicalCallArgumentPiece8616(
                width=width,
                source=source,
                push_addr=push_addr,
            )
        )
    return source_order_pieces


@cython.ccall
def _grouped_arguments_8616(
    logical_widths: object,
    source_order_pieces: object,
) -> object:
    """Group source-order pieces into logical-width arguments."""
    logical_width: object
    groups: list[PhysicalCallArgument8616] = []
    piece_index = 0
    for logical_width in logical_widths:
        pieces: list[PhysicalCallArgumentPiece8616] = []
        grouped_width = 0
        while piece_index < len(source_order_pieces) and grouped_width < logical_width:
            piece = source_order_pieces[piece_index]
            pieces.append(piece)
            grouped_width += piece.width
            piece_index += 1
        if grouped_width != logical_width:
            return None
        groups.append(PhysicalCallArgument8616(width=logical_width, pieces=tuple(pieces)))
    if operator.ne(piece_index, len(source_order_pieces)):
        return None
    return groups


def resolve_call_argument_reaching_definition_8616(
    function_ssa: SSAFunctionArtifact,
    summary: CallsiteSummary8616,
    logical_index: cython.longlong,
    *,
    project: object | None = None,
    expected_target_addr: int | None = None,
    callsite_index: DecodedDirectCallsiteIndex8616 | None = None,
    projection: CallSemanticProjection8616 | None = None,
) -> CallArgumentDefinitionResolution8616:
    """Resolve one source-order call argument without inventing missing proof."""
    call_failure: object
    definitions: object
    fact: object
    logical_failure: object
    physical_failure: object
    piece_affine: object
    source_failure: object
    use: object
    piece: object
    sites = _sites_8616(function_ssa)
    use, call_failure = _call_use_8616(
        sites,
        summary,
        function_ssa=function_ssa,
        project=project,
        expected_target_addr=expected_target_addr,
        callsite_index=callsite_index,
        projection=projection,
    )
    if call_failure is not None or use is None:
        failure = call_failure or CallArgumentDefinitionFailure8616.CALLSITE_NOT_FOUND
        return _refusal_8616(
            failure,
            normalized=False,
            conflict=failure
            in {
                CallArgumentDefinitionFailure8616.CALLSITE_CONFLICT,
                CallArgumentDefinitionFailure8616.CALL_TARGET_CONFLICT,
            },
        )
    fact, physical_failure = physical_call_argument_8616(summary, logical_index)
    if physical_failure is not None or fact is None:
        return _refusal_8616(
            physical_failure or CallArgumentDefinitionFailure8616.INCOMPLETE_PHYSICAL_ARGUMENT,
            normalized=False,
        )
    resolved_definitions: list[StorageReachingDefinition8616] = []
    affine_expression: ScalarAffineExpression8616 | None = None
    single_piece = len(fact.pieces) == 1
    for piece in fact.pieces:
        source_kind = piece.source[0] if piece.source else None
        piece_affine = None
        if source_kind in {
            CallsitePushSourceKind8616.EXPR,
            CallsitePushSourceKind8616.EXPR.value,
        } or (
            single_piece
            and source_kind
            in {
                CallsitePushSourceKind8616.IMMEDIATE,
                CallsitePushSourceKind8616.IMMEDIATE.value,
            }
        ):
            definitions, piece_affine, source_failure = (
                resolve_expression_argument_definitions_8616(
                    function_ssa,
                    sites,
                    piece,
                )
            )
        elif source_kind in {
            CallsitePushSourceKind8616.IMMEDIATE,
            CallsitePushSourceKind8616.IMMEDIATE.value,
            CallsitePushSourceKind8616.BP_ADDRESS,
            CallsitePushSourceKind8616.BP_ADDRESS.value,
        }:
            definitions, source_failure = resolve_physical_store_definitions_8616(
                sites,
                piece,
            )
        else:
            definitions, source_failure = resolve_argument_source_definitions_8616(
                sites,
                piece,
            )
        if source_failure is not None or definitions is None:
            failure = source_failure or CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
            return _refusal_8616(
                failure,
                normalized=True,
                conflict=failure
                in {
                    CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT,
                    CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT,
                    CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT,
                    CallArgumentDefinitionFailure8616.EXPRESSION_DEFINITION_CONFLICT,
                    CallArgumentDefinitionFailure8616.EXPRESSION_SOURCE_MISMATCH,
                },
            )
        logical_failure = logical_source_definitions_failure_8616(
            function_ssa.logical_memory,
            function_ssa.function_addr,
            piece,
            definitions,
        )
        if logical_failure is not None:
            return _refusal_8616(
                logical_failure,
                normalized=True,
                conflict=logical_failure
                is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT,
            )
        resolved_definitions.extend(definitions)
        if single_piece and piece_affine is not None:
            affine_expression = piece_affine
    definitions = tuple(resolved_definitions)
    if operator.ne(sum(reaching_definition_width_8616(definition) for definition in iter(definitions)), fact.width):
        return _refusal_8616(
            CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT,
            normalized=True,
            conflict=True,
        )
    return CallArgumentDefinitionResolution8616(
        verdict=CallArgumentDefinitionVerdict8616.PROVEN,
        definitions=definitions,
        use=use,
        failure=None,
        stats=CallArgumentDefinitionStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        ),
        affine_expression=affine_expression,
    )
