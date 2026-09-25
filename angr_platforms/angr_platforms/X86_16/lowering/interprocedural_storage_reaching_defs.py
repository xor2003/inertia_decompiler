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

from ..call_target_identity import x86_16_call_targets_equivalent_8616
from ..callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
    logical_argument_widths_from_callsite_8616,
)
from ..ir import IRValue, ScalarAffineExpression8616
from ..ir.ssa_function import SSAFunctionArtifact
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

__all__ = [
    "CallArgumentDefinitionFailure8616",
    "CallArgumentDefinitionResolution8616",
    "CallArgumentDefinitionStats8616",
    "CallArgumentDefinitionVerdict8616",
    "physical_call_argument_8616",
    "resolve_call_argument_reaching_definition_8616",
]


def _refusal_8616(
    failure: CallArgumentDefinitionFailure8616,
    *,
    normalized: bool,
    conflict: bool = False,
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
        for block in sorted(function_ssa.blocks, key=lambda item: item.addr)
        for instr_index, instr in enumerate(block.instrs)
    )


def _call_use_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    summary: CallsiteSummary8616,
    *,
    project: object | None,
    expected_target_addr: int | None,
) -> tuple[
    StorageUseEvidence8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Find one exact SSA CALL and verify its constant internal target."""
    calls = tuple(site for site in sites if site.instr.op == "CALL" and site.instr.addr == summary.callsite_addr)
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
    if project is None:
        target_matches = target.const == expected_target
        summary_matches = summary.target_addr in {None, expected_target}
    else:
        target_matches = x86_16_call_targets_equivalent_8616(
            project,
            target.const,
            expected_target,
        )
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


def physical_call_argument_8616(
    summary: CallsiteSummary8616,
    logical_index: int,
) -> tuple[
    PhysicalCallArgument8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Map one source-order argument to all of its exact physical pushes."""
    physical_count = summary.arg_count
    if not isinstance(physical_count, int) or physical_count <= 0:
        return None, CallArgumentDefinitionFailure8616.INVALID_ARGUMENT_INDEX
    physical_widths: tuple[int, ...] = summary.arg_widths
    logical_widths: tuple[int, ...] = summary.logical_arg_widths
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
    physical_widths: tuple[int, ...],
    logical_widths: tuple[int, ...],
    physical_count: int,
) -> bool:
    """Return whether the pushed widths/addr census is incomplete or unequal."""
    return bool(
        len(physical_widths) != physical_count
        or len(summary.push_arg_instruction_addrs) != physical_count
        or len(summary.push_arg_sources) != physical_count
        or any(width <= 0 for width in physical_widths)
        or any(width <= 0 for width in logical_widths)
        or sum(physical_widths) != sum(logical_widths)
    )


def _source_order_pieces_8616(
    summary: CallsiteSummary8616,
    physical_widths: tuple[int, ...],
) -> list[PhysicalCallArgumentPiece8616] | None:
    """Build source-order pieces or refuse incomplete push-site evidence."""
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


def _grouped_arguments_8616(
    logical_widths: tuple[int, ...],
    source_order_pieces: list[PhysicalCallArgumentPiece8616],
) -> list[PhysicalCallArgument8616] | None:
    """Group source-order pieces into logical-width arguments."""
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
    if piece_index != len(source_order_pieces):
        return None
    return groups


def resolve_call_argument_reaching_definition_8616(
    function_ssa: SSAFunctionArtifact,
    summary: CallsiteSummary8616,
    logical_index: int,
    *,
    project: object | None = None,
    expected_target_addr: int | None = None,
) -> CallArgumentDefinitionResolution8616:
    """Resolve one source-order call argument without inventing missing proof."""
    sites = _sites_8616(function_ssa)
    use, call_failure = _call_use_8616(
        sites,
        summary,
        project=project,
        expected_target_addr=expected_target_addr,
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
    if sum(reaching_definition_width_8616(definition) for definition in definitions) != fact.width:
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
