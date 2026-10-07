"""Transport proven condition-load provenance across structured C-AST rebuilds.

Layer: Structuring.
Responsibility: binds structured condition owners to exact ``ConditionIR`` facts
and preserves operand-owned memory-access instruction addresses.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
Do not infer producers, recover aliases or types, relax segmented-memory policy,
or inspect rendered C here.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CWhileLoop,
)

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.widening.segmented_load_identity import segmented_load_identity_8616

from .condition_lowering import attach_condition_segment_access_provenance_8616

_SOURCE_INSTRUCTION_ADDRS_TAG_8616 = "inertia_source_instruction_addrs"
_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StructuredConditionProvenanceStats8616:
    """Evidence census for exact structured-condition provenance transport."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    updated_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether any typed segment helper gained provenance."""
        return self.updated_count > 0


def _condition_expressions_8616(root: object) -> Iterator[CExpression]:
    """Yield expressions owned by structured branch and loop nodes."""
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            if isinstance(node.condition, CExpression):
                yield node.condition
            continue
        if isinstance(node, CIfElse):
            for condition, _body in tuple(node.condition_and_nodes):
                if isinstance(condition, CExpression):
                    yield condition


def _direct_condition_key_8616(expression: CExpression) -> tuple[int, int] | None:
    """Return provenance owned directly by one structured condition expression."""
    boundary = cast(Any, expression)  # tags are an angr C-AST boundary
    tags = boundary.tags
    if not isinstance(tags, dict):
        return None
    src_insn = tags.get("ins_addr")
    block_addr = tags.get("vex_block_addr")
    if not isinstance(src_insn, int) or not isinstance(block_addr, int):
        return None
    return src_insn, block_addr


def _typed_segment_helpers_8616(expression: object) -> tuple[CFunctionCall, ...]:
    """Return typed segmented-load helpers nested in one condition."""
    helpers: list[CFunctionCall] = []
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, CFunctionCall):
            continue
        if segmented_load_identity_8616(node) is not None:
            helpers.append(node)
    return tuple(helpers)


def _helper_source_addrs_8616(helper: CFunctionCall) -> tuple[int, ...]:
    """Return exact memory-access instructions already owned by one helper."""
    boundary = cast(Any, helper)  # tags are an angr C-AST boundary
    tags = boundary.tags
    if not isinstance(tags, dict):
        return ()
    source_addrs = tags.get(_SOURCE_INSTRUCTION_ADDRS_TAG_8616, ())
    if not isinstance(source_addrs, tuple):
        return ()
    return tuple(addr for addr in source_addrs if isinstance(addr, int))


def _dynamic_node_tag_keys_8616(node: object) -> tuple[str, ...]:
    """Return tag keys from the dynamic third-party angr C-AST boundary."""
    boundary = cast(Any, node)
    try:
        tags = boundary.tags
    except AttributeError:
        return ()
    if not isinstance(tags, dict):
        return ()
    return tuple(sorted(key for key in tags if isinstance(key, str)))


def structured_loop_segment_provenance_surface_8616(
    root: object,
) -> tuple[tuple[object, ...], ...]:
    """Describe typed segmented helpers owned by structured loop fields."""
    surface: list[tuple[object, ...]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            continue
        fields = (
            ("initializer", node.initializer),
            ("condition", node.condition),
            ("iterator", node.iterator),
        ) if isinstance(node, CForLoop) else (("condition", node.condition),)
        for field_name, expression in fields:
            boundary = cast(Any, expression)  # tags are an angr C-AST boundary
            try:
                tags = boundary.tags
            except AttributeError:
                tags = {}
            owner_insn = tags.get("ins_addr") if isinstance(tags, dict) else None
            for helper in _typed_segment_helpers_8616(expression):
                helper_boundary = cast(Any, helper)
                helper_tags = helper_boundary.tags
                source_addrs = (
                    helper_tags.get(_SOURCE_INSTRUCTION_ADDRS_TAG_8616, ())
                    if isinstance(helper_tags, dict)
                    else ()
                )
                surface.append(
                    (
                        type(node).__name__,
                        field_name,
                        owner_insn,
                        segmented_load_identity_8616(helper),
                        source_addrs,
                    )
                )
    return tuple(surface)


def transport_structured_condition_segment_provenance_8616(
    root: object,
    conditions: Iterable[ConditionIR],
) -> StructuredConditionProvenanceStats8616:
    """Carry exact operand access evidence onto structured load helpers.

    Binding requires a unique match to the condition expression's own
    instruction and block tags. CMP/JCC addresses and body ownership are not
    substitutes for the memory access attached to an operand or helper.
    """
    facts_by_key: dict[tuple[int, int], list[ConditionIR]] = {}
    for condition in conditions:
        if isinstance(condition.src_insn, int) and isinstance(condition.block_addr, int):
            facts_by_key.setdefault((condition.src_insn, condition.block_addr), []).append(condition)

    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0
    updated_count = 0
    for expression in _condition_expressions_8616(root):
        helpers = _typed_segment_helpers_8616(expression)
        if os.environ.get("INERTIA_DEBUG_CONDITION_PROVENANCE") == "1":
            _LOG.warning(
                "[condition-provenance] key=%r nodes=%r",
                _direct_condition_key_8616(expression),
                tuple(
                    (
                        type(node).__name__,
                        segmented_load_identity_8616(node),
                        _dynamic_node_tag_keys_8616(node),
                    )
                    for node in _iter_c_nodes_deep_8616(expression)
                ),
            )
        if not helpers:
            continue
        key = _direct_condition_key_8616(expression)
        candidates = facts_by_key.get(key, ()) if key is not None else ()
        if not candidates:
            continue
        raw_count += len(helpers)
        normalized_count += len(helpers)
        if len(candidates) != 1:
            failure_count += len(helpers)
            continue

        condition = candidates[0]
        sources_before = tuple(_helper_source_addrs_8616(helper) for helper in helpers)
        attach_condition_segment_access_provenance_8616(
            expression,
            condition,
        )
        sources_after = tuple(_helper_source_addrs_8616(helper) for helper in helpers)
        proven_after = sum(bool(source_addrs) for source_addrs in sources_after)
        classified_count += proven_after
        materialized_count += proven_after
        failure_count += len(helpers) - proven_after
        updated_count += sum(
            before != after
            for before, after in zip(sources_before, sources_after, strict=True)
        )

    if classified_count > 0 and materialized_count == 0:
        raise PipelineHardError(
            "structured condition provenance was classified but not materialized"
        )
    return StructuredConditionProvenanceStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        updated_count=updated_count,
    )


def replay_codegen_structured_condition_segment_provenance_8616(
    codegen: object,
) -> StructuredConditionProvenanceStats8616:
    """Replay exact condition-load provenance on the current angr C AST.

    Late structuring, DCE, and codegen regeneration may replace C nodes after
    the initial transport. Call this immediately before a segment/global
    lowering replay so its ambiguity policy receives operand-owned instruction
    evidence rather than borrowing CMP or JCC addresses.
    """
    boundary = cast(Any, codegen)  # metadata and cfunc are an angr plugin boundary
    try:
        root = boundary.cfunc.statements
        conditions = tuple(
            condition
            for condition in boundary._inertia_typed_conditions
            if isinstance(condition, ConditionIR)
        )
    except (AttributeError, TypeError):
        conditions = ()
        root = None
    replay_key = (id(root), len(conditions))
    # Dynamic angr codegen metadata boundary: replay cache fields are optional.
    if getattr(boundary, "_inertia_structured_condition_provenance_replay_key_8616", None) == replay_key:
        # Dynamic angr codegen metadata boundary: cached stats are optional.
        cached = getattr(boundary, "_inertia_structured_condition_provenance_stats_8616", None)
        if isinstance(cached, StructuredConditionProvenanceStats8616):
            return cached
    stats = transport_structured_condition_segment_provenance_8616(root, conditions)
    boundary._inertia_structured_condition_provenance_stats_8616 = stats
    boundary._inertia_structured_condition_provenance_replay_key_8616 = replay_key
    return stats
