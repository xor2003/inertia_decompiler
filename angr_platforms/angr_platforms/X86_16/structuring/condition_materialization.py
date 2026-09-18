"""Structuring-owned condition materialization boundary.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

Condition semantics belong before rewrite.  This module is the migration
surface for applying already-proven ``ConditionIR`` facts while the historical
AST consumers still live in ``decompiler_postprocess_*`` compatibility modules.

Allowed work here:
- consume ``ConditionIR`` facts already transferred to codegen;
- orient a structured branch only from target-bearing ``ConditionIR`` and
  exclusive CFG ownership of its body;
- call legacy consumers only as a temporary implementation detail;
- record structured per-consumer materialization status for validation/debugging.

Do not add fresh instruction decoding, operand recovery, condition inference,
or text-based repair here. Branch orientation must consume explicit
``taken_target``/``fallthrough_target`` facts and refuse non-exclusive CFG
ownership. Those facts must be produced by lift/IR, alias/lowering, or
structuring analysis before this materialization boundary. When the legacy
consumers are migrated, keep this API and replace the delegates.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CContinue,
    CDirtyExpression,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfElse,
    CLabel,
    CReturn,
    CStatement,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimStackVariable

from .. import decompiler_postprocess_jcc as _legacy_jcc
from .. import decompiler_postprocess_typed_conditions as _legacy_typed_conditions
from ..alias.condition_register_bindings import condition_operand_storage_binding_8616
from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..callsite_summary import callsite_machine_frame_kind_8616
from ..condition_call_effects import classify_condition_call_effects_8616
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from ..ir.function_ssa_registry import registered_function_ssa_artifact_8616
from ..lowering.call_execution_frame_carriers import (
    CallExecutionFrameCarrierStats8616,
    prune_consumed_call_execution_frame_carriers_8616,
)
from ..lowering.call_output_stack_objects import (
    lower_call_output_stack_fields_in_condition_8616,
    lower_wide_call_return_condition_chain_8616,
    prune_materialized_call_output_stack_carriers_8616,
    prune_materialized_wide_condition_call_carrier_8616,
    select_wide_call_return_condition_chain_8616,
)
from ..lowering.condition_argument_type_facts import (
    record_wide_condition_argument_type_evidence_8616,
)
from ..lowering.condition_operand_views import materialize_condition_operand_views_8616
from ..lowering.packed_flags_liveness import PackedFlagsCycleStats8616, prune_unobserved_flag_cycles_8616
from ..lowering.scalar_return_types import record_scalar_return_type_evidence_8616
from ..lowering.wide_call_condition_capture import (
    build_proven_wide_call_condition_8616,
    commit_wide_call_condition_captures_8616,
)
from ..lowering.wide_stack_pair_evidence import proven_wide_stack_ir_pair_8616
from ..pipeline.errors import PipelineHardError
from ..postprocess import flags_cleanup as _flags_cleanup
from ..structured_tags import copy_structured_tags_8616
from ..validation_condition_precision import record_condition_precision_evidence_8616
from .branch_return_expressions import (
    binary_return_arm_polarity_8616,
    recover_branch_target_return_expression_8616,
    sole_return_expression_8616,
    sole_return_statement_8616,
)
from .composite_pretest_conditions import CompositePretestStats8616, materialize_composite_pretest_conditions_8616
from .condition_binding import select_unique_condition_by_expression_8616
from .condition_chain_provenance import bind_condition_chain_provenance_8616
from .condition_evidence_closure import (
    ConditionEvidenceClosure8616,
    classify_condition_evidence_closure_8616,
)
from .condition_exit_normalization import (
    conditional_goto_polarity_8616,
    exact_condition_exit_polarity_8616,
    transparent_condition_exit_8616,
)
from .condition_lowering import (
    SameBlockRegisterAssignmentIndex8616,
    build_same_block_register_assignment_index_8616,
    condition_op_to_structured_kind_8616,
    condition_origin_tags_8616,
    lower_ir_value_to_c_expr_8616,
    materialize_same_block_register_projection_8616,
)
from .condition_ownership import select_composite_preheader_root_8616
from .condition_ownership import structured_node_owns_condition_fact_8616 as _structured_node_owns_condition_fact_8616
from .condition_provenance import (
    StructuredConditionProvenanceStats8616,
    replay_codegen_structured_condition_segment_provenance_8616,
    structured_loop_segment_provenance_surface_8616,
)
from .condition_replay import (
    bind_condition_replay_identity_8616,
    condition_replay_facts_8616,
    record_condition_replay_fact_8616,
    select_condition_replay_fact_8616,
)
from .existing_loop_exit_conditions import ExistingLoopExitStats8616, materialize_existing_loop_exit_conditions_8616
from .local_condition_regions import local_condition_continuations_8616, prove_local_condition_region_8616
from .local_wide_stack_condition_chains import (
    recover_local_wide_stack_condition_chain_8616,
)
from .loop_break_topology import collect_loop_break_topology_8616
from .loop_condition_materialization import (
    LoopConditionMaterializationStats8616,
    materialize_typed_loop_continuation_conditions_8616,
)
from .multi_arm_condition_ownership import (
    first_statement_block_8616,
    materialize_multi_arm_condition_owners_8616,
    select_exact_multi_arm_condition_owners_8616,
    select_multi_arm_condition_owners_8616,
)
from .multi_arm_return_chains import (
    MultiArmReturnChainStatus8616,
    is_materialized_multi_arm_return_chain_8616,
    recover_structured_multi_arm_wide_return_chain_8616,
)
from .scalar_return_evidence import materialize_complete_scalar_return_leaves_8616
from .single_branch_return_orientation import (
    classify_cfg_binary_arm_orientation_8616,
    classify_direct_or_one_hop_target_orientation_8616,
    classify_single_branch_return_orientation_8616,
)
from .tagged_subtree_projection import (
    StructuredSubtreeEntryTagQuerySession8616,
    StructuredSubtreeEntryTagQueryStats8616,
    collect_structured_subtree_entry_tags_8616,
)
from .terminal_loop_exit_conditions import materialize_terminal_loop_exit_conditions_8616
from .total_return_suffixes import (
    TotalReturnSuffixPruneStats8616,
    prune_unreachable_total_return_suffixes_8616,
)
from .wide_call_condition_plan import plan_wide_call_condition_8616
from .wide_call_return_guard_chains import (
    WideCallReturnGuardCollapseStats8616,
    WideCallReturnGuardCollapseStatus8616,
    collapse_wide_call_return_guard_chain_8616,
)
from .wide_stack_condition_chains import recover_wide_stack_condition_chain_8616
from .wide_stack_return_predicates import (
    wide_stack_return_predicate_materialized_8616,
)
from .wide_stack_single_branches import recover_wide_stack_single_body_condition_8616

log: logging.Logger = logging.getLogger(__name__)


def materialize_condition_ir_expression_8616(
    project: object,
    codegen: object,
    condition: ConditionIR,
    *,
    assignment_index: SameBlockRegisterAssignmentIndex8616 | None = None,
) -> CExpression | None:
    """Lower one proven ConditionIR through the Structuring-owned boundary.

    The historical expression builder remains a compatibility implementation
    detail while its register-expression lookup moves into Structuring. Callers
    must provide the exact typed condition selected from CFG ownership; this
    function performs no condition discovery or instruction decoding.
    """
    bound_condition = replace(
        condition,
        lhs=condition_operand_storage_binding_8616(condition, condition.lhs),
        rhs=condition_operand_storage_binding_8616(condition, condition.rhs),
    )
    projection_stats = []
    projected_operands: dict[int, CExpression] = {}
    for value in (bound_condition.lhs, bound_condition.rhs):
        if isinstance(value, IRValue):
            projection = materialize_same_block_register_projection_8616(
                value, bound_condition, project, codegen, assignment_index=assignment_index,
            )
            projection_stats.append(projection.stats)
            if isinstance(projection.expression, CExpression):
                projected_operands[id(value)] = projection.expression

    def build_operand(value: object) -> object | None:
        """Use a proven view before attempting the general register binding."""
        projected = projected_operands.get(id(value))
        if projected is not None:
            return cast(object, projected)
        expression: object | None = _legacy_typed_conditions._build_c_expr_for_operand(
            project, value, codegen, bound_condition,
        )
        return expression

    expression = (
        _legacy_typed_conditions._build_c_condition_expr(
            project, bound_condition, codegen, operand_builder=build_operand,
        )
        if projected_operands
        else _legacy_typed_conditions._build_c_condition_expr(project, bound_condition, codegen)
    )
    if isinstance(expression, CExpression):
        expression = materialize_condition_operand_views_8616(expression, condition)
    if isinstance(expression, CExpression):
        bind_condition_replay_identity_8616(expression, condition)
    if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") == "1":
        _debug_condition_chain_8616(
            "lowered-expression",
            condition=condition,
            expression_tree=_condition_debug_tree_8616(expression),
            register_projection_stats=tuple(projection_stats),
        )
    return expression if isinstance(expression, CExpression) else None


def _debug_condition_chain_8616(event: str, **fields: object) -> None:
    """Log one structuring condition-chain decision when diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") != "1":
        return
    details = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
    log.warning("[condition-materialization] event=%s %s", event, details)


class _ConditionMaterializationCodegen8616(Protocol):
    """Dynamic codegen metadata slots written by structuring condition materialization."""

    _inertia_structuring_condition_materialization_8616: dict[str, object]
    _inertia_structuring_condition_materialization_result_8616: StructuringConditionMaterializationResult8616
    _inertia_structuring_condition_replay_cleanup_8616: dict[str, object]
    _inertia_structuring_dead_flag_cleanup_8616: dict[str, object]
    _inertia_packed_flags_cycle_stats_8616: PackedFlagsCycleStats8616
    _inertia_condition_materialization_structuring_pass_ran_8616: bool
    _inertia_structuring_condition_chain_stats_8616: StructuringConditionChainStats8616
    _inertia_structuring_condition_evidence_closure_8616: ConditionEvidenceClosure8616
    _inertia_typed_loop_condition_stats_8616: LoopConditionMaterializationStats8616
    _inertia_composite_pretest_condition_stats_8616: CompositePretestStats8616
    _inertia_existing_loop_exit_condition_stats_8616: ExistingLoopExitStats8616
    _inertia_terminal_loop_exit_condition_stats_8616: ExistingLoopExitStats8616
    _inertia_structured_condition_provenance_stats_8616: StructuredConditionProvenanceStats8616
    _inertia_same_block_condition_register_projection_stats_8616: SameBlockConditionRegisterProjectionStats8616
    _inertia_multi_arm_return_chain_materialized_8616: bool
    _inertia_multi_arm_return_expressions_8616: tuple[CExpression, ...]
    _inertia_return_expr_chain_materialized_8616: bool
    _inertia_total_return_suffix_prune_stats_8616: TotalReturnSuffixPruneStats8616
    _inertia_wide_call_return_guard_collapse_stats_8616: WideCallReturnGuardCollapseStats8616
    _inertia_call_execution_frame_carrier_stats_8616: CallExecutionFrameCarrierStats8616
    _inertia_structured_subtree_entry_tag_query_stats_8616: StructuredSubtreeEntryTagQueryStats8616
    _inertia_typed_conditions: object
    cfunc: object


class _ConditionMaterializationProject8616(Protocol):
    """Project diagnostics written while condition consumers run."""

    _inertia_decompiler_stage: str
    kb: object


class _ConditionMaterializationCFunction8616(Protocol):
    """Dynamic angr CFunction fields consumed at the structuring boundary."""

    addr: int
    statements: object


class _ConditionMaterializationKnowledgeBase8616(Protocol):
    """Dynamic angr knowledge-base fields consumed at the structuring boundary."""

    functions: object


class _ConditionMaterializationFunctionManager8616(Protocol):
    """Dynamic angr function lookup used by structuring condition chains."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Return one function without creating it."""


class _ConditionMaterializationFunction8616(Protocol):
    """Dynamic angr Function fields consumed by CFG condition materialization."""

    transition_graph: object
    block_addrs_set: set[int]


@dataclass(frozen=True, slots=True)
class SameBlockConditionRegisterProjectionStats8616:
    """Account for exact same-block subregister projections in conditions."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0


class _ConditionMaterializationGraph8616(Protocol):
    """Minimal networkx-compatible graph contract used by structuring."""

    nodes: object

    def successors(self, node: object) -> object:
        """Return graph successors for one node."""


class _ConditionMaterializationGraphNode8616(Protocol):
    """Dynamic angr CFG node address."""

    addr: int


class _ConditionMaterializationTaggedNode8616(Protocol):
    """Dynamic angr C-AST tag dictionary."""

    tags: dict[str, object]


class _StructuredSubtreeEntryTagsBoundary8616(Protocol):
    """Typed boundary for immutable subtree-entry tag projections."""

    first_instruction_addr: int | None
    block_addrs: tuple[int, ...]
    first_block_addr: int | None


@dataclass(frozen=True, slots=True)
class StructuringConditionChainStats8616:
    """Evidence accounting for CFG-proven short-circuit condition chains."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    preserved_side_effect_count: int = 0


@dataclass(frozen=True, slots=True)
class StructuringConditionMaterializationResult8616:
    """Structured result for condition materialization during structuring."""

    typed_conditions_changed: bool
    condition_chains_changed: bool
    decoded_jcc_changed: bool
    loop_conditions_changed: bool
    segment_access_provenance_changed: bool
    condition_evidence_complete: bool = True

    @property
    def changed(self) -> bool:
        """Return True when any delegated materializer changed the AST."""
        return (
            self.typed_conditions_changed
            or self.condition_chains_changed
            or self.decoded_jcc_changed
            or self.loop_conditions_changed
            or self.segment_access_provenance_changed
        )


@dataclass(frozen=True, slots=True)
class StructuringConditionReplayCleanupResult8616:
    """Structured result for late condition replay cleanup."""

    materialization: StructuringConditionMaterializationResult8616
    flag_condition_pairs_changed: bool
    flag_bit_values_changed: bool
    interval_guards_changed: bool
    unused_flag_assignments_pruned: bool
    overwritten_flag_assignments_pruned: bool

    @property
    def changed(self) -> bool:
        """Return True when materialization or cleanup changed the AST."""
        return (
            self.materialization.changed
            or self.flag_condition_pairs_changed
            or self.flag_bit_values_changed
            or self.interval_guards_changed
            or self.unused_flag_assignments_pruned
            or self.overwritten_flag_assignments_pruned
        )


@dataclass(frozen=True, slots=True)
class StructuringDeadFlagCleanupResult8616:
    """Typed result for final proven-dead flag-assignment cleanup."""

    overwritten_flag_assignments_pruned: bool
    unused_flag_assignments_pruned: bool

    @property
    def changed(self) -> bool:
        """Return whether the final Structuring cleanup changed the AST."""
        return self.overwritten_flag_assignments_pruned or self.unused_flag_assignments_pruned


@dataclass(frozen=True, slots=True)
class _AssignmentDiamond8616:
    """One CFG-proven conditional assignment diamond ready for structuring."""

    condition: CExpression
    true_assignment: CAssignment
    false_assignment: CAssignment
    true_target: int
    false_target: int


def _cfg_node_addr_8616(node: object) -> int | None:
    """Return one address from a dynamic angr CFG node."""
    if isinstance(node, int):
        return node
    boundary = cast(_ConditionMaterializationGraphNode8616, node)
    try:
        return boundary.addr if isinstance(boundary.addr, int) else None
    except AttributeError:
        return None


def condition_chain_successors_8616(project: object, codegen: object) -> dict[int, tuple[int, ...]]:
    """Return in-function CFG successors keyed by block address."""
    try:
        cfunc = cast(_ConditionMaterializationCFunction8616, cast(_ConditionMaterializationCodegen8616, codegen).cfunc)
        function_manager = cast(
            _ConditionMaterializationFunctionManager8616,
            cast(
                _ConditionMaterializationKnowledgeBase8616,
                cast(_ConditionMaterializationProject8616, project).kb,
            ).functions,
        )
        function = cast(_ConditionMaterializationFunction8616, function_manager.function(addr=cfunc.addr, create=False))
        graph = cast(_ConditionMaterializationGraph8616, function.transition_graph)
        block_addrs = set(function.block_addrs_set)
    except (AttributeError, TypeError):
        return {}
    successors: dict[int, tuple[int, ...]] = {}
    try:
        nodes = tuple(cast(Any, graph.nodes))
    except (AttributeError, TypeError):
        return {}
    for node in nodes:
        addr = _cfg_node_addr_8616(node)
        if addr not in block_addrs:
            continue
        try:
            target_addrs = tuple(
                target_addr
                for successor in cast(Any, graph.successors(node))
                if (target_addr := _cfg_node_addr_8616(successor)) in block_addrs
            )
        except (AttributeError, TypeError):
            continue
        successors[addr] = tuple(dict.fromkeys(target_addrs))
    return successors


def _first_tagged_ins_addr_8616(node: object) -> int | None:
    """Return the first binary instruction tag in one structured C subtree."""
    return cast(
        _StructuredSubtreeEntryTagsBoundary8616,
        collect_structured_subtree_entry_tags_8616(node),
    ).first_instruction_addr


def _tagged_block_addrs_8616(
    node: object,
    session: StructuredSubtreeEntryTagQuerySession8616 | None = None,
) -> tuple[int, ...]:
    """Return every VEX block tag in one structured C subtree."""
    if session is not None:
        return cast(_StructuredSubtreeEntryTagsBoundary8616, session.current(node)).block_addrs
    return cast(
        _StructuredSubtreeEntryTagsBoundary8616,
        collect_structured_subtree_entry_tags_8616(node),
    ).block_addrs


def _first_tagged_block_addr_8616(node: object) -> int | None:
    """Return the first VEX block tag in one structured C subtree."""
    return cast(
        _StructuredSubtreeEntryTagsBoundary8616,
        collect_structured_subtree_entry_tags_8616(node),
    ).first_block_addr


def _first_tagged_cfg_target_8616(node: object) -> int | None:
    """Return the first executed statement's exact CFG block identity.

    A subtree's lowest address may belong to a later statement or an operand
    definition. Neither proves its entry, especially for backward dispatch.
    Keep subtree tag inventories for membership queries, not execution order.
    """
    # A tagged arm container retains its entry even after its body is folded
    # into a return. Do not replace that explicit identity with a child tag.
    block = _copied_condition_tags_8616(node).get("vex_block_addr")
    if isinstance(block, int) and not isinstance(block, bool):
        return block
    return first_statement_block_8616(node)


def _cfg_reaches_address_8616(
    successors: dict[int, tuple[int, ...]],
    start: int,
    target: int,
    *,
    stop_at: int | None = None,
) -> bool:
    """Return whether a bounded CFG path reaches ``target`` before ``stop_at``."""
    pending = [start]
    visited: set[int] = set()
    while pending and len(visited) < 64:
        address = pending.pop()
        if address == target:
            return True
        if address == stop_at:
            continue
        if address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def condition_key_from_tags_8616(node: object) -> tuple[int, int] | None:
    """Return the first complete instruction/block tag pair in a C expression."""
    for current in _iter_c_nodes_deep_8616(node):
        boundary = cast(_ConditionMaterializationTaggedNode8616, current)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        copied_tags = copy_structured_tags_8616(tags)
        if copied_tags is None:
            continue
        ins_addr = copied_tags.get("ins_addr")
        block_addr = copied_tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            return ins_addr, block_addr
    return None


def materialize_same_block_condition_register_projections_8616(
    root: object,
    project: object,
    codegen: object,
    conditions: tuple[ConditionIR, ...],
) -> SameBlockConditionRegisterProjectionStats8616:
    """Replay exact same-block register projections into typed comparisons."""
    assignment_index = build_same_block_register_assignment_index_8616(codegen)
    conditions_by_key: dict[tuple[int, int], list[ConditionIR]] = {}
    conditions_by_block: dict[int, list[ConditionIR]] = {}
    for condition in conditions:
        if isinstance(condition.src_insn, int) and isinstance(condition.block_addr, int):
            conditions_by_key.setdefault(
                (condition.src_insn, condition.block_addr),
                [],
            ).append(condition)
            conditions_by_block.setdefault(condition.block_addr, []).append(condition)

    raw_count = normalized_count = classified_count = 0
    materialized_count = failure_count = changed_count = 0
    seen_nodes: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in seen_nodes or not isinstance(node, CBinaryOp):
            continue
        seen_nodes.add(id(node))
        if not str(node.op).startswith("Cmp"):
            continue
        tags = _copied_condition_tags_8616(node)
        key = condition_key_from_tags_8616(node)
        _debug_condition_chain_8616(
            "register-projection-candidate",
            key=key,
            op=node.op,
            typed=tags.get("typed_condition"),
        )
        if key is None:
            continue
        matching = tuple(conditions_by_key.get(key, ()))
        if not matching and key[0] == key[1]:
            matching = tuple(conditions_by_block.get(key[1], ()))
        if len(matching) != 1:
            if matching:
                raw_count += len(matching)
                failure_count += 1
            continue
        condition = matching[0]
        if node.op != condition_op_to_structured_kind_8616(condition.op):
            continue
        bound_lhs = condition_operand_storage_binding_8616(condition, condition.lhs)
        bound_rhs = condition_operand_storage_binding_8616(condition, condition.rhs)
        if bound_lhs != condition.lhs or bound_rhs != condition.rhs:
            lowered = materialize_condition_ir_expression_8616(
                project,
                codegen,
                condition,
                assignment_index=assignment_index,
            )
            raw_count += 1
            normalized_count += 1
            if not isinstance(lowered, CBinaryOp) or lowered.op != node.op:
                failure_count += 1
                continue
            classified_count += 1
            materialized_count += 1
            changed = not _same_c_expression_8616(node, lowered)
            if changed:
                node.lhs = lowered.lhs
                node.rhs = lowered.rhs
                changed_count += 1
            node.tags = {
                **tags,
                **condition_origin_tags_8616(condition),
            }
            continue
        projected = False
        for side, value in (("lhs", condition.lhs), ("rhs", condition.rhs)):
            if not isinstance(value, IRValue) or value.space is not MemSpace.REG:
                continue
            result = materialize_same_block_register_projection_8616(
                value,
                condition,
                project,
                codegen,
                assignment_index=assignment_index,
            )
            raw_count += result.stats.raw_fact_count
            normalized_count += result.stats.normalized_fact_count
            classified_count += result.stats.classified_fact_count
            materialized_count += result.stats.materialized_count
            failure_count += result.stats.failure_count
            replacement = result.expression
            current = node.lhs if side == "lhs" else node.rhs
            if not isinstance(replacement, CExpression) or _same_c_expression_8616(
                current,
                replacement,
            ):
                continue
            if side == "lhs":
                node.lhs = replacement
            else:
                node.rhs = replacement
            changed_count += 1
            projected = True
        if projected:
            node.tags = {
                **tags,
                **condition_origin_tags_8616(condition),
            }

    stats = SameBlockConditionRegisterProjectionStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        changed_count=changed_count,
    )
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    metadata_codegen._inertia_same_block_condition_register_projection_stats_8616 = stats
    _debug_condition_chain_8616("register-projection-stats", stats=stats)
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified same-block condition register projection was not materialized"
        )
    return stats


def _direct_tagged_ins_addr_8616(node: object) -> int | None:
    """Return the instruction tag owned directly by one structured node."""
    boundary = cast(_ConditionMaterializationTaggedNode8616, node)
    try:
        tags = boundary.tags
    except AttributeError:
        return None
    copied_tags = copy_structured_tags_8616(tags)
    if copied_tags is None:
        return None
    ins_addr = copied_tags.get("ins_addr")
    return ins_addr if isinstance(ins_addr, int) else None


def _copied_condition_tags_8616(node: object) -> dict[str, object]:
    """Copy C-expression tags at the dynamic angr boundary."""
    boundary = cast(_ConditionMaterializationTaggedNode8616, node)
    try:
        tags = boundary.tags
    except AttributeError:
        return {}
    return copy_structured_tags_8616(tags) or {}


def _condition_structure_token_8616(
    condition: object,
    *,
    depth: int = 0,
) -> tuple[object, ...]:
    """Return a bounded identity-sensitive token for one structured condition."""
    if depth >= 8:
        return ("depth-limit", type(condition).__name__, id(condition))
    if isinstance(condition, CUnaryOp):
        return (
            "unary",
            condition.op,
            id(condition),
            _condition_structure_token_8616(
                condition.operand,
                depth=depth + 1,
            ),
        )
    if isinstance(condition, CBinaryOp):
        return (
            "binary",
            condition.op,
            id(condition),
            _condition_structure_token_8616(
                condition.lhs,
                depth=depth + 1,
            ),
            _condition_structure_token_8616(
                condition.rhs,
                depth=depth + 1,
            ),
        )
    return (type(condition).__name__, id(condition))


def _condition_debug_tree_8616(condition: object, *, depth: int = 0) -> tuple[object, ...]:
    """Return a bounded operator tree for opt-in condition diagnostics."""
    if depth >= 8:
        return ("depth-limit",)
    if isinstance(condition, CUnaryOp):
        return (
            "unary",
            condition.op,
            _condition_debug_tree_8616(condition.operand, depth=depth + 1),
        )
    if isinstance(condition, CBinaryOp):
        return (
            "binary",
            condition.op,
            _condition_debug_tree_8616(condition.lhs, depth=depth + 1),
            _condition_debug_tree_8616(condition.rhs, depth=depth + 1),
        )
    if isinstance(condition, CVariable) and isinstance(condition.variable, SimStackVariable):
        variable = condition.variable
        return ("stack-variable", variable.base, variable.offset, variable.size, tuple(sorted(condition.tags)))
    return (type(condition).__name__,)


def structuring_condition_surface_token_8616(codegen: object) -> tuple[tuple[object, ...], ...]:
    """Describe branch ownership so later AST mutation invalidates materialization."""
    try:
        cfunc = cast(
            _ConditionMaterializationCFunction8616,
            cast(_ConditionMaterializationCodegen8616, codegen).cfunc,
        )
        statements = cfunc.statements
    except AttributeError:
        return ()
    surface: list[tuple[object, ...]] = []
    for node in _iter_c_nodes_deep_8616(statements):
        if isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            condition = node.condition
            tags = _copied_condition_tags_8616(condition)
            body_entry_tags = collect_structured_subtree_entry_tags_8616(node.body)
            surface.append(
                (
                    "loop",
                    type(node).__name__,
                    id(condition),
                    condition_key_from_tags_8616(condition),
                    _condition_structure_token_8616(condition),
                    body_entry_tags.first_block_addr,
                    body_entry_tags.first_instruction_addr,
                    tags.get("inertia_jcc_polarity_evidence_8616"),
                    tags.get(
                        "inertia_structuring_condition_cfg_materialized_8616"
                    )
                    is True,
                )
            )
            continue
        if not isinstance(node, CIfElse):
            continue
        pairs = tuple(node.condition_and_nodes)
        for condition, body in pairs:
            tags = _copied_condition_tags_8616(condition)
            body_entry_tags = collect_structured_subtree_entry_tags_8616(body)
            else_entry_tags = collect_structured_subtree_entry_tags_8616(
                node.else_node
            )
            surface.append(
                (
                    "ifelse",
                    id(condition),
                    condition_key_from_tags_8616(condition),
                    _condition_structure_token_8616(condition),
                    len(pairs),
                    node.else_node is not None,
                    body_entry_tags.first_block_addr,
                    body_entry_tags.first_instruction_addr,
                    else_entry_tags.first_block_addr,
                    else_entry_tags.first_instruction_addr,
                    tags.get("inertia_jcc_polarity_evidence_8616"),
                    tags.get("inertia_structuring_condition_cfg_materialized_8616") is True,
                )
            )
    return tuple(surface)


def invert_structured_condition_8616(condition: CExpression, codegen: object) -> CExpression:
    """Invert one materialized comparison without recovering new semantics."""
    inverted_ops = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
    }
    if isinstance(condition, CBinaryOp) and condition.op in inverted_ops:
        result = CBinaryOp(inverted_ops[condition.op], condition.lhs, condition.rhs, codegen=codegen)
    elif isinstance(condition, CUnaryOp) and condition.op == "Not":
        result = condition.operand
    else:
        result = CUnaryOp("Not", condition, codegen=codegen)
    result.tags = {**_copied_condition_tags_8616(result), **_copied_condition_tags_8616(condition)}
    return result


def _combine_condition_outcomes_8616(
    condition: CExpression,
    taken: CExpression | bool,
    fallthrough: CExpression | bool,
    codegen: object,
) -> CExpression | bool:
    """Build the predicate that reaches the selected CFG leaf."""
    if isinstance(taken, bool) and isinstance(fallthrough, bool):
        if taken == fallthrough:
            return taken
        return condition if taken else invert_structured_condition_8616(condition, codegen)
    if taken is True:
        return CBinaryOp("LogicalOr", condition, cast(CExpression, fallthrough), codegen=codegen)
    if fallthrough is True:
        return CBinaryOp(
            "LogicalOr",
            invert_structured_condition_8616(condition, codegen),
            cast(CExpression, taken),
            codegen=codegen,
        )
    if taken is False:
        return CBinaryOp(
            "LogicalAnd",
            invert_structured_condition_8616(condition, codegen),
            cast(CExpression, fallthrough),
            codegen=codegen,
        )
    if fallthrough is False:
        return CBinaryOp("LogicalAnd", condition, cast(CExpression, taken), codegen=codegen)
    return CBinaryOp(
        "LogicalOr",
        CBinaryOp("LogicalAnd", condition, cast(CExpression, taken), codegen=codegen),
        CBinaryOp(
            "LogicalAnd",
            invert_structured_condition_8616(condition, codegen),
            cast(CExpression, fallthrough),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _materialize_cfg_condition_chain_expr_8616(
    project: object,
    codegen: object,
    root_condition: ConditionIR,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    true_target: int,
    false_target: int,
    *,
    required_conditions: tuple[ConditionIR, ...] = (),
) -> CExpression | None:
    """Materialize one target-directed predicate from typed conditions and CFG."""
    metadata = cast(_ConditionMaterializationCodegen8616, codegen)
    try:
        function_addr = cast(_ConditionMaterializationCFunction8616, metadata.cfunc).addr
    except AttributeError:
        function_addr = None
    condition_ssa = None
    if isinstance(function_addr, int):
        resolution = registered_function_ssa_artifact_8616(project, function_addr)
        condition_ssa = resolution.artifact
        false_target = transparent_condition_exit_8616(
            resolution.artifact, false_target, successors, stop_at=true_target
        )
    consumed_conditions: list[ConditionIR] = []
    assignment_index = build_same_block_register_assignment_index_8616(codegen)
    call_plan = plan_wide_call_condition_8616(
        root_condition, conditions_by_block, successors, true_target, false_target,
        artifact=condition_ssa,
    )
    if call_plan is not None and all(condition in call_plan.conditions for condition in required_conditions):
        call_expression = build_proven_wide_call_condition_8616(
            codegen, call_plan.conditions, call_plan.low_stack, call_plan.operator,
        )
        if call_expression is not None:
            bind_condition_chain_provenance_8616(call_expression, call_plan.conditions)
            return call_expression

    def prove_wide_pair(high_value: IRValue, low_value: IRValue) -> bool:
        high_expression = lower_ir_value_to_c_expr_8616(high_value, project, codegen)
        low_expression = lower_ir_value_to_c_expr_8616(low_value, project, codegen)
        return bool(proven_wide_stack_ir_pair_8616(
            high_value,
            low_value,
            high_expression,
            low_expression,
        ))

    wide_result = recover_wide_stack_condition_chain_8616(
        root_condition,
        conditions_by_block,
        successors,
        true_target,
        false_target,
        prove_wide_pair,
    )
    if wide_result.condition is not None:
        wide_expression = materialize_condition_ir_expression_8616(
            project,
            codegen,
            wide_result.condition,
            assignment_index=assignment_index,
        )
        if wide_expression is not None:
            record_wide_condition_argument_type_evidence_8616(codegen, wide_result.condition)
            return wide_expression

    materialized_by_address: dict[int, CExpression | bool] = {}
    active_addresses: set[int] = set()

    def build_from_address(address: int) -> CExpression | bool | None:
        """Build one acyclic CFG suffix once and reuse its identical predicate."""
        if address == true_target:
            return True
        if address == false_target:
            return False
        cached = materialized_by_address.get(address)
        if cached is not None:
            return cached
        if address in active_addresses:
            _debug_condition_chain_8616(
                "cfg-chain-address-cycle",
                address=address,
                visited=tuple(sorted(active_addresses)),
            )
            return None
        active_addresses.add(address)
        try:
            condition = conditions_by_block.get(address)
            if condition is not None:
                result = build_from_condition(condition)
            else:
                next_addrs = successors.get(address, ())
                if len(next_addrs) != 1:
                    _debug_condition_chain_8616(
                        "cfg-chain-successor-refused",
                        address=address,
                        successors=next_addrs,
                        visited=tuple(sorted(active_addresses)),
                    )
                    return None
                result = build_from_address(next_addrs[0])
        finally:
            active_addresses.remove(address)
        if result is not None:
            materialized_by_address[address] = result
        return result

    def build_from_condition(condition: ConditionIR) -> CExpression | bool | None:
        """Materialize one typed branch after its owning address is cycle-guarded."""
        if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
            _debug_condition_chain_8616(
                "cfg-chain-target-refused",
                block_addr=condition.block_addr,
                src_insn=condition.src_insn,
                taken_target=condition.taken_target,
                fallthrough_target=condition.fallthrough_target,
            )
            return None
        local_wide = recover_local_wide_stack_condition_chain_8616(
            condition,
            conditions_by_block,
            successors,
            prove_wide_pair,
        )
        if (
            local_wide.condition is not None
            and isinstance(local_wide.true_target, int)
            and isinstance(local_wide.false_target, int)
        ):
            for consumed in local_wide.consumed_conditions:
                if consumed not in consumed_conditions:
                    consumed_conditions.append(consumed)
            materialized_wide = materialize_condition_ir_expression_8616(
                project,
                codegen,
                local_wide.condition,
                assignment_index=assignment_index,
            )
            if materialized_wide is None:
                return None
            record_wide_condition_argument_type_evidence_8616(
                codegen,
                local_wide.condition,
            )
            consumed_addrs = {
                consumed.block_addr
                for consumed in local_wide.consumed_conditions
                if isinstance(consumed.block_addr, int)
            }
            newly_active = consumed_addrs - active_addresses
            active_addresses.update(newly_active)
            try:
                taken = build_from_address(local_wide.true_target)
                fallthrough = build_from_address(local_wide.false_target)
            finally:
                active_addresses.difference_update(newly_active)
            if taken is None or fallthrough is None:
                return None
            return _combine_condition_outcomes_8616(
                materialized_wide,
                taken,
                fallthrough,
                codegen,
            )
        if condition not in consumed_conditions:
            consumed_conditions.append(condition)
        materialized = materialize_condition_ir_expression_8616(
            project,
            codegen,
            condition,
            assignment_index=assignment_index,
        )
        if materialized is None:
            _debug_condition_chain_8616(
                "cfg-chain-expression-refused",
                block_addr=condition.block_addr,
                src_insn=condition.src_insn,
            )
            return None
        taken = build_from_address(condition.taken_target)
        fallthrough = build_from_address(condition.fallthrough_target)
        if taken is None or fallthrough is None:
            _debug_condition_chain_8616(
                "cfg-chain-outcome-refused",
                block_addr=condition.block_addr,
                src_insn=condition.src_insn,
                taken_available=taken is not None,
                fallthrough_available=fallthrough is not None,
            )
            return None
        return _combine_condition_outcomes_8616(materialized, taken, fallthrough, codegen)

    root_addr = root_condition.block_addr
    root_added = isinstance(root_addr, int) and root_addr not in active_addresses
    if root_added and isinstance(root_addr, int):
        active_addresses.add(root_addr)
    try:
        result = build_from_condition(root_condition)
    finally:
        if root_added:
            active_addresses.remove(cast(int, root_addr))
    if not isinstance(result, CExpression):
        _debug_condition_chain_8616(
            "cfg-chain-result-refused",
            result_type=type(result).__name__,
            root_block=root_condition.block_addr,
            root_src=root_condition.src_insn,
        )
        return None
    if any(
        all(consumed is not required for consumed in consumed_conditions)
        for required in required_conditions
    ):
        _debug_condition_chain_8616(
            "cfg-chain-required-condition-refused",
            consumed_sources=tuple(condition.src_insn for condition in consumed_conditions),
            required_sources=tuple(condition.src_insn for condition in required_conditions),
        )
        return None
    lowering = lower_call_output_stack_fields_in_condition_8616(codegen, result, tuple(consumed_conditions))
    bind_condition_chain_provenance_8616(
        lowering.expression,
        tuple(consumed_conditions),
    )
    return lowering.expression


def _tagged_statement_block_addr_8616(node: object) -> int | None:
    """Return the exact CFG block tag attached to one structured statement."""
    boundary = cast(_ConditionMaterializationTaggedNode8616, node)
    try:
        value = boundary.tags.get("vex_block_addr")
    except AttributeError:
        return None
    return value if isinstance(value, int) else None


def _assignment_diamond_nested_conditions_8616(
    node: CIfElse,
    root_condition: ConditionIR,
    conditions_by_src: dict[int, ConditionIR],
) -> tuple[ConditionIR, ...] | None:
    """Collect every typed guard represented by one nested conditional subtree."""
    conditions: list[ConditionIR] = [root_condition]
    for current in _iter_c_nodes_deep_8616(node):
        if not isinstance(current, CIfElse) or current is node:
            continue
        source = _direct_tagged_ins_addr_8616(current)
        condition = conditions_by_src.get(source) if isinstance(source, int) else None
        if condition is None:
            return None
        if all(existing is not condition for existing in conditions):
            conditions.append(condition)
    return tuple(conditions) if len(conditions) > 1 else None


def _assignment_diamond_scaffolding_is_safe_8616(
    node: CIfElse,
    *,
    condition_blocks: frozenset[int],
    leaf_assignments: tuple[CAssignment, CAssignment],
    leaf_targets: frozenset[int],
) -> bool:
    """Refuse a malformed diamond unless discarded nodes are control-only scaffolding."""
    leaf_ids = {id(assignment) for assignment in leaf_assignments}
    for current in _iter_c_nodes_deep_8616(node):
        if isinstance(current, CFunctionCall):
            return False
        if isinstance(current, CAssignment):
            if id(current) in leaf_ids:
                continue
            block_addr = _tagged_statement_block_addr_8616(current)
            if block_addr not in condition_blocks or not isinstance(current.lhs, CDirtyExpression):
                return False
            continue
        if isinstance(current, CGoto):
            if not isinstance(current.target, int) or current.target not in leaf_targets:
                return False
            continue
        if isinstance(current, CLabel):
            label_target = _first_tagged_ins_addr_8616(current)
            if label_target not in leaf_targets:
                return False
            continue
        if isinstance(current, CStatement) and not isinstance(current, (CIfElse, CStatements)):
            return False
    return True


def _materialize_cfg_assignment_diamond_8616(
    project: object,
    codegen: object,
    node: CIfElse,
    root_condition: ConditionIR,
    conditions_by_src: dict[int, ConditionIR],
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
) -> _AssignmentDiamond8616 | None:
    """Collapse one nested-goto assignment diamond from typed CFG evidence."""
    required_conditions = _assignment_diamond_nested_conditions_8616(
        node,
        root_condition,
        conditions_by_src,
    )
    if required_conditions is None:
        return None
    condition_blocks = frozenset(
        condition.block_addr
        for condition in required_conditions
        if isinstance(condition.block_addr, int)
    )
    leaf_candidates = tuple(
        (block_addr, current)
        for current in _iter_c_nodes_deep_8616(node)
        if isinstance(current, CAssignment)
        and isinstance(block_addr := _tagged_statement_block_addr_8616(current), int)
        and block_addr not in condition_blocks
    )
    if len(leaf_candidates) != 2:
        return None
    ordered_candidates = tuple(sorted(leaf_candidates, key=lambda candidate: candidate[0]))
    (true_target, true_assignment), (false_target, false_assignment) = ordered_candidates
    if true_target == false_target or not _same_c_expression_8616(
        true_assignment.lhs,
        false_assignment.lhs,
    ):
        return None
    true_successors = successors.get(true_target, ())
    false_successors = successors.get(false_target, ())
    if (
        len(true_successors) != 1
        or len(false_successors) != 1
        or true_successors[0] != false_successors[0]
    ):
        return None
    root_block = root_condition.block_addr
    if not isinstance(root_block, int):
        return None
    if not _cfg_reaches_address_8616(successors, root_block, true_target):
        return None
    if not _cfg_reaches_address_8616(successors, root_block, false_target):
        return None
    leaf_assignments = (true_assignment, false_assignment)
    leaf_targets = frozenset((true_target, false_target))
    if not _assignment_diamond_scaffolding_is_safe_8616(
        node,
        condition_blocks=condition_blocks,
        leaf_assignments=leaf_assignments,
        leaf_targets=leaf_targets,
    ):
        return None
    replacement = _materialize_cfg_condition_chain_expr_8616(
        project,
        codegen,
        root_condition,
        conditions_by_block,
        successors,
        true_target,
        false_target,
        required_conditions=required_conditions,
    )
    if replacement is None:
        return None
    return _AssignmentDiamond8616(
        condition=replacement,
        true_assignment=true_assignment,
        false_assignment=false_assignment,
        true_target=true_target,
        false_target=false_target,
    )


def _materialize_cfg_shared_body_condition_chain_expr_8616(
    project: object,
    codegen: object,
    root_condition: ConditionIR,
    required_conditions: tuple[ConditionIR, ...],
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    body_target: int,
) -> CExpression | None:
    """Build the predicate that reaches one body before repeating the condition chain.

    A repeated CFG address is the outer control-flow backedge for this
    structured decision, so it means that the shared body is not reached by
    the current evaluation. Unknown untyped forks remain a refusal.
    """
    consumed_conditions: list[ConditionIR] = []

    def build_from_address(address: int, visited: frozenset[int]) -> CExpression | bool | None:
        if address == body_target:
            return True
        if address in visited or len(visited) >= 24:
            return False
        condition = conditions_by_block.get(address)
        if condition is not None:
            return build_from_condition(condition, visited | {address})
        next_addrs = successors.get(address, ())
        if not next_addrs:
            return False
        if len(next_addrs) != 1:
            return None
        return build_from_address(next_addrs[0], visited | {address})

    def build_from_condition(condition: ConditionIR, visited: frozenset[int]) -> CExpression | bool | None:
        if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
            return None
        if all(existing is not condition for existing in consumed_conditions):
            consumed_conditions.append(condition)
        materialized = materialize_condition_ir_expression_8616(project, codegen, condition)
        if not isinstance(materialized, CExpression):
            return None
        taken = build_from_address(condition.taken_target, visited)
        fallthrough = build_from_address(condition.fallthrough_target, visited)
        if taken is None or fallthrough is None:
            return None
        return _combine_condition_outcomes_8616(materialized, taken, fallthrough, codegen)

    initial_visited = (
        frozenset({root_condition.block_addr})
        if isinstance(root_condition.block_addr, int)
        else frozenset()
    )
    result = build_from_condition(root_condition, initial_visited)
    if not isinstance(result, CExpression):
        return None
    if any(
        all(consumed is not required for consumed in consumed_conditions)
        for required in required_conditions
    ):
        return None
    _debug_condition_chain_8616(
        "shared-body-expression-built",
        conditions=tuple(
            (
                condition.src_insn,
                condition.op,
                condition.lhs,
                condition.rhs,
                condition.taken_target,
                condition.fallthrough_target,
            )
            for condition in consumed_conditions
        ),
        consumed_sources=tuple(condition.src_insn for condition in consumed_conditions),
        expression_tree=_condition_debug_tree_8616(result),
    )
    lowering = lower_call_output_stack_fields_in_condition_8616(codegen, result, tuple(consumed_conditions))
    try:
        wide_lowering = lower_wide_call_return_condition_chain_8616(
            codegen,
            lowering.expression,
            tuple(consumed_conditions),
        )
    except Exception:
        if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") == "1":
            log.exception("wide call-return condition lowering failed")
        raise
    _debug_condition_chain_8616(
        "shared-body-expression-lowered",
        expression_tree=_condition_debug_tree_8616(wide_lowering.expression),
        lowering_stats=lowering.stats,
        wide_lowering_stats=wide_lowering.stats,
    )
    wide_stats = wide_lowering.stats
    if (
        wide_stats.raw_fact_count != 1
        or wide_stats.normalized_fact_count != 1
        or wide_stats.classified_fact_count != 1
        or wide_stats.materialized_count != 1
        or wide_stats.failure_count != 0
    ):
        _debug_condition_chain_8616(
            "shared-body-wide-proof-refused",
            wide_lowering_stats=wide_stats,
        )
        return None
    if wide_lowering.consumed_call is not None:
        prune_materialized_wide_condition_call_carrier_8616(
            codegen,
            wide_lowering.consumed_call,
        )
    return wide_lowering.expression


def _shared_body_target_8616(
    condition_and_nodes: tuple[tuple[object, object], ...],
) -> int | None:
    """Return one exact CFG entry shared by every structured branch body."""
    targets: list[int] = []
    for _condition, body in condition_and_nodes:
        target = _first_tagged_block_addr_8616(body)
        if target is None:
            target = _first_tagged_ins_addr_8616(body)
        if target is None:
            return None
        targets.append(target)
    return targets[0] if targets and all(target == targets[0] for target in targets) else None


def _materialize_cfg_single_branch_expr_8616(
    project: object,
    codegen: object,
    condition: ConditionIR,
    structured_condition: CExpression,
    body: object,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    *,
    materialize_return: bool = True,
    continuation: int | None = None,
) -> CExpression | None:
    """Orient one no-else branch from typed targets and exclusive CFG reachability."""
    artifact = None
    if continuation is not None:
        metadata = cast(_ConditionMaterializationCodegen8616, codegen)
        function = cast(_ConditionMaterializationCFunction8616, metadata.cfunc)
        artifact = registered_function_ssa_artifact_8616(project, function.addr).artifact
    goto_polarity = conditional_goto_polarity_8616(body, artifact, condition, continuation, successors)
    if goto_polarity is not None:
        replacement = materialize_condition_ir_expression_8616(project, codegen, condition)
        if replacement is not None:
            return replacement if goto_polarity else invert_structured_condition_8616(replacement, codegen)
    body_target = first_statement_block_8616(body)
    if continuation is not None and body_target is not None:
        region = prove_local_condition_region_8616(
            condition, body_target, continuation, conditions_by_block, successors, artifact,
        )
        if region is not None:
            replacement = _materialize_cfg_condition_chain_expr_8616(
                project, codegen, condition, conditions_by_block, successors,
                region.body_target, region.continuation, required_conditions=region.conditions,
            )
            if replacement is not None:
                record_condition_replay_fact_8616(codegen, condition, region.body_target, region.continuation)
                return replacement
    proven_return_orientation: bool | None = None
    body_return = sole_return_statement_8616(body)
    expected_return = sole_return_expression_8616(body)
    if body_return is not None and (expected_return is not None or body_return.retval is None):
        root_expression = materialize_condition_ir_expression_8616(project, codegen, condition)
        root_orientation: bool | None = None
        if root_expression is not None:
            if _same_c_expression_8616(structured_condition, root_expression):
                root_orientation = True
            elif _same_c_expression_8616(
                structured_condition,
                invert_structured_condition_8616(root_expression, codegen),
            ):
                root_orientation = False

        exit_expressions: dict[int, CExpression | None] = {}
        candidate_returns: list[CExpression] = []
        cfg_addresses = set(successors)
        cfg_addresses.update(target for targets in successors.values() for target in targets)
        for target in sorted(cfg_addresses):
            recovered = recover_branch_target_return_expression_8616(
                project, codegen, target
            )
            exit_expressions[target] = recovered
            if recovered is not None and not any(
                _same_c_expression_8616(recovered, existing)
                for existing in candidate_returns
            ):
                candidate_returns.append(recovered)
        recovered_returns = tuple(candidate_returns)
        if expected_return is not None:
            candidate_returns = [
                candidate
                for candidate in candidate_returns
                if _same_c_expression_8616(candidate, expected_return)
            ]

        def prove_wide_pair(high_value: IRValue, low_value: IRValue) -> bool:
            """Require active stack-object evidence for one high/low pair."""
            high_expression = lower_ir_value_to_c_expr_8616(high_value, project, codegen)
            low_expression = lower_ir_value_to_c_expr_8616(low_value, project, codegen)
            return bool(
                proven_wide_stack_ir_pair_8616(
                    high_value, low_value, high_expression, low_expression
                )
            )

        proofs: list[tuple[ConditionIR, CExpression]] = []
        for candidate_return in candidate_returns:

            def classify_return_exit(
                target: int,
                candidate: CExpression = candidate_return,
            ) -> bool | None:
                """Classify one target against the active return candidate."""
                recovered = exit_expressions.get(target)
                if recovered is None:
                    return None
                return bool(_same_c_expression_8616(recovered, candidate))

            wide_result = recover_wide_stack_single_body_condition_8616(
                condition,
                conditions_by_block,
                successors,
                prove_wide_pair,
                classify_return_exit,
                required_root_outcome=root_orientation,
            )
            if wide_result.condition is not None:
                proofs.append((wide_result.condition, candidate_return))
        _debug_condition_chain_8616(
            "single-return-wide-proof",
            exit_tokens=tuple(
                (target, _condition_structure_token_8616(expression))
                for target, expression in sorted(exit_expressions.items())
                if expression is not None
            ),
            expected_token=(
                _condition_structure_token_8616(expected_return)
                if expected_return is not None
                else None
            ),
            proof_count=len(proofs),
            root_block=condition.block_addr,
            root_orientation=root_orientation,
            root_token=(
                _condition_structure_token_8616(root_expression)
                if root_expression is not None
                else None
            ),
            structured_token=_condition_structure_token_8616(structured_condition),
        )
        if len(proofs) == 1:
            wide_condition, recovered_return = proofs[0]
            materialized_wide = materialize_condition_ir_expression_8616(
                project, codegen, wide_condition
            )
            if materialized_wide is not None:
                if materialize_return:
                    if body_return.retval is None or _same_c_expression_8616(
                        body_return.retval, recovered_return
                    ):
                        body_return.retval = recovered_return
                    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
                    cfunc = cast(_ConditionMaterializationCFunction8616, metadata_codegen.cfunc)
                    record_scalar_return_type_evidence_8616(
                        project, cfunc.addr, recovered_returns
                    )
                lowering = lower_call_output_stack_fields_in_condition_8616(
                    codegen, materialized_wide, (wide_condition,)
                )
                return lowering.expression
        if expected_return is not None:
            orientation_evidence = classify_single_branch_return_orientation_8616(
                condition,
                expected_return,
                exit_expressions,
                successors,
                _same_c_expression_8616,
                _single_branch_orientation_8616,
            )
            proven_return_orientation = orientation_evidence.orientation.as_taken_polarity()
            _debug_condition_chain_8616(
                "single-return-orientation",
                evidence=orientation_evidence,
            )
    body_orientation = _single_branch_body_orientation_8616(
        condition,
        body,
        successors,
    )
    orientation = (
        proven_return_orientation
        if proven_return_orientation is not None
        else body_orientation
    )
    if orientation is None:
        return None
    true_target = condition.taken_target if orientation else condition.fallthrough_target
    false_target = condition.fallthrough_target if orientation else condition.taken_target
    replacement = None
    if body_orientation == orientation and isinstance(false_target, int):
        for body_target in (
            _first_tagged_ins_addr_8616(body),
            _first_tagged_block_addr_8616(body),
        ):
            if (
                body_target is None
                or body_target == condition.block_addr
                or _single_branch_orientation_8616(
                    condition,
                    body_target,
                    successors,
                )
                != orientation
            ):
                continue
            replacement = _materialize_cfg_condition_chain_expr_8616(
                project,
                codegen,
                condition,
                conditions_by_block,
                successors,
                body_target,
                false_target,
            )
            if replacement is not None:
                true_target = body_target
                break
    if replacement is None:
        # Root-edge orientation does not prove every guard in a compound body.
        if any(
            isinstance(node, CBinaryOp) and node.op in {"LogicalAnd", "LogicalOr"}
            for node in _iter_c_nodes_deep_8616(structured_condition)
        ):
            return None
        materialized = materialize_condition_ir_expression_8616(
            project,
            codegen,
            condition,
        )
        if materialized is None:
            return None
        oriented = (
            materialized
            if orientation
            else invert_structured_condition_8616(materialized, codegen)
        )
        replacement = lower_call_output_stack_fields_in_condition_8616(
            codegen,
            oriented,
            (condition,),
        ).expression
    if isinstance(true_target, int) and isinstance(false_target, int):
        record_condition_replay_fact_8616(codegen, condition, true_target, false_target)
    return replacement


def _single_branch_orientation_8616(
    condition: ConditionIR,
    body_target: int,
    successors: dict[int, tuple[int, ...]],
) -> bool | None:
    """Return whether the taken side uniquely owns one structured body."""
    direct_orientation = classify_direct_or_one_hop_target_orientation_8616(
        condition,
        body_target,
        successors,
    )
    if isinstance(direct_orientation, bool):
        return direct_orientation
    if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
        return None
    taken_reaches = _cfg_reaches_address_8616(
        successors,
        condition.taken_target,
        body_target,
        stop_at=condition.block_addr,
    )
    fallthrough_reaches = _cfg_reaches_address_8616(
        successors,
        condition.fallthrough_target,
        body_target,
        stop_at=condition.block_addr,
    )
    if taken_reaches == fallthrough_reaches:
        return None
    return taken_reaches


def _single_branch_body_orientation_8616(
    condition: ConditionIR,
    body: object,
    successors: dict[int, tuple[int, ...]],
) -> bool | None:
    """Resolve body ownership; loop-jump origins cannot prove their destinations."""
    terminal = body
    while isinstance(terminal, CStatements) and len(terminal.statements) == 1:
        terminal = terminal.statements[0]
    if isinstance(terminal, (CBreak, CContinue)):
        # Their tags identify source instructions, not loop exit/header targets.
        return None
    exact_target = _first_tagged_ins_addr_8616(body)
    if exact_target is not None:
        orientation = _single_branch_orientation_8616(condition, exact_target, successors)
        if orientation is not None:
            return orientation
    broad_target = _first_tagged_block_addr_8616(body)
    if broad_target is None or broad_target == exact_target:
        return None
    return _single_branch_orientation_8616(condition, broad_target, successors)


def _select_single_branch_condition_8616(
    preferred: ConditionIR | None,
    conditions: tuple[ConditionIR, ...],
    body: object,
    successors: dict[int, tuple[int, ...]],
) -> ConditionIR | None:
    """Preserve a tagged owner, or infer one from exclusive CFG body ownership."""
    if preferred is not None:
        return preferred
    owners = tuple(
        condition
        for condition in conditions
        if _single_branch_body_orientation_8616(condition, body, successors) is not None
    )
    return owners[0] if len(owners) == 1 else None


def _wide_condition_chain_cfg_connected_8616(
    chain: tuple[ConditionIR, ConditionIR, ConditionIR],
    successors: dict[int, tuple[int, ...]],
) -> bool:
    """Return whether each typed wide-condition stage reaches the next stage."""

    def reaches_next(condition: ConditionIR, target_block: int) -> bool:
        """Check both explicit condition outcomes for bounded CFG reachability."""
        return any(
            _cfg_reaches_address_8616(successors, start, target_block)
            for start in (condition.taken_target, condition.fallthrough_target)
            if isinstance(start, int)
        )

    root, high_ge, low_le = chain
    return (
        isinstance(high_ge.block_addr, int)
        and isinstance(low_le.block_addr, int)
        and reaches_next(root, high_ge.block_addr)
        and reaches_next(high_ge, low_le.block_addr)
    )


def _materialize_existing_wide_call_return_conditions_8616(
    codegen: object,
    targeted: tuple[ConditionIR, ...],
    conditions_by_src: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
) -> tuple[bool, StructuringConditionChainStats8616]:
    """Lower already-structured split DX:AX predicates from typed IR and CFG."""
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    try:
        root = cast(_ConditionMaterializationCFunction8616, metadata_codegen.cfunc).statements
    except AttributeError:
        return False, StructuringConditionChainStats8616()
    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0
    guard_collapse_stats = WideCallReturnGuardCollapseStats8616()
    execution_frame_stats = CallExecutionFrameCarrierStats8616()
    pending_execution_frames: list[tuple[CFunctionCall, int, int]] = []
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse):
            continue
        replacement_pairs: list[tuple[CExpression, CStatement | None]] = []
        pair_changed = False
        for expression, body in tuple(node.condition_and_nodes):
            tags = _copied_condition_tags_8616(expression)
            if tags.get("inertia_structuring_wide_call_return_condition_materialized_8616") is True:
                replacement_pairs.append((expression, body))
                continue
            key = condition_key_from_tags_8616(expression)
            root_condition = conditions_by_src.get(key[0]) if key is not None else None
            if (
                root_condition is None
                or key is None
                or root_condition.block_addr != key[1]
            ):
                replacement_pairs.append((expression, body))
                continue
            chain = select_wide_call_return_condition_chain_8616(root_condition, targeted)
            if chain is None or not _wide_condition_chain_cfg_connected_8616(chain, successors):
                replacement_pairs.append((expression, body))
                continue
            raw_count += 1
            lowering = lower_wide_call_return_condition_chain_8616(
                codegen,
                expression,
                chain,
            )
            normalized_count += lowering.stats.normalized_fact_count
            classified_count += lowering.stats.classified_fact_count
            if lowering.stats.materialized_count != 1:
                failure_count += 1
                replacement_pairs.append((expression, body))
                continue
            replacement = lowering.expression
            guard_collapse = collapse_wide_call_return_guard_chain_8616(
                node,
                chain,
                _direct_tagged_ins_addr_8616,
                _same_c_expression_8616,
            )
            guard_collapse_stats = guard_collapse_stats.merged(guard_collapse.stats)
            _debug_condition_chain_8616(
                "wide-call-return-guard-collapse",
                chain_sources=tuple(condition.src_insn for condition in chain),
                reason=guard_collapse.reason,
                stats=guard_collapse.stats,
                status=guard_collapse.status,
            )
            if guard_collapse.status is WideCallReturnGuardCollapseStatus8616.REFUSED:
                failure_count += 1
                replacement_pairs.append((expression, body))
                continue
            replacement.tags = {**_copied_condition_tags_8616(replacement), **tags}
            replacement.tags["inertia_structuring_condition_cfg_materialized_8616"] = True
            replacement.tags["inertia_structuring_wide_call_return_condition_materialized_8616"] = True
            replacement_pairs.append((replacement, body))
            pair_changed = True
            materialized_count += 1
            changed = True
            if lowering.consumed_call is not None:
                prune_materialized_wide_condition_call_carrier_8616(
                    codegen,
                    lowering.consumed_call,
                )
                if lowering.consumed_callsite is not None:
                    frame_kind = callsite_machine_frame_kind_8616(
                        lowering.consumed_callsite
                    )
                    if frame_kind is not None:
                        pending_execution_frames.append(
                            (
                                lowering.consumed_call,
                                lowering.consumed_callsite.callsite_addr,
                                frame_kind.return_frame_width,
                            )
                        )
            prune_materialized_call_output_stack_carriers_8616(codegen)
        if pair_changed:
            node.condition_and_nodes = replacement_pairs
    seen_frame_calls: set[int] = set()
    for call, callsite_addr, return_frame_width in pending_execution_frames:
        if id(call) in seen_frame_calls:
            continue
        seen_frame_calls.add(id(call))
        frame_result = prune_consumed_call_execution_frame_carriers_8616(
            codegen,
            call,
            callsite_addr=callsite_addr,
            return_frame_width=return_frame_width,
        )
        execution_frame_stats = execution_frame_stats.merged(frame_result.stats)
        changed |= frame_result.stats.materialized_count > 0
    metadata_codegen._inertia_wide_call_return_guard_collapse_stats_8616 = (
        guard_collapse_stats
    )
    metadata_codegen._inertia_call_execution_frame_carrier_stats_8616 = (
        execution_frame_stats
    )
    stats = StructuringConditionChainStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    return changed, stats


def materialize_structuring_condition_chains_8616(project: object, codegen: object) -> bool:
    """Materialize CFG-proven branch predicates from target-bearing ConditionIR."""
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    try:
        conditions_value = metadata_codegen._inertia_typed_conditions
        cfunc = cast(_ConditionMaterializationCFunction8616, metadata_codegen.cfunc)
        root = cfunc.statements
    except AttributeError:
        return False
    try:
        conditions = tuple(item for item in cast(Any, conditions_value) if isinstance(item, ConditionIR))
    except TypeError:
        return False
    targeted = tuple(
        item
        for item in conditions
        if isinstance(item.src_insn, int)
        and isinstance(item.block_addr, int)
        and isinstance(item.taken_target, int)
        and isinstance(item.fallthrough_target, int)
    )
    successors = condition_chain_successors_8616(project, codegen)
    _debug_condition_chain_8616(
        "typed-cfg-surface",
        conditions=tuple(
            (
                item.block_addr,
                item.src_insn,
                item.taken_target,
                item.fallthrough_target,
                item.op,
                item.producer_insn,
            )
            for item in targeted
        ),
        successors=tuple(sorted(successors.items())),
    )
    conditions_by_src = {
        item.src_insn: item
        for item in targeted
        if isinstance(item.src_insn, int)
    }
    conditions_by_block_candidates: dict[int, list[ConditionIR]] = {}
    for item in targeted:
        if isinstance(item.block_addr, int):
            conditions_by_block_candidates.setdefault(item.block_addr, []).append(item)
    conditions_by_block = {
        block_addr: candidates[0]
        for block_addr, candidates in conditions_by_block_candidates.items()
        if len(candidates) == 1
    }
    condition_blocks = frozenset(
        item.block_addr for item in targeted if isinstance(item.block_addr, int)
    )
    raw_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0
    preserved_side_effect_count = 0
    changed = False
    tag_session = StructuredSubtreeEntryTagQuerySession8616(root)
    local_continuations = local_condition_continuations_8616(
        _iter_c_nodes_deep_8616(root), conditions_by_src,
    )
    typed_surface_ids_by_key: dict[tuple[int, int], set[int]] = {}
    for candidate_node in _iter_c_nodes_deep_8616(root):
        if not isinstance(candidate_node, CIfElse):
            continue
        for candidate_condition, _candidate_body in candidate_node.condition_and_nodes:
            candidate_tags = _copied_condition_tags_8616(candidate_condition)
            candidate_key = condition_key_from_tags_8616(candidate_condition)
            if candidate_key is not None and candidate_tags.get("typed_condition") is True:
                typed_surface_ids_by_key.setdefault(candidate_key, set()).add(
                    id(candidate_condition)
                )
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse):
            continue
        call_effects = tuple(
            classify_condition_call_effects_8616(condition)
            for condition, _body in node.condition_and_nodes
        )
        semantic_call_count = sum(
            evidence.semantic_call_count for evidence in call_effects
        )
        if semantic_call_count:
            raw_count += semantic_call_count
            classified_count += semantic_call_count
            materialized_count += semantic_call_count
            preserved_side_effect_count += semantic_call_count
            replay_evidence = None
            if len(node.condition_and_nodes) == 1:
                semantic_condition, semantic_body = node.condition_and_nodes[0]
                key = condition_key_from_tags_8616(semantic_condition)
                semantic_root_fact = conditions_by_src.get(key[0]) if key is not None else None
                if (
                    semantic_root_fact is not None
                    and isinstance(semantic_root_fact.taken_target, int)
                    and isinstance(semantic_root_fact.fallthrough_target, int)
                    and key == (semantic_root_fact.src_insn, semantic_root_fact.block_addr)
                    and node.else_node is not None
                ):
                    replay_evidence = classify_cfg_binary_arm_orientation_8616(
                        semantic_root_fact,
                        _tagged_block_addrs_8616(semantic_body, tag_session),
                        _tagged_block_addrs_8616(node.else_node, tag_session),
                        successors,
                    )
                    if replay_evidence.is_complementary:
                        true_polarity = replay_evidence.true_polarity
                        record_condition_replay_fact_8616(
                            codegen,
                            semantic_root_fact,
                            semantic_root_fact.taken_target
                            if true_polarity
                            else semantic_root_fact.fallthrough_target,
                            semantic_root_fact.fallthrough_target
                            if true_polarity
                            else semantic_root_fact.taken_target,
                        )
            _debug_condition_chain_8616(
                "semantic-call-condition-preserved",
                replay_evidence=replay_evidence,
                replay_facts=condition_replay_facts_8616(codegen),
                semantic_call_count=semantic_call_count,
            )
            continue
        if len(node.condition_and_nodes) != 1:
            condition_and_nodes = tuple(node.condition_and_nodes)
            if is_materialized_multi_arm_return_chain_8616(
                cast(tuple[tuple[CExpression, object], ...], condition_and_nodes),
                node.else_node,
            ):
                raw_count += len(condition_and_nodes)
                classified_count += len(condition_and_nodes)
                materialized_count += len(condition_and_nodes)
                continue
            keys = tuple(condition_key_from_tags_8616(condition) for condition, _body in condition_and_nodes)
            source_facts = tuple(
                conditions_by_src.get(key[0]) if key is not None else None
                for key in keys
            )
            _debug_condition_chain_8616(
                "multi-arm-candidate",
                arm_count=len(condition_and_nodes),
                arm_condition_addrs=keys,
                arm_body_addrs=tuple(
                    _first_tagged_ins_addr_8616(arm_body)
                    for _condition, arm_body in condition_and_nodes
                ),
                arm_body_types=tuple(
                    tuple(type(child).__name__ for child in _iter_c_nodes_deep_8616(arm_body))
                    for _condition, arm_body in condition_and_nodes
                ),
                else_body_addr=_first_tagged_ins_addr_8616(node.else_node),
                else_body_types=tuple(
                    type(child).__name__
                    for child in _iter_c_nodes_deep_8616(node.else_node)
                ),
            )
            if not any(fact is not None for fact in source_facts):
                continue
            exact_facts = tuple(
                fact
                if fact is not None
                and key is not None
                and fact.src_insn == key[0]
                and fact.block_addr == key[1]
                else None
                for key, fact in zip(keys, source_facts, strict=True)
            )
            candidate_raw_count = (
                len(condition_and_nodes) if node.else_node is not None else 1
            )
            duplicate_origins = all(key is not None for key in keys) and len(
                set(keys)
            ) < len(keys)
            root_source_fact = source_facts[0] if source_facts else None
            node_ins_addr = _direct_tagged_ins_addr_8616(node)
            if (
                duplicate_origins
                and root_source_fact is not None
                and successors
                and _structured_node_owns_condition_fact_8616(
                    node_ins_addr,
                    root_source_fact,
                    successors,
                    condition_blocks,
                )
            ):
                ownership = select_multi_arm_condition_owners_8616(
                    tuple(
                        _first_tagged_ins_addr_8616(body)
                        for _condition, body in condition_and_nodes
                    ),
                    targeted,
                    root=root_source_fact,
                    successors=successors,
                )
                if ownership.selected:
                    owned_arms = materialize_multi_arm_condition_owners_8616(
                        condition_and_nodes,
                        ownership,
                        lambda fact: materialize_condition_ir_expression_8616(
                            project,
                            codegen,
                            fact,
                        ),
                    )
                    raw_count += owned_arms.raw_fact_count
                    classified_count += owned_arms.classified_fact_count
                    materialized_count += owned_arms.materialized_count
                    failure_count += owned_arms.failure_count
                    if owned_arms.materialized_count:
                        for (before, _body), (after, _replacement_body) in zip(
                            condition_and_nodes,
                            owned_arms.condition_and_nodes,
                            strict=True,
                        ):
                            record_condition_precision_evidence_8616(
                                project,
                                codegen,
                                before,
                                after,
                            )
                        node.condition_and_nodes = list(
                            owned_arms.condition_and_nodes
                        )
                        tag_session.record_mutation()
                        changed = True
                        _debug_condition_chain_8616(
                            "multi-arm-owner-materialized",
                            arm_count=owned_arms.materialized_count,
                            fact_sources=tuple(
                                fact.src_insn for fact in ownership.facts
                            ),
                        )
                    else:
                        _debug_condition_chain_8616(
                            "multi-arm-owner-materialization-refused",
                            fact_sources=tuple(
                                fact.src_insn for fact in ownership.facts
                            ),
                        )
                    continue
            if not successors or any(fact is None for fact in exact_facts):
                raw_count += candidate_raw_count
                _debug_condition_chain_8616(
                    "multi-arm-proof-refused",
                    else_present=node.else_node is not None,
                    exact_fact_count=sum(fact is not None for fact in exact_facts),
                    successor_count=len(successors),
                )
                failure_count += 1
                continue
            proven_facts = cast(tuple[ConditionIR, ...], exact_facts)
            multi_arm_root_fact = proven_facts[0]
            if not _structured_node_owns_condition_fact_8616(
                node_ins_addr,
                multi_arm_root_fact,
                successors,
                condition_blocks,
            ):
                _debug_condition_chain_8616(
                    "multi-arm-owner-mismatch",
                    fact_block=multi_arm_root_fact.block_addr,
                    fact_src=multi_arm_root_fact.src_insn,
                    node_ins_addr=node_ins_addr,
                )
                raw_count += candidate_raw_count
                failure_count += 1
                continue
            if node.else_node is not None:
                exact_ownership = select_exact_multi_arm_condition_owners_8616(
                    tuple(first_statement_block_8616(body) for _condition, body in condition_and_nodes),
                    proven_facts, else_target=first_statement_block_8616(node.else_node),
                    successors=successors,
                    artifact=registered_function_ssa_artifact_8616(project, cfunc.addr).artifact,
                )
                if exact_ownership.selected:
                    owned = materialize_multi_arm_condition_owners_8616(
                        condition_and_nodes, exact_ownership,
                        lambda fact: materialize_condition_ir_expression_8616(project, codegen, fact),
                        invert=lambda expression: invert_structured_condition_8616(expression, codegen),
                    )
                    raw_count += owned.raw_fact_count
                    classified_count += owned.classified_fact_count
                    materialized_count += owned.materialized_count
                    failure_count += owned.failure_count
                    if owned.materialized_count:
                        for (before, _body), (after, _), fact, taken in zip(
                            condition_and_nodes, owned.condition_and_nodes,
                            proven_facts, exact_ownership.taken_polarities, strict=True,
                        ):
                            taken_target = fact.taken_target
                            fallthrough_target = fact.fallthrough_target
                            # Exact ladder selection proves two concrete CFG edges.
                            assert taken_target is not None and fallthrough_target is not None
                            record_condition_precision_evidence_8616(project, codegen, before, after)
                            record_condition_replay_fact_8616(
                                codegen, fact,
                                taken_target if taken else fallthrough_target,
                                fallthrough_target if taken else taken_target,
                            )
                        node.condition_and_nodes = list(owned.condition_and_nodes)
                        tag_session.record_mutation()
                        changed = True
                    continue
                multi_arm = recover_structured_multi_arm_wide_return_chain_8616(
                    codegen,
                    cast(tuple[tuple[CExpression, object], ...], condition_and_nodes),
                    proven_facts,
                    node.else_node,
                    _first_tagged_ins_addr_8616,
                    lambda fact, true_target, false_target: (
                        _materialize_cfg_condition_chain_expr_8616(
                            project,
                            codegen,
                            fact,
                            conditions_by_block,
                            successors,
                            true_target,
                            false_target,
                        )
                    ),
                    lambda target: recover_branch_target_return_expression_8616(
                        project, codegen, target
                    ),
                )
                raw_count += multi_arm.stats.raw_fact_count
                classified_count += multi_arm.stats.classified_fact_count
                materialized_count += multi_arm.stats.materialized_count
                failure_count += multi_arm.stats.failure_count
                if (
                    multi_arm.status is MultiArmReturnChainStatus8616.MATERIALIZED
                    and multi_arm.else_node is not None
                ):
                    for (before, _before_body), (after, _after_body) in zip(
                        condition_and_nodes,
                        multi_arm.condition_and_nodes,
                        strict=True,
                    ):
                        record_condition_precision_evidence_8616(
                            project, codegen, before, after
                        )
                    node.condition_and_nodes = list(multi_arm.condition_and_nodes)
                    node.else_node = multi_arm.else_node
                    tag_session.record_mutation()
                    metadata_codegen._inertia_multi_arm_return_chain_materialized_8616 = True
                    metadata_codegen._inertia_multi_arm_return_expressions_8616 = (
                        multi_arm.return_expressions
                    )
                    record_scalar_return_type_evidence_8616(
                        project, cfunc.addr, multi_arm.return_expressions
                    )
                    metadata_codegen._inertia_return_expr_chain_materialized_8616 = True
                    prune_materialized_call_output_stack_carriers_8616(codegen)
                    changed = True
                    _debug_condition_chain_8616(
                        "multi-arm-return-chain-materialized",
                        arm_count=len(multi_arm.condition_and_nodes),
                        fact_sources=tuple(fact.src_insn for fact in proven_facts),
                    )
                else:
                    _debug_condition_chain_8616(
                        "multi-arm-return-chain-refused",
                        fact_sources=tuple(fact.src_insn for fact in proven_facts),
                        stats=multi_arm.stats,
                    )
                continue
            raw_count += 1
            body_target = _shared_body_target_8616(condition_and_nodes)
            if body_target is None:
                _debug_condition_chain_8616(
                    "multi-arm-proof-refused",
                    body_target=body_target,
                    else_present=False,
                    exact_fact_count=len(proven_facts),
                    successor_count=len(successors),
                )
                failure_count += 1
                continue
            first_condition, first_body = condition_and_nodes[0]
            replacement = _materialize_cfg_shared_body_condition_chain_expr_8616(
                project,
                codegen,
                multi_arm_root_fact,
                proven_facts,
                conditions_by_block,
                successors,
                body_target,
            )
            if replacement is None:
                _debug_condition_chain_8616(
                    "multi-arm-replacement-refused",
                    body_target=body_target,
                    fact_block=multi_arm_root_fact.block_addr,
                    fact_src=multi_arm_root_fact.src_insn,
                )
                failure_count += 1
                continue
            classified_count += 1
            tags = _copied_condition_tags_8616(first_condition)
            if isinstance(multi_arm_root_fact.src_insn, int):
                tags["ins_addr"] = multi_arm_root_fact.src_insn
            if isinstance(multi_arm_root_fact.block_addr, int):
                tags["vex_block_addr"] = multi_arm_root_fact.block_addr
            if isinstance(multi_arm_root_fact.producer_insn, int):
                tags["condition_producer_insn"] = (
                    multi_arm_root_fact.producer_insn
                )
            tags["inertia_structuring_condition_cfg_materialized_8616"] = True
            tags["inertia_structuring_shared_body_condition_chain_materialized_8616"] = True
            tags["inertia_structuring_shared_body_target_8616"] = body_target
            replacement.tags = {**_copied_condition_tags_8616(replacement), **tags}
            record_condition_precision_evidence_8616(
                project, codegen, first_condition, replacement
            )
            node.condition_and_nodes = [(replacement, first_body)]
            prune_materialized_call_output_stack_carriers_8616(codegen)
            tag_session.record_mutation()
            materialized_count += 1
            changed = True
            _debug_condition_chain_8616(
                "multi-arm-materialized",
                body_target=body_target,
                fact_block=multi_arm_root_fact.block_addr,
                fact_src=multi_arm_root_fact.src_insn,
            )
            continue
        condition, body = node.condition_and_nodes[0]
        condition_tags = _copied_condition_tags_8616(condition)
        shared_body_target = condition_tags.get(
            "inertia_structuring_shared_body_target_8616"
        )
        if (
            condition_tags.get(
                "inertia_structuring_shared_body_condition_chain_materialized_8616"
            )
            is True
            and isinstance(shared_body_target, int)
            and _first_tagged_cfg_target_8616(body) == shared_body_target
        ):
            raw_count += 1
            classified_count += 1
            materialized_count += 1
            continue
        key = condition_key_from_tags_8616(condition)
        node_ins_addr = _direct_tagged_ins_addr_8616(node)
        condition_ins_addr = key[0] if key is not None else None
        typed_surface_ids = typed_surface_ids_by_key.get(key, set()) if key is not None else set()
        if len(typed_surface_ids) == 1 and id(condition) not in typed_surface_ids:
            _debug_condition_chain_8616(
                "noncanonical-duplicate-surface-preserved",
                condition_key=key,
                node_ins_addr=node_ins_addr,
            )
            continue
        condition_fact = conditions_by_src.get(condition_ins_addr) if condition_ins_addr is not None else None
        node_fact = conditions_by_src.get(node_ins_addr) if node_ins_addr is not None else None
        node_owner_overrode_condition_origin = False
        composite_root_selected = False
        semantic_owner_proven = False
        root_fact: ConditionIR | None
        if node_fact is not None and node_fact is not condition_fact:
            node_owner_overrode_condition_origin = True
            root_fact = node_fact
            _debug_condition_chain_8616(
                "node-owner-overrode-condition-origin",
                condition_ins_addr=condition_ins_addr,
                fact_block=node_fact.block_addr,
                fact_src=node_fact.src_insn,
                node_ins_addr=node_ins_addr,
            )
        else:
            root_fact = condition_fact or node_fact
        if node.else_node is not None:
            composite_root = select_composite_preheader_root_8616(
                node_ins_addr, condition, root_fact, targeted, successors,
            )
            if composite_root is not None:
                root_fact = composite_root
                composite_root_selected = True
                node_owner_overrode_condition_origin = True
        if node.else_node is None:
            tagged_fact = root_fact
            has_tagged_owner = condition_ins_addr is not None or node_ins_addr is not None
            if root_fact is None and not has_tagged_owner:
                root_fact = select_unique_condition_by_expression_8616(
                    condition,
                    targeted,
                    lambda candidate: materialize_condition_ir_expression_8616(project, codegen, candidate),
                    _same_c_expression_8616,
                )
            if root_fact is None and not has_tagged_owner:
                root_fact = _select_single_branch_condition_8616(
                    None,
                    targeted,
                    body,
                    successors,
                )
            if root_fact is None and not has_tagged_owner:
                semantic_candidates: list[tuple[ConditionIR, CExpression]] = []
                for candidate in targeted:
                    candidate_replacement = _materialize_cfg_single_branch_expr_8616(
                        project,
                        codegen,
                        candidate,
                        cast(CExpression, condition),
                        body,
                        conditions_by_block,
                        successors,
                        materialize_return=False,
                    )
                    if candidate_replacement is not None:
                        semantic_candidates.append((candidate, candidate_replacement))
                if len(semantic_candidates) == 1:
                    root_fact = semantic_candidates[0][0]
                    semantic_owner_proven = True
                    _debug_condition_chain_8616(
                        "single-return-semantic-owner",
                        fact_block=root_fact.block_addr,
                        fact_src=root_fact.src_insn,
                    )
            if root_fact is None and tagged_fact is not None:
                raw_count += 1
                failure_count += 1
                continue
        if root_fact is None:
            _debug_condition_chain_8616(
                "no-root-fact",
                condition_ins_addr=condition_ins_addr,
                node_ins_addr=node_ins_addr,
            )
            continue
        raw_count += 1
        if not semantic_owner_proven and not _structured_node_owns_condition_fact_8616(
            node_ins_addr, root_fact, successors, condition_blocks
        ):
            _debug_condition_chain_8616(
                "owner-mismatch",
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
                node_ins_addr=node_ins_addr,
            )
            failure_count += 1
            continue
        if (
            condition_ins_addr is not None
            and root_fact.src_insn != condition_ins_addr
            and not node_owner_overrode_condition_origin
        ):
            _debug_condition_chain_8616(
                "condition-origin-mismatch",
                condition_ins_addr=condition_ins_addr,
                fact_src=root_fact.src_insn,
            )
            failure_count += 1
            continue
        tags = _copied_condition_tags_8616(condition)
        if not successors:
            _debug_condition_chain_8616("no-successors", fact_src=root_fact.src_insn)
            failure_count += 1
            continue
        assignment_diamond = (
            _materialize_cfg_assignment_diamond_8616(
                project,
                codegen,
                node,
                root_fact,
                conditions_by_src,
                conditions_by_block,
                successors,
            )
            if node.else_node is not None
            else None
        )
        if assignment_diamond is not None:
            classified_count += 1
            if isinstance(root_fact.src_insn, int):
                tags["ins_addr"] = root_fact.src_insn
            if isinstance(root_fact.block_addr, int):
                tags["vex_block_addr"] = root_fact.block_addr
            if isinstance(root_fact.producer_insn, int):
                tags["condition_producer_insn"] = root_fact.producer_insn
            tags["inertia_structuring_condition_cfg_materialized_8616"] = True
            tags["inertia_structuring_assignment_diamond_materialized_8616"] = True
            assignment_diamond.condition.tags = tags
            record_condition_precision_evidence_8616(
                project, codegen, cast(CExpression, condition), assignment_diamond.condition
            )
            record_condition_replay_fact_8616(
                codegen,
                root_fact,
                assignment_diamond.true_target,
                assignment_diamond.false_target,
            )
            true_body: CStatement = CStatements(
                [assignment_diamond.true_assignment],
                codegen=codegen,
            )
            replacement_arms: list[tuple[CExpression, CStatement | None]] = [
                (
                    assignment_diamond.condition,
                    true_body,
                )
            ]
            node.condition_and_nodes = replacement_arms
            node.else_node = CStatements(
                [assignment_diamond.false_assignment],
                codegen=codegen,
            )
            prune_materialized_call_output_stack_carriers_8616(codegen)
            tag_session.record_mutation()
            materialized_count += 1
            changed = True
            _debug_condition_chain_8616(
                "assignment-diamond-materialized",
                false_target=assignment_diamond.false_target,
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
                true_target=assignment_diamond.true_target,
            )
            continue
        prune_call_output_carriers = True
        if node.else_node is None:
            replacement = _materialize_cfg_single_branch_expr_8616(
                project,
                codegen,
                root_fact,
                cast(CExpression, condition),
                body,
                conditions_by_block,
                successors,
                continuation=local_continuations.get(id(node)),
            )
            if replacement is None:
                replay = select_condition_replay_fact_8616(
                    root_fact, condition_replay_facts_8616(codegen)
                )
                if replay is not None:
                    replacement = _materialize_cfg_condition_chain_expr_8616(
                        project,
                        codegen,
                        root_fact,
                        conditions_by_block,
                        successors,
                        replay.true_target,
                        replay.false_target,
                    )
            marker = "inertia_structuring_single_branch_materialized_8616"
        else:
            assignment_replay_required = (
                tags.get("inertia_structuring_assignment_diamond_materialized_8616") is True
            )
            replay = select_condition_replay_fact_8616(
                root_fact,
                condition_replay_facts_8616(codegen),
            )
            if assignment_replay_required and replay is None:
                _debug_condition_chain_8616(
                    "assignment-diamond-replay-fact-refused",
                    fact_block=root_fact.block_addr,
                    fact_src=root_fact.src_insn,
                )
                failure_count += 1
                continue
            arm_orientation = classify_cfg_binary_arm_orientation_8616(
                root_fact,
                _tagged_block_addrs_8616(body, tag_session),
                _tagged_block_addrs_8616(node.else_node, tag_session),
                successors,
            )
            true_orientation = arm_orientation.true_arm
            false_orientation = arm_orientation.false_arm
            true_polarity = arm_orientation.true_polarity
            true_target = _first_tagged_cfg_target_8616(body)
            false_target = _first_tagged_cfg_target_8616(node.else_node)
            exact_polarity = exact_condition_exit_polarity_8616(
                registered_function_ssa_artifact_8616(project, cfunc.addr).artifact,
                root_fact, true_target, false_target, successors,
            )
            direct_complementary_arms = exact_polarity is not None
            if exact_polarity is not None:
                true_polarity = exact_polarity
            if not direct_complementary_arms:
                return_polarity = binary_return_arm_polarity_8616(
                    root_fact, body, node.else_node,
                    lambda target: recover_branch_target_return_expression_8616(project, codegen, target),
                )
                if return_polarity is not None:
                    true_polarity = return_polarity
                    direct_complementary_arms = True
            replay_true_target = replay.true_target if replay is not None else true_target
            replay_false_target = replay.false_target if replay is not None else false_target
            replacement = None
            if (
                replay is not None
                and replay_true_target is not None
                and replay_false_target is not None
            ):
                replacement = _materialize_cfg_condition_chain_expr_8616(
                    project,
                    codegen,
                    root_fact,
                    conditions_by_block,
                    successors,
                    replay_true_target,
                    replay_false_target,
                )
            if assignment_replay_required and replacement is None:
                _debug_condition_chain_8616(
                    "assignment-diamond-replay-materialization-refused",
                    fact_block=root_fact.block_addr,
                    fact_src=root_fact.src_insn,
                )
                failure_count += 1
                continue
            if replacement is None and direct_complementary_arms and not composite_root_selected:
                materialized = materialize_condition_ir_expression_8616(project, codegen, root_fact)
                if materialized is not None:
                    replacement = materialized if true_polarity else invert_structured_condition_8616(
                        materialized,
                        codegen,
                    )
                    prune_call_output_carriers = False
                    replay_true_target = (
                        root_fact.taken_target if true_polarity else root_fact.fallthrough_target
                    )
                    replay_false_target = (
                        root_fact.fallthrough_target if true_polarity else root_fact.taken_target
                    )
            if (
                replacement is None
                and replay is None
                and replay_true_target is not None
                and replay_false_target is not None
            ):
                replacement = _materialize_cfg_condition_chain_expr_8616(
                    project,
                    codegen,
                    root_fact,
                    conditions_by_block,
                    successors,
                    replay_true_target,
                    replay_false_target,
                    required_conditions=(condition_fact,) if composite_root_selected and condition_fact is not None else (),
                )
            if replacement is not None:
                if replay_true_target is not None and replay_false_target is not None:
                    record_condition_replay_fact_8616(
                        codegen,
                        root_fact,
                        replay_true_target,
                        replay_false_target,
                    )
                _debug_condition_chain_8616(
                    "if-else-arm-ownership-materialized",
                    false_evidence=false_orientation,
                    true_evidence=true_orientation,
                )
            marker = "inertia_structuring_condition_chain_materialized_8616"
        if replacement is None:
            _debug_condition_chain_8616(
                "replacement-refused",
                else_present=node.else_node is not None,
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
                false_target=(
                    _first_tagged_ins_addr_8616(node.else_node)
                    if node.else_node is not None
                    else None
                ),
                true_target=_first_tagged_ins_addr_8616(body),
            )
            failure_count += 1
            continue
        classified_count += 1
        if (
            tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
            and _same_c_expression_8616(condition, replacement)
        ):
            materialized_count += 1
            continue
        if tags.get("inertia_structuring_condition_cfg_materialized_8616") is True:
            _debug_condition_chain_8616(
                "tagged-condition-drift-rematerialized",
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
            )
        if isinstance(root_fact.src_insn, int):
            tags["ins_addr"] = root_fact.src_insn
        if isinstance(root_fact.block_addr, int):
            tags["vex_block_addr"] = root_fact.block_addr
        if isinstance(root_fact.producer_insn, int):
            tags["condition_producer_insn"] = root_fact.producer_insn
        tags["inertia_structuring_condition_cfg_materialized_8616"] = True
        tags[marker] = True
        replacement.tags = {**_copied_condition_tags_8616(replacement), **tags}
        record_condition_precision_evidence_8616(
            project, codegen, cast(CExpression, condition), replacement
        )
        node.condition_and_nodes = [(replacement, body)]
        if prune_call_output_carriers:
            prune_materialized_call_output_stack_carriers_8616(codegen)
        tag_session.record_mutation()
        materialized_count += 1
        changed = True
        _debug_condition_chain_8616(
            "materialized",
            body_target=_first_tagged_ins_addr_8616(body),
            condition_tags=tags,
            fact_block=root_fact.block_addr,
            fact_src=root_fact.src_insn,
            marker=marker,
            node_ins_addr=node_ins_addr,
        )
    scalar_returns = materialize_complete_scalar_return_leaves_8616(
        tuple(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn)),
        set(successors).union(
            target for targets in successors.values() for target in targets
        ),
        lambda target: recover_branch_target_return_expression_8616(
            project, codegen, target
        ),
    )
    if scalar_returns.complete:
        record_scalar_return_type_evidence_8616(
            project, cfunc.addr, scalar_returns.expressions
        )
        changed = scalar_returns.changed or changed
    pruning_closure = classify_condition_evidence_closure_8616(
        root,
        targeted,
        successors,
    )
    if failure_count or not pruning_closure.complete:
        metadata_codegen._inertia_total_return_suffix_prune_stats_8616 = (
            TotalReturnSuffixPruneStats8616(failure_count=1)
        )
    else:
        suffix_prune = prune_unreachable_total_return_suffixes_8616(root)
        metadata_codegen._inertia_total_return_suffix_prune_stats_8616 = (
            suffix_prune.stats
        )
        changed = bool(suffix_prune.removed_statement_count) or changed
    changed = bool(commit_wide_call_condition_captures_8616(codegen)) or changed
    wide_changed, wide_stats = _materialize_existing_wide_call_return_conditions_8616(
        codegen,
        targeted,
        conditions_by_src,
        successors,
    )
    changed = wide_changed or changed
    stats = StructuringConditionChainStats8616(
        raw_fact_count=raw_count + wide_stats.raw_fact_count,
        normalized_fact_count=raw_count + wide_stats.normalized_fact_count,
        classified_fact_count=classified_count + wide_stats.classified_fact_count,
        materialized_count=materialized_count + wide_stats.materialized_count,
        failure_count=failure_count + wide_stats.failure_count,
        preserved_side_effect_count=preserved_side_effect_count,
    )
    metadata_codegen._inertia_structuring_condition_chain_stats_8616 = stats
    metadata_codegen._inertia_structured_subtree_entry_tag_query_stats_8616 = (
        tag_session.stats()
    )
    _debug_condition_chain_8616("stats", stats=stats)
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified structuring condition chain was not materialized")
    return changed


def materialize_structuring_conditions_8616(
    project: object,
    codegen: object,
) -> StructuringConditionMaterializationResult8616:
    """Apply already-proven condition facts at the structuring boundary."""
    legacy_project = cast(SimpleNamespace, project)
    legacy_codegen = cast(SimpleNamespace, codegen)
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    stage_project = cast(_ConditionMaterializationProject8616, project)
    try:
        root = cast(
            _ConditionMaterializationCFunction8616,
            metadata_codegen.cfunc,
        ).statements
    except AttributeError:
        root = None
    try:
        raw_typed_conditions = metadata_codegen._inertia_typed_conditions
    except AttributeError:
        raw_typed_conditions = ()
    typed_conditions = (
        tuple(condition for condition in raw_typed_conditions if isinstance(condition, ConditionIR))
        if isinstance(raw_typed_conditions, (list, tuple))
        else ()
    )
    if wide_stack_return_predicate_materialized_8616(codegen):
        chains_changed = typed_changed = jcc_changed = False
        metadata_codegen._inertia_same_block_condition_register_projection_stats_8616 = (
            SameBlockConditionRegisterProjectionStats8616()
        )
    else:
        stage_project._inertia_decompiler_stage = "structuring:condition_materialization:typed"
        typed_changed = bool(
            _legacy_typed_conditions._apply_typed_conditions_to_codegen_8616(
                legacy_project,
                legacy_codegen,
            )
        )
        stage_project._inertia_decompiler_stage = "structuring:condition_materialization:jcc"
        jcc_changed = bool(
            _legacy_jcc._rewrite_decoded_jcc_conditions_8616(
                legacy_project,
                legacy_codegen,
            )
        )
        stage_project._inertia_decompiler_stage = "structuring:condition_materialization:chains"
        chains_changed = materialize_structuring_condition_chains_8616(project, codegen)
        stage_project._inertia_decompiler_stage = (
            "structuring:condition_materialization:register_projections"
        )
        projection_stats = materialize_same_block_condition_register_projections_8616(
            root,
            project,
            codegen,
            typed_conditions,
        )
        typed_changed = bool(projection_stats.changed_count) or typed_changed
    stage_project._inertia_decompiler_stage = "structuring:condition_materialization:loops"
    function_addr = cast(_ConditionMaterializationCFunction8616, metadata_codegen.cfunc).addr if root is not None else None
    loop_topology = collect_loop_break_topology_8616(project, codegen)
    terminal_stats = materialize_terminal_loop_exit_conditions_8616(
        root, typed_conditions, loop_topology,
        condition_chain_successors_8616(project, codegen),
        registered_function_ssa_artifact_8616(project, function_addr).artifact if isinstance(function_addr, int) else None,
        lambda plan: build_proven_wide_call_condition_8616(codegen, plan.conditions, plan.low_stack, plan.operator),
        lambda before, after: record_condition_precision_evidence_8616(project, codegen, before, after),
    )
    metadata_codegen._inertia_terminal_loop_exit_condition_stats_8616 = terminal_stats
    if terminal_stats.changed_count:
        commit_wide_call_condition_captures_8616(codegen)
    loop_assignment_index = build_same_block_register_assignment_index_8616(codegen)
    loop_stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        typed_conditions,
        condition_chain_successors_8616(project, codegen),
        lambda condition: materialize_condition_ir_expression_8616(
            project,
            codegen,
            condition,
            assignment_index=loop_assignment_index,
        ),
    )
    metadata_codegen._inertia_typed_loop_condition_stats_8616 = loop_stats
    exit_stats = materialize_existing_loop_exit_conditions_8616(
        root, typed_conditions, loop_topology,
        condition_key=condition_key_from_tags_8616,
        lower=lambda condition: materialize_condition_ir_expression_8616(project, codegen, condition),
        invert=lambda condition: invert_structured_condition_8616(condition, codegen),
        record_precision=lambda before, after: record_condition_precision_evidence_8616(project, codegen, before, after),
    )
    metadata_codegen._inertia_existing_loop_exit_condition_stats_8616 = exit_stats
    _debug_condition_chain_8616("existing-loop-exits", stats=exit_stats)
    composite_stats = materialize_composite_pretest_conditions_8616(
        root, typed_conditions, condition_chain_successors_8616(project, codegen),
        registered_function_ssa_artifact_8616(project, function_addr).artifact if isinstance(function_addr, int) else None,
        lambda plan: _materialize_cfg_condition_chain_expr_8616(
            project, codegen, plan.root_condition,
            {cast(int, fact.block_addr): fact for fact in plan.conditions},
            condition_chain_successors_8616(project, codegen),
            plan.exit_target, plan.body_target, required_conditions=plan.conditions,
        ),
        lambda before, after: record_condition_precision_evidence_8616(project, codegen, before, after),
    )
    metadata_codegen._inertia_composite_pretest_condition_stats_8616 = composite_stats
    _debug_condition_chain_8616("composite-pretests", stats=composite_stats)
    if composite_stats.classified_fact_count > 0 and composite_stats.materialized_count == 0:
        raise PipelineHardError(f"function={function_addr!r}: classified composite pretest condition was not materialized")
    _debug_condition_chain_8616("typed-loops", stats=loop_stats)
    if loop_stats.classified_fact_count > 0 and loop_stats.materialized_count == 0:
        raise PipelineHardError("classified typed loop condition was not materialized")
    stage_project._inertia_decompiler_stage = "structuring:condition_materialization:provenance"
    provenance_stats = replay_codegen_structured_condition_segment_provenance_8616(codegen)
    _debug_condition_chain_8616(
        "segment-provenance",
        loop_surface=structured_loop_segment_provenance_surface_8616(root),
        stats=provenance_stats,
    )
    condition_closure = classify_condition_evidence_closure_8616(
        root,
        typed_conditions,
        condition_chain_successors_8616(project, codegen),
    )
    metadata_codegen._inertia_structuring_condition_evidence_closure_8616 = (
        condition_closure
    )
    _debug_condition_chain_8616("evidence-closure", closure=condition_closure)
    result = StructuringConditionMaterializationResult8616(
        typed_conditions_changed=typed_changed,
        condition_chains_changed=chains_changed,
        decoded_jcc_changed=jcc_changed,
        loop_conditions_changed=(
            loop_stats.changed or composite_stats.changed
            or bool(exit_stats.changed_count) or bool(terminal_stats.changed_count)
        ),
        segment_access_provenance_changed=provenance_stats.changed,
        condition_evidence_complete=(
            condition_closure.complete
            and provenance_stats.failure_count == 0
        ),
    )
    metadata_codegen._inertia_structuring_condition_materialization_result_8616 = result
    metadata_codegen._inertia_condition_materialization_structuring_pass_ran_8616 = True
    metadata_codegen._inertia_structuring_condition_materialization_8616 = {
        "typed_conditions_changed": result.typed_conditions_changed,
        "condition_chains_changed": result.condition_chains_changed,
        "decoded_jcc_changed": result.decoded_jcc_changed,
        "loop_conditions_changed": result.loop_conditions_changed,
        "segment_access_provenance_changed": result.segment_access_provenance_changed,
        "condition_evidence_complete": result.condition_evidence_complete,
        "changed": result.changed,
        "owner": "structuring.condition_materialization",
    }
    return result


def apply_structuring_condition_materialization_8616(project: object, codegen: object) -> bool:
    """Compatibility bool-returning entry point for structuring passes."""
    return materialize_structuring_conditions_8616(project, codegen).changed


def cleanup_structuring_conditions_after_replay_8616(
    project: object,
    codegen: object,
) -> StructuringConditionReplayCleanupResult8616:
    """Apply proven condition materialization plus late flag-expression cleanup.

    This is the migration facade for late SeqNode switch replay.  It delegates
    to the historical flag cleanup implementation as a temporary implementation
    detail, but keeps the sequencing and evidence accounting at the
    structuring condition boundary instead of in CLI orchestration.
    """
    materialization = materialize_structuring_conditions_8616(project, codegen)
    legacy_project = cast(SimpleNamespace, project)
    legacy_codegen = cast(SimpleNamespace, codegen)
    flag_condition_pairs_changed = bool(_flags_cleanup._rewrite_flag_condition_pairs_8616(legacy_codegen))
    flag_bit_values_changed = bool(_flags_cleanup._rewrite_flag_bit_value_uses_8616(legacy_codegen))
    interval_guards_changed = bool(_flags_cleanup._fix_interval_guard_conditions_8616(legacy_codegen))
    unused_flag_assignments_pruned = False
    overwritten_flag_assignments_pruned = False
    if materialization.condition_evidence_complete:
        unused_flag_assignments_pruned = bool(
            _flags_cleanup._prune_unused_flag_assignments_8616(
                legacy_project,
                legacy_codegen,
            )
        )
        overwritten_flag_assignments_pruned = bool(
            _flags_cleanup._prune_overwritten_flag_assignments_8616(
                legacy_project,
                legacy_codegen,
            )
        )
    result = StructuringConditionReplayCleanupResult8616(
        materialization=materialization,
        flag_condition_pairs_changed=flag_condition_pairs_changed,
        flag_bit_values_changed=flag_bit_values_changed,
        interval_guards_changed=interval_guards_changed,
        unused_flag_assignments_pruned=unused_flag_assignments_pruned,
        overwritten_flag_assignments_pruned=overwritten_flag_assignments_pruned,
    )
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    metadata_codegen._inertia_structuring_condition_replay_cleanup_8616 = {
        "typed_conditions_changed": materialization.typed_conditions_changed,
        "condition_chains_changed": materialization.condition_chains_changed,
        "decoded_jcc_changed": materialization.decoded_jcc_changed,
        "condition_evidence_complete": materialization.condition_evidence_complete,
        "flag_condition_pairs_changed": result.flag_condition_pairs_changed,
        "flag_bit_values_changed": result.flag_bit_values_changed,
        "interval_guards_changed": result.interval_guards_changed,
        "unused_flag_assignments_pruned": result.unused_flag_assignments_pruned,
        "overwritten_flag_assignments_pruned": result.overwritten_flag_assignments_pruned,
        "changed": result.changed,
        "owner": "structuring.condition_materialization",
    }
    return result


def prune_dead_flag_assignments_after_structuring_8616(
    project: object,
    codegen: object,
) -> StructuringDeadFlagCleanupResult8616:
    """Prune flag chains made dead by later Structuring and Lowering passes.

    Callsite lowering can replace register-carrier argument setup with a
    self-contained expression after normal condition cleanup. Run only the
    Lowering-owned dependency proof before cleanup; never initialize unknown incoming flags.
    """
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    evidence_recorded = True
    try:
        evidence_complete = (
            metadata_codegen._inertia_structuring_condition_materialization_result_8616.condition_evidence_complete
        )
    except AttributeError:
        evidence_recorded = False
        evidence_complete = True
    if not evidence_complete:
        metadata_codegen._inertia_packed_flags_cycle_stats_8616 = PackedFlagsCycleStats8616(failure_count=1)
        result = StructuringDeadFlagCleanupResult8616(
            overwritten_flag_assignments_pruned=False,
            unused_flag_assignments_pruned=False,
        )
        metadata_codegen._inertia_structuring_dead_flag_cleanup_8616 = {
            "condition_evidence_complete": False,
            "overwritten_flag_assignments_pruned": False,
            "unused_flag_assignments_pruned": False,
            "changed": False,
            "owner": "structuring.condition_materialization",
        }
        return result
    legacy_project = cast(SimpleNamespace, project)
    legacy_codegen = cast(SimpleNamespace, codegen)
    try:
        flags_offset = legacy_project.arch.registers["flags"][0]
        root = legacy_codegen.cfunc.statements
    except (AttributeError, KeyError, TypeError):
        cycle_stats = PackedFlagsCycleStats8616(failure_count=1)
    else:
        # The stronger cycle proof requires positive evidence, unlike the
        # historical unread-definition cleanup retained below.
        if not evidence_recorded:
            cycle_stats = PackedFlagsCycleStats8616(failure_count=1)
        else:
            cycle_stats = prune_unobserved_flag_cycles_8616(root, flags_offset)
    metadata_codegen._inertia_packed_flags_cycle_stats_8616 = cycle_stats
    overwritten = bool(
        _flags_cleanup._prune_overwritten_flag_assignments_8616(
            legacy_project,
            legacy_codegen,
        )
    )
    unused = bool(
        _flags_cleanup._prune_unused_flag_assignments_8616(
            legacy_project,
            legacy_codegen,
        )
    )
    result = StructuringDeadFlagCleanupResult8616(
        overwritten_flag_assignments_pruned=overwritten or cycle_stats.materialized_count > 0,
        unused_flag_assignments_pruned=unused,
    )
    metadata_codegen._inertia_structuring_dead_flag_cleanup_8616 = {
        "condition_evidence_complete": True,
        "overwritten_flag_assignments_pruned": result.overwritten_flag_assignments_pruned,
        "unused_flag_assignments_pruned": unused,
        "changed": result.changed,
        "owner": "structuring.condition_materialization",
    }
    return result


def apply_structuring_condition_replay_cleanup_8616(project: object, codegen: object) -> bool:
    """Compatibility bool-returning entry point for late condition replay."""
    return cleanup_structuring_conditions_after_replay_8616(project, codegen).changed
