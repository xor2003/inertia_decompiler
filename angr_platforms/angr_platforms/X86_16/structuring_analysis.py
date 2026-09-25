"""Region-based control-flow structuring algorithm.

Layer: Structuring.
Responsibility: convert typed region graphs into structured control-flow regions.

This module implements the core control-flow analysis that converts a region graph
into structured control-flow patterns (sequence, if-then-else, loops, etc).
Dynamic boundary: codegen/cfunc attribute access is limited to angr pass
integration at the boundary; owned Inertia contracts use typed fields.

The main algorithm operates iteratively:
1. Build a region graph from the CFG
2. Compute dominator relationships
3. Iteratively match and merge regions into structured patterns
4. Apply refinement strategies when no progress is made
5. Post-process to refine high-level constructs (loops, switches, etc)

Inspired by:
  - Reko's StructureAnalysis.cs
  - "Native x86 Decompilation using Semantics-Preserving Structural Analysis
     and Iterative Control-Flow Structuring"
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from .ir.condition_ir import ConditionIR
from .ir.core import IRValue, MemSpace
from .structuring.natural_loop_topology import NaturalLoopTopology8616
from .structuring_graph_builder import build_region_graph
from .structuring_loops import detect_natural_loop
from .structuring_region import (
    DominatorInfo,
    Region,
    RegionGraph,
    RegionType,
    compute_dominators,
)
from .structuring_sequences import merge_would_hide_cycle, sequence_merge_is_safe

__all__ = ["Region", "RegionBasedStructuringPass", "RegionGraph", "RegionType"]

if TYPE_CHECKING:
    pass

logger: logging.Logger = logging.getLogger(__name__)


@runtime_checkable
class _SerializableCondition8616(Protocol):
    """Protocol for owned condition payloads that can serialize themselves."""

    def to_dict(self) -> dict[str, object]:
        """Return a stable serializable condition payload."""
        ...


def _object_sequence_8616(value: object) -> tuple[object, ...]:
    """Return a tuple only for sequence-like metadata payloads."""
    if isinstance(value, str | bytes | bytearray | Mapping):
        return ()
    if isinstance(value, Iterable):
        return tuple(value)
    return ()


def _metadata_sequence_8616(region: Region, key: str) -> tuple[object, ...]:
    """Return a typed tuple from untyped region metadata."""
    return _object_sequence_8616(region.metadata.get(key))


def _summary_sequence_8616(summary: Mapping[str, object], key: str) -> tuple[object, ...]:
    """Return a typed tuple from untyped summary metadata."""
    return _object_sequence_8616(summary.get(key))


def _summary_int_8616(summary: Mapping[str, object], key: str, default: int = 0) -> int:
    """Return an integer counter from untyped summary metadata."""
    value = summary.get(key, default)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return default


def _region_metadata_int_8616(region: Region, key: str, default: int = 0) -> int:
    """Return an integer counter from untyped region metadata."""
    value = region.metadata.get(key, default)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return default


def _summary_mapping_8616(summary: Mapping[str, object], key: str) -> dict[object, object]:
    """Return a plain dict from untyped summary metadata."""
    value = summary.get(key)
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _condition_const_value_8616(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, IRValue) and value.space == MemSpace.CONST and isinstance(value.const, int):
        return value.const
    return None


def _single_eq_edge_guard_8616(region: Region) -> ConditionIR | None:
    """Project one equality guard, including an explicit unary zero test."""
    guards = _metadata_sequence_8616(region, "typed_condition_edge_guards")
    typed_guards = tuple(guard for guard in guards if isinstance(guard, ConditionIR))
    if len(typed_guards) != 1:
        return None
    guard = typed_guards[0]
    if guard.op == "zero" and guard.rhs is None:
        guard = replace(
            guard, op="eq",
            rhs=IRValue(MemSpace.CONST, const=0, size=guard.width_bits // 8),
        )
    if guard.op != "eq":
        return None
    if _condition_const_value_8616(guard.rhs) is None:
        return None
    return guard


def _region_statement_ins_addrs_8616(region: Region) -> tuple[int, ...]:
    addrs = _metadata_sequence_8616(region, "region_statement_ins_addrs")
    return tuple(int(addr) for addr in addrs if isinstance(addr, int))


def _region_statement_provenance_keys_8616(region: Region) -> tuple[tuple[str, int, int], ...]:
    keys = _metadata_sequence_8616(region, "region_statement_provenance_keys")
    return tuple(
        key
        for key in keys
        if (
            isinstance(key, tuple)
            and len(key) == 3
            and isinstance(key[0], str)
            and isinstance(key[1], int)
            and isinstance(key[2], int)
        )
    )


def _region_has_typed_edge_guard_8616(region: Region) -> bool:
    guards = _metadata_sequence_8616(region, "typed_condition_edge_guards")
    return any(isinstance(guard, ConditionIR) for guard in guards)


def _region_edge_producer_semantics_8616(region: Region) -> tuple[tuple[object, ...], ...]:
    semantics = _metadata_sequence_8616(region, "typed_condition_edge_producer_semantics")
    return tuple(item for item in semantics if isinstance(item, tuple) and item)


def _region_typed_condition_summary_8616(region: Region) -> dict[str, object]:
    return {
        "typed_ir_condition_hint": region.metadata.get("typed_ir_condition_hint"),
        "typed_ir_condition_kinds": list(_metadata_sequence_8616(region, "typed_ir_condition_kinds")),
        "typed_condition_ir_hint": region.metadata.get("typed_condition_ir_hint"),
        "typed_condition_ir_ops": list(_metadata_sequence_8616(region, "typed_condition_ir_ops")),
        "typed_condition_edge_guard_hints": list(
            _metadata_sequence_8616(region, "typed_condition_edge_guard_hints")
        ),
        "typed_condition_edge_guard_ops": list(_metadata_sequence_8616(region, "typed_condition_edge_guard_ops")),
        "typed_condition_edge_guard_count": _region_metadata_int_8616(region, "typed_condition_edge_guard_count"),
    }


def _region_typed_condition_summaries_8616(regions: tuple[Region, ...]) -> list[dict[str, object]]:
    return [
        {
            "region_id": region.region_id if isinstance(region.region_id, int) else None,
            **_region_typed_condition_summary_8616(region),
        }
        for region in regions
    ]


class BranchSplitPartitionStatus8616(Enum):
    """Typed status for path-scoped switch branch-split partition evidence."""

    UnsupportedSuccessorCount = "unsupported_successor_count"
    ExplicitPredicateNotUnique = "explicit_predicate_not_unique"
    ImplicitComplementNotClean = "implicit_complement_not_clean"
    SubtreePartitionNotReady = "subtree_partition_not_ready"
    Ready = "ready"


_COMPLEMENT_CONDITION_OPS_8616: dict[str, str] = {
    "sgt": "sle",
    "sge": "slt",
    "slt": "sge",
    "sle": "sgt",
    "ugt": "ule",
    "uge": "ult",
    "ult": "uge",
    "ule": "ugt",
    "eq": "ne",
    "ne": "eq",
}


def _condition_op_matches_value_8616(op: str, value: int, rhs: int) -> bool:
    if op == "eq":
        return value == rhs
    if op == "ne":
        return value != rhs
    if op in {"sgt", "ugt"}:
        return value > rhs
    if op in {"sge", "uge"}:
        return value >= rhs
    if op in {"slt", "ult"}:
        return value < rhs
    if op in {"sle", "ule"}:
        return value <= rhs
    return False


def _single_typed_edge_condition_8616(region: Region) -> ConditionIR | None:
    guards = _metadata_sequence_8616(region, "typed_condition_edge_guards")
    typed_guards = tuple(guard for guard in guards if isinstance(guard, ConditionIR))
    if len(typed_guards) != 1:
        return None
    return typed_guards[0]


def _split_predicate_roles_8616(
    successor_regions: tuple[Region, ...],
) -> tuple[list[tuple[Region, ConditionIR]], list[Region]]:
    """Classify successors into explicit-predicate and implicit-complement arms."""
    explicit: list[tuple[Region, ConditionIR]] = []
    implicit: list[Region] = []
    for region in successor_regions:
        condition = _single_typed_edge_condition_8616(region)
        if condition is not None and condition.op in _COMPLEMENT_CONDITION_OPS_8616:
            explicit.append((region, condition))
        elif condition is None:
            implicit.append(region)
    return explicit, implicit


def _partitioned_successor_8616(
    item: dict[str, object],
    explicit_region_id: int | None,
    explicit_op: str,
    implicit_op: str,
    predicate_rhs: int | None,
) -> dict[str, object]:
    """Partition one successor's normalized case values by the edge predicate."""
    region_id = item.get("region_id")
    raw_values = item.get("normalized_case_values", ())
    raw_region_ids = item.get("normalized_case_region_ids", ())
    normalized_values = [value for value in raw_values if isinstance(value, int)] if isinstance(raw_values, (tuple, list)) else []
    normalized_region_ids = [
        region_id for region_id in raw_region_ids if isinstance(region_id, int)
    ] if isinstance(raw_region_ids, (tuple, list)) else [
    ]
    predicate_op = explicit_op if region_id == explicit_region_id else implicit_op
    matching_values: list[int] = []
    mismatching_values: list[int] = []
    matching_region_ids: list[int] = []
    mismatching_region_ids: list[int] = []
    if predicate_rhs is not None:
        for index, value in enumerate(normalized_values):
            value_region_id = normalized_region_ids[index] if index < len(normalized_region_ids) else None
            if _condition_op_matches_value_8616(predicate_op, value, predicate_rhs):
                matching_values.append(value)
                if value_region_id is not None:
                    matching_region_ids.append(value_region_id)
            else:
                mismatching_values.append(value)
                if value_region_id is not None:
                    mismatching_region_ids.append(value_region_id)
    return {
        **item,
        "partition_predicate_op": predicate_op,
        "predicate_matching_normalized_case_region_ids": matching_region_ids,
        "predicate_matching_normalized_case_values": matching_values,
        "predicate_mismatching_normalized_case_region_ids": mismatching_region_ids,
        "predicate_mismatching_normalized_case_values": mismatching_values,
    }


def _branch_split_partition_evidence_8616(
    successor_regions: tuple[Region, ...],
    subtree_summaries: list[dict[str, object]],
) -> dict[str, object]:
    """Summarize whether a binary split partitions switch cases by typed guards."""
    subtree_by_region_id = {
        summary.get("child_region_id"): summary for summary in subtree_summaries if summary.get("child_region_id") is not None
    }
    base_successors = [
        {
            "region_id": region.region_id if isinstance(region.region_id, int) else None,
            "explicit_predicate_hint": region.metadata.get("typed_ir_condition_hint"),
            "explicit_predicate_ops": list(_metadata_sequence_8616(region, "typed_ir_condition_kinds")),
            "edge_guard_count": _region_metadata_int_8616(region, "typed_condition_edge_guard_count"),
            "normalized_case_values": list(
                _summary_sequence_8616(
                    subtree_by_region_id.get(region.region_id if isinstance(region.region_id, int) else None, {}),
                    "normalized_case_values",
                )
            ),
            "normalized_case_region_ids": list(
                _summary_sequence_8616(
                    subtree_by_region_id.get(region.region_id if isinstance(region.region_id, int) else None, {}),
                    "normalized_case_region_ids",
                )
            ),
            "subtree_partition_status": subtree_by_region_id.get(
                region.region_id if isinstance(region.region_id, int) else None,
                {},
            ).get("partition_status"),
        }
        for region in successor_regions
    ]
    base: dict[str, object] = {
        "ready": False,
        "status": BranchSplitPartitionStatus8616.UnsupportedSuccessorCount.value,
        "successor_count": len(successor_regions),
        "successors": base_successors,
    }
    if len(successor_regions) != 2:
        return base

    explicit, implicit = _split_predicate_roles_8616(successor_regions)

    if len(explicit) != 1:
        base["status"] = BranchSplitPartitionStatus8616.ExplicitPredicateNotUnique.value
        return base
    if len(implicit) != 1:
        base["status"] = BranchSplitPartitionStatus8616.ImplicitComplementNotClean.value
        return base

    explicit_region, explicit_condition = explicit[0]
    implicit_region = implicit[0]
    explicit_region_id = explicit_region.region_id if isinstance(explicit_region.region_id, int) else None
    implicit_region_id = implicit_region.region_id if isinstance(implicit_region.region_id, int) else None
    predicate_rhs = _condition_const_value_8616(explicit_condition.rhs)
    explicit_op = explicit_condition.op
    implicit_op = _COMPLEMENT_CONDITION_OPS_8616[explicit_condition.op]
    partitioned_successors = [
        _partitioned_successor_8616(item, explicit_region_id, explicit_op, implicit_op, predicate_rhs)
        for item in base_successors
    ]
    subtree_partition_statuses = [
        subtree_by_region_id.get(region.region_id if isinstance(region.region_id, int) else None, {}).get(
            "partition_status"
        )
        for region in successor_regions
    ]
    base.update(
        {
            "explicit_successor_region_id": explicit_region_id,
            "explicit_predicate_hint": explicit_region.metadata.get("typed_ir_condition_hint"),
            "explicit_predicate_op": explicit_op,
            "implicit_complement_successor_region_id": implicit_region_id,
            "implicit_complement_op": implicit_op,
            "subtree_partition_statuses": subtree_partition_statuses,
            "successors": partitioned_successors,
        }
    )
    if any(status != "single_default_candidate" for status in subtree_partition_statuses):
        base["status"] = BranchSplitPartitionStatus8616.SubtreePartitionNotReady.value
        return base
    base["ready"] = True
    base["status"] = BranchSplitPartitionStatus8616.Ready.value
    return base


def _edge_guard_affine_delta_8616(semantics: tuple[object, ...]) -> int | None:
    if (
        len(semantics) >= 4
        and semantics[0] == "normalized_cmp_reg_imm16"
        and isinstance(semantics[2], int)
        and isinstance(semantics[3], tuple)
    ):
        nested_delta = _edge_guard_affine_delta_8616(semantics[3])
        if nested_delta is not None and int(semantics[2]) == nested_delta:
            return nested_delta
        return None
    if len(semantics) >= 3 and semantics[0] == "sub_reg_imm16" and isinstance(semantics[2], int):
        return int(semantics[2])
    if len(semantics) >= 3 and semantics[0] == "dec_reg16" and isinstance(semantics[2], int):
        return int(semantics[2])
    if len(semantics) >= 2 and semantics[0] == "dec_reg16":
        return 1
    return None


def _edge_guard_cmp_value_8616(semantics: tuple[object, ...]) -> int | None:
    if len(semantics) >= 3 and semantics[0] == "normalized_cmp_reg_imm16" and isinstance(semantics[2], int):
        if len(semantics) >= 4 and isinstance(semantics[3], tuple):
            nested_delta = _edge_guard_affine_delta_8616(semantics[3])
            if nested_delta is not None and int(semantics[2]) == nested_delta:
                return None
        return int(semantics[2])
    if len(semantics) >= 3 and semantics[0] == "cmp_reg_imm16" and isinstance(semantics[2], int):
        return int(semantics[2])
    return None


def _continuation_sibling_affine_delta_8616(graph: RegionGraph, current: Region, continuation: Region) -> int | None:
    """Return affine delta carried by the non-continuation sibling of a switch step."""
    if not _region_reaches_eq_switch_head_8616(graph, continuation):
        return None
    deltas: list[int] = []
    for sibling in graph.successors(current):
        if sibling is continuation:
            continue
        for semantics in _region_edge_producer_semantics_8616(sibling):
            delta = _edge_guard_affine_delta_8616(semantics)
            if delta is not None:
                deltas.append(delta)
                break
    unique_deltas = tuple(dict.fromkeys(deltas))
    return unique_deltas[0] if len(unique_deltas) == 1 else None


def _region_has_single_eq_guarded_successor_8616(graph: RegionGraph, region: Region) -> bool:
    succs = graph.successors(region)
    if len(succs) != 2:
        return False
    return sum(1 for succ in succs if _single_eq_edge_guard_8616(succ) is not None) == 1


def _region_is_eq_switch_head_8616(graph: RegionGraph, region: Region) -> bool:
    return _region_has_single_eq_guarded_successor_8616(graph, region)


def _region_edge_guard_cases_8616(graph: RegionGraph, region: Region) -> tuple[tuple[Region, ConditionIR, int], ...]:
    """Return equality-guarded case successors from a decision-tree node."""
    cases: list[tuple[Region, ConditionIR, int]] = []
    for succ in graph.successors(region):
        guard = _single_eq_edge_guard_8616(succ)
        if guard is None:
            continue
        value = _condition_const_value_8616(guard.rhs)
        if value is None:
            continue
        cases.append((succ, guard, value))
    return tuple(cases)


def _region_reaches_eq_switch_head_8616(
    graph: RegionGraph,
    region: Region,
    *,
    max_depth: int = 8,
) -> bool:
    """Return whether unguarded continuation flow reaches another eq-switch head."""
    pending: list[tuple[Region, int]] = [(region, 0)]
    visited: set[Region] = set()
    while pending:
        current, depth = pending.pop(0)
        if current in visited or current not in graph.nodes:
            continue
        visited.add(current)
        if _region_is_eq_switch_head_8616(graph, current):
            return True
        if depth >= max_depth or _region_has_typed_edge_guard_8616(current):
            continue
        for succ in graph.successors(current):
            if _single_eq_edge_guard_8616(succ) is not None:
                continue
            pending.append((succ, depth + 1))
    return False


def _region_reaches_region_through_continuation_8616(
    graph: RegionGraph,
    start: Region,
    target: Region,
    *,
    max_depth: int = 8,
) -> bool:
    """Return whether continuation flow reaches target without entering a case edge."""
    pending: list[tuple[Region, int]] = [(start, 0)]
    visited: set[Region] = set()
    while pending:
        current, depth = pending.pop(0)
        if current is target:
            return True
        if current in visited or current not in graph.nodes or depth >= max_depth:
            continue
        visited.add(current)
        current_cases = _region_edge_guard_cases_8616(graph, current)
        case_regions = {case_region for case_region, _guard, _value in current_cases}
        for succ in graph.successors(current):
            if succ in case_regions:
                continue
            pending.append((succ, depth + 1))
    return False


def _expanded_edge_guard_switch_root_8616(
    graph: RegionGraph,
    region: Region,
    *,
    max_depth: int = 8,
) -> tuple[Region, str, tuple[int, ...]]:
    """Find an earlier unique typed switch head that reaches this candidate."""
    def _candidate_predecessors(target: Region) -> tuple[Region, ...]:
        candidates: list[Region] = []
        pending: list[tuple[Region, int]] = [(pred, 0) for pred in graph.predecessors(target)]
        visited: set[Region] = set()
        while pending:
            pred, depth = pending.pop(0)
            if pred in visited or pred not in graph.nodes:
                continue
            visited.add(pred)
            if len(_region_edge_guard_cases_8616(graph, pred)) == 1 and _region_reaches_region_through_continuation_8616(
                graph, pred, target
            ):
                candidates.append(pred)
                continue
            if depth >= 8 or _region_has_typed_edge_guard_8616(pred):
                continue
            pending.extend((parent, depth + 1) for parent in graph.predecessors(pred))
        return tuple(candidates)

    current = region
    chain: list[int] = []
    for _depth in range(max_depth):
        candidates = list(_candidate_predecessors(current))
        if not candidates:
            return current, "none" if current is region else "unique_predecessor_chain", tuple(chain)
        unique = {id(candidate): candidate for candidate in candidates}
        if len(unique) != 1:
            return current, "ambiguous_predecessor", tuple(chain)
        current = next(iter(unique.values()))
        if isinstance(current.region_id, int):
            chain.append(current.region_id)
    return current, "max_depth", tuple(chain)


def _edge_guard_partition_status_8616(
    *,
    case_count: int,
    default_candidate_count: int,
    duplicate_value_count: int,
    lhs_mismatch_count: int,
    unresolved_continuation_count: int,
) -> str:
    """Typed switch-decision partition status for diagnostics and later lowering."""
    if case_count <= 0:
        return "no_cases"
    if lhs_mismatch_count:
        return "lhs_mismatch"
    if duplicate_value_count:
        return "duplicate_case_values"
    if unresolved_continuation_count:
        return "unresolved_continuation"
    if default_candidate_count != 1:
        return "default_not_unique"
    return "single_default_candidate"


def _edge_guard_normalization_readiness_8616(summary: dict[str, object]) -> dict[str, object]:
    """Summarize whether normalized switch evidence is ready for later lowering."""
    case_count = _summary_int_8616(summary, "case_count")
    normalized_case_count = _summary_int_8616(summary, "normalized_case_count")
    partition_status = summary.get("partition_status")
    normalization_status = summary.get("normalization_status")
    branch_splits = [item for item in _summary_sequence_8616(summary, "normalization_branch_splits") if isinstance(item, dict)]
    branch_split_count = len(branch_splits)
    ready_branch_splits = [
        item
        for item in branch_splits
        if isinstance(item.get("branch_partition"), dict) and item["branch_partition"].get("ready") is True
    ]
    unready_branch_splits = [
        {
            "from_region_id": item.get("from_region_id"),
            "split_region_id": item.get("split_region_id"),
            "status": item.get("branch_partition", {}).get("status")
            if isinstance(item.get("branch_partition"), dict)
            else None,
        }
        for item in branch_splits
        if item not in ready_branch_splits
    ]
    base: dict[str, object] = {
        "ready": False,
        "status": normalization_status,
        "case_count": case_count,
        "normalized_case_count": normalized_case_count,
        "partition_status": partition_status,
        "branch_split_count": branch_split_count,
        "ready_branch_split_count": len(ready_branch_splits),
        "unready_branch_splits": unready_branch_splits,
    }
    if _summary_int_8616(summary, "normalized_duplicate_value_count"):
        base["status"] = "duplicate_normalized_values"
        return base
    if normalized_case_count < case_count:
        base["status"] = "partial"
        return base
    if partition_status != "single_default_candidate":
        base["status"] = "partition_not_ready"
        return base
    if normalization_status == "complete":
        base["ready"] = True
        base["status"] = "complete"
        return base
    if normalization_status == "branch_split_unmodeled":
        if branch_split_count <= 0:
            base["status"] = "branch_split_missing"
            return base
        if len(ready_branch_splits) != branch_split_count:
            base["status"] = "branch_split_not_ready"
            return base
        base["ready"] = True
        base["status"] = "branch_splits_ready"
        return base
    return base


def _same_lhs_8616(lhs: object | None, guard: ConditionIR) -> object | None:
    if lhs is None:
        return cast(object, guard.lhs)
    return lhs if guard.lhs == lhs else None


@dataclass(slots=True)
class _DecisionTreeScan8616:
    """Accumulating scan state for edge-guard decision-tree case collection."""

    graph: RegionGraph
    include_branch_split_subtrees: bool
    stop_region_set: set[Region]
    loopback_target: Region
    visited: set[Region] = field(default_factory=set)
    lhs_key: object | None = None
    cases: list[tuple[Region, int]] = field(default_factory=list)
    normalized_cases: list[tuple[Region, int]] = field(default_factory=list)
    case_values: set[int] = field(default_factory=set)
    normalized_case_values: set[int] = field(default_factory=set)
    producer_semantics: list[tuple[object, ...]] = field(default_factory=list)
    normalized_duplicate_value_count: int = 0
    normalization_branch_split_count: int = 0
    normalization_branch_splits: list[dict[str, object]] = field(default_factory=list)
    normalization_branch_subtrees: list[dict[str, object]] = field(default_factory=list)
    range_split_count: int = 0
    duplicate_value_count: int = 0
    lhs_mismatch_count: int = 0
    default_candidates: list[Region] = field(default_factory=list)
    loopback_default_candidates: list[Region] = field(default_factory=list)
    nondefault_empty_regions: list[Region] = field(default_factory=list)
    unresolved_continuation_count: int = 0

    def record_case(
        self,
        case_region: Region,
        guard: ConditionIR,
        value: int,
        affine_offset: int,
        last_affine_semantics: tuple[object, ...] | None,
    ) -> None:
        """Record one equality-guarded case successor and its normalized value."""
        if case_region in self.stop_region_set:
            return
        next_lhs = _same_lhs_8616(self.lhs_key, guard)
        if next_lhs is None:
            self.lhs_mismatch_count += 1
            return
        self.lhs_key = next_lhs
        if value not in self.case_values:
            self.case_values.add(value)
            self.cases.append((case_region, value))
        else:
            self.duplicate_value_count += 1
        case_semantics = _region_edge_producer_semantics_8616(case_region)
        self.producer_semantics.extend(case_semantics)
        normalized_value = None
        for semantics in case_semantics:
            cmp_value = _edge_guard_cmp_value_8616(semantics)
            if cmp_value is not None:
                normalized_value = cmp_value
                break
            delta = _edge_guard_affine_delta_8616(semantics)
            if delta is not None:
                normalized_value = affine_offset if semantics == last_affine_semantics else affine_offset + delta
                break
        if normalized_value is not None:
            if normalized_value in self.normalized_case_values:
                self.normalized_duplicate_value_count += 1
            else:
                self.normalized_case_values.add(normalized_value)
                self.normalized_cases.append((case_region, normalized_value))

    def record_empty_region(self, current: Region, default_eligible_path: bool) -> bool:
        """Classify a case-less region; return True when the succ walk is skipped."""
        if not _region_reaches_eq_switch_head_8616(self.graph, current):
            self.default_candidates.append(current)
            return True
        if (
            default_eligible_path
            and len(self.graph.successors(current)) == 1
            and _region_reaches_region_through_continuation_8616(self.graph, current, self.loopback_target)
        ):
            self.loopback_default_candidates.append(current)
            return True
        self.nondefault_empty_regions.append(current)
        return False

    def record_branch_split(
        self,
        current: Region,
        succ: Region,
        current_cases: tuple[tuple[Region, ConditionIR, int], ...],
        depth: int,
        affine_offset: int,
        max_depth: int,
    ) -> None:
        """Record a normalization branch split under a non-case successor."""
        if not (
            current_cases
            and len(self.graph.successors(succ)) > 1
            and not _region_is_eq_switch_head_8616(self.graph, succ)
        ):
            return
        self.normalization_branch_split_count += 1
        successor_regions = tuple(self.graph.successors(succ))
        current_case_region_ids = [
            case_region.region_id
            for case_region, _guard, _value in current_cases
            if isinstance(case_region.region_id, int)
        ]
        current_case_values = [value for _case_region, _guard, value in current_cases]
        split_record: dict[str, object] = {
            "from_region_id": current.region_id if isinstance(current.region_id, int) else None,
            "split_region_id": succ.region_id if isinstance(succ.region_id, int) else None,
            "current_case_region_ids": current_case_region_ids,
            "current_case_values": current_case_values,
            "successor_region_ids": [
                child.region_id
                for child in successor_regions
                if isinstance(child.region_id, int)
            ],
            "split_condition": _region_typed_condition_summary_8616(succ),
            "successor_conditions": _region_typed_condition_summaries_8616(successor_regions),
            "affine_offset": affine_offset,
        }
        subtree_summaries: list[dict[str, object]] = []
        if self.include_branch_split_subtrees:
            prior_case_regions = tuple(case_region for case_region, _value in self.cases)
            for child in successor_regions:
                sibling_stop_regions = (
                    *(sibling for sibling in successor_regions if sibling is not child),
                    *prior_case_regions,
                )
                child_summary = _collect_edge_guard_decision_tree_cases_8616(
                    self.graph,
                    child,
                    include_expanded_root=False,
                    include_branch_split_subtrees=False,
                    initial_affine_offset=affine_offset,
                    loopback_region=current,
                    max_depth=max(0, max_depth - depth - 1),
                    stop_regions=sibling_stop_regions,
                )
                subtree_summaries.append(_branch_split_child_summary_8616(child, child_summary))
        branch_partition = _branch_split_partition_evidence_8616(successor_regions, subtree_summaries)
        split_record["branch_partition"] = branch_partition
        self.normalization_branch_splits.append(split_record)
        if self.include_branch_split_subtrees:
            self.normalization_branch_subtrees.append(
                {
                    "from_region_id": current.region_id if isinstance(current.region_id, int) else None,
                    "split_region_id": succ.region_id if isinstance(succ.region_id, int) else None,
                    "current_case_region_ids": current_case_region_ids,
                    "current_case_values": current_case_values,
                    "affine_offset": affine_offset,
                    "split_condition": _region_typed_condition_summary_8616(succ),
                    "successor_conditions": _region_typed_condition_summaries_8616(successor_regions),
                    "branch_partition": branch_partition,
                    "subtrees": subtree_summaries,
                }
            )

    def _affine_step(
        self,
        current: Region,
        succ: Region,
        current_cases: tuple[tuple[Region, ConditionIR, int], ...],
        affine_offset: int,
        last_affine_semantics: tuple[object, ...] | None,
    ) -> tuple[int, tuple[object, ...] | None]:
        """Advance the affine offset carried into the ``succ`` continuation."""
        next_affine_offset = affine_offset
        next_last_affine_semantics = last_affine_semantics
        if current_cases:
            case_region = current_cases[0][0]
            for semantics in _region_edge_producer_semantics_8616(case_region):
                delta = _edge_guard_affine_delta_8616(semantics)
                if delta is not None:
                    if semantics != next_last_affine_semantics:
                        next_affine_offset += delta
                    next_last_affine_semantics = semantics
                    break
        else:
            for semantics in _region_edge_producer_semantics_8616(current):
                delta = _edge_guard_affine_delta_8616(semantics)
                if delta is not None:
                    next_affine_offset += delta
                    next_last_affine_semantics = semantics
                    break
            sibling_delta = _continuation_sibling_affine_delta_8616(self.graph, current, succ)
            if sibling_delta is not None:
                next_affine_offset += sibling_delta
                next_last_affine_semantics = None
            for semantics in _region_edge_producer_semantics_8616(succ):
                delta = _edge_guard_affine_delta_8616(semantics)
                if delta is not None:
                    next_affine_offset += delta
                    next_last_affine_semantics = semantics
                    break
        return next_affine_offset, next_last_affine_semantics

    def continuation_step(
        self,
        current: Region,
        succ: Region,
        current_cases: tuple[tuple[Region, ConditionIR, int], ...],
        affine_offset: int,
        last_affine_semantics: tuple[object, ...] | None,
        default_eligible_path: bool,
    ) -> tuple[int, tuple[object, ...] | None, bool] | None:
        """Advance the affine/default-eligible scan state across ``succ``."""
        next_affine_offset = affine_offset
        next_last_affine_semantics = last_affine_semantics
        if _region_has_typed_edge_guard_8616(succ):
            guards = _metadata_sequence_8616(succ, "typed_condition_edge_guards")
            has_non_eq_guard = any(isinstance(guard, ConditionIR) and guard.op != "eq" for guard in guards)
            if has_non_eq_guard:
                self.range_split_count += 1
                if _region_reaches_eq_switch_head_8616(self.graph, succ):
                    return (next_affine_offset, next_last_affine_semantics, default_eligible_path)
                self.unresolved_continuation_count += 1
                return None
            self.unresolved_continuation_count += 1
            return None
        next_affine_offset, next_last_affine_semantics = self._affine_step(
            current, succ, current_cases, next_affine_offset, next_last_affine_semantics
        )
        next_default_eligible = default_eligible_path
        if current_cases:
            next_default_eligible = True
        elif _region_reaches_eq_switch_head_8616(self.graph, succ):
            next_default_eligible = False
        return (next_affine_offset, next_last_affine_semantics, next_default_eligible)

    def _normalization_status(self) -> str:
        """Classify the normalization outcome for the collected cases."""
        first_producer_kind = (
            str(self.producer_semantics[0][0])
            if self.producer_semantics and self.producer_semantics[0]
            else None
        )
        if self.normalized_duplicate_value_count:
            return "duplicate_normalized_values"
        if len(self.normalized_cases) < len(self.cases):
            return "partial"
        if self.normalization_branch_split_count:
            return "branch_split_unmodeled"
        if first_producer_kind not in {"cmp_reg_imm16", "normalized_cmp_reg_imm16"}:
            return "root_seed_missing"
        return "complete"

    def summary(self, region: Region) -> dict[str, object]:
        """Render the collected scan state as the decision-tree record."""
        default_candidate_ids = list(
            dict.fromkeys(candidate.region_id for candidate in self.default_candidates)
        )
        loopback_default_candidate_ids = list(
            dict.fromkeys(candidate.region_id for candidate in self.loopback_default_candidates)
        )
        effective_default_candidate_ids = default_candidate_ids or loopback_default_candidate_ids
        default_candidate_successors = {
            candidate.region_id: [
                succ.region_id for succ in self.graph.successors(candidate) if isinstance(succ.region_id, int)
            ]
            for candidate in self.default_candidates
            if isinstance(candidate.region_id, int)
        }
        effective_duplicate_value_count = self.duplicate_value_count
        if len(self.normalized_cases) >= len(self.cases) and self.normalized_duplicate_value_count == 0:
            effective_duplicate_value_count = 0
        partition_status = _edge_guard_partition_status_8616(
            case_count=len(self.cases),
            default_candidate_count=len(effective_default_candidate_ids),
            duplicate_value_count=effective_duplicate_value_count,
            lhs_mismatch_count=self.lhs_mismatch_count,
            unresolved_continuation_count=self.unresolved_continuation_count,
        )
        producer_kinds = tuple(sorted({str(item[0]) for item in self.producer_semantics if item}))
        producer_registers = tuple(
            sorted(
                {
                    str(item[1]).lower()
                    for item in self.producer_semantics
                    if len(item) >= 3 and str(item[0]) in {"cmp_reg_imm16", "normalized_cmp_reg_imm16", "sub_reg_imm16"}
                }
            )
        )
        affine_reg_imm_case_count = sum(
            1
            for item in self.producer_semantics
            if len(item) >= 3 and str(item[0]) in {"cmp_reg_imm16", "sub_reg_imm16"} and isinstance(item[2], int)
        )
        result = {
            "affine_reg_imm_case_count": affine_reg_imm_case_count,
            "case_count": len(self.cases),
            "case_region_ids": [case.region_id for case, _value in self.cases],
            "case_values": [value for _case, value in self.cases],
            "default_candidate_count": len(effective_default_candidate_ids),
            "default_candidate_region_ids": effective_default_candidate_ids,
            "default_candidate_successor_region_ids": default_candidate_successors,
            "duplicate_value_count": self.duplicate_value_count,
            "lhs": self.lhs_key,
            "lhs_mismatch_count": self.lhs_mismatch_count,
            "loopback_default_candidate_region_ids": loopback_default_candidate_ids,
            "loopback_default_successor_region_ids": {
                candidate.region_id: [
                    succ.region_id for succ in self.graph.successors(candidate) if isinstance(succ.region_id, int)
                ]
                for candidate in self.loopback_default_candidates
                if isinstance(candidate.region_id, int)
            },
            "normalized_case_count": len(self.normalized_cases),
            "normalized_case_region_ids": [case.region_id for case, _value in self.normalized_cases],
            "normalized_case_values": [value for _case, value in self.normalized_cases],
            "normalized_duplicate_value_count": self.normalized_duplicate_value_count,
            "nondefault_empty_region_ids": [
                item.region_id for item in self.nondefault_empty_regions if isinstance(item.region_id, int)
            ],
            "nondefault_empty_successor_region_ids": {
                item.region_id: [succ.region_id for succ in self.graph.successors(item) if isinstance(succ.region_id, int)]
                for item in self.nondefault_empty_regions
                if isinstance(item.region_id, int)
            },
            "normalization_branch_split_count": self.normalization_branch_split_count,
            "normalization_branch_splits": self.normalization_branch_splits,
            "normalization_branch_subtrees": self.normalization_branch_subtrees,
            "normalization_status": self._normalization_status(),
            "partition_status": partition_status,
            "predecessor_region_ids": [
                pred.region_id for pred in self.graph.predecessors(region) if isinstance(pred.region_id, int)
            ],
            "producer_semantics_case_count": len(self.producer_semantics),
            "producer_semantics_kinds": list(producer_kinds),
            "producer_semantics_registers": list(producer_registers),
            "range_split_count": self.range_split_count,
            "unresolved_continuation_count": self.unresolved_continuation_count,
            "visited_count": len(self.visited),
            "visited_region_ids": [
                item.region_id
                for item in sorted(self.visited, key=lambda region_item: region_item.region_id or 0)
                if isinstance(item.region_id, int)
            ],
        }
        result["normalization_readiness"] = _edge_guard_normalization_readiness_8616(result)
        return result


def _branch_split_child_summary_8616(child: Region, child_summary: dict[str, object]) -> dict[str, object]:
    """Render one branch-split subtree scan as a normalized summary record."""
    return {
        "child_region_id": child.region_id if isinstance(child.region_id, int) else None,
        "case_count": child_summary.get("case_count", 0),
        "case_region_ids": list(_summary_sequence_8616(child_summary, "case_region_ids")),
        "case_values": list(_summary_sequence_8616(child_summary, "case_values")),
        "default_candidate_count": child_summary.get("default_candidate_count", 0),
        "default_candidate_region_ids": list(
            _summary_sequence_8616(child_summary, "default_candidate_region_ids")
        ),
        "default_candidate_successor_region_ids": _summary_mapping_8616(
            child_summary, "default_candidate_successor_region_ids"
        ),
        "normalized_case_count": child_summary.get("normalized_case_count", 0),
        "normalized_case_region_ids": list(
            _summary_sequence_8616(child_summary, "normalized_case_region_ids")
        ),
        "normalized_case_values": list(
            _summary_sequence_8616(child_summary, "normalized_case_values")
        ),
        "loopback_default_candidate_region_ids": list(
            _summary_sequence_8616(child_summary, "loopback_default_candidate_region_ids")
        ),
        "loopback_default_successor_region_ids": _summary_mapping_8616(
            child_summary, "loopback_default_successor_region_ids"
        ),
        "nondefault_empty_region_ids": list(
            _summary_sequence_8616(child_summary, "nondefault_empty_region_ids")
        ),
        "nondefault_empty_successor_region_ids": _summary_mapping_8616(
            child_summary, "nondefault_empty_successor_region_ids"
        ),
        "normalization_status": child_summary.get("normalization_status"),
        "partition_status": child_summary.get("partition_status"),
        "range_split_count": child_summary.get("range_split_count", 0),
        "unresolved_continuation_count": child_summary.get(
            "unresolved_continuation_count",
            0,
        ),
        "visited_count": child_summary.get("visited_count", 0),
        "visited_region_ids": list(_summary_sequence_8616(child_summary, "visited_region_ids")),
    }


def _attach_expanded_root_summary_8616(
    graph: RegionGraph,
    region: Region,
    summary: dict[str, object],
    max_depth: int,
) -> None:
    """Attach expanded-root scan fields when the root is a descendant head."""
    expanded_root, expanded_root_status, expanded_chain = _expanded_edge_guard_switch_root_8616(graph, region)
    summary["expanded_root_region_id"] = expanded_root.region_id if isinstance(expanded_root.region_id, int) else None
    summary["expanded_root_status"] = expanded_root_status
    summary["expanded_root_chain"] = list(expanded_chain)
    if expanded_root is not region:
        expanded_summary = _collect_edge_guard_decision_tree_cases_8616(
            graph,
            expanded_root,
            include_expanded_root=False,
            include_branch_split_subtrees=True,
            max_depth=max_depth,
        )
        summary["expanded_root_case_count"] = expanded_summary.get("case_count", 0)
        summary["expanded_root_case_values"] = list(_summary_sequence_8616(expanded_summary, "case_values"))
        summary["expanded_root_normalization_status"] = expanded_summary.get("normalization_status")
        summary["expanded_root_normalization_branch_split_count"] = expanded_summary.get(
            "normalization_branch_split_count",
            0,
        )
        summary["expanded_root_normalization_branch_splits"] = list(
            _summary_sequence_8616(expanded_summary, "normalization_branch_splits")
        )
        summary["expanded_root_normalization_branch_subtrees"] = list(
            _summary_sequence_8616(expanded_summary, "normalization_branch_subtrees")
        )
        summary["expanded_root_normalized_case_values"] = list(
            _summary_sequence_8616(expanded_summary, "normalized_case_values")
        )
        summary["expanded_root_partition_status"] = expanded_summary.get("partition_status")
        summary["expanded_root_normalization_readiness"] = _summary_mapping_8616(
            expanded_summary, "normalization_readiness"
        )


def _collect_edge_guard_decision_tree_cases_8616(
    graph: RegionGraph,
    region: Region,
    *,
    include_expanded_root: bool = True,
    include_branch_split_subtrees: bool = True,
    initial_affine_offset: int = 0,
    loopback_region: Region | None = None,
    max_depth: int = 64,
    stop_regions: tuple[Region, ...] = (),
) -> dict[str, object]:
    """Collect equality case leaves from a mixed switch decision tree.

    This is diagnostic-only until all branch predicates in the tree can be
    proven to partition the same switch expression.
    """
    scan = _DecisionTreeScan8616(
        graph,
        include_branch_split_subtrees=include_branch_split_subtrees,
        stop_region_set=set(stop_regions),
        loopback_target=loopback_region or region,
    )
    pending: list[tuple[Region, int, int, bool, tuple[object, ...] | None]] = [
        (region, 0, initial_affine_offset, True, None)
    ]

    while pending:
        current, depth, affine_offset, default_eligible_path, last_affine_semantics = pending.pop(0)
        if current in scan.stop_region_set or current in scan.visited or current not in graph.nodes:
            continue
        scan.visited.add(current)
        if depth > max_depth:
            continue

        current_cases = _region_edge_guard_cases_8616(graph, current)
        for case_region, guard, value in current_cases:
            scan.record_case(case_region, guard, value, affine_offset, last_affine_semantics)

        if not current_cases and scan.record_empty_region(current, default_eligible_path):
            continue

        for succ in graph.successors(current):
            if any(succ is case_region for case_region, _guard, _value in current_cases):
                continue
            scan.record_branch_split(current, succ, current_cases, depth, affine_offset, max_depth)
            step = scan.continuation_step(
                current, succ, current_cases, affine_offset, last_affine_semantics, default_eligible_path
            )
            if step is None:
                continue
            next_affine_offset, next_last_affine_semantics, next_default_eligible = step
            pending.append(
                (succ, depth + 1, next_affine_offset, next_default_eligible, next_last_affine_semantics)
            )

    summary = scan.summary(region)
    if include_expanded_root:
        _attach_expanded_root_summary_8616(graph, region, summary, max_depth)
    return summary


class TypedEdgeSwitchRegionStatus8616(Enum):
    """Typed structuring-layer status for edge-guard switch artifacts."""

    PartialLadder = "partial_ladder"
    Ready = "ready"


def _reachable_edge_guarded_successor_count_8616(
    graph: RegionGraph,
    start: Region | None,
    *,
    excluded: tuple[Region, ...] = (),
    limit: int = 128,
) -> int:
    """Count remaining edge-guarded case successors below a candidate default."""
    if start is None or start not in graph.nodes:
        return 0
    excluded_set = set(excluded)
    pending: list[Region] = [start]
    visited: set[Region] = set()
    count = 0
    while pending and len(visited) < limit:
        current = pending.pop()
        if current in visited or current in excluded_set or current not in graph.nodes:
            continue
        visited.add(current)
        for succ in graph.successors(current):
            if succ in excluded_set:
                continue
            if _single_eq_edge_guard_8616(succ) is not None:
                count += 1
                continue
            if succ not in visited:
                pending.append(succ)
    return count


def _typed_edge_switch_region_artifact_8616(
    region: Region,
    *,
    cases: tuple[Region, ...],
    case_values: tuple[int, ...],
    default_target: Region | None,
    guard_statement_addrs: tuple[int, ...],
    guard_statement_keys: tuple[tuple[str, int, int], ...],
    guard_span_complete: bool,
    decision_tree_summary: dict[str, object] | None,
    remaining_edge_guard_count: int,
    status: TypedEdgeSwitchRegionStatus8616,
    switch_condition_lhs: object | None,
) -> dict[str, object]:
    """Build a serializable structuring-layer switch artifact."""
    lhs_payload = (
        switch_condition_lhs.to_dict() if isinstance(switch_condition_lhs, _SerializableCondition8616) else None
    )
    summary = dict(decision_tree_summary or {})
    decision_tree_case_region_ids = [
        int(region_id) for region_id in _summary_sequence_8616(summary, "case_region_ids") if isinstance(region_id, int)
    ]
    decision_tree_case_values = [
        int(value) for value in _summary_sequence_8616(summary, "case_values") if isinstance(value, int)
    ]
    return {
        "status": status.value,
        "owner": "structuring.analysis",
        "detection": "typed_condition_edge_cascade",
        "decision_tree_case_region_ids": decision_tree_case_region_ids,
        "decision_tree_case_values": decision_tree_case_values,
        "decision_tree_summary": summary,
        "region_id": region.region_id,
        "case_region_ids": [case.region_id for case in cases],
        "case_values": list(case_values),
        "default_region_id": default_target.region_id if default_target is not None else None,
        "guard_statement_addr_count": len(guard_statement_addrs),
        "guard_statement_key_count": len(guard_statement_keys),
        "guard_span_complete": bool(guard_span_complete),
        "remaining_edge_guard_count": int(remaining_edge_guard_count),
        "status_reason": "default_subtree_contains_edge_guards"
        if status == TypedEdgeSwitchRegionStatus8616.PartialLadder
        else None,
        "switch_condition_lhs": lhs_payload,
    }


@dataclass
class StructuringStats:
    """Statistics about the structuring process."""

    iterations: int = 0
    regions_reduced: int = 0
    cycles_resolved: int = 0
    sequences_created: int = 0
    max_iterations_reached: bool = False
    had_unstructured_gotos: bool = False
    edge_guard_switches_detected: int = 0


def _cascade_guarded_successors_8616(succs: list[Region]) -> list[tuple[Region, ConditionIR, int]]:
    """Collect successors carrying a single constant equality edge guard."""
    guarded_successors: list[tuple[Region, ConditionIR, int]] = []
    for succ in succs:
        guard = _single_eq_edge_guard_8616(succ)
        if guard is None:
            continue
        value = _condition_const_value_8616(guard.rhs)
        if value is None:
            continue
        guarded_successors.append((succ, guard, value))
    return guarded_successors


@dataclass(slots=True)
class _CascadeScan8616:
    """Accumulating state for the edge-guard cascade scan."""

    cases: list[Region] = field(default_factory=list)
    case_values: list[int] = field(default_factory=list)
    guard_statement_addrs: list[int] = field(default_factory=list)
    guard_statement_keys: list[tuple[str, int, int]] = field(default_factory=list)
    guard_span_complete: bool = True
    lhs_key: object | None = None

    def record_case_guard(self, guard: ConditionIR, value: int) -> bool:
        """Accept a same-LHS unique-valued case guard; return False to stop."""
        if self.lhs_key is None:
            self.lhs_key = guard.lhs
        elif guard.lhs != self.lhs_key:
            return False
        return value not in self.case_values

    def record_guard_span(
        self,
        addrs: list[int],
        keys: list[tuple[str, int, int]],
    ) -> None:
        """Record one condition region's guard statement span."""
        if addrs:
            self.guard_statement_addrs.extend(addrs)
        else:
            self.guard_span_complete = False
        if keys:
            self.guard_statement_keys.extend(keys)

class StructureAnalysis:
    """Main control-flow structuring algorithm.

    This class takes a region graph and iteratively refines it into structured
    control-flow patterns through pattern matching and selective refinement.
    """

    # Maximum iterations before giving up (matches Reko)
    MAX_ITERATIONS = 1000

    def __init__(
        self,
        graph: RegionGraph,
        event_listener: Callable[[str], None] | None = None,
        max_iterations: int = MAX_ITERATIONS,
    ) -> None:
        """Initialize the structuring analyzer.

        Args:
            graph: The region graph to structure
            event_listener: Optional callback for diagnostic messages
            max_iterations: Maximum iterations before stopping
        """
        self.graph = graph
        self.event_listener = event_listener or (lambda msg: None)
        self.max_iterations = max_iterations
        self.dominators: DominatorInfo | None = None
        self.stats = StructuringStats()
        self.natural_loop_topologies: dict[int, NaturalLoopTopology8616] = {}
        self.unresolved_switches: list[Region] = []

    def structure(self) -> RegionGraph:
        """Perform control-flow structuring on the region graph.

        Returns:
            The refined region graph
        """
        return self._execute()

    def _execute(self) -> RegionGraph:
        """Core structuring algorithm.

        Iteratively:
        1. Recompute dominators
        2. Visit regions in post-order
        3. Try to match acyclic patterns
        4. Try to match cyclic patterns
        5. If no progress, apply refinement strategies
        6. Repeat until graph converges to a single region or max iterations
        """
        iterations = 0

        while True:
            iterations += 1
            self.stats.iterations = iterations

            # Check cancellation
            self.event_listener(f"Structuring iteration {iterations}")

            # Check iteration limit
            if iterations > self.max_iterations:
                logger.warning(
                    "Structure analysis stopped due to iteration limit (%d). Control flow may not be fully structured.",
                    self.max_iterations,
                )
                self.stats.max_iterations_reached = True
                break

            if self._structure_iteration_8616():
                break

        return self.graph

    def _structure_iteration_8616(self) -> bool:
        """Run one structuring pass; return True when the pass converged."""
        # Recompute dominators for this iteration
        self.dominators = compute_dominators(self.graph)

        # Track progress
        old_node_count = len(self.graph.nodes)

        # Reset evidence and unresolved switches for this iteration
        self.natural_loop_topologies.clear()
        self.unresolved_switches.clear()

        for region in sorted(self.graph.nodes, key=lambda item: item.region_id or 0):
            if self._try_edge_guard_switch_cascade(region):
                self.stats.regions_reduced += 1

        # Visit regions in post-order
        post_order = self.graph.iter_postorder()

        for region in post_order:
            # Try to reduce acyclic regions
            reduced = self._reduce_acyclic(region)

            # If no acyclic reduction, try cyclic patterns
            if not reduced and self._is_cyclic(region):
                reduced = self._reduce_cyclic(region)

        # Check for progress
        new_node_count = len(self.graph.nodes)
        if new_node_count == old_node_count and new_node_count > 1:
            # No progress this round - try refinement strategies
            # But only if there are unresolved regions to process
            if self.unresolved_switches:
                self._process_unresolved_regions()
            else:
                # No unresolved regions and no progress - we're stuck
                # This is normal for well-structured CFGs that can't be fully reduced
                logger.debug(
                    "No progress and no unresolved regions, stopping at %d nodes",
                    new_node_count,
                )
                return True

        # Check convergence
        return len(self.graph.nodes) <= 1

    def _reduce_acyclic(self, region: Region) -> bool:
        """Try to match and reduce acyclic patterns.

        Acyclic patterns include:
        - Sequence (merge two linear regions)
        - If-then (merge condition with single branch)
        - If-then-else (merge condition with two branches)
        - If-cascade-to-switch (merge 3+ conditions on same expression)

        Args:
            region: Region to attempt to reduce

        Returns:
            True if a reduction occurred, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Try sequence first (linear merge)
        if self._try_sequence(region):
            self.stats.sequences_created += 1
            return True

        # Try switch pattern detection (before if-then patterns)
        if self._try_if_switch_cascade(region):
            self.stats.regions_reduced += 1
            return True

        # Try if-then pattern
        if self._try_if_then(region):
            self.stats.regions_reduced += 1
            return True

        # Try if-then-else pattern
        if self._try_if_then_else(region):
            self.stats.regions_reduced += 1
            return True

        return False

    def _reduce_cyclic(self, region: Region) -> bool:
        """Try to match and reduce cyclic patterns.

        Cyclic patterns are loops with special structure.

        Args:
            region: Region to attempt to reduce

        Returns:
            True if a reduction occurred, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Try to detect and reduce natural loop
        if self._try_natural_loop(region):
            self.stats.cycles_resolved += 1
            return True

        return False

    def _try_natural_loop(self, region: Region) -> bool:
        """Publish exact loop topology without reducing the region graph.

        Args:
            region: Candidate loop header region

        Returns:
            Always False because topology alone cannot authorize collapse
        """
        topology = self._detect_natural_loop(region)
        if topology is None:
            return False
        self.natural_loop_topologies[topology.header] = topology
        return False

    def _try_sequence(self, region: Region) -> bool:
        """Try to merge region into a sequence with its predecessor or successor.

        A sequence is two regions where one flows directly to the other.

        Args:
            region: Candidate region for sequence formation

        Returns:
            True if merge occurred, False otherwise
        """
        # Look for a single successor
        succs = self.graph.successors(region)
        if len(succs) == 1:
            succ = succs[0]
            if sequence_merge_is_safe(self.graph, self.dominators, region, succ):
                self.graph.merge_regions(succ, region, transfer_edges="succ")
                return True

        return False

    def _try_if_switch_cascade(self, region: Region) -> bool:
        """Try to detect and reduce an if-cascade pattern as a switch statement.

        An if-cascade is a sequence of if-else regions comparing the same
        expression against different constants. When 3+ branches are detected,
        this is a strong candidate for a switch statement.

        Args:
            region: Candidate region (typically a condition region)

        Returns:
            True if switch pattern was detected and region marked, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Skip if already marked as switch
        if region.region_type == RegionType.IncSwitch:
            return False

        # Check if this region has multiple successors (branch point)
        succs = self.graph.successors(region)
        if len(succs) < 3:
            return self._try_edge_guard_switch_cascade(region)

        # Mark as switch region - this indicates potential for switch statement
        # Full switch code generation happens in Phase 1.3
        region.region_type = RegionType.IncSwitch
        region.metadata["switch_candidates"] = list(succs)
        self.unresolved_switches.append(region)
        logger.debug(f"Marked region {region} as switch candidate with {len(succs)} branches")

        return True  # Count as processed since we marked it

    def _try_edge_guard_switch_cascade(self, region: Region) -> bool:
        """Detect binary comparison cascades whose case targets carry edge guards."""
        if region not in self.graph.nodes:
            return False
        if region.region_type == RegionType.IncSwitch:
            return False

        scan = _CascadeScan8616()
        current = region
        visited: set[Region] = set()

        while current in self.graph.nodes and current not in visited:
            visited.add(current)
            next_region = self._cascade_step_8616(current, visited, scan)
            if next_region is None:
                break
            current = next_region

        if len(scan.cases) < 3:
            return False

        self._publish_edge_guard_cascade_8616(region, scan, current)
        return True

    def _cascade_step_8616(
        self,
        current: Region,
        visited: set[Region],
        scan: _CascadeScan8616,
    ) -> Region | None:
        """Advance the edge-guard cascade one condition region."""
        succs = self.graph.successors(current)
        if len(succs) != 2:
            return None

        guarded_successors = _cascade_guarded_successors_8616(succs)
        if len(guarded_successors) != 1:
            return None

        case_region, guard, value = guarded_successors[0]
        if not scan.record_case_guard(guard, value):
            return None
        scan.cases.append(case_region)
        scan.case_values.append(value)
        scan.record_guard_span(_region_statement_ins_addrs_8616(current), _region_statement_provenance_keys_8616(current))

        next_regions = [succ for succ in succs if succ is not case_region]
        if len(next_regions) != 1:
            return None
        next_region, skipped_addrs, skipped_keys, skipped_complete = self._find_next_edge_guard_switch_head_8616(
            next_regions[0],
            visited,
        )
        if skipped_addrs:
            scan.guard_statement_addrs.extend(skipped_addrs)
        if skipped_keys:
            scan.guard_statement_keys.extend(skipped_keys)
        if not skipped_complete:
            scan.guard_span_complete = False
        return next_region

    def _publish_edge_guard_cascade_8616(
        self,
        region: Region,
        scan: _CascadeScan8616,
        current: Region,
    ) -> None:
        """Publish the accumulated cascade as a typed edge-guard switch."""
        region.region_type = RegionType.IncSwitch
        region.metadata["switch_candidates"] = scan.cases
        region.metadata["switch_case_values"] = tuple(scan.case_values)
        region.metadata["switch_condition_lhs"] = scan.lhs_key
        region.metadata["switch_detection"] = "typed_condition_edge_cascade"
        if scan.guard_span_complete:
            region.metadata["switch_guard_statement_ins_addrs"] = tuple(dict.fromkeys(scan.guard_statement_addrs))
            region.metadata["switch_guard_statement_span_source"] = "condition_region_statement_ins_addrs"
        if scan.guard_statement_keys:
            region.metadata["switch_guard_statement_provenance_keys"] = tuple(
                dict.fromkeys(scan.guard_statement_keys)
            )
        default_target = current if current in self.graph.nodes and current not in scan.cases else None
        if default_target is not None:
            region.metadata["switch_default_target"] = current
        remaining_edge_guard_count = _reachable_edge_guarded_successor_count_8616(
            self.graph,
            default_target,
            excluded=tuple(scan.cases),
        )
        decision_tree_summary = _collect_edge_guard_decision_tree_cases_8616(self.graph, region)
        artifact_status = (
            TypedEdgeSwitchRegionStatus8616.PartialLadder
            if remaining_edge_guard_count
            else TypedEdgeSwitchRegionStatus8616.Ready
        )
        region.metadata["typed_edge_switch_region_status"] = artifact_status.value
        region.metadata["typed_edge_switch_region_artifact"] = _typed_edge_switch_region_artifact_8616(
            region,
            cases=tuple(scan.cases),
            case_values=tuple(scan.case_values),
            default_target=default_target,
            guard_statement_addrs=tuple(dict.fromkeys(scan.guard_statement_addrs)),
            guard_statement_keys=tuple(dict.fromkeys(scan.guard_statement_keys)),
            guard_span_complete=scan.guard_span_complete,
            decision_tree_summary={key: value for key, value in decision_tree_summary.items() if key != "lhs"},
            remaining_edge_guard_count=remaining_edge_guard_count,
            status=artifact_status,
            switch_condition_lhs=scan.lhs_key,
        )
        region.metadata["typed_edge_switch_decision_tree_summary"] = {
            key: value for key, value in decision_tree_summary.items() if key != "lhs"
        }
        self.unresolved_switches.append(region)
        self.stats.edge_guard_switches_detected += 1
        logger.debug(
            "Marked region %s as typed edge-guard switch candidate with %d cases",
            region,
            len(scan.cases),
        )

    def _find_next_edge_guard_switch_head_8616(
        self,
        region: Region,
        visited: set[Region],
    ) -> tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool]:
        """Find the next unambiguous eq-guard switch head through continuation blocks."""
        if region not in self.graph.nodes or region in visited:
            return region, (), (), True
        if _region_is_eq_switch_head_8616(self.graph, region):
            return region, (), (), True

        candidates: list[tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool]] = []
        worklist: list[tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool, int]] = [
            (region, (), (), True, 0)
        ]
        seen: set[Region] = set()
        while worklist:
            current, path_addrs, path_keys, path_complete, depth = worklist.pop(0)
            found, pushes = self._next_head_walk_step_8616(
                current, path_addrs, path_keys, path_complete, depth, seen, visited
            )
            candidates.extend(found)
            worklist.extend(pushes)

        unique: dict[int, tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool]] = {}
        for candidate, path_addrs, path_keys, path_complete in candidates:
            key = id(candidate)
            existing = unique.get(key)
            if existing is None or len(path_addrs) < len(existing[1]):
                unique[key] = (candidate, path_addrs, path_keys, path_complete)
        if len(unique) == 1:
            return next(iter(unique.values()))
        return region, (), (), True

    def _next_head_walk_step_8616(
        self,
        current: Region,
        path_addrs: tuple[int, ...],
        path_keys: tuple[tuple[str, int, int], ...],
        path_complete: bool,
        depth: int,
        seen: set[Region],
        visited: set[Region],
    ) -> tuple[
        list[tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool]],
        list[tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool, int]],
    ]:
        """Process one walk item; return (found head candidates, worklist pushes)."""
        if current in seen or current in visited or current not in self.graph.nodes:
            return [], []
        seen.add(current)
        if _region_has_typed_edge_guard_8616(current):
            return [], []
        current_addrs = _region_statement_ins_addrs_8616(current)
        current_keys = _region_statement_provenance_keys_8616(current)
        next_path_addrs = (*path_addrs, *current_addrs)
        next_path_keys = (*path_keys, *current_keys)
        next_path_complete = path_complete and bool(current_addrs)
        if _region_is_eq_switch_head_8616(self.graph, current):
            return [(current, path_addrs, path_keys, path_complete)], []
        if depth >= 8:
            return [], []
        found: list[tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool]] = []
        pushes: list[tuple[Region, tuple[int, ...], tuple[tuple[str, int, int], ...], bool, int]] = []
        for succ in sorted(self.graph.successors(current), key=lambda item: item.region_id or 0):
            if _single_eq_edge_guard_8616(succ) is not None:
                continue
            if _region_is_eq_switch_head_8616(self.graph, succ):
                found.append((succ, next_path_addrs, next_path_keys, next_path_complete))
                continue
            pushes.append((succ, next_path_addrs, next_path_keys, next_path_complete, depth + 1))
        return found, pushes

    def _try_if_then(self, region: Region) -> bool:
        """Try to form an if-then pattern.

        If-then is: a condition region with exactly two successors where one
        is a straightforward branch and the other is a fall-through that only
        this region branches to.

        Args:
            region: Candidate condition region

        Returns:
            True if pattern found and merged, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Don't process if already marked as switch candidate
        if region.region_type == RegionType.IncSwitch:
            return False
        if self._is_cyclic(region):
            return False

        succs = self.graph.successors(region)
        if len(succs) != 2:
            return False

        # Check if either successor has only this region as predecessor
        # (meaning it's a dedicated then-block)
        for _i, succ in enumerate(succs):
            preds = self.graph.predecessors(succ)
            if len(preds) == 1 and succ in preds[0].successors:
                if merge_would_hide_cycle(self.graph, self.dominators, region, succ):
                    continue
                # This is a dedicated branch - merge it into region
                self.graph.merge_regions(succ, region, transfer_edges="succ")
                # Update region type to reflect it's now a condition structure
                if region.region_type == RegionType.Linear:
                    region.region_type = RegionType.Condition
                return True

        return False

    def _try_if_then_else(self, region: Region) -> bool:
        """Try to form an if-then-else pattern.

        If-then-else is: a condition region with exactly two branches that
        can be merged together as a complete if-then-else structure.

        Conservative: don't merge if the region itself is cyclic (has back-edges),
        to preserve loop detection.

        Args:
            region: Candidate condition region

        Returns:
            True if pattern found and merged, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Don't process if already marked as switch candidate
        if region.region_type == RegionType.IncSwitch:
            return False

        succs = self.graph.successors(region)
        if len(succs) != 2:
            return False

        # Don't merge if this region is cyclic (has back-edges to it)
        # This preserves the ability to detect loops
        if self._is_cyclic(region):
            return False

        # Try to merge both branches into the condition region
        # This creates a complete if-then-else structure
        branch1, branch2 = succs
        if merge_would_hide_cycle(self.graph, self.dominators, region, branch1):
            return False
        if merge_would_hide_cycle(self.graph, self.dominators, region, branch2):
            return False

        return self._merge_if_then_else_8616(region, branch1, branch2)

    def _merge_if_then_else_8616(self, region: Region, branch1: Region, branch2: Region) -> bool:
        """Merge both branches into the condition region."""
        try:
            # Merge first branch
            if branch1 in self.graph.nodes:
                self.graph.merge_regions(branch1, region, transfer_edges="succ")

            # Merge second branch (if still present after first merge)
            if branch2 in self.graph.nodes and branch2 != region:
                self.graph.merge_regions(branch2, region, transfer_edges="succ")

            # Mark region as a condition structure
            region.region_type = RegionType.Condition
            return True
        except Exception as e:
            logger.debug(f"Failed to merge if-then-else branches: {e}")
            return False

    def _is_cyclic(self, region: Region) -> bool:
        """Check if a region is part of a cycle (back edge exists).

        A region is cyclic if any of its predecessors is dominated by it.

        Args:
            region: Region to check

        Returns:
            True if region is cyclic, False otherwise
        """
        if self.dominators is None:
            return False

        preds = self.graph.predecessors(region)
        return any(self.dominators.strictly_dominates(region, pred) for pred in preds)

    def _detect_natural_loop(self, region: Region) -> NaturalLoopTopology8616 | None:
        """Return typed topology evidence for one dominance-backed header."""
        if self.dominators is None:
            self.dominators = compute_dominators(self.graph)
        return detect_natural_loop(
            self.graph,
            self.dominators,
            region,
        )

    def _process_unresolved_regions(self) -> None:
        """Apply refinement strategies for unstructured regions.

        When the main algorithm makes no progress, we apply last-resort
        refinement strategies to ensure forward progress:
        - Convert remaining multi-exit regions to explicit gotos
        """
        if not self.unresolved_switches:
            # No unresolved regions to process - fall back to goto refinement
            self._refine_to_gotos()
            return

        # Process unresolved switches
        for region in self.unresolved_switches:
            region.region_type = RegionType.IncSwitch

    def _refine_to_gotos(self) -> None:
        """Last-resort refinement: convert unstructured regions to explicit gotos.

        When no structuring pattern matches, we create explicit goto metadata
        to preserve the control flow while admitting we can't structure it.
        """
        # Find all regions with multiple successors that haven't been reduced
        unstructured = [
            r for r in self.graph.nodes if r.region_type == RegionType.Linear and len(self.graph.successors(r)) > 1
        ]

        for region in unstructured:
            # Create labeled exits for each successor
            for i, succ in enumerate(self.graph.successors(region)):
                label = f"__unstructured_{region.region_id:x}_{i}"
                existing_exits = region.metadata.get("goto_exits")
                exits = existing_exits if isinstance(existing_exits, list) else []
                exits.append((succ, label))
                region.metadata["goto_exits"] = exits

            self.stats.had_unstructured_gotos = True

        if unstructured:
            logger.debug(f"Applied goto refinement for {len(unstructured)} unstructured regions")
        else:
            logger.debug("No unstructured regions to refine to gotos")


class RegionBasedStructuringPass:
    """A decompiler pass that applies region-based structuring to codegen.

    This is the interface between the decompiler pass framework and the
    structuring algorithm.
    """

    def __init__(self) -> None:
        """Initialize the pass."""
        self.stats = StructuringStats()

    def __call__(self, codegen: object) -> bool:
        """Apply region-based structuring to codegen."""

        def _impl() -> bool:
            codegen_dynamic = cast(Any, codegen)
            if getattr(codegen_dynamic, "cfunc", None) is None:
                return False

            try:
                # Build region graph from the decompiler's AIL/Clinic graph
                graph, entry = self._build_region_graph(codegen)
                if graph is None or entry is None or len(graph.nodes) < 2:
                    # Nothing to structure
                    return False

                # Run StructureAnalysis
                analysis = StructureAnalysis(graph)
                structured = analysis.structure()
                self.stats = analysis.stats

                # Record structuring stats on cfunc metadata
                cfunc = codegen_dynamic.cfunc
                if not hasattr(cfunc, "_structuring_stats"):
                    cfunc._structuring_stats = {}
                cfunc._structuring_stats["iterations"] = self.stats.iterations
                cfunc._structuring_stats["regions_reduced"] = self.stats.regions_reduced
                cfunc._structuring_stats["cycles_resolved"] = self.stats.cycles_resolved
                cfunc._structuring_stats["sequences_created"] = self.stats.sequences_created
                cfunc._structuring_stats["final_node_count"] = len(structured.nodes)

                # Record structured region types on cfunc
                structured_regions = [
                    {
                        "addr": region.block_addr,
                        "type": region.region_type.value,
                        "metadata_keys": list(region.metadata.keys()),
                    }
                    for region in structured.nodes
                    if region.region_type != RegionType.Linear
                ]
                cfunc._structuring_stats["structured_regions"] = structured_regions

                # Return True if any structuring occurred
                changed = (
                    self.stats.regions_reduced > 0 or self.stats.cycles_resolved > 0 or self.stats.sequences_created > 0
                )
                return changed
            except Exception as ex:
                logger.warning("Region-based structuring pass failed: %s", ex)
                return False

        return _impl()

    def _build_region_graph(self, codegen: object) -> tuple[RegionGraph | None, Region | None]:
        result = build_region_graph(codegen)
        return result.graph, result.entry


def apply_region_based_structuring(codegen: object) -> bool:
    """Apply region-based structuring pass to codegen.

    This is the entry point for the decompiler framework.

    Args:
        codegen: The codegen object to structure

    Returns:
        True if changes were made, False otherwise
    """
    pass_instance = RegionBasedStructuringPass()
    return pass_instance(codegen)
