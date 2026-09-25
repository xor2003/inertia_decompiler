"""Remove duplicated unused-call projections from self-XOR expressions.

Layer: Structuring.
Responsibility: retain one exact machine-call side effect while replacing a
regenerated ``call ^ call`` value projection with its proven zero value.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This owner consumes typed callsite summaries and exact structured C-AST
identity. It does not infer call targets from names, recover return types, or
inspect rendered C. Missing or conflicting evidence is an explicit refusal.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616

__all__ = (
    "UnusedCallResultSelfXorResult8616",
    "UnusedCallResultSelfXorStats8616",
    "UnusedCallResultSelfXorVerdict8616",
    "materialize_unused_call_result_self_xor_8616",
)


class UnusedCallResultSelfXorVerdict8616(StrEnum):
    """Typed outcome of unused call-result self-XOR materialization."""

    NO_CANDIDATE = "no_candidate"
    MATERIALIZED = "materialized"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(slots=True)
class UnusedCallResultSelfXorStats8616:
    """Closed evidence counters for unused call-result self-XOR facts."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class UnusedCallResultSelfXorResult8616:
    """Typed result published by the Structuring projection owner."""

    verdict: UnusedCallResultSelfXorVerdict8616
    stats: UnusedCallResultSelfXorStats8616

    @property
    def changed(self) -> bool:
        """Return whether one or more self-XOR projections were replaced."""
        return self.stats.materialized_count > 0


class _CFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by this Structuring owner."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Owned and third-party codegen fields consumed or published here."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_unused_call_result_self_xor_8616: UnusedCallResultSelfXorResult8616


def _direct_call_8616(node: object) -> structured_c.CFunctionCall | None:
    """Return a call evaluated directly by one structured statement."""
    if isinstance(node, structured_c.CExpressionStatement):
        return node.expr if isinstance(node.expr, structured_c.CFunctionCall) else None
    if isinstance(node, structured_c.CAssignment):
        return node.rhs if isinstance(node.rhs, structured_c.CFunctionCall) else None
    return None


def _summary_for_call_8616(
    call: structured_c.CFunctionCall,
    summary_map: dict[int, CallsiteSummary8616],
    inventory: dict[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve one call only from its owned identity or exact callsite tag."""
    summary = summary_map.get(id(call))
    if summary is not None:
        return summary
    callsite_addr = structured_callsite_addr_8616(call)
    if not isinstance(callsite_addr, int):
        return None
    summary = inventory.get(callsite_addr)
    if summary is not None:
        summary_map[id(call)] = summary
    return summary


def _retained_callsite_counts_8616(
    root: object,
    summary_map: dict[int, CallsiteSummary8616],
    inventory: dict[int, CallsiteSummary8616],
) -> dict[int, int]:
    """Count retained direct-call occurrences per proven callsite."""
    retained_counts: dict[int, int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        call = _direct_call_8616(node)
        if call is None:
            continue
        summary = _summary_for_call_8616(call, summary_map, inventory)
        if summary is not None:
            retained_counts[summary.callsite_addr] = retained_counts.get(summary.callsite_addr, 0) + 1
    return retained_counts


@dataclass(slots=True)
class _SelfXorReplace8616:
    """Classify and replace nested exact-call self-XOR candidates."""

    codegen: object
    stats: UnusedCallResultSelfXorStats8616
    summary_map: dict[int, CallsiteSummary8616]
    inventory: dict[int, CallsiteSummary8616]
    retained_counts: dict[int, int]

    def replace(self, node: object) -> object:
        """Classify and replace one nested exact-call self-XOR candidate."""
        if (
            not isinstance(node, structured_c.CBinaryOp)
            or node.op != "Xor"
            or not isinstance(node.lhs, structured_c.CFunctionCall)
            or not isinstance(node.rhs, structured_c.CFunctionCall)
        ):
            return node
        lhs_addr = structured_callsite_addr_8616(node.lhs)
        rhs_addr = structured_callsite_addr_8616(node.rhs)
        if node.lhs is not node.rhs and (
            not isinstance(lhs_addr, int) or lhs_addr != rhs_addr
        ):
            return node
        self.stats.raw_fact_count += 1
        lhs_summary = _summary_for_call_8616(node.lhs, self.summary_map, self.inventory)
        rhs_summary = _summary_for_call_8616(node.rhs, self.summary_map, self.inventory)
        if lhs_summary is None or rhs_summary is None or lhs_summary != rhs_summary:
            self.stats.failure_count += 1
            return node
        self.stats.normalized_fact_count += 1
        if lhs_summary.return_used is not False or self.retained_counts.get(
            lhs_summary.callsite_addr
        ) != 1:
            self.stats.failure_count += 1
            return node
        result_type = node.type
        if result_type is None:
            self.stats.failure_count += 1
            return node
        self.stats.classified_fact_count += 1
        self.stats.materialized_count += 1
        return structured_c.CConstant(0, result_type, codegen=self.codegen)


def materialize_unused_call_result_self_xor_8616(
    codegen: object,
) -> UnusedCallResultSelfXorResult8616:
    """Keep one unused call effect and replace its duplicated self-XOR value with zero."""
    boundary = cast(_CodegenSurface8616, codegen)
    stats = UnusedCallResultSelfXorStats8616()
    try:
        root = boundary.cfunc.statements
        summary_map = boundary._inertia_callsite_summaries
        inventory = boundary._inertia_callsite_summary_inventory_8616
    except AttributeError:
        result = UnusedCallResultSelfXorResult8616(
            UnusedCallResultSelfXorVerdict8616.NO_CANDIDATE,
            stats,
        )
        boundary._inertia_unused_call_result_self_xor_8616 = result
        return result
    if not isinstance(summary_map, dict) or not isinstance(inventory, dict):
        raise TypeError("unused call-result self-XOR requires typed callsite mappings")
    if any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in summary_map.items()
    ) or any(
        not isinstance(key, int)
        or not isinstance(summary, CallsiteSummary8616)
        or summary.callsite_addr != key
        for key, summary in inventory.items()
    ):
        raise TypeError("unused call-result self-XOR received an invalid owned contract")

    retained_counts = _retained_callsite_counts_8616(root, summary_map, inventory)

    scan = _SelfXorReplace8616(codegen, stats, summary_map, inventory, retained_counts)
    _replace_c_children_8616(root, scan.replace)
    verdict = (
        UnusedCallResultSelfXorVerdict8616.UNKNOWN_REFUSE
        if stats.failure_count
        else UnusedCallResultSelfXorVerdict8616.MATERIALIZED
        if stats.materialized_count
        else UnusedCallResultSelfXorVerdict8616.NO_CANDIDATE
    )
    result = UnusedCallResultSelfXorResult8616(verdict, stats)
    boundary._inertia_unused_call_result_self_xor_8616 = result
    return result
