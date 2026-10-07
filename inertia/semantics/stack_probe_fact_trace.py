"""Layer: Recovery metadata.

Responsibility: count stack-probe fact flow through existing recovery stages.
Forbidden: creating stack facts, hiding failures, or treating counts as proof.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .callsite_summary import CallsiteSummary8616

__all__ = [
    "STACK_PROBE_FACT_STAT_KEYS",
    "callsite_stack_probe_evidence_8616",
    "ensure_stack_probe_fact_stats_8616",
    "format_stack_probe_fact_stats_8616",
    "record_callsite_summary_fact_8616",
    "record_callsite_summary_map_facts_8616",
    "record_stable_ss_lowering_refusal_8616",
    "record_stable_ss_lowering_replacement_8616",
    "record_stack_arg_materialization_8616",
]

STACK_PROBE_FACT_STAT_KEYS: tuple[str, ...] = (
    "summaries_attached",
    "stack_probe_summaries",
    "ss_stack_address_returns",
    "stack_probe_calls_pruned",
    "stack_probe_calls_refused",
    "stack_arg_materializations",
    "stable_ss_lowering_replacements",
    "stable_ss_lowering_refusals",
    "callsite_count",
    "raw_fact_count",
    "normalized_fact_count",
    "classified_fact_count",
    "materialized_count",
    "call_target_fact_count",
    "call_target_materialized_count",
    "call_arg_fact_count",
    "call_arg_materialized_count",
    "bp_slot_arg_value_normalized_count",
    "pointer_arg_materialized_count",
    "push_order_reversed_count",
    "consumed_outgoing_stack_placeholder_count",
    "stale_target_rejected_count",
    "known_prototype_arg_mismatch_count",
    "has_push_arg_evidence_count",
    "no_push_arg_evidence_count",
    "source_proven_stack_probe_count",
    "byte_merge_raw_fact_count",
    "byte_merge_classified_fact_count",
    "byte_merge_materialized_count",
    "byte_merge_refused_count",
    "failure_count",
)


def callsite_stack_probe_evidence_8616(summary: object) -> tuple[bool, int | None]:
    """Return typed stack-probe classification and target from a callsite summary."""
    if not isinstance(summary, CallsiteSummary8616):
        return False, None
    return summary.stack_probe_helper, summary.target_addr


def ensure_stack_probe_fact_stats_8616(codegen: Any) -> dict[str, int]:
    """Return the per-codegen stack-probe fact trace counters."""
    stats = codegen._inertia_stack_probe_fact_stats if hasattr(codegen, "_inertia_stack_probe_fact_stats") else None
    if not isinstance(stats, dict):
        stats = dict.fromkeys(STACK_PROBE_FACT_STAT_KEYS, 0)
        codegen._inertia_stack_probe_fact_stats = stats
    for key in STACK_PROBE_FACT_STAT_KEYS:
        value = stats.get(key)
        if not isinstance(value, int):
            stats[key] = 0
    return stats


def _seen_tokens(codegen: Any) -> set[tuple[object, ...]]:
    seen = codegen._inertia_stack_probe_fact_seen if hasattr(codegen, "_inertia_stack_probe_fact_seen") else None
    if not isinstance(seen, set):
        seen = set()
        codegen._inertia_stack_probe_fact_seen = seen
    return seen


def record_callsite_summary_fact_8616(
    codegen: Any,
    summary: CallsiteSummary8616,
    *,
    node_id: int | None = None,
    attached: bool = False,
) -> None:
    """Count callsite facts once per summary identity without changing C output."""
    stats = ensure_stack_probe_fact_stats_8616(codegen)
    token = (
        "summary",
        node_id,
        summary.callsite_addr,
        summary.target_addr,
        summary.return_addr,
    )
    seen = _seen_tokens(codegen)
    if attached and ("attached", token) not in seen:
        stats["summaries_attached"] += 1
        seen.add(("attached", token))
    if token in seen:
        return
    seen.add(token)
    if summary.stack_probe_helper:
        stats["stack_probe_summaries"] += 1
        if summary.helper_return_state == "stack_address" and summary.helper_return_space == "ss":
            stats["ss_stack_address_returns"] += 1


def record_callsite_summary_map_facts_8616(codegen: Any, summary_map: Mapping[object, object] | None) -> None:
    """Record already-attached summary facts for focused diagnostics."""
    if not isinstance(summary_map, Mapping):
        return
    for node_id, summary in summary_map.items():
        if isinstance(summary, CallsiteSummary8616):
            record_callsite_summary_fact_8616(codegen, summary, node_id=node_id if isinstance(node_id, int) else None)


def record_stack_arg_materialization_8616(codegen: Any, count: int) -> None:
    """Count stack arguments converted into call arguments."""
    if count <= 0:
        return
    ensure_stack_probe_fact_stats_8616(codegen)["stack_arg_materializations"] += count


def record_stable_ss_lowering_replacement_8616(codegen: Any) -> None:
    """Count a successful stable-SS lowering callback pass."""
    ensure_stack_probe_fact_stats_8616(codegen)["stable_ss_lowering_replacements"] += 1


def record_stable_ss_lowering_refusal_8616(codegen: Any) -> None:
    """Count a lowering pass that saw typed SS facts but could not lower them."""
    ensure_stack_probe_fact_stats_8616(codegen)["stable_ss_lowering_refusals"] += 1


def format_stack_probe_fact_stats_8616(codegen: Any) -> str | None:
    """Return a deterministic compact trace string for debug logs."""
    stats = codegen._inertia_stack_probe_fact_stats if hasattr(codegen, "_inertia_stack_probe_fact_stats") else None
    if not isinstance(stats, dict):
        return None
    return " ".join(f"{key}={int(stats.get(key, 0) or 0)}" for key in STACK_PROBE_FACT_STAT_KEYS)
