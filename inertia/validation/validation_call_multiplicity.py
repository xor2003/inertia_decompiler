"""Validate exact callsite multiplicity in the final structured C AST.

Layer: Tail validation.
Responsibility: compare binary-required callsite identities with the number of
final C call nodes carrying each exact instruction address.
Forbidden: target-name inference, rendered-C/assembly inspection, AST repair,
or treating an untagged call as evidence for or against multiplicity.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

import logging
import os
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from inertia.lowering.c_ast_utils import (
    _iter_c_node_occurrences_8616,
    _structured_codegen_node_8616,
    _structured_slot_names_8616,
)
from inertia.semantics.callsite_summary import CallsiteSummary8616, callsite_summary_inventory_8616

log: logging.Logger = logging.getLogger(__name__)

__all__ = [
    "CallsiteMultiplicityIssue8616",
    "CallsiteMultiplicityIssueKind8616",
    "CallsiteMultiplicityValidationReport8616",
    "validate_required_callsite_multiplicity_8616",
]


class _CodegenCallsiteSurface8616(Protocol):
    """Dynamic angr codegen metadata consumed by final call validation."""

    _inertia_callsite_summaries: object


class _CallTargetFunction8616(Protocol):
    """Dynamic third-party function target used for exact target identity."""

    addr: int


def _iter_c_node_occurrence_paths_8616(
    value: object,
    path: str = "root",
    active_node_ids: frozenset[int] = frozenset(),
) -> Iterator[tuple[object, str]]:
    """Yield render-authoritative AST occurrences with diagnostic edge paths."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _iter_c_node_occurrence_paths_8616(
                child,
                f"{path}[{key!r}]",
                active_node_ids,
            )
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _iter_c_node_occurrence_paths_8616(
                child,
                f"{path}[{index}]",
                active_node_ids,
            )
        return
    if not _structured_codegen_node_8616(value):
        return
    node_id = id(value)
    if node_id in active_node_ids:
        return
    yield value, path
    child_active_ids = active_node_ids | {node_id}
    for attr in _structured_slot_names_8616(value):
        try:
            # Dynamic third-party angr C-AST boundary: child slots vary by release.
            child = getattr(value, attr)
        except Exception:
            continue
        yield from _iter_c_node_occurrence_paths_8616(
            child,
            f"{path}.{attr}",
            child_active_ids,
        )


class CallsiteMultiplicityIssueKind8616(StrEnum):
    """Typed contradictions between one machine callsite and final C calls."""

    DUPLICATE_FINAL_CALLSITE = "duplicate-final-callsite"
    DUPLICATE_FINAL_TARGET = "duplicate-final-target"


@dataclass(frozen=True, slots=True)
class CallsiteMultiplicityIssue8616:
    """One binary callsite projected more than once into final structured C."""

    kind: CallsiteMultiplicityIssueKind8616
    callsite_addr: int | None
    target_addr: int | None
    actual_count: int
    expected_count: int = 1

    def token(self) -> str:
        """Return a deterministic token for tail-validation diagnostics."""
        callsite = "aggregate" if self.callsite_addr is None else f"{self.callsite_addr:#x}"
        target = "unknown" if self.target_addr is None else f"{self.target_addr:#x}"
        return (
            f"callsite-multiplicity:{self.kind}:callsite={callsite}:"
            f"target={target}:expected={self.expected_count}:actual={self.actual_count}"
        )


@dataclass(frozen=True, slots=True)
class CallsiteMultiplicityValidationReport8616:
    """Closed evidence-loop counters for exact final callsite multiplicity."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[CallsiteMultiplicityIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every observed required callsite appears exactly once."""
        return self.failure_count == 0 and self.classified_fact_count == self.materialized_count

    def issue_tokens(self) -> tuple[str, ...]:
        """Return deterministic issue tokens for canonical tail snapshots."""
        return tuple(issue.token() for issue in self.issues)


def _required_targets_by_callsite_8616(codegen: object) -> dict[int, tuple[int, ...]]:
    """Return exact binary target evidence grouped by required callsite address."""
    inventory = callsite_summary_inventory_8616(codegen)
    if inventory:
        raw_summary_source: object = inventory
    else:
        try:
            raw_summary_source = cast(_CodegenCallsiteSurface8616, codegen)._inertia_callsite_summaries
        except AttributeError:
            return {}
    if not isinstance(raw_summary_source, Mapping):
        return {}
    targets: defaultdict[int, set[int]] = defaultdict(set)
    for summary in raw_summary_source.values():
        if (
            isinstance(summary, CallsiteSummary8616)
            and not summary.stack_probe_helper
            and isinstance(summary.target_addr, int)
        ):
            targets[summary.callsite_addr].add(summary.target_addr)
    return {
        callsite_addr: tuple(sorted(callsite_targets))
        for callsite_addr, callsite_targets in targets.items()
    }


def _callsite_addr_8616(call: CFunctionCall) -> int | None:
    """Return exact instruction identity retained on a third-party C call."""
    tags = call.tags
    try:
        get_tag = tags.get
    except AttributeError:
        return None
    for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
        value = get_tag(key)
        if isinstance(value, int):
            return value
    return None


def _call_target_addr_8616(codegen: object, call: CFunctionCall) -> int | None:
    """Return exact target identity from owned summary or third-party function."""
    try:
        summaries = cast(_CodegenCallsiteSurface8616, codegen)._inertia_callsite_summaries
    except AttributeError:
        summaries = None
    if isinstance(summaries, Mapping):
        summary = summaries.get(id(call))
        if isinstance(summary, CallsiteSummary8616) and isinstance(summary.target_addr, int):
            return summary.target_addr
    callee_func = call.callee_func
    if callee_func is not None:
        try:
            target_addr = cast(_CallTargetFunction8616, callee_func).addr
        except AttributeError:
            target_addr = None
        if isinstance(target_addr, int):
            return target_addr
    return call.callee_target if isinstance(call.callee_target, int) else None


def validate_required_callsite_multiplicity_8616(
    codegen: object,
    root: object,
) -> CallsiteMultiplicityValidationReport8616:
    """Reject duplicate final calls proven to represent one machine callsite."""
    targets_by_callsite = _required_targets_by_callsite_8616(codegen)
    if not targets_by_callsite:
        return CallsiteMultiplicityValidationReport8616()

    required_by_target: Counter[int] = Counter(
        targets[0]
        for targets in targets_by_callsite.values()
        if len(targets) == 1
    )
    observed: Counter[int] = Counter()
    observed_by_target: Counter[int] = Counter()
    debug_occurrences: defaultdict[int, list[tuple[int, int | None]]] = defaultdict(list)
    for node in _iter_c_node_occurrences_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        callsite_addr = _callsite_addr_8616(node)
        if callsite_addr in targets_by_callsite:
            observed[callsite_addr] += 1
        target_addr = _call_target_addr_8616(codegen, node)
        if target_addr is not None and target_addr in required_by_target:
            observed_by_target[target_addr] += 1
        if callsite_addr in targets_by_callsite:
            debug_occurrences[callsite_addr].append((id(node), target_addr))

    if os.environ.get("INERTIA_DEBUG_CALLSITE_MULTIPLICITY") == "1":
        occurrence_paths = tuple(
            (callsite_addr, id(node), path)
            for node, path in _iter_c_node_occurrence_paths_8616(root)
            if isinstance(node, CFunctionCall)
            for callsite_addr in (_callsite_addr_8616(node),)
            if callsite_addr in targets_by_callsite
        )
        log.warning(
            "[callsite-multiplicity] required=%r observed=%r occurrences=%r paths=%r",
            targets_by_callsite,
            dict(sorted(observed.items())),
            tuple(
                (callsite_addr, tuple(occurrences))
                for callsite_addr, occurrences in sorted(debug_occurrences.items())
            ),
            occurrence_paths,
        )

    callsite_issues = tuple(
        CallsiteMultiplicityIssue8616(
            kind=CallsiteMultiplicityIssueKind8616.DUPLICATE_FINAL_CALLSITE,
            callsite_addr=callsite_addr,
            target_addr=(targets[0] if len(targets) == 1 else None),
            actual_count=count,
        )
        for callsite_addr, count in sorted(observed.items())
        if count > 1
        for targets in (targets_by_callsite[callsite_addr],)
    )
    callsite_issue_targets = frozenset(
        issue.target_addr
        for issue in callsite_issues
        if isinstance(issue.target_addr, int)
    )
    target_issues = tuple(
        CallsiteMultiplicityIssue8616(
            kind=CallsiteMultiplicityIssueKind8616.DUPLICATE_FINAL_TARGET,
            callsite_addr=None,
            target_addr=target_addr,
            actual_count=count,
            expected_count=required_by_target[target_addr],
        )
        for target_addr, count in sorted(observed_by_target.items())
        if count > required_by_target[target_addr]
        and target_addr not in callsite_issue_targets
    )
    issues = (*callsite_issues, *target_issues)
    return CallsiteMultiplicityValidationReport8616(
        raw_fact_count=max(sum(observed.values()), sum(observed_by_target.values())),
        normalized_fact_count=len(observed),
        classified_fact_count=len(observed),
        materialized_count=sum(count == 1 for count in observed.values()),
        failure_count=len(issues),
        issues=issues,
    )
