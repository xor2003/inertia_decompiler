"""Validate binary-proven control-flow obligations against the final C AST.

Layer: Tail validation.
Responsibility: consume Structuring-owned typed exit evidence and report whether
the exact final AST still materializes every required function exit.
Forbidden: semantic recovery, AST mutation, rendered-C inspection, or repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CReturn,
    CStatements,
    CSwitchCase,
)

from .c_ast_utils import _iter_c_nodes_deep_8616
from .structuring.loop_body_repair import SwitchLoopExitReturnEvidence8616
from .structuring.shared_loop_exit import SharedLoopExitBinding8616, matching_shared_loop_exits_8616

_CASE_ENTRY_ARITY: int = 2

__all__ = [
    "ControlFlowObligationIssue8616",
    "ControlFlowObligationIssueKind8616",
    "ControlFlowObligationValidationReport8616",
    "switch_exit_obligations_from_codegen_8616",
    "validate_switch_exit_obligations_8616",
]


class ControlFlowObligationIssueKind8616(StrEnum):
    """Terminal failures while matching binary exit facts to structured C."""

    AMBIGUOUS_CASE = "ambiguous-case"
    CONFLICTING_EVIDENCE = "conflicting-evidence"
    INVALID_EVIDENCE = "invalid-evidence"
    MISSING_CASE = "missing-case"
    MISSING_TARGET_ANCHOR = "missing-target-anchor"
    WRONG_EXIT_SHAPE = "wrong-exit-shape"


@dataclass(frozen=True, slots=True)
class ControlFlowObligationIssue8616:
    """One binary-proven exit that the final structured AST did not satisfy."""

    kind: ControlFlowObligationIssueKind8616
    evidence_index: int
    case_value: int | None = None
    case_target: int | None = None
    exit_target: int | None = None
    match_count: int = 0

    def token(self) -> str:
        """Return a deterministic binary-evidence failure fingerprint."""
        case_value = "unknown" if self.case_value is None else str(self.case_value)
        case_target = "unknown" if self.case_target is None else f"{self.case_target:#x}"
        exit_target = "unknown" if self.exit_target is None else f"{self.exit_target:#x}"
        return (
            f"switch-exit:{self.kind.value}:index={self.evidence_index}:"
            f"case={case_value}:target={case_target}:exit={exit_target}:"
            f"matches={self.match_count}"
        )


@dataclass(frozen=True, slots=True)
class ControlFlowObligationValidationReport8616:
    """Closed evidence-loop report for final structured exit obligations."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    issues: tuple[ControlFlowObligationIssue8616, ...] = ()

    @property
    def failure_count(self) -> int:
        """Return the number of unsatisfied or malformed obligations."""
        return len(self.issues)

    @property
    def passed(self) -> bool:
        """Return whether every classified obligation has one exact exit."""
        return (
            self.failure_count == 0
            and self.classified_fact_count == self.materialized_count
        )

    def issue_tokens(self) -> tuple[str, ...]:
        """Return stable issue fingerprints for tail-validation summaries."""
        return tuple(issue.token() for issue in self.issues)


class _SwitchExitEvidenceCarrier8616(Protocol):
    """Dynamic codegen surface carrying Structuring-owned typed evidence."""

    _inertia_structuring_switch_loop_exit_return_evidence_8616: object


class _TaggedNode8616(Protocol):
    """Third-party C AST surface carrying instruction-address tags."""

    tags: Mapping[str, object] | None


def switch_exit_obligations_from_codegen_8616(codegen: object) -> tuple[object, ...]:
    """Read the exact Structuring evidence tuple from a dynamic codegen object."""
    surface = cast(_SwitchExitEvidenceCarrier8616, codegen)
    try:
        raw_evidence = surface._inertia_structuring_switch_loop_exit_return_evidence_8616
    except AttributeError:
        return ()
    if isinstance(raw_evidence, tuple):
        return cast(tuple[object, ...], raw_evidence)
    return (raw_evidence,)


def _node_tags_8616(node: object) -> Mapping[str, object]:
    """Read optional tags at the third-party C AST boundary."""
    tagged = cast(_TaggedNode8616, node)
    try:
        tags = tagged.tags
    except AttributeError:
        return {}
    return tags if isinstance(tags, Mapping) else {}


def _body_has_target_anchor_8616(body: object, target: int) -> bool:
    """Return whether a case body retains the exact binary case target."""
    if isinstance(body, CStatements) and body.addr == target:
        return True
    return any(
        _node_tags_8616(node).get("ins_addr") == target
        for node in (body, *_iter_c_nodes_deep_8616(body))
    )


def _body_is_unconditional_return_8616(body: object) -> bool:
    """Return whether a case body consists solely of a function return."""
    if isinstance(body, CReturn):
        return True
    if not isinstance(body, CStatements):
        return False
    statements = tuple(body.statements)
    return len(statements) == 1 and _body_is_unconditional_return_8616(statements[0])


def _case_values_8616(raw_value: object) -> tuple[int, ...]:
    """Normalize one third-party switch case key to explicit integer values."""
    if isinstance(raw_value, int):
        return (raw_value,)
    if isinstance(raw_value, tuple):
        return tuple(value for value in raw_value if isinstance(value, int))
    return ()


def _switch_case_entries_8616(switch: CSwitchCase) -> tuple[tuple[int, object], ...]:
    """Return normalized value/body pairs from supported angr switch surfaces."""
    raw_cases = switch.cases
    items: Iterable[tuple[object, object]]
    if isinstance(raw_cases, Mapping):
        items = raw_cases.items()
    else:
        items = (
            item
            for item in cast(Iterable[object], raw_cases)
            if isinstance(item, tuple) and len(item) == _CASE_ENTRY_ARITY
        )
    entries: list[tuple[int, object]] = []
    for raw_value, body in items:
        entries.extend((value, body) for value in _case_values_8616(raw_value))
    return tuple(entries)


def _case_bodies_8616(root: object, case_value: int) -> tuple[object, ...]:
    """Find all final switch bodies for one proven selector value."""
    bodies: list[object] = []
    seen: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, CSwitchCase):
            continue
        for value, body in _switch_case_entries_8616(node):
            if value != case_value or id(body) in seen:
                continue
            seen.add(id(body))
            bodies.append(body)
    return tuple(bodies)


def _valid_evidence_8616(evidence: SwitchLoopExitReturnEvidence8616) -> bool:
    """Return whether one owned evidence record has valid binary addresses."""
    return evidence.case_target >= 0 and evidence.exit_target >= 0


def _issue_8616(
    kind: ControlFlowObligationIssueKind8616,
    index: int,
    evidence: SwitchLoopExitReturnEvidence8616 | None,
    *,
    match_count: int = 0,
) -> ControlFlowObligationIssue8616:
    """Build one deterministic issue from optional typed evidence."""
    return ControlFlowObligationIssue8616(
        kind=kind,
        evidence_index=index,
        case_value=evidence.case_value if evidence is not None else None,
        case_target=evidence.case_target if evidence is not None else None,
        exit_target=evidence.exit_target if evidence is not None else None,
        match_count=match_count,
    )


def _literal_case_issue_8616(
    bodies: tuple[object, ...],
    index: int,
    evidence: SwitchLoopExitReturnEvidence8616,
) -> ControlFlowObligationIssue8616 | None:
    """Check target ownership and unconditional return shape of existing cases."""
    anchored = tuple(
        body for body in bodies if _body_has_target_anchor_8616(body, evidence.case_target)
    )
    if not anchored:
        return _issue_8616(
            ControlFlowObligationIssueKind8616.MISSING_TARGET_ANCHOR,
            index, evidence, match_count=len(bodies),
        )
    if len(anchored) != 1:
        return _issue_8616(
            ControlFlowObligationIssueKind8616.AMBIGUOUS_CASE,
            index, evidence, match_count=len(anchored),
        )
    if not _body_is_unconditional_return_8616(anchored[0]):
        return _issue_8616(
            ControlFlowObligationIssueKind8616.WRONG_EXIT_SHAPE,
            index, evidence, match_count=1,
        )
    return None


def validate_switch_exit_obligations_8616(
    root: object,
    evidence_items: tuple[object, ...],
    *,
    shared_bindings: tuple[SharedLoopExitBinding8616, ...] = (),
    fingerprint: Callable[[object], str] | None = None,
) -> ControlFlowObligationValidationReport8616:
    """Require an exact case return or an unchanged proven shared-epilogue exit."""
    normalized: list[tuple[int, SwitchLoopExitReturnEvidence8616]] = []
    issues: list[ControlFlowObligationIssue8616] = []
    seen: set[SwitchLoopExitReturnEvidence8616] = set()
    for index, item in enumerate(evidence_items):
        if not isinstance(item, SwitchLoopExitReturnEvidence8616) or not _valid_evidence_8616(item):
            issues.append(_issue_8616(ControlFlowObligationIssueKind8616.INVALID_EVIDENCE, index, None))
            continue
        if item in seen:
            continue
        seen.add(item)
        normalized.append((index, item))

    conflicting_keys = {
        (item.case_value, item.case_target)
        for _, item in normalized
        if len(
            {
                other.exit_target
                for _, other in normalized
                if other.case_value == item.case_value
                and other.case_target == item.case_target
            }
        )
        > 1
    }
    materialized_count = 0
    for index, evidence in normalized:
        if (evidence.case_value, evidence.case_target) in conflicting_keys:
            issues.append(
                _issue_8616(
                    ControlFlowObligationIssueKind8616.CONFLICTING_EVIDENCE,
                    index,
                    evidence,
                )
            )
            continue
        bodies = _case_bodies_8616(root, evidence.case_value)
        if not bodies:
            if fingerprint is not None and len(matching_shared_loop_exits_8616(root, evidence, shared_bindings, fingerprint)) == 1:
                materialized_count += 1
                continue
            issues.append(_issue_8616(ControlFlowObligationIssueKind8616.MISSING_CASE, index, evidence))
            continue
        case_issue = _literal_case_issue_8616(bodies, index, evidence)
        if case_issue is not None:
            issues.append(case_issue)
            continue
        materialized_count += 1

    normalized_count = len(normalized) + sum(
        issue.kind is ControlFlowObligationIssueKind8616.INVALID_EVIDENCE
        for issue in issues
    )
    return ControlFlowObligationValidationReport8616(
        raw_fact_count=len(evidence_items),
        normalized_fact_count=normalized_count,
        classified_fact_count=normalized_count,
        materialized_count=materialized_count,
        issues=tuple(issues),
    )
