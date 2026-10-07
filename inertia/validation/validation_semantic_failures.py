"""Classify semantic failures for final and intermediate validation gates.

Layer: Tail Validation.
Responsibility: select all or newly introduced structured semantic failures
when comparing two validation summaries.
Do not recover, rewrite, or suppress semantic evidence. Final validation must
use the complete after-state; intermediate pass gates may attribute only
failures introduced relative to their explicit before-state.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Protocol


class TailSemanticFailureScope8616(Enum):
    """Select which after-state semantic failures make validation fail."""

    ALL_AFTER = "all_after"
    INTRODUCED = "introduced"


class TailSemanticIssueSurface8616(Protocol):
    """Owned semantic-issue fields consumed from a validation summary."""

    @property
    def def_use_issues(self) -> tuple[str, ...]:
        """Return structured def-use failures."""
        ...

    @property
    def missing_required_calls(self) -> tuple[str, ...]:
        """Return missing binary-required calls."""
        ...

    @property
    def callsite_multiplicity_issues(self) -> tuple[str, ...]:
        """Return exact machine-callsite overmaterialization failures."""
        ...

    @property
    def call_interface_issues(self) -> tuple[str, ...]:
        """Return call-interface failures."""
        ...

    @property
    def call_argument_class_issues(self) -> tuple[str, ...]:
        """Return value-versus-pointer argument failures."""
        ...

    @property
    def function_parameter_issues(self) -> tuple[str, ...]:
        """Return function-parameter failures."""
        ...

    @property
    def function_return_class_issues(self) -> tuple[str, ...]:
        """Return function-return-class failures."""
        ...

    @property
    def control_flow_issues(self) -> tuple[str, ...]:
        """Return control-flow failures."""
        ...

    @property
    def storage_identity_issues(self) -> tuple[str, ...]:
        """Return storage-identity failures."""
        ...


def _introduced_issues_8616(before: tuple[str, ...], after: tuple[str, ...]) -> tuple[str, ...]:
    """Return deterministic multiset additions from ``before`` to ``after``."""
    remaining = Counter(before)
    introduced: list[str] = []
    for issue in after:
        if remaining[issue] > 0:
            remaining[issue] -= 1
        else:
            introduced.append(issue)
    return tuple(introduced)


def collect_tail_semantic_failures_8616(
    after: TailSemanticIssueSurface8616,
    *,
    before: TailSemanticIssueSurface8616 | None = None,
    scope: TailSemanticFailureScope8616 = TailSemanticFailureScope8616.ALL_AFTER,
) -> dict[str, tuple[str, ...]]:
    """Collect semantic failures according to one explicit validation scope."""
    after_fields = (
        ("def_use", after.def_use_issues),
        ("required_calls", after.missing_required_calls),
        ("callsite_multiplicity", after.callsite_multiplicity_issues),
        ("call_interfaces", after.call_interface_issues),
        ("call_argument_classes", after.call_argument_class_issues),
        ("function_parameters", after.function_parameter_issues),
        ("function_return_class", after.function_return_class_issues),
        ("control_flow", after.control_flow_issues),
        ("storage_identities", after.storage_identity_issues),
    )
    before_fields = (
        before.def_use_issues,
        before.missing_required_calls,
        before.callsite_multiplicity_issues,
        before.call_interface_issues,
        before.call_argument_class_issues,
        before.function_parameter_issues,
        before.function_return_class_issues,
        before.control_flow_issues,
        before.storage_identity_issues,
    ) if before is not None else ((),) * len(after_fields)

    failures: dict[str, tuple[str, ...]] = {}
    for (family, after_issues), prior_issues in zip(after_fields, before_fields, strict=True):
        selected = (
            _introduced_issues_8616(prior_issues, after_issues)
            if scope is TailSemanticFailureScope8616.INTRODUCED
            else after_issues
        )
        if selected:
            failures[family] = selected
    return failures


def normalize_tail_semantic_failures_8616(value: object) -> dict[str, tuple[str, ...]]:
    """Normalize the serialized semantic-failure contract for reporting."""
    if not isinstance(value, Mapping):
        return {}
    normalized: dict[str, tuple[str, ...]] = {}
    for family, raw_issues in value.items():
        if not isinstance(family, str) or isinstance(raw_issues, (str, bytes)):
            continue
        if not isinstance(raw_issues, Sequence):
            continue
        issues = tuple(issue for issue in raw_issues if isinstance(issue, str) and issue)
        if issues:
            normalized[family] = issues
    return normalized


def format_tail_semantic_failures_8616(failures: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
    """Format deterministic semantic-failure families for a validation verdict."""
    return tuple(f"{family}: {', '.join(issues)}" for family, issues in failures.items() if issues)


__all__ = [
    "TailSemanticFailureScope8616",
    "TailSemanticIssueSurface8616",
    "collect_tail_semantic_failures_8616",
    "format_tail_semantic_failures_8616",
    "normalize_tail_semantic_failures_8616",
]
