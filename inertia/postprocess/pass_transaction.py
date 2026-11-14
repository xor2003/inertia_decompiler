# cython: language_level=3, infer_types=True
"""Own typed state and preflight policy for guarded postprocess passes.

Layer: Rewrite/Postprocess cleanup.
Responsibility: hold request-local guarded-pass state and decide whether one
already-selected cleanup pass must probe local evidence, execute, or be refused.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
This module does not execute passes, inspect the C AST, or publish metadata at
the dynamic angr boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, cast
import typing
import cython
import dataclasses
import operator
T = typing.TypeVar("T")
X86_16TailValidationSummary = typing.TypeVar("X86_16TailValidationSummary")

if TYPE_CHECKING:
    from inertia.validation.tail_validation import X86_16TailValidationSummary

from .pass_validation_policy import (
    FORCE_PER_PASS_VALIDATION_NAMES_8616,
    LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616,
    MANDATORY_VALIDATION_PASS_NAMES_8616,
    OPTIMIZATION_VALIDATION_PASS_NAMES_8616,
    PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616,
)

__all__ = [
    "PostprocessMutationGeneration8616",
    "PostprocessMutationWitnessCache8616",
    "PostprocessMutationWitnessStats8616",
    "PostprocessPassPreflightAction8616",
    "PostprocessPassPreflightDecision8616",
    "PostprocessPassPreflightInput8616",
    "PostprocessPassTransactionState8616",
    "decide_postprocess_pass_preflight_8616",
]


class PostprocessPassPreflightAction8616(Enum):
    """Describe the next guarded-pass action selected by static policy."""

    PROBE_LOCAL_EVIDENCE = "probe_local_evidence"
    EXECUTE = "execute"
    REFUSE_LOCAL_PROOF = "refuse_local_proof"
    SKIP_REJECT_BUDGET = "skip_reject_budget"


@dataclasses.dataclass(frozen=True, )
class PostprocessPassPreflightInput8616:
    """Collect immutable inputs used to select one guarded-pass action."""

    pass_name: object
    validation_enabled: cython.bint
    per_pass_validation_enabled: cython.bint
    large_function_skip: cython.bint
    force_per_pass_requested: cython.bint
    optional_reject_budget: cython.longlong
    optional_reject_count: cython.longlong
    local_evidence_present: bool | None = None

    def with_local_evidence(self, present: cython.bint) -> PostprocessPassPreflightInput8616:
        """Return the same preflight request with its lazy evidence probe closed."""
        return PostprocessPassPreflightInput8616(
            pass_name=self.pass_name,
            validation_enabled=self.validation_enabled,
            per_pass_validation_enabled=self.per_pass_validation_enabled,
            large_function_skip=self.large_function_skip,
            force_per_pass_requested=self.force_per_pass_requested,
            optional_reject_budget=self.optional_reject_budget,
            optional_reject_count=self.optional_reject_count,
            local_evidence_present=present,
        )


@dataclasses.dataclass(frozen=True, )
class PostprocessPassPreflightDecision8616:
    """Return one action and the validation obligations for an executable pass."""

    action: PostprocessPassPreflightAction8616
    is_optimization_pass: cython.bint
    force_pass_validation: cython.bint
    requires_snapshot: cython.bint
    enforce_pass_validation: cython.bint


@dataclasses.dataclass(frozen=True, )
class PostprocessMutationGeneration8616:
    """Accepted AST mutation generation published by one guarded transaction."""

    value: cython.longlong
    last_changed_pass: object

    def __post_init__(self) -> None:
        """Reject an invalid monotonic generation at its owning boundary."""
        if self.value < 0:
            raise ValueError("postprocess mutation generation must be non-negative")


@dataclasses.dataclass(frozen=True, )
class PostprocessMutationWitnessStats8616:
    """Closed accounting for exact transaction-local witness reuse."""

    lookup_count: cython.longlong
    rebuild_count: cython.longlong
    reuse_count: cython.longlong
    record_count: cython.longlong
    invalidation_count: cython.longlong

    @property
    def closed(self) -> cython.bint:
        """Return whether every lookup was rebuilt or safely reused."""
        counts = (
            self.lookup_count,
            self.rebuild_count,
            self.reuse_count,
            self.record_count,
            self.invalidation_count,
        )
        return all(count >= 0 for count in iter(counts)) and operator.eq(self.lookup_count, (
            self.rebuild_count + self.reuse_count
        ))


class PostprocessMutationWitnessCache8616(typing.Generic[T]):
    """Reuse one exact witness only while guarded passes report no mutation."""
    _generation: object
    _has_generation: cython.bint
    _invalidation_count: cython.longlong
    _lookup_count: cython.longlong
    _rebuild_count: cython.longlong
    _record_count: cython.longlong
    _reuse_count: cython.longlong

    def __init__(self) -> None:
        """Start without a proven witness or accounting events."""
        self._generation: T | None = None
        self._has_generation = False
        self._lookup_count = 0
        self._rebuild_count = 0
        self._reuse_count = 0
        self._record_count = 0
        self._invalidation_count = 0

    def current_or_build(self, builder: Callable[[], T]) -> T:
        """Return the stable witness or build it once for the current state."""
        self._lookup_count += 1
        if self._has_generation:
            self._reuse_count += 1
            return cast(T, self._generation)
        generation = builder()
        self._generation = generation
        self._has_generation = True
        self._rebuild_count += 1
        return generation

    def record(self, generation: T) -> None:
        """Record an exact witness computed after an unchanged pass."""
        self._generation = generation
        self._has_generation = True
        self._record_count += 1

    def invalidate(self) -> None:
        """Refuse reuse after a reported or independently witnessed mutation."""
        self._generation = None
        self._has_generation = False
        self._invalidation_count += 1

    def stats(self) -> PostprocessMutationWitnessStats8616:
        """Return immutable closed cache accounting for diagnostics and tests."""
        stats = PostprocessMutationWitnessStats8616(
            lookup_count=self._lookup_count,
            rebuild_count=self._rebuild_count,
            reuse_count=self._reuse_count,
            record_count=self._record_count,
            invalidation_count=self._invalidation_count,
        )
        if not stats.closed:
            raise ValueError("postprocess mutation witness accounting did not close")
        return stats


@cython.dataclasses.dataclass()
class PostprocessPassTransactionState8616:
    """Own mutable state shared by all guarded passes in one rewrite request."""

    baseline_summary: X86_16TailValidationSummary | None
    known_cycle_path: object
    accepted_changed: cython.bint = False
    last_changed_pass: object = None
    accepted_mutation_count: cython.longlong = 0

    @cython.ccall
    def accept_change(self, pass_name: object) -> None:
        """Record one accepted mutation and its deterministic pass identity."""
        self.accepted_changed = True
        self.last_changed_pass = pass_name
        self.accepted_mutation_count += 1

    @cython.ccall
    def mutation_generation(self) -> PostprocessMutationGeneration8616:
        """Return the immutable accepted generation for downstream consumers."""
        return PostprocessMutationGeneration8616(
            value=self.accepted_mutation_count,
            last_changed_pass=self.last_changed_pass,
        )

    @cython.ccall
    def replace_baseline(self, summary: X86_16TailValidationSummary) -> None:
        """Advance validation baseline after an explicitly accepted delta."""
        self.baseline_summary = summary

    @cython.ccall
    def record_cycle_path(self, cycle_path: object) -> None:
        """Publish the cycle witness for the current accepted AST state."""
        self.known_cycle_path = cycle_path


@cython.ccall
def decide_postprocess_pass_preflight_8616(
    request: PostprocessPassPreflightInput8616,
) -> PostprocessPassPreflightDecision8616:
    """Select a fail-closed guarded-pass action without inspecting runtime AST state."""
    pass_name = request.pass_name
    is_optimization_pass = pass_name in OPTIMIZATION_VALIDATION_PASS_NAMES_8616
    force_pass_validation = request.force_per_pass_requested and (
        pass_name in FORCE_PER_PASS_VALIDATION_NAMES_8616
        or pass_name in MANDATORY_VALIDATION_PASS_NAMES_8616
    )
    force_pass_validation = force_pass_validation or (
        request.validation_enabled
        and not request.large_function_skip
        and pass_name in MANDATORY_VALIDATION_PASS_NAMES_8616
    )
    requires_snapshot = request.validation_enabled and (
        request.per_pass_validation_enabled
        or force_pass_validation
        or is_optimization_pass
    )
    enforce_pass_validation = (
        request.per_pass_validation_enabled
        or force_pass_validation
        or is_optimization_pass
    )
    if (
        request.large_function_skip
        and not request.force_per_pass_requested
        and not force_pass_validation
        and not is_optimization_pass
    ):
        enforce_pass_validation = False

    refuse_without_local_proof = bool(
        request.validation_enabled
        and request.large_function_skip
        and not request.per_pass_validation_enabled
        and not force_pass_validation
        and not is_optimization_pass
        and pass_name in LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
    )
    reject_budget_reached = bool(
        request.validation_enabled
        and not request.per_pass_validation_enabled
        and request.optional_reject_budget > 0
        and request.optional_reject_count >= request.optional_reject_budget
        and pass_name in PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616
    )
    if (
        (refuse_without_local_proof or reject_budget_reached)
        and request.local_evidence_present is None
    ):
        action = PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE
    elif refuse_without_local_proof and not request.local_evidence_present:
        action = PostprocessPassPreflightAction8616.REFUSE_LOCAL_PROOF
    elif reject_budget_reached and not request.local_evidence_present:
        action = PostprocessPassPreflightAction8616.SKIP_REJECT_BUDGET
    else:
        action = PostprocessPassPreflightAction8616.EXECUTE
    return PostprocessPassPreflightDecision8616(
        action=action,
        is_optimization_pass=is_optimization_pass,
        force_pass_validation=force_pass_validation,
        requires_snapshot=requires_snapshot,
        enforce_pass_validation=enforce_pass_validation,
    )
