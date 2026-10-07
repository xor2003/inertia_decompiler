"""Classify whether recovered callers consume a function result.

Layer: Types/lowering.
Responsibility: classify caller result observation and join it with complete
terminal-storage evidence when an unobserved callee result is proven void.
Consumes alias, widening, and typed facts from caller/terminal-return evidence.
An ignored result alone does not prove that the callee returns void.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not inspect function names or postprocess output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_function_boundary_index import exact_function_entry_boundary_8616
from inertia.semantics.call_target_identity import resolve_x86_16_canonical_call_target_function_8616
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    caller_return_use_evidence_by_addr_8616,
)
from inertia.semantics.terminal_return_storage import (
    TerminalReturnStorage8616,
    terminal_return_storage_8616,
)

__all__ = [
    "FunctionReturnClass8616",
    "UnobservedCalleeVoidEvidence8616",
    "caller_return_use_evidence_proves_unused_8616",
    "caller_return_use_evidence_proves_used_8616",
    "collect_unobserved_callee_void_evidence_8616",
    "function_result_is_proven_unobserved_8616",
    "proven_function_result_observation_8616",
    "proven_function_return_class_8616",
]

class _ProjectReturnTypeSurface8616(Protocol):
    """Third-party project fields required for address-domain resolution."""

    _inertia_original_linear_delta: int


class _FunctionProjectSurface8616(Protocol):
    """Third-party function field identifying its evidence project."""

    project: object


class _FunctionBlocksSurface8616(Protocol):
    """Third-party function block ownership used to reject empty stubs."""

    block_addrs_set: object


class _ProjectFunctionRangesSurface8616(Protocol):
    """Owned Frontend range inventory carried by the project boundary."""

    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]


class FunctionReturnClass8616(StrEnum):
    """Logical class of a materialized function result surface."""

    VOID = "void"
    VALUE = "value"


@dataclass(frozen=True, slots=True)
class UnobservedCalleeVoidEvidence8616:
    """Closed join of caller observation and terminal return storage."""

    target_addr: int
    caller_observation: CallerReturnUseVerdict8616 | None
    terminal_storage: TerminalReturnStorage8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def proves_void(self) -> bool:
        """Return whether both complete facts prove an empty C result."""
        return (
            self.caller_observation is CallerReturnUseVerdict8616.UNUSED
            and self.terminal_storage
            in {TerminalReturnStorage8616.NONE, TerminalReturnStorage8616.CALL_OUTPUT}
            and self.raw_fact_count == 2
            and self.normalized_fact_count == self.raw_fact_count
            and self.classified_fact_count == self.raw_fact_count
            and self.materialized_count == self.classified_fact_count
            and self.failure_count == 0
        )


def caller_return_use_evidence_proves_used_8616(
    evidence: CallerReturnUseEvidence8616,
) -> bool:
    """Return whether at least one classified caller provably consumes the result."""
    return (
        evidence.verdict is CallerReturnUseVerdict8616.USED
        and evidence.raw_fact_count > 0
        and evidence.normalized_fact_count == evidence.raw_fact_count
        and evidence.classified_fact_count > 0
        and evidence.materialized_count == evidence.classified_fact_count
        and evidence.used_callsite_count > 0
        and evidence.used_callsite_count <= evidence.classified_fact_count
    )


def caller_return_use_evidence_proves_unused_8616(
    evidence: CallerReturnUseEvidence8616,
) -> bool:
    """Return whether caller-use evidence proves an unused result without gaps."""
    return (
        evidence.verdict is CallerReturnUseVerdict8616.UNUSED
        and evidence.raw_fact_count > 0
        and evidence.normalized_fact_count == evidence.raw_fact_count
        and evidence.classified_fact_count > 0
        and evidence.classified_fact_count + evidence.excluded_callsite_count
        == evidence.normalized_fact_count
        and evidence.materialized_count == evidence.classified_fact_count
        and evidence.failure_count == 0
        and evidence.used_callsite_count == 0
        and evidence.unused_callsite_count == evidence.classified_fact_count
    )


def _candidate_return_evidence_addrs_8616(project: object, function_addr: int) -> tuple[int, ...]:
    """Return current and exact-slice original addresses for caller-use evidence."""
    project_surface = cast(_ProjectReturnTypeSurface8616, project)
    try:
        original_delta = project_surface._inertia_original_linear_delta
    except AttributeError:
        original_delta = None
    candidates = [function_addr]
    if isinstance(original_delta, int) and original_delta:
        candidates.extend((function_addr + original_delta, function_addr - original_delta))
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate >= 0))


def _caller_return_use_evidence_for_function_8616(
    project: object,
    function_addr: int,
) -> CallerReturnUseEvidence8616 | None:
    """Resolve one non-conflicting caller-use proof across address domains."""
    evidence_by_addr = caller_return_use_evidence_by_addr_8616(project)
    matches = tuple(
        evidence
        for candidate in _candidate_return_evidence_addrs_8616(project, function_addr)
        if isinstance((evidence := evidence_by_addr.get(candidate)), CallerReturnUseEvidence8616)
    )
    if not matches:
        return None
    proof_states = {
        (
            evidence.verdict,
            caller_return_use_evidence_proves_used_8616(evidence),
            caller_return_use_evidence_proves_unused_8616(evidence),
        )
        for evidence in matches
    }
    return matches[0] if len(proof_states) == 1 else None


def proven_function_return_class_8616(
    project: object,
    function_addr: int,
) -> FunctionReturnClass8616 | None:
    """Prove only the value-returning class from closed caller-use evidence."""
    if proven_function_result_observation_8616(project, function_addr) is CallerReturnUseVerdict8616.USED:
        return FunctionReturnClass8616.VALUE
    return None


def proven_function_result_observation_8616(
    project: object,
    function_addr: int,
) -> CallerReturnUseVerdict8616 | None:
    """Return a closed proof that callers observe or ignore the function result."""
    evidence = _caller_return_use_evidence_for_function_8616(project, function_addr)
    if not isinstance(evidence, CallerReturnUseEvidence8616):
        return None
    if caller_return_use_evidence_proves_used_8616(evidence):
        return CallerReturnUseVerdict8616.USED
    if caller_return_use_evidence_proves_unused_8616(evidence):
        return CallerReturnUseVerdict8616.UNUSED
    return None


def collect_unobserved_callee_void_evidence_8616(
    project: object,
    function_addr: int,
) -> UnobservedCalleeVoidEvidence8616:
    """Join closed caller-use and terminal-storage facts for one callee."""
    observation = proven_function_result_observation_8616(project, function_addr)
    function = resolve_x86_16_canonical_call_target_function_8616(project, function_addr)
    try:
        has_blocks = bool(cast(_FunctionBlocksSurface8616, function).block_addrs_set)
    except AttributeError:
        has_blocks = False
    boundary = None
    if not has_blocks:
        try:
            ranges = cast(_ProjectFunctionRangesSurface8616, project)._inertia_caller_function_ranges_8616
        except AttributeError:
            ranges = ()
        boundary = exact_function_entry_boundary_8616(project, function_addr, ranges)
    evidence_function = function if has_blocks else boundary
    try:
        evidence_project = cast(_FunctionProjectSurface8616, evidence_function).project
    except AttributeError:
        evidence_project = project
    terminal_storage = (
        terminal_return_storage_8616(evidence_project, evidence_function)
        if evidence_function is not None
        else None
    )
    normalized_count = int(observation is not None) + int(terminal_storage is not None)
    return UnobservedCalleeVoidEvidence8616(
        target_addr=function_addr,
        caller_observation=observation,
        terminal_storage=terminal_storage,
        raw_fact_count=2,
        normalized_fact_count=normalized_count,
        classified_fact_count=normalized_count,
        materialized_count=normalized_count,
        failure_count=2 - normalized_count,
    )


def function_result_is_proven_unobserved_8616(
    project: object,
    function_addr: int,
) -> bool:
    """Prove that a closed caller census never observes this function result.

    This evidence may narrow validation liveness, but it does not prove a void
    ABI and must not mutate the function prototype or delete a return value.
    """
    return proven_function_result_observation_8616(project, function_addr) is CallerReturnUseVerdict8616.UNUSED
