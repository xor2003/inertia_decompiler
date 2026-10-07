"""Collect exact terminal call-result pass-through evidence.

Layer: Semantics.
Responsibility: prove that caller-selected machine calls reach one exact
function return while preserving the call result, and retain the direct target
and CFG path needed by later interprocedural return trials.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
This module does not infer return storage or types and does not mutate codegen.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from .terminal_call_paths import (
    TerminalCallPathStatus8616,
    angr_terminal_call_path_callbacks_8616,
    prove_terminal_call_path_8616,
)

__all__ = [
    "TerminalReturnPassThroughEvidence8616",
    "TerminalReturnPassThroughFact8616",
    "TerminalReturnPassThroughFailure8616",
    "TerminalReturnPassThroughFailureKind8616",
    "collect_terminal_return_passthrough_evidence_8616",
]


class TerminalReturnPassThroughFailureKind8616(StrEnum):
    """Stable reasons why one candidate cannot become a pass-through fact."""

    INVALID_FUNCTION_IDENTITY = "invalid_function_identity"
    INVALID_CALLSITE = "invalid_callsite"
    DUPLICATE_CALLSITE = "duplicate_callsite"
    PATH_REFUSED = "path_refused"
    DIRECT_TARGET_UNKNOWN = "direct_target_unknown"
    RETURN_IDENTITY_UNKNOWN = "return_identity_unknown"


@dataclass(frozen=True, slots=True)
class TerminalReturnPassThroughFact8616:
    """One direct call whose result reaches an exact function-return boundary."""

    caller_addr: int
    callsite_addr: int
    target_addr: int
    return_instruction_addr: int
    path_block_addrs: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class TerminalReturnPassThroughFailure8616:
    """One retained candidate refusal with its Semantics path verdict."""

    kind: TerminalReturnPassThroughFailureKind8616
    callsite_addr: int | None
    path_status: TerminalCallPathStatus8616 | None = None


@dataclass(frozen=True, slots=True)
class TerminalReturnPassThroughEvidence8616:
    """Closed accounting for caller-selected terminal pass-through candidates."""

    function_addr: int | None
    facts: tuple[TerminalReturnPassThroughFact8616, ...]
    failures: tuple[TerminalReturnPassThroughFailure8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every supplied candidate produced one exact fact."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == len(self.facts)
            and self.failure_count == len(self.failures) == 0
        )


class _FunctionSurface8616(Protocol):
    """Owned function identity consumed before the dynamic angr adapter."""

    addr: int


def collect_terminal_return_passthrough_evidence_8616(
    project: object,
    function: object,
    candidate_callsite_addrs: Iterable[int],
) -> TerminalReturnPassThroughEvidence8616:
    """Prove every selected call-to-return relation without inferring a type."""
    candidates = tuple(candidate_callsite_addrs)
    try:
        function_addr = cast(_FunctionSurface8616, function).addr
    except AttributeError:
        function_addr = None
    valid_function_addr = (
        function_addr
        if isinstance(function_addr, int) and not isinstance(function_addr, bool)
        else None
    )
    callbacks = angr_terminal_call_path_callbacks_8616(project, function)
    facts: list[TerminalReturnPassThroughFact8616] = []
    failures: list[TerminalReturnPassThroughFailure8616] = []
    normalized_count = 0
    classified_count = 0
    seen: set[int] = set()

    for candidate in candidates:
        if not isinstance(candidate, int) or isinstance(candidate, bool) or candidate < 0:
            failures.append(
                TerminalReturnPassThroughFailure8616(
                    TerminalReturnPassThroughFailureKind8616.INVALID_CALLSITE,
                    None,
                )
            )
            continue
        if candidate in seen:
            failures.append(
                TerminalReturnPassThroughFailure8616(
                    TerminalReturnPassThroughFailureKind8616.DUPLICATE_CALLSITE,
                    candidate,
                )
            )
            continue
        seen.add(candidate)
        if valid_function_addr is None:
            failures.append(
                TerminalReturnPassThroughFailure8616(
                    TerminalReturnPassThroughFailureKind8616.INVALID_FUNCTION_IDENTITY,
                    candidate,
                )
            )
            continue
        result = prove_terminal_call_path_8616(candidate, callbacks)
        if result.status is not TerminalCallPathStatus8616.PROVEN:
            failures.append(
                TerminalReturnPassThroughFailure8616(
                    TerminalReturnPassThroughFailureKind8616.PATH_REFUSED,
                    candidate,
                    result.status,
                )
            )
            continue
        normalized_count += 1
        if result.call_target_addr is None:
            failures.append(
                TerminalReturnPassThroughFailure8616(
                    TerminalReturnPassThroughFailureKind8616.DIRECT_TARGET_UNKNOWN,
                    candidate,
                    result.status,
                )
            )
            continue
        if result.return_instruction_addr is None:
            failures.append(
                TerminalReturnPassThroughFailure8616(
                    TerminalReturnPassThroughFailureKind8616.RETURN_IDENTITY_UNKNOWN,
                    candidate,
                    result.status,
                )
            )
            continue
        classified_count += 1
        facts.append(
            TerminalReturnPassThroughFact8616(
                caller_addr=valid_function_addr,
                callsite_addr=candidate,
                target_addr=result.call_target_addr,
                return_instruction_addr=result.return_instruction_addr,
                path_block_addrs=result.path_block_addrs,
            )
        )

    ordered_facts = tuple(sorted(facts, key=lambda fact: fact.callsite_addr))
    ordered_failures = tuple(
        sorted(
            failures,
            key=lambda failure: (
                -1 if failure.callsite_addr is None else failure.callsite_addr,
                failure.kind.value,
            ),
        )
    )
    return TerminalReturnPassThroughEvidence8616(
        function_addr=valid_function_addr,
        facts=ordered_facts,
        failures=ordered_failures,
        raw_fact_count=len(candidates),
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=len(ordered_facts),
        failure_count=len(ordered_failures),
    )
