"""Describe atomic C-AST call-argument mutation outcomes.

Layer: Rewrite/Postprocess cleanup.
Responsibility: distinguish accepted, unchanged, and refused argument mutations
so compatibility cleanup never consumes setup evidence after a refusal.

This contract carries no argument-recovery semantics. Types/Lowering owns the
candidate and its evidence; Rewrite only reports whether the requested C-AST
mutation was accepted before pruning already-consumed carrier artifacts.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "CallArgumentMutationResult8616",
    "CallArgumentMutationVerdict8616",
    "accepted_call_argument_mutation_8616",
    "refused_call_argument_mutation_8616",
]


class CallArgumentMutationVerdict8616(StrEnum):
    """Typed outcome for one requested C-AST argument-list mutation."""

    APPLIED = "applied"
    UNCHANGED = "unchanged"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class CallArgumentMutationResult8616:
    """Atomic result for argument and call-target mutations at one callsite."""

    verdict: CallArgumentMutationVerdict8616
    arguments_changed: bool = False
    target_changed: bool = False

    @property
    def arguments_accepted(self) -> bool:
        """Return whether cleanup may consume the candidate's setup evidence."""
        return self.verdict is not CallArgumentMutationVerdict8616.REFUSED

    @property
    def changed(self) -> bool:
        """Return whether any accepted call-node state changed."""
        return self.arguments_changed or self.target_changed


def accepted_call_argument_mutation_8616(
    *,
    arguments_changed: bool,
    target_changed: bool,
) -> CallArgumentMutationResult8616:
    """Build an accepted applied-or-unchanged mutation result."""
    return CallArgumentMutationResult8616(
        verdict=(
            CallArgumentMutationVerdict8616.APPLIED
            if arguments_changed
            else CallArgumentMutationVerdict8616.UNCHANGED
        ),
        arguments_changed=arguments_changed,
        target_changed=target_changed,
    )


def refused_call_argument_mutation_8616(
    *,
    arguments_changed: bool = False,
    target_changed: bool = False,
) -> CallArgumentMutationResult8616:
    """Build a refusal while retaining any independent accepted mutation."""
    return CallArgumentMutationResult8616(
        verdict=CallArgumentMutationVerdict8616.REFUSED,
        arguments_changed=arguments_changed,
        target_changed=target_changed,
    )
