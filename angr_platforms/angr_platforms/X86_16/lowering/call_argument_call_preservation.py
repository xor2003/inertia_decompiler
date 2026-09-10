"""Veto loss of exact machine-call occurrences during argument replacement.

Layer: Types/Lowering.
Responsibility: preserve already-materialized call execution when a later
argument candidate falls back to register carriers. Consumes alias, widening,
and typed facts. Do not recover semantics from COD, source, assembly, or
rendered C text. This veto is not proof of candidate equivalence: call arguments,
memory effects, and untagged runtime helpers retain their separate validators.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from ..c_ast_utils import _iter_c_node_occurrences_8616
from ..callsite_summary import structured_callsite_addr_8616


@dataclass(frozen=True, slots=True)
class CallArgumentCallPreservation8616:
    """Count exact embedded machine-call occurrences retained by a candidate."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def preserves_calls(self) -> bool:
        """Allow further candidate checks only when no occurrence is lost."""
        return self.failure_count == 0


def _call_occurrences_8616(arguments: Sequence[object]) -> Counter[int]:
    """Count each execution edge, including repeated references to one node."""
    occurrences: Counter[int] = Counter()
    for node in _iter_c_node_occurrences_8616(arguments):
        if isinstance(node, CFunctionCall):
            address = structured_callsite_addr_8616(node)
            if address is not None:
                occurrences[address] += 1
    return occurrences


def classify_call_argument_call_preservation_8616(
    previous: Sequence[object], candidate: Sequence[object],
) -> CallArgumentCallPreservation8616:
    """Refuse replacement that loses a previously embedded machine call.

    Machine instruction identity survives cloning and rebasing of target names.
    A register read does not substitute for executing a call already folded
    into these arguments. New calls are checked by the owning materializer;
    retaining existing occurrences alone does not establish equivalence.
    """
    before = _call_occurrences_8616(previous)
    after = _call_occurrences_8616(candidate) if before else Counter()
    missing = sum((before - after).values())
    count = sum(before.values())
    return CallArgumentCallPreservation8616(
        raw_fact_count=count, normalized_fact_count=count,
        classified_fact_count=count, materialized_count=count - missing,
        failure_count=missing,
    )
