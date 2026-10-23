"""Typed contracts for register outputs produced by exact machine calls.

Layer: Semantics.
Responsibility: own immutable call-output identities, shapes, verdicts,
failures, and closed accounting before SSA and Alias consume those outputs.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRCallOutputShape8616 as CallOutputShape8616
from inertia.ir.core import IRValue, MemSpace


class CallOutputVerdict8616(StrEnum):
    """Typed result for one exact CALL output classification."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallOutputFailure8616(StrEnum):
    """Stable reasons a used call result cannot become SSA definitions."""

    CALL_ADDRESS_MISSING = "call_address_missing"
    CALL_NOT_TERMINAL = "call_not_terminal"
    DUPLICATE_CALL_ADDRESS = "duplicate_call_address"
    FRAME_KIND_UNKNOWN = "frame_kind_unknown"
    OUTPUT_PROVENANCE_MISMATCH = "output_provenance_mismatch"
    OUTPUT_SHAPE_MISMATCH = "output_shape_mismatch"
    OUTPUT_WIDTH_MISMATCH = "output_width_mismatch"
    RETURN_BLOCK_HAS_OTHER_PREDECESSOR = "return_block_has_other_predecessor"
    RETURN_BLOCK_MISSING = "return_block_missing"
    RETURN_EDGE_MISMATCH = "return_edge_mismatch"
    RETURN_SHAPE_UNKNOWN = "return_shape_unknown"
    RETURN_USE_UNKNOWN = "return_use_unknown"
    SUMMARY_MISSING = "summary_missing"
    TARGET_UNRESOLVED = "target_unresolved"


@dataclass(frozen=True, slots=True)
class CallOutputFact8616:
    """One CALL and the exact register definitions on its return edge."""

    call_block_addr: int
    call_instr_index: int
    callsite_addr: int | None
    target_addr: int | None
    return_block_addr: int | None
    shape: CallOutputShape8616 | None
    outputs: tuple[IRValue, ...]
    verdict: CallOutputVerdict8616
    failure: CallOutputFailure8616 | None


@dataclass(frozen=True, slots=True)
class CallOutputStats8616:
    """Closed accounting for every CALL output decision in one function."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every CALL has one retained typed outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )

    @property
    def complete(self) -> bool:
        """Return whether every output decision is positively proven."""
        return self.closed and self.failure_count == 0

    def to_dict(self) -> dict[str, int]:
        """Return deterministic closed-loop counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


CALL_OUTPUT_SHAPE_REGISTERS_8616: dict[CallOutputShape8616, tuple[tuple[str, int], ...]] = {
    CallOutputShape8616.AX: (("ax", 2),),
    CallOutputShape8616.DX_AX: (("ax", 2), ("dx", 2)),
}
"""Canonical (register name, byte width) layout each proven shape must carry."""


def validate_call_output_fact_8616(
    fact: CallOutputFact8616,
) -> tuple[CallOutputFailure8616, ...]:
    """Authenticate one retained output fact's inner provenance and shape.

    An empty tuple means the fact is internally consistent. Refused facts and
    proven no-output observations (``return_used is False``) are valid; a
    proven shaped fact must carry exactly the canonical register layout, with
    every value's ``IRCallOutputProvenance8616``, architecture width and
    cardinality matching the outer fact identity.
    """
    if fact.verdict is not CallOutputVerdict8616.PROVEN:
        return ()
    if fact.shape is None:
        return () if not fact.outputs else (CallOutputFailure8616.OUTPUT_SHAPE_MISMATCH,)
    expected = CALL_OUTPUT_SHAPE_REGISTERS_8616.get(fact.shape)
    if expected is None:
        return (CallOutputFailure8616.RETURN_SHAPE_UNKNOWN,)
    expected_widths = dict(expected)
    failures: set[CallOutputFailure8616] = set()
    names: list[str] = []
    for output in fact.outputs:
        # IRValue.name is optional at the proof boundary; an unnamed value
        # can never satisfy the canonical register layout.
        if output.name is None:
            failures.add(CallOutputFailure8616.OUTPUT_SHAPE_MISMATCH)
        else:
            names.append(output.name)
    if sorted(names) != sorted(expected_widths):
        failures.add(CallOutputFailure8616.OUTPUT_SHAPE_MISMATCH)
    failures |= _output_value_failures_8616(fact, expected_widths)
    return tuple(sorted(failures, key=lambda failure: failure.value))


def _output_value_failures_8616(
    fact: CallOutputFact8616,
    expected_widths: dict[str, int],
) -> set[CallOutputFailure8616]:
    """Check each output's space, architecture width and inner provenance."""
    failures: set[CallOutputFailure8616] = set()
    for output in fact.outputs:
        if output.space is not MemSpace.REG or output.name is None:
            failures.add(CallOutputFailure8616.OUTPUT_SHAPE_MISMATCH)
            continue
        if output.size != expected_widths.get(output.name, -1):
            failures.add(CallOutputFailure8616.OUTPUT_WIDTH_MISMATCH)
        provenance = output.call_output
        if (
            provenance is None
            or provenance.callsite_addr != fact.callsite_addr
            or provenance.target_addr != fact.target_addr
            or provenance.shape is not fact.shape
        ):
            failures.add(CallOutputFailure8616.OUTPUT_PROVENANCE_MISMATCH)
    return failures


__all__ = [
    "CALL_OUTPUT_SHAPE_REGISTERS_8616",
    "CallOutputFact8616",
    "CallOutputFailure8616",
    "CallOutputShape8616",
    "CallOutputStats8616",
    "CallOutputVerdict8616",
    "validate_call_output_fact_8616",
]
