"""Typed binary caller return-use evidence contracts.

Layer: Recovery metadata.
Responsibility: retain exact caller, callsite, witness-instruction, and typed
return-use observations for downstream semantic and Types/Lowering consumers.
Forbidden: inferring C return types, repairing emitted calls, or using
source/COD/rendered-C text as semantic proof.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.semantics.register_value_preservation import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
)

__all__ = [
    "AxValueView8616",
    "ByteReturnExtensionKind8616",
    "CallerReturnUseEvidence8616",
    "CallerReturnUseFact8616",
    "CallerReturnUseVerdict8616",
    "CallsiteReturnUseKind8616",
]


class CallsiteReturnUseKind8616(StrEnum):
    """How one caller path consumes an AX-family return value."""

    VALUE = "value"
    CONDITION = "condition"
    CLOBBERED = "clobbered"
    FUNCTION_RETURN = "function_return"


class CallerReturnUseVerdict8616(StrEnum):
    """Whether a caller or complete caller census observes a return value."""

    USED = "used"
    UNUSED = "unused"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CallerReturnUseFact8616:
    """One exact direct-call observation before function-contract recovery."""

    caller_addr: int
    callsite_addr: int
    verdict: CallerReturnUseVerdict8616
    kind: CallsiteReturnUseKind8616 | None
    witness_instruction_addr: int | None
    excluded_recursive_passthrough: bool = False
    byte_extension: ByteReturnExtensionKind8616 | None = None
    byte_extension_instruction_addr: int | None = None
    observed_value_view: AxValueView8616 | None = None

    @property
    def extension_complete(self) -> bool:
        """Return whether optional byte-extension provenance is internally closed."""
        if self.byte_extension is None:
            return self.byte_extension_instruction_addr is None
        return (
            isinstance(self.byte_extension_instruction_addr, int)
            and self.byte_extension_instruction_addr >= 0
            and self.observed_value_view is AxValueView8616.AX
        )

    @property
    def classified(self) -> bool:
        """Return whether this retained fact has an exact usable witness."""
        return (
            not self.excluded_recursive_passthrough
            and self.caller_addr >= 0
            and self.callsite_addr >= 0
            and self.verdict is not CallerReturnUseVerdict8616.UNKNOWN
            and isinstance(self.witness_instruction_addr, int)
            and self.witness_instruction_addr >= 0
            and self.extension_complete
        )


@dataclass(frozen=True, slots=True)
class CallerReturnUseEvidence8616:
    """Closed evidence loop for one function's binary caller census."""

    target_addr: int
    verdict: CallerReturnUseVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    used_callsite_count: int
    unused_callsite_count: int
    callsite_addrs: tuple[int, ...]
    excluded_callsite_count: int = 0
    facts: tuple[CallerReturnUseFact8616, ...] = ()

    @property
    def fact_census_complete(self) -> bool:
        """Return whether exact retained facts account for every raw callsite."""
        included = tuple(
            fact for fact in self.facts if not fact.excluded_recursive_passthrough
        )
        return (
            len(self.facts) == self.raw_fact_count == self.normalized_fact_count
            and tuple(fact.callsite_addr for fact in self.facts) == self.callsite_addrs
            and sum(fact.excluded_recursive_passthrough for fact in self.facts)
            == self.excluded_callsite_count
            and sum(fact.classified for fact in included)
            == self.classified_fact_count
            == self.materialized_count
            and sum(not fact.classified for fact in included) == self.failure_count
        )
