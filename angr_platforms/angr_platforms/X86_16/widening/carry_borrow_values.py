"""Widen exact Alias-projected carry/borrow links into typed split values.

Layer: Widening.
Responsibility: consume the canonical carry/borrow Alias projection and
materialize immutable wide-value facts. This bounded producer supports exact
register results with register or segmented-memory sources; unsupported forms
refuse in Alias.
Consumes alias-proven storage identity before joining values or propagating widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..alias.carry_borrow_contracts import (
    CarryBorrowAliasEvidence8616,
    CarryBorrowAliasFact8616,
    CarryBorrowAliasResolution8616,
    CarryBorrowAliasVerdict8616,
    CarryBorrowCallOutputAlias8616,
)
from ..alias.domains import DomainKey
from ..alias.storage_fact_join import SegmentedAliasRange8616
from ..ir import IRValue, MemSpace
from ..semantics.carry_borrow_contracts import (
    CarryBorrowDefinitionSite8616,
    CarryBorrowIROp8616,
    CarryBorrowKind8616,
    CarryBorrowLink8616,
    CarryBorrowOperandUse8616,
)


class WideCarryBorrowVerdict8616(StrEnum):
    """Stable Widening outcome for one Alias resolution."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class WideCarryBorrowFailure8616(StrEnum):
    """Stable reasons an Alias-proven link cannot become a wide value."""

    ALIAS_EVIDENCE_MISMATCH = "alias_evidence_mismatch"
    ALIAS_INCOMPLETE = "alias_incomplete"
    ALIAS_REFUSED = "alias_refused"
    ARITHMETIC_LINK_MISMATCH = "arithmetic_link_mismatch"


class WideValueSignedness8616(StrEnum):
    """Signedness retained until Types provides stronger evidence."""

    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class WideRegisterSlice8616:
    """One exact 16-bit result slice of a proven wide arithmetic value."""

    result: IRValue
    result_domain: DomainKey
    lhs: CarryBorrowOperandUse8616
    lhs_domain: DomainKey
    rhs: CarryBorrowOperandUse8616
    rhs_domain: DomainKey | None
    rhs_memory: SegmentedAliasRange8616 | None
    rhs_constant: IRValue | None
    arithmetic: CarryBorrowDefinitionSite8616
    result_write: CarryBorrowDefinitionSite8616


@dataclass(frozen=True, slots=True)
class WideCarryBorrowValue8616:
    """Typed 32-bit value retaining exact slices and carry/borrow provenance."""

    kind: CarryBorrowKind8616
    size: int
    signedness: WideValueSignedness8616
    address_space: MemSpace | None
    source_memory: SegmentedAliasRange8616 | None
    source_constant: int | None
    lhs_call_output: CarryBorrowCallOutputAlias8616 | None
    low: WideRegisterSlice8616
    high: WideRegisterSlice8616
    provenance: CarryBorrowLink8616


@dataclass(frozen=True, slots=True)
class WideCarryBorrowResolution8616:
    """Materialized wide value or typed refusal for one Alias outcome."""

    alias: CarryBorrowAliasResolution8616 | None
    verdict: WideCarryBorrowVerdict8616
    value: WideCarryBorrowValue8616 | None = None
    failure: WideCarryBorrowFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class WideCarryBorrowStats8616:
    """Closed evidence accounting for carry-linked Widening candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether each Alias outcome has one Widening result."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class WideCarryBorrowEvidence8616:
    """Function-level wide values and refusals derived from Alias evidence."""

    function_addr: int
    resolutions: tuple[WideCarryBorrowResolution8616, ...]
    stats: WideCarryBorrowStats8616

    @property
    def values(self) -> tuple[WideCarryBorrowValue8616, ...]:
        """Return materialized wide values in deterministic order."""
        return tuple(item.value for item in self.resolutions if item.value is not None)

    @property
    def complete(self) -> bool:
        """Return whether Widening outcomes and counters are closed."""
        return self.stats.complete and len(self.resolutions) == self.stats.raw_fact_count


def _operation_source_matches(
    result_write: CarryBorrowDefinitionSite8616,
    arithmetic: CarryBorrowDefinitionSite8616,
) -> bool:
    args = result_write.instruction.args
    destination = arithmetic.instruction.dst
    return (
        len(args) == 1
        and isinstance(args[0], IRValue)
        and destination is not None
        and args[0].source_tmp is not None
        and args[0].source_tmp == destination.source_tmp
    )


def _refusal(
    alias: CarryBorrowAliasResolution8616 | None,
    failure: WideCarryBorrowFailure8616,
) -> WideCarryBorrowResolution8616:
    return WideCarryBorrowResolution8616(
        alias=alias,
        verdict=WideCarryBorrowVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
    )


def _source_alias_matches(fact: CarryBorrowAliasFact8616) -> bool:
    source_memory = fact.source_memory
    source_constant = fact.source_constant
    if source_memory is None and source_constant is None:
        return (
            fact.low_rhs.register_domain is not None
            and fact.high_rhs.register_domain is not None
            and fact.low_rhs.register_domain != fact.high_rhs.register_domain
            and fact.low_rhs.memory is None
            and fact.high_rhs.memory is None
            and fact.low_rhs.constant is None
            and fact.high_rhs.constant is None
        )
    if source_constant is not None:
        low_constant = fact.low_rhs.constant
        high_constant = fact.high_rhs.constant
        return (
            source_memory is None
            and fact.low_rhs.register_domain is None
            and fact.high_rhs.register_domain is None
            and fact.low_rhs.memory is None
            and fact.high_rhs.memory is None
            and low_constant is not None
            and high_constant is not None
            and isinstance(low_constant.const, int)
            and isinstance(high_constant.const, int)
            and source_constant
            == ((high_constant.const & 0xFFFF) << 16) | (low_constant.const & 0xFFFF)
        )
    if source_memory is None:
        return False
    low_memory = fact.low_rhs.memory
    high_memory = fact.high_rhs.memory
    return (
        fact.low_rhs.register_domain is None
        and fact.high_rhs.register_domain is None
        and fact.low_rhs.constant is None
        and fact.high_rhs.constant is None
        and low_memory is not None
        and high_memory is not None
        and source_memory.space is low_memory.space is high_memory.space
        and source_memory.addresses == low_memory.addresses + high_memory.addresses
        and source_memory.source_facts == low_memory.source_facts + high_memory.source_facts
        and source_memory.size == 4
    )


def _fact_gate_8616(
    alias: CarryBorrowAliasResolution8616,
    fact: CarryBorrowAliasFact8616,
) -> WideCarryBorrowResolution8616 | None:
    """Refuse when the alias fact and arithmetic link do not close."""
    link = fact.link
    low_result = link.low_result_write.instruction.dst
    high_result = link.high_result_write.instruction.dst
    if low_result is None or high_result is None:
        return _refusal(alias, WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH)
    if low_result.space is not MemSpace.REG or high_result.space is not MemSpace.REG:
        return _refusal(alias, WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH)
    if fact.low_result_domain == fact.high_result_domain:
        return _refusal(alias, WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH)
    if (
        fact.low_lhs.use != link.low_lhs
        or fact.low_rhs.use != link.low_rhs
        or fact.high_lhs.use != link.high_lhs
        or fact.high_rhs.use != link.high_rhs
    ):
        return _refusal(alias, WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH)
    if (
        fact.low_lhs.register_domain != fact.low_result_domain
        or fact.high_lhs.register_domain != fact.high_result_domain
        or fact.low_lhs.memory is not None
        or fact.high_lhs.memory is not None
    ):
        return _refusal(alias, WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH)
    if not _source_alias_matches(fact):
        return _refusal(alias, WideCarryBorrowFailure8616.ALIAS_EVIDENCE_MISMATCH)
    if not _arithmetic_link_proven_8616(link):
        return _refusal(alias, WideCarryBorrowFailure8616.ARITHMETIC_LINK_MISMATCH)
    return None


def _arithmetic_link_proven_8616(link: CarryBorrowLink8616) -> bool:
    """Return whether the three arithmetic sites and operands chain exactly."""
    expected_op = (
        CarryBorrowIROp8616.ADD16
        if link.kind is CarryBorrowKind8616.ADD_WITH_CARRY
        else CarryBorrowIROp8616.SUB16
    )
    if any(
        site.instruction.op != expected_op.value
        for site in (link.low_arithmetic, link.high_base_arithmetic, link.high_final_arithmetic)
    ):
        return False
    if not _operation_source_matches(link.low_result_write, link.low_arithmetic):
        return False
    if not _operation_source_matches(link.high_result_write, link.high_final_arithmetic):
        return False
    final_args = link.high_final_arithmetic.instruction.args
    base_dst = link.high_base_arithmetic.instruction.dst
    return base_dst is not None and any(
        isinstance(arg, IRValue) and arg.source_tmp == base_dst.source_tmp for arg in final_args
    )


def _materialize_fact(
    alias: CarryBorrowAliasResolution8616,
    fact: CarryBorrowAliasFact8616,
) -> WideCarryBorrowResolution8616:
    """Materialize one proven carry/borrow alias fact as a wide register pair."""
    link = fact.link
    gate = _fact_gate_8616(alias, fact)
    if gate is not None:
        return gate
    low_result = link.low_result_write.instruction.dst
    high_result = link.high_result_write.instruction.dst
    assert low_result is not None and high_result is not None
    low_slice = WideRegisterSlice8616(
        result=low_result,
        result_domain=fact.low_result_domain,
        lhs=link.low_lhs,
        lhs_domain=fact.low_lhs.register_domain,
        rhs=link.low_rhs,
        rhs_domain=fact.low_rhs.register_domain,
        rhs_memory=fact.low_rhs.memory,
        rhs_constant=fact.low_rhs.constant,
        arithmetic=link.low_arithmetic,
        result_write=link.low_result_write,
    )
    high_slice = WideRegisterSlice8616(
        result=high_result,
        result_domain=fact.high_result_domain,
        lhs=link.high_lhs,
        lhs_domain=fact.high_lhs.register_domain,
        rhs=link.high_rhs,
        rhs_domain=fact.high_rhs.register_domain,
        rhs_memory=fact.high_rhs.memory,
        rhs_constant=fact.high_rhs.constant,
        arithmetic=link.high_base_arithmetic,
        result_write=link.high_result_write,
    )
    return WideCarryBorrowResolution8616(
        alias=alias,
        verdict=WideCarryBorrowVerdict8616.PROVEN,
        value=WideCarryBorrowValue8616(
            kind=link.kind,
            size=4,
            signedness=WideValueSignedness8616.UNKNOWN,
            address_space=None if fact.source_memory is None else fact.source_memory.space,
            source_memory=fact.source_memory,
            source_constant=fact.source_constant,
            lhs_call_output=fact.lhs_call_output,
            low=low_slice,
            high=high_slice,
            provenance=link,
        ),
    )


def widen_carry_borrow_values_8616(
    evidence: CarryBorrowAliasEvidence8616,
) -> WideCarryBorrowEvidence8616:
    """Consume complete Alias evidence and materialize exact register pairs."""
    if not evidence.complete:
        refusal = _refusal(None, WideCarryBorrowFailure8616.ALIAS_INCOMPLETE)
        return WideCarryBorrowEvidence8616(
            function_addr=evidence.function_addr,
            resolutions=(refusal,),
            stats=WideCarryBorrowStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                failure_count=1,
            ),
        )
    resolutions = tuple(
        _materialize_fact(item, item.fact)
        if item.verdict is CarryBorrowAliasVerdict8616.PROVEN and item.fact is not None
        else _refusal(item, WideCarryBorrowFailure8616.ALIAS_REFUSED)
        for item in evidence.resolutions
    )
    materialized = sum(item.value is not None for item in resolutions)
    stats = WideCarryBorrowStats8616(
        raw_fact_count=len(resolutions),
        normalized_fact_count=len(resolutions),
        classified_fact_count=materialized,
        materialized_count=materialized,
        failure_count=len(resolutions) - materialized,
    )
    return WideCarryBorrowEvidence8616(
        function_addr=evidence.function_addr,
        resolutions=resolutions,
        stats=stats,
    )


__all__ = [
    "WideCarryBorrowEvidence8616",
    "WideCarryBorrowFailure8616",
    "WideCarryBorrowResolution8616",
    "WideCarryBorrowStats8616",
    "WideCarryBorrowValue8616",
    "WideCarryBorrowVerdict8616",
    "WideRegisterSlice8616",
    "WideValueSignedness8616",
    "widen_carry_borrow_values_8616",
]
