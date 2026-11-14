# cython: language_level=3, infer_types=True
"""Typed contracts for carry-linked split arithmetic.

Layer: Semantics.
Responsibility: own immutable carry/borrow links between exact function-SSA
definitions and closed refusal accounting. This module does not infer aliases,
widen values, lower types, structure control flow, or inspect rendered text.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRAddress, IRInstr, IRValue
import dataclasses
import operator


class CarryBorrowKind8616(StrEnum):
    """Arithmetic relation represented by one proven flags link."""

    ADD_WITH_CARRY = "add_with_carry"
    SUB_WITH_BORROW = "sub_with_borrow"


class CarryBorrowIROp8616(StrEnum):
    """Exact IR operations admitted by the bounded carry-link proof."""

    ADD16 = "Iop_Add16"
    AND16 = "Iop_And16"
    LOAD = "LOAD"
    MOV = "MOV"
    OR16 = "Iop_Or16"
    SHL16 = "Iop_Shl16"
    SHR16 = "Iop_Shr16"
    SUB16 = "Iop_Sub16"


class CarryBorrowConversion8616(StrEnum):
    """Exact unary conversions admitted in the carry extraction chain."""

    NARROW_TO_BIT = "Iop_16to1"
    WIDEN_BYTE_TO_WORD = "Iop_8Uto16"
    WIDEN_BIT_TO_WORD = "Iop_1Uto16"


class CarryBorrowVerdict8616(StrEnum):
    """Stable outcome for one candidate split arithmetic result."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CarryBorrowFailure8616(StrEnum):
    """Stable reasons a candidate cannot become carry/borrow evidence."""

    AMBIGUOUS_BASE_OPERATION = "ambiguous_base_operation"
    CARRY_CONVERSION_MISMATCH = "carry_conversion_mismatch"
    CARRY_MASK_MISMATCH = "carry_mask_mismatch"
    CARRY_SHIFT_MISMATCH = "carry_shift_mismatch"
    CFG_PREDECESSOR_MISMATCH = "cfg_predecessor_mismatch"
    FLAGS_DEFINITION_MISSING = "flags_definition_missing"
    FLAGS_PHI_CONFLICT = "flags_phi_conflict"
    FLAGS_PROVENANCE_MISMATCH = "flags_provenance_mismatch"
    LOW_RESULT_AMBIGUOUS = "low_result_ambiguous"
    OPERAND_DEFINITION_MISSING = "operand_definition_missing"
    TEMP_DEFINITION_MISSING = "temp_definition_missing"


@dataclasses.dataclass(frozen=True, )
class CarryBorrowDefinitionSite8616:
    """One exact instruction definition retained from function SSA."""

    block_addr: cython.longlong
    instr_index: cython.longlong
    instruction: IRInstr

    @property
    def value(self) -> IRValue | None:
        """Return the value defined at this site, when present."""
        return self.instruction.dst


@dataclasses.dataclass(frozen=True, )
class CarryBorrowMemoryLoadUse8616:
    """One raw LOAD definition and its exact segmented execution address."""

    site: CarryBorrowDefinitionSite8616
    address: IRAddress


@dataclasses.dataclass(frozen=True, )
class CarryBorrowMemoryWordUse8616:
    """Raw load executions and the authoritative address for one memory word."""

    execution_loads: object
    logical_address: IRAddress
    address_bits: cython.longlong

    @property
    def size(self) -> cython.longlong:
        """Return the authoritative logical width of this memory operand."""
        return int(self.logical_address.size)


@dataclasses.dataclass(frozen=True, )
class CarryBorrowOperandUse8616:
    """One arithmetic operand and its exact temporary definition, if required."""

    value: IRValue
    definition: CarryBorrowDefinitionSite8616 | None
    memory_word: CarryBorrowMemoryWordUse8616 | None = None


@dataclasses.dataclass(frozen=True, )
class CarryBorrowLink8616:
    """Exact low/high arithmetic and flags chain for one split value."""

    function_addr: cython.longlong
    kind: CarryBorrowKind8616
    low_result_write: CarryBorrowDefinitionSite8616
    low_arithmetic: CarryBorrowDefinitionSite8616
    low_lhs: CarryBorrowOperandUse8616
    low_rhs: CarryBorrowOperandUse8616
    flags_definition: CarryBorrowDefinitionSite8616
    flags_read: CarryBorrowDefinitionSite8616
    carry_shift: CarryBorrowDefinitionSite8616
    carry_mask: CarryBorrowDefinitionSite8616
    carry_narrow: CarryBorrowDefinitionSite8616
    carry_extend: CarryBorrowDefinitionSite8616
    high_base_arithmetic: CarryBorrowDefinitionSite8616
    high_final_arithmetic: CarryBorrowDefinitionSite8616
    high_result_write: CarryBorrowDefinitionSite8616
    high_lhs: CarryBorrowOperandUse8616
    high_rhs: CarryBorrowOperandUse8616


@dataclasses.dataclass(frozen=True, )
class CarryBorrowResolution8616:
    """Proven link or typed refusal for one candidate result write."""

    candidate: CarryBorrowDefinitionSite8616
    verdict: CarryBorrowVerdict8616
    link: CarryBorrowLink8616 | None = None
    failure: CarryBorrowFailure8616 | None = None


@dataclasses.dataclass(frozen=True, )
class CarryBorrowStats8616:
    """Closed evidence accounting for carry/borrow candidates."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every raw candidate has one retained outcome."""
        return (
            operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and operator.eq(self.classified_fact_count, self.materialized_count)
        )


@dataclasses.dataclass(frozen=True, )
class CarryBorrowEvidence8616:
    """Function-level collection of proven carry links and refusals."""

    function_addr: cython.longlong
    resolutions: object
    stats: CarryBorrowStats8616

    @property
    def links(self) -> tuple[CarryBorrowLink8616, ...]:
        """Return every proven carry/borrow link in deterministic order."""
        return tuple(item.link for item in iter(self.resolutions) if item.link is not None)

    @property
    def complete(self) -> cython.bint:
        """Return whether resolution count and evidence accounting are closed."""
        return self.stats.complete and operator.eq(len(self.resolutions), self.stats.raw_fact_count)


__all__ = [
    "CarryBorrowConversion8616",
    "CarryBorrowDefinitionSite8616",
    "CarryBorrowEvidence8616",
    "CarryBorrowFailure8616",
    "CarryBorrowIROp8616",
    "CarryBorrowKind8616",
    "CarryBorrowLink8616",
    "CarryBorrowMemoryLoadUse8616",
    "CarryBorrowMemoryWordUse8616",
    "CarryBorrowOperandUse8616",
    "CarryBorrowResolution8616",
    "CarryBorrowStats8616",
    "CarryBorrowVerdict8616",
]
