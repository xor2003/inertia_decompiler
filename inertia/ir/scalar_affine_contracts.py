# cython: language_level=3, infer_types=True
"""Typed contracts for exact scalar affine-expression provenance.

Layer: IR.
Responsibility: retain one modular scalar expression as a constant plus exact
stack-derived or explicit entry-register terms and their SSA definition path.
This module does not interpret values as pointers, choose segments, infer
aliases or types, mutate code generation, or consume callsite summaries.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from .core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin
from .indexed_address_contracts import IndexedAddressDefinitionSite8616
import dataclasses
import operator


class ScalarAffineFailure8616(StrEnum):
    """Stable reasons an exact affine scalar trace cannot close."""

    ROOT_UNPROVEN = "root_unproven"
    DEFINITION_MISSING = "definition_missing"
    DEFINITION_CONFLICT = "definition_conflict"
    WIDTH_CONFLICT = "width_conflict"
    EXPRESSION_UNSUPPORTED = "expression_unsupported"
    SOURCE_UNPROVEN = "source_unproven"


@dataclasses.dataclass(frozen=True, )
class ScalarAffineEntryRegister8616:
    """An exact 16-bit SP/BP value at one function's entry boundary."""

    function_addr: cython.longlong
    register_name: object
    size: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Refuse non-stack registers, unknown entries and non-word roots."""
        return self.function_addr >= 0 and self.register_name in {"sp", "bp"} and self.size == 2


@dataclasses.dataclass(frozen=True, )
class ScalarAffineTerm8616:
    """One proven scalar source multiplied by a modular coefficient."""

    value: IRValue
    source: IRAddress | ScalarAffineEntryRegister8616
    coefficient: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether this term retains exact value and stack identity."""
        if isinstance(self.source, ScalarAffineEntryRegister8616):
            return bool(
                self.coefficient != 0 and self.source.complete
                and self.value.space is MemSpace.REG
                and operator.eq(self.value.name, self.source.register_name)
                and operator.eq(self.value.size, self.source.size)
                and self.value.version == 0 and self.value.source_tmp is None
                and self.value.offset == 0 and self.value.index is None
            )
        return bool(
            self.coefficient != 0
            and (
                isinstance(self.value.version, int)
                or isinstance(self.value.source_tmp, int)
            )
            and self.source.space is MemSpace.SS
            and self.source.base == ("bp",)
            and operator.eq(self.source.size, self.value.size)
            and self.source.status is AddressStatus.STABLE
            and self.source.segment_origin is SegmentOrigin.PROVEN
        )


@dataclasses.dataclass(frozen=True, )
class ScalarAffineExpression8616:
    """One exact width-bounded affine value and its complete SSA proof path."""

    root: IRValue
    width: cython.longlong
    constant: cython.longlong
    terms: object
    definition_path: object

    @property
    def complete(self) -> cython.bint:
        """Return whether the root, terms, constant, and path agree."""
        mask = (1 << (self.width * 8)) - 1 if self.width in {1, 2, 4} else -1
        root_exact = bool(
            isinstance(self.root.const, int)
            or isinstance(self.root.version, int)
            or isinstance(self.root.source_tmp, int)
        )
        return bool(
            mask >= 0
            and operator.eq(self.root.size, self.width)
            and root_exact
            and 0 <= self.constant <= mask
            and all(term.complete for term in iter(self.terms))
            and (not self.terms or self.definition_path or all(
                isinstance(term.source, ScalarAffineEntryRegister8616) for term in iter(self.terms)
            ))
            and all(site.complete for site in iter(self.definition_path))
        )


@dataclasses.dataclass(frozen=True, )
class ScalarAffineTraceStats8616:
    """Closed accounting for one scalar affine trace attempt."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether one raw value became one retained expression."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class ScalarAffineTrace8616:
    """One proven scalar affine expression or one atomic typed refusal."""

    expression: ScalarAffineExpression8616 | None
    failure: ScalarAffineFailure8616 | None
    stats: ScalarAffineTraceStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether the trace closed without partial publication."""
        return bool(
            self.failure is None
            and self.expression is not None
            and self.expression.complete
            and self.stats.complete
        )


__all__ = [
    "ScalarAffineEntryRegister8616",
    "ScalarAffineExpression8616",
    "ScalarAffineFailure8616",
    "ScalarAffineTerm8616",
    "ScalarAffineTrace8616",
    "ScalarAffineTraceStats8616",
]
