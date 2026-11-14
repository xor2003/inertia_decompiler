# cython: language_level=3, infer_types=True
"""Typed whole-program contracts for indexed-address collector migration.

Layer: Types/Lowering diagnostics.
Responsibility: retain exact per-function collector parity, mechanically
classified mismatches, and closed whole-program accounting without selecting
semantic evidence or changing generated C.
Consumes alias, widening, and typed facts; do not recover new semantics here.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not perform structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessRole8616,
    IndexedAliasAccessStats8616,
)
from inertia.alias.indexed_address_contracts import (
    IndexedAddressAliasFailureKind8616,
    IndexedAddressAliasStats8616,
)
from inertia.alias.indexed_address_copy_contracts import IndexedAliasCopyStats8616
from inertia.ir.indexed_address_contracts import (
    IndexedAddressFailureKind8616,
    IndexedAddressStats8616,
)
from inertia.ir.indexed_address_copy_contracts import IndexedAddressCopyStats8616

from .indexed_address_collector_parity import (
    IndexedAddressCollectorKey8616,
    IndexedAddressCollectorParity8616,
)
import dataclasses
import operator


class IndexedAddressCollectorSide8616(StrEnum):
    """Collector that owns one unmatched migration key."""

    ALIAS = "alias"
    LEGACY = "legacy"


class IndexedAddressMismatchKind8616(StrEnum):
    """Mechanically proven relationship for one unmatched collector key."""

    IDENTITY_CONFLICT = "identity_conflict"
    ALIAS_ONLY_NO_LEGACY_CANDIDATE = "alias_only_no_legacy_candidate"
    LEGACY_ONLY_NO_IR_CANDIDATE = "legacy_only_no_ir_candidate"
    LEGACY_ONLY_IR_REFUSED = "legacy_only_ir_refused"
    LEGACY_ONLY_ALIAS_REFUSED = "legacy_only_alias_refused"


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCollectorMismatch8616:
    """One unmatched key plus only the typed evidence that classifies it."""

    side: IndexedAddressCollectorSide8616
    kind: IndexedAddressMismatchKind8616
    key: IndexedAddressCollectorKey8616
    counterpart_keys: tuple[IndexedAddressCollectorKey8616, ...] = ()
    ir_failures: tuple[IndexedAddressFailureKind8616, ...] = ()
    alias_failures: tuple[IndexedAddressAliasFailureKind8616, ...] = ()

    @property
    def complete(self) -> cython.bint:
        """Return whether the classification has exactly its required proof."""
        if not self.key.complete or not all(key.complete for key in iter(self.counterpart_keys)):
            return False
        if self.kind is IndexedAddressMismatchKind8616.IDENTITY_CONFLICT:
            return bool(self.counterpart_keys and not self.ir_failures and not self.alias_failures)
        if self.kind is IndexedAddressMismatchKind8616.ALIAS_ONLY_NO_LEGACY_CANDIDATE:
            return bool(
                self.side is IndexedAddressCollectorSide8616.ALIAS
                and not self.counterpart_keys
                and not self.ir_failures
                and not self.alias_failures
            )
        if self.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_NO_IR_CANDIDATE:
            return bool(
                self.side is IndexedAddressCollectorSide8616.LEGACY
                and not self.counterpart_keys
                and not self.ir_failures
                and not self.alias_failures
            )
        if self.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_IR_REFUSED:
            return bool(
                self.side is IndexedAddressCollectorSide8616.LEGACY
                and not self.counterpart_keys
                and self.ir_failures
                and not self.alias_failures
            )
        return bool(
            self.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_ALIAS_REFUSED
            and self.side is IndexedAddressCollectorSide8616.LEGACY
            and not self.counterpart_keys
            and self.alias_failures
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressCopySite8616:
    """Exact machine and segmented-base identity of one Alias-proven copy."""

    source_instr_addr: cython.longlong
    destination_instr_addr: cython.longlong
    source_base_offset: cython.longlong
    destination_base_offset: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether this diagnostic identifies two distinct endpoints."""
        return bool(
            self.source_instr_addr >= 0
            and self.destination_instr_addr > self.source_instr_addr
            and 0 <= self.source_base_offset <= 0xFFFF
            and 0 <= self.destination_base_offset <= 0xFFFF
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressFunctionParityReport8616:
    """Closed indexed-address migration report for one recovered function."""

    function_addr: cython.longlong
    ir_stats: IndexedAddressStats8616
    alias_stats: IndexedAddressAliasStats8616
    access_stats: IndexedAliasAccessStats8616
    access_roles: object
    copy_stats: IndexedAddressCopyStats8616
    alias_copy_stats: IndexedAliasCopyStats8616
    alias_copy_sites: object
    parity: IndexedAddressCollectorParity8616
    mismatches: object

    @property
    def closed(self) -> cython.bint:
        """Return whether all source, projection, and mismatch counts agree."""
        alias_mismatches = frozenset(
            mismatch.key
            for mismatch in iter(self.mismatches)
            if mismatch.side is IndexedAddressCollectorSide8616.ALIAS
        )
        legacy_mismatches = frozenset(
            mismatch.key
            for mismatch in iter(self.mismatches)
            if mismatch.side is IndexedAddressCollectorSide8616.LEGACY
        )
        return bool(
            self.function_addr >= 0
            and operator.eq(self.function_addr, self.parity.function_addr)
            and self.ir_stats.closed
            and self.alias_stats.closed
            and self.access_stats.closed
            and self.copy_stats.closed
            and self.alias_copy_stats.closed
            and operator.eq(self.alias_stats.raw_fact_count, self.ir_stats.normalized_fact_count)
            and operator.eq(self.access_stats.raw_fact_count, self.alias_stats.raw_fact_count)
            and operator.eq(len(self.access_roles), self.access_stats.materialized_count)
            and operator.eq(self.alias_copy_stats.raw_fact_count, self.copy_stats.raw_fact_count)
            and operator.eq(len(self.alias_copy_sites), self.alias_copy_stats.materialized_count)
            and all(site.complete for site in iter(self.alias_copy_sites))
            and self.parity.closed
            and all(mismatch.complete for mismatch in iter(self.mismatches))
            and operator.eq(len(self.mismatches), self.parity.stats.alias_only_count + self.parity.stats.legacy_only_count)
            and operator.eq(alias_mismatches, frozenset(self.parity.alias_only))
            and operator.eq(legacy_mismatches, frozenset(self.parity.legacy_only))
        )

    @property
    def exact(self) -> cython.bint:
        """Return whether both collectors agree and all source evidence closes."""
        return self.closed and self.parity.exact and not self.mismatches


@dataclasses.dataclass(frozen=True, )
class IndexedAddressParityInventoryStats8616:
    """Closed aggregate accounting for a whole-program migration inventory."""

    function_count: cython.longlong
    exact_function_count: cython.longlong
    divergent_function_count: cython.longlong
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    alias_materialized_count: cython.longlong
    alias_failure_count: cython.longlong
    access_materialized_count: cython.longlong
    access_failure_count: cython.longlong
    pointer_relative_count: cython.longlong
    global_indexed_count: cython.longlong
    copy_raw_fact_count: cython.longlong
    copy_materialized_count: cython.longlong
    copy_failure_count: cython.longlong
    alias_copy_materialized_count: cython.longlong
    alias_copy_failure_count: cython.longlong
    raw_key_count: cython.longlong
    normalized_key_count: cython.longlong
    matched_key_count: cython.longlong
    alias_only_count: cython.longlong
    legacy_only_count: cython.longlong
    duplicate_key_count: cython.longlong
    identity_conflict_count: cython.longlong
    alias_only_no_legacy_count: cython.longlong
    legacy_only_no_ir_count: cython.longlong
    legacy_only_ir_refusal_count: cython.longlong
    legacy_only_alias_refusal_count: cython.longlong
    coalesced_fact_count: cython.longlong = 0

    @classmethod
    def from_reports(
        cls,
        reports: object,
    ) -> IndexedAddressParityInventoryStats8616:
        """Aggregate deterministic counters from closed function reports."""
        mismatches = tuple(mismatch for report in iter(reports) for mismatch in iter(report.mismatches))
        return cls(
            function_count=len(reports),
            exact_function_count=sum(report.exact for report in iter(reports)),
            divergent_function_count=sum(not report.exact for report in iter(reports)),
            raw_fact_count=sum(report.ir_stats.raw_fact_count for report in iter(reports)),
            normalized_fact_count=sum(report.ir_stats.normalized_fact_count for report in iter(reports)),
            classified_fact_count=sum(report.ir_stats.classified_fact_count for report in iter(reports)),
            materialized_count=sum(report.ir_stats.materialized_count for report in iter(reports)),
            failure_count=sum(report.ir_stats.failure_count for report in iter(reports)),
            alias_materialized_count=sum(report.alias_stats.materialized_count for report in iter(reports)),
            alias_failure_count=sum(report.alias_stats.failure_count for report in iter(reports)),
            access_materialized_count=sum(report.access_stats.materialized_count for report in iter(reports)),
            access_failure_count=sum(report.access_stats.failure_count for report in iter(reports)),
            pointer_relative_count=sum(
                role is IndexedAliasAccessRole8616.POINTER_RELATIVE
                for report in iter(reports)
                for role in iter(report.access_roles)
            ),
            global_indexed_count=sum(
                role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
                for report in iter(reports)
                for role in iter(report.access_roles)
            ),
            copy_raw_fact_count=sum(report.copy_stats.raw_fact_count for report in iter(reports)),
            copy_materialized_count=sum(
                report.copy_stats.materialized_count for report in iter(reports)
            ),
            copy_failure_count=sum(report.copy_stats.failure_count for report in iter(reports)),
            alias_copy_materialized_count=sum(
                report.alias_copy_stats.materialized_count for report in iter(reports)
            ),
            alias_copy_failure_count=sum(
                report.alias_copy_stats.failure_count for report in iter(reports)
            ),
            raw_key_count=sum(report.parity.stats.raw_key_count for report in iter(reports)),
            normalized_key_count=sum(report.parity.stats.normalized_key_count for report in iter(reports)),
            matched_key_count=sum(report.parity.stats.matched_key_count for report in iter(reports)),
            alias_only_count=sum(report.parity.stats.alias_only_count for report in iter(reports)),
            legacy_only_count=sum(report.parity.stats.legacy_only_count for report in iter(reports)),
            duplicate_key_count=sum(report.parity.stats.duplicate_key_count for report in iter(reports)),
            identity_conflict_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.IDENTITY_CONFLICT
                for mismatch in iter(mismatches)
            ),
            alias_only_no_legacy_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.ALIAS_ONLY_NO_LEGACY_CANDIDATE
                for mismatch in iter(mismatches)
            ),
            legacy_only_no_ir_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_NO_IR_CANDIDATE
                for mismatch in iter(mismatches)
            ),
            legacy_only_ir_refusal_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_IR_REFUSED
                for mismatch in iter(mismatches)
            ),
            legacy_only_alias_refusal_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_ALIAS_REFUSED
                for mismatch in iter(mismatches)
            ),
            coalesced_fact_count=sum(
                report.ir_stats.coalesced_fact_count for report in iter(reports)
            ),
        )

    @property
    def closed(self) -> cython.bint:
        """Return whether every function, fact, key, and mismatch is counted."""
        mismatch_count = (
            self.identity_conflict_count
            + self.alias_only_no_legacy_count
            + self.legacy_only_no_ir_count
            + self.legacy_only_ir_refusal_count
            + self.legacy_only_alias_refusal_count
        )
        return bool(
            operator.eq(self.function_count, self.exact_function_count + self.divergent_function_count)
            and operator.eq(self.raw_fact_count, self.normalized_fact_count + self.coalesced_fact_count)
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.alias_materialized_count + self.alias_failure_count
            == self.access_materialized_count + self.access_failure_count
            and operator.eq(self.access_materialized_count, self.pointer_relative_count + self.global_indexed_count)
            and self.copy_raw_fact_count
            == self.copy_materialized_count + self.copy_failure_count
            == self.alias_copy_materialized_count + self.alias_copy_failure_count
            and operator.eq(self.raw_key_count, self.normalized_key_count + self.duplicate_key_count)
            and operator.eq(self.normalized_key_count, self.matched_key_count * 2 + self.alias_only_count + self.legacy_only_count)
            and operator.eq(mismatch_count, self.alias_only_count + self.legacy_only_count)
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAddressParityInventory8616:
    """Deterministic whole-program indexed-address migration inventory."""

    functions: object
    stats: IndexedAddressParityInventoryStats8616

    @property
    def closed(self) -> cython.bint:
        """Return whether every unique function and aggregate counter closes."""
        addresses = tuple(report.function_addr for report in iter(self.functions))
        return bool(
            operator.eq(addresses, tuple(sorted(addresses)))
            and operator.eq(len(addresses), len(set(addresses)))
            and all(report.closed for report in iter(self.functions))
            and operator.eq(self.stats, IndexedAddressParityInventoryStats8616.from_reports(self.functions))
            and self.stats.closed
        )

    @property
    def exact(self) -> cython.bint:
        """Return whether the inventory is closed with no collector divergence."""
        return self.closed and self.stats.divergent_function_count == 0


__all__ = [
    "IndexedAddressCollectorMismatch8616",
    "IndexedAddressCollectorSide8616",
    "IndexedAddressCopySite8616",
    "IndexedAddressFunctionParityReport8616",
    "IndexedAddressMismatchKind8616",
    "IndexedAddressParityInventory8616",
    "IndexedAddressParityInventoryStats8616",
]
