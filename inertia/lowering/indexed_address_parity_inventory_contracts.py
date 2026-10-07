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


@dataclass(frozen=True, slots=True)
class IndexedAddressCollectorMismatch8616:
    """One unmatched key plus only the typed evidence that classifies it."""

    side: IndexedAddressCollectorSide8616
    kind: IndexedAddressMismatchKind8616
    key: IndexedAddressCollectorKey8616
    counterpart_keys: tuple[IndexedAddressCollectorKey8616, ...] = ()
    ir_failures: tuple[IndexedAddressFailureKind8616, ...] = ()
    alias_failures: tuple[IndexedAddressAliasFailureKind8616, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether the classification has exactly its required proof."""
        if not self.key.complete or not all(key.complete for key in self.counterpart_keys):
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


@dataclass(frozen=True, slots=True)
class IndexedAddressCopySite8616:
    """Exact machine and segmented-base identity of one Alias-proven copy."""

    source_instr_addr: int
    destination_instr_addr: int
    source_base_offset: int
    destination_base_offset: int

    @property
    def complete(self) -> bool:
        """Return whether this diagnostic identifies two distinct endpoints."""
        return bool(
            self.source_instr_addr >= 0
            and self.destination_instr_addr > self.source_instr_addr
            and 0 <= self.source_base_offset <= 0xFFFF
            and 0 <= self.destination_base_offset <= 0xFFFF
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressFunctionParityReport8616:
    """Closed indexed-address migration report for one recovered function."""

    function_addr: int
    ir_stats: IndexedAddressStats8616
    alias_stats: IndexedAddressAliasStats8616
    access_stats: IndexedAliasAccessStats8616
    access_roles: tuple[IndexedAliasAccessRole8616, ...]
    copy_stats: IndexedAddressCopyStats8616
    alias_copy_stats: IndexedAliasCopyStats8616
    alias_copy_sites: tuple[IndexedAddressCopySite8616, ...]
    parity: IndexedAddressCollectorParity8616
    mismatches: tuple[IndexedAddressCollectorMismatch8616, ...]

    @property
    def closed(self) -> bool:
        """Return whether all source, projection, and mismatch counts agree."""
        alias_mismatches = frozenset(
            mismatch.key
            for mismatch in self.mismatches
            if mismatch.side is IndexedAddressCollectorSide8616.ALIAS
        )
        legacy_mismatches = frozenset(
            mismatch.key
            for mismatch in self.mismatches
            if mismatch.side is IndexedAddressCollectorSide8616.LEGACY
        )
        return bool(
            self.function_addr >= 0
            and self.function_addr == self.parity.function_addr
            and self.ir_stats.closed
            and self.alias_stats.closed
            and self.access_stats.closed
            and self.copy_stats.closed
            and self.alias_copy_stats.closed
            and self.alias_stats.raw_fact_count == self.ir_stats.normalized_fact_count
            and self.access_stats.raw_fact_count == self.alias_stats.raw_fact_count
            and len(self.access_roles) == self.access_stats.materialized_count
            and self.alias_copy_stats.raw_fact_count == self.copy_stats.raw_fact_count
            and len(self.alias_copy_sites) == self.alias_copy_stats.materialized_count
            and all(site.complete for site in self.alias_copy_sites)
            and self.parity.closed
            and all(mismatch.complete for mismatch in self.mismatches)
            and len(self.mismatches)
            == self.parity.stats.alias_only_count + self.parity.stats.legacy_only_count
            and alias_mismatches == frozenset(self.parity.alias_only)
            and legacy_mismatches == frozenset(self.parity.legacy_only)
        )

    @property
    def exact(self) -> bool:
        """Return whether both collectors agree and all source evidence closes."""
        return self.closed and self.parity.exact and not self.mismatches


@dataclass(frozen=True, slots=True)
class IndexedAddressParityInventoryStats8616:
    """Closed aggregate accounting for a whole-program migration inventory."""

    function_count: int
    exact_function_count: int
    divergent_function_count: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    alias_materialized_count: int
    alias_failure_count: int
    access_materialized_count: int
    access_failure_count: int
    pointer_relative_count: int
    global_indexed_count: int
    copy_raw_fact_count: int
    copy_materialized_count: int
    copy_failure_count: int
    alias_copy_materialized_count: int
    alias_copy_failure_count: int
    raw_key_count: int
    normalized_key_count: int
    matched_key_count: int
    alias_only_count: int
    legacy_only_count: int
    duplicate_key_count: int
    identity_conflict_count: int
    alias_only_no_legacy_count: int
    legacy_only_no_ir_count: int
    legacy_only_ir_refusal_count: int
    legacy_only_alias_refusal_count: int
    coalesced_fact_count: int = 0

    @classmethod
    def from_reports(
        cls,
        reports: tuple[IndexedAddressFunctionParityReport8616, ...],
    ) -> IndexedAddressParityInventoryStats8616:
        """Aggregate deterministic counters from closed function reports."""
        mismatches = tuple(mismatch for report in reports for mismatch in report.mismatches)
        return cls(
            function_count=len(reports),
            exact_function_count=sum(report.exact for report in reports),
            divergent_function_count=sum(not report.exact for report in reports),
            raw_fact_count=sum(report.ir_stats.raw_fact_count for report in reports),
            normalized_fact_count=sum(report.ir_stats.normalized_fact_count for report in reports),
            classified_fact_count=sum(report.ir_stats.classified_fact_count for report in reports),
            materialized_count=sum(report.ir_stats.materialized_count for report in reports),
            failure_count=sum(report.ir_stats.failure_count for report in reports),
            alias_materialized_count=sum(report.alias_stats.materialized_count for report in reports),
            alias_failure_count=sum(report.alias_stats.failure_count for report in reports),
            access_materialized_count=sum(report.access_stats.materialized_count for report in reports),
            access_failure_count=sum(report.access_stats.failure_count for report in reports),
            pointer_relative_count=sum(
                role is IndexedAliasAccessRole8616.POINTER_RELATIVE
                for report in reports
                for role in report.access_roles
            ),
            global_indexed_count=sum(
                role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
                for report in reports
                for role in report.access_roles
            ),
            copy_raw_fact_count=sum(report.copy_stats.raw_fact_count for report in reports),
            copy_materialized_count=sum(
                report.copy_stats.materialized_count for report in reports
            ),
            copy_failure_count=sum(report.copy_stats.failure_count for report in reports),
            alias_copy_materialized_count=sum(
                report.alias_copy_stats.materialized_count for report in reports
            ),
            alias_copy_failure_count=sum(
                report.alias_copy_stats.failure_count for report in reports
            ),
            raw_key_count=sum(report.parity.stats.raw_key_count for report in reports),
            normalized_key_count=sum(report.parity.stats.normalized_key_count for report in reports),
            matched_key_count=sum(report.parity.stats.matched_key_count for report in reports),
            alias_only_count=sum(report.parity.stats.alias_only_count for report in reports),
            legacy_only_count=sum(report.parity.stats.legacy_only_count for report in reports),
            duplicate_key_count=sum(report.parity.stats.duplicate_key_count for report in reports),
            identity_conflict_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.IDENTITY_CONFLICT
                for mismatch in mismatches
            ),
            alias_only_no_legacy_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.ALIAS_ONLY_NO_LEGACY_CANDIDATE
                for mismatch in mismatches
            ),
            legacy_only_no_ir_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_NO_IR_CANDIDATE
                for mismatch in mismatches
            ),
            legacy_only_ir_refusal_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_IR_REFUSED
                for mismatch in mismatches
            ),
            legacy_only_alias_refusal_count=sum(
                mismatch.kind is IndexedAddressMismatchKind8616.LEGACY_ONLY_ALIAS_REFUSED
                for mismatch in mismatches
            ),
            coalesced_fact_count=sum(
                report.ir_stats.coalesced_fact_count for report in reports
            ),
        )

    @property
    def closed(self) -> bool:
        """Return whether every function, fact, key, and mismatch is counted."""
        mismatch_count = (
            self.identity_conflict_count
            + self.alias_only_no_legacy_count
            + self.legacy_only_no_ir_count
            + self.legacy_only_ir_refusal_count
            + self.legacy_only_alias_refusal_count
        )
        return bool(
            self.function_count == self.exact_function_count + self.divergent_function_count
            and self.raw_fact_count
            == self.normalized_fact_count + self.coalesced_fact_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.alias_materialized_count + self.alias_failure_count
            == self.access_materialized_count + self.access_failure_count
            and self.access_materialized_count
            == self.pointer_relative_count + self.global_indexed_count
            and self.copy_raw_fact_count
            == self.copy_materialized_count + self.copy_failure_count
            == self.alias_copy_materialized_count + self.alias_copy_failure_count
            and self.raw_key_count == self.normalized_key_count + self.duplicate_key_count
            and self.normalized_key_count
            == self.matched_key_count * 2 + self.alias_only_count + self.legacy_only_count
            and mismatch_count == self.alias_only_count + self.legacy_only_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressParityInventory8616:
    """Deterministic whole-program indexed-address migration inventory."""

    functions: tuple[IndexedAddressFunctionParityReport8616, ...]
    stats: IndexedAddressParityInventoryStats8616

    @property
    def closed(self) -> bool:
        """Return whether every unique function and aggregate counter closes."""
        addresses = tuple(report.function_addr for report in self.functions)
        return bool(
            addresses == tuple(sorted(addresses))
            and len(addresses) == len(set(addresses))
            and all(report.closed for report in self.functions)
            and self.stats == IndexedAddressParityInventoryStats8616.from_reports(self.functions)
            and self.stats.closed
        )

    @property
    def exact(self) -> bool:
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
