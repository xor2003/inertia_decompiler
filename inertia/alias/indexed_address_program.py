# cython: language_level=3, infer_types=True
"""Build a closed program census of indexed-address Alias evidence.

Layer: Alias.
Responsibility: project exact selected function boundaries through the existing
IR and Alias indexed-address owners, retaining unavailable functions as typed
refusals before Widening consumes any project-wide evidence.
Owns storage identity and exact Alias-domain relationships.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactVerdict8616,
    function_ssa_artifact_for_boundary_8616,
)
from inertia.ir.indexed_address_copy_evidence import (
    collect_indexed_address_copy_evidence_8616,
)
from inertia.ir.indexed_address_evidence import collect_indexed_address_evidence_8616
from inertia.ir.indexed_address_range_candidates import (
    collect_indexed_loop_ranges_from_ssa_8616,
)

from .indexed_address_access_classification import (
    classify_indexed_alias_accesses_8616,
)
from .indexed_address_access_contracts import IndexedAliasAccessEvidence8616
from .indexed_address_contracts import IndexedAddressAliasEvidence8616
from .indexed_address_copy_contracts import IndexedAliasCopyEvidence8616
from .indexed_address_copy_projection import project_indexed_address_copies_8616
from .indexed_address_projection import project_indexed_address_aliases_8616
from .indexed_address_range_contracts import IndexedAliasLoopRangeEvidence8616
from .indexed_address_range_projection import project_indexed_loop_ranges_to_alias_8616
import dataclasses
import operator


class IndexedAliasProgramFailureKind8616(StrEnum):
    """Stable reason one selected function has no Alias program fact."""

    FUNCTION_MISSING = "function_missing"
    FUNCTION_BOUNDARY_CONFLICT = "function_boundary_conflict"
    IR_BUILD_FAILED = "ir_build_failed"


@dataclasses.dataclass(frozen=True, )
class IndexedAliasFunctionSelection8616:
    """One exact project function address and its optional recovered boundary."""

    function_addr: cython.longlong
    function: object | None

    @property
    def complete(self) -> cython.bint:
        """Return whether the selection has a valid canonical address."""
        return self.function_addr >= 0


@dataclasses.dataclass(frozen=True, )
class IndexedAliasFunctionEvidence8616:
    """Coherent indexed Alias address, role, and copy evidence for one function."""

    function_addr: cython.longlong
    addresses: IndexedAddressAliasEvidence8616
    accesses: IndexedAliasAccessEvidence8616
    copies: IndexedAliasCopyEvidence8616
    ranges: IndexedAliasLoopRangeEvidence8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every artifact derives from one exact IR source."""
        return bool(
            self.function_addr >= 0
            and self.addresses.closed
            and self.accesses.closed
            and self.copies.closed
            and self.ranges.closed
            and self.function_addr == self.addresses.function_addr
            == self.accesses.function_addr
            == self.copies.function_addr
            == self.ranges.function_addr
            and operator.eq(self.accesses.source, self.addresses)
            and operator.eq(self.copies.aliases, self.addresses)
            and operator.eq(self.copies.accesses, self.accesses)
            and operator.eq(self.copies.source.source, self.addresses.source)
            and operator.eq(self.ranges.accesses, self.accesses)
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAliasFunctionRefusal8616:
    """One selected function unavailable to the program Alias census."""

    function_addr: cython.longlong
    failure: IndexedAliasProgramFailureKind8616
    detail: object

    @property
    def complete(self) -> cython.bint:
        """Return whether the refusal identifies one function and stable reason."""
        return self.function_addr >= 0 and bool(self.detail)


@dataclasses.dataclass(frozen=True, )
class IndexedAliasProgramStats8616:
    """Closed function-level accounting for the Alias program census."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def closed(self) -> cython.bint:
        """Return whether every selected function became evidence or refusal."""
        return bool(
            operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclasses.dataclass(frozen=True, )
class IndexedAliasProgramEvidence8616:
    """Deterministic project-wide indexed Alias evidence and refusals."""

    functions: object
    refusals: object
    stats: IndexedAliasProgramStats8616

    @property
    def closed(self) -> cython.bint:
        """Return whether function identities and all census counters close."""
        function_addresses = tuple(fact.function_addr for fact in iter(self.functions))
        refusal_addresses = tuple(
            refusal.function_addr for refusal in iter(self.refusals)
        )
        addresses = (*function_addresses, *refusal_addresses)
        return bool(
            operator.eq(function_addresses, tuple(sorted(function_addresses)))
            and operator.eq(refusal_addresses, tuple(sorted(refusal_addresses)))
            and operator.eq(len(addresses), len(set(addresses)))
            and operator.eq(len(self.functions), self.stats.materialized_count)
            and operator.eq(len(self.refusals), self.stats.failure_count)
            and operator.eq(self.stats.raw_fact_count, len(addresses))
            and self.stats.closed
            and all(fact.complete for fact in iter(self.functions))
            and all(refusal.complete for refusal in iter(self.refusals))
        )


@cython.ccall
def build_indexed_alias_function_evidence_8616(
    project: object,
    selection: IndexedAliasFunctionSelection8616,
) -> IndexedAliasFunctionEvidence8616 | IndexedAliasFunctionRefusal8616:
    """Build all indexed Alias artifacts for one exact selected function."""
    failure: object
    function: object
    function_ssa: object
    function = selection.function
    if function is None:
        return IndexedAliasFunctionRefusal8616(
            selection.function_addr,
            IndexedAliasProgramFailureKind8616.FUNCTION_MISSING,
            "exact recovered function boundary is unavailable",
        )
    resolution = function_ssa_artifact_for_boundary_8616(
        project,
        selection.function_addr,
        function,
    )
    if (
        resolution.failure
        is FunctionSSAArtifactFailure8616.FUNCTION_BOUNDARY_CONFLICT
    ):
        return IndexedAliasFunctionRefusal8616(
            selection.function_addr,
            IndexedAliasProgramFailureKind8616.FUNCTION_BOUNDARY_CONFLICT,
            "recovered function boundary does not match its selected address",
        )
    function_ssa = resolution.artifact
    if (
        resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        or function_ssa is None
    ):
        failure = resolution.failure
        detail = failure.value if failure is not None else "unknown_ir_failure"
        return IndexedAliasFunctionRefusal8616(
            selection.function_addr,
            IndexedAliasProgramFailureKind8616.IR_BUILD_FAILED,
            f"exact IR/SSA construction refused: {detail}",
        )
    ir_evidence = collect_indexed_address_evidence_8616(function_ssa)
    ir_copies = collect_indexed_address_copy_evidence_8616(
        function_ssa,
        ir_evidence,
    )
    aliases = project_indexed_address_aliases_8616(ir_evidence)
    accesses = classify_indexed_alias_accesses_8616(aliases)
    ir_ranges = collect_indexed_loop_ranges_from_ssa_8616(
        function_ssa,
        ir_evidence,
    )
    copies = project_indexed_address_copies_8616(
        ir_copies,
        aliases,
        accesses,
    )
    ranges = project_indexed_loop_ranges_to_alias_8616(ir_ranges, accesses)
    result = IndexedAliasFunctionEvidence8616(
        selection.function_addr,
        aliases,
        accesses,
        copies,
        ranges,
    )
    if not result.complete:
        raise ValueError("indexed-address function Alias artifacts are incoherent")
    return result


def assemble_indexed_alias_program_evidence_8616(
    results: Sequence[
        IndexedAliasFunctionEvidence8616 | IndexedAliasFunctionRefusal8616
    ],
    expected_addresses: Sequence[cython.longlong],
) -> IndexedAliasProgramEvidence8616:
    """Assemble exact per-function results into one closed Alias census."""
    addresses = tuple(sorted(expected_addresses))
    if any(address < 0 for address in iter(addresses)) or operator.ne(len(addresses), len(
        set(addresses)
    )):
        raise ValueError("indexed-address program contains invalid function identities")
    functions = tuple(
        sorted(
            (
                result
                for result in iter(results)
                if isinstance(result, IndexedAliasFunctionEvidence8616)
            ),
            key=lambda fact: fact.function_addr,
        )
    )
    refusals = tuple(
        sorted(
            (
                result
                for result in iter(results)
                if isinstance(result, IndexedAliasFunctionRefusal8616)
            ),
            key=lambda refusal: refusal.function_addr,
        )
    )
    result_addresses = tuple(
        sorted(
            tuple(fact.function_addr for fact in iter(functions))
            + tuple(refusal.function_addr for refusal in iter(refusals))
        )
    )
    if result_addresses != addresses:
        raise ValueError("indexed-address program results do not match selections")
    evidence = IndexedAliasProgramEvidence8616(
        functions,
        refusals,
        IndexedAliasProgramStats8616(
            raw_fact_count=len(addresses),
            normalized_fact_count=len(functions),
            classified_fact_count=len(functions),
            materialized_count=len(functions),
            failure_count=len(refusals),
        ),
    )
    if not evidence.closed:
        raise ValueError("indexed-address program Alias accounting did not close")
    return evidence


def build_indexed_alias_program_evidence_8616(
    project: object,
    selections: Sequence[IndexedAliasFunctionSelection8616],
) -> IndexedAliasProgramEvidence8616:
    """Build one closed Alias census from exact recovered function selections."""
    ordered = tuple(sorted(selections, key=lambda selection: selection.function_addr))
    if not all(selection.complete for selection in iter(ordered)):
        raise ValueError("indexed-address program selection contains an invalid address")
    addresses = tuple(selection.function_addr for selection in iter(ordered))
    if operator.ne(len(addresses), len(set(addresses))):
        raise ValueError("indexed-address program selection contains duplicate functions")
    results = [
        build_indexed_alias_function_evidence_8616(project, selection)
        for selection in iter(ordered)
    ]
    return assemble_indexed_alias_program_evidence_8616(
        results,
        addresses,
    )


__all__ = [
    "IndexedAliasFunctionEvidence8616",
    "IndexedAliasFunctionRefusal8616",
    "IndexedAliasFunctionSelection8616",
    "IndexedAliasProgramEvidence8616",
    "IndexedAliasProgramFailureKind8616",
    "IndexedAliasProgramStats8616",
    "assemble_indexed_alias_program_evidence_8616",
    "build_indexed_alias_function_evidence_8616",
    "build_indexed_alias_program_evidence_8616",
]
