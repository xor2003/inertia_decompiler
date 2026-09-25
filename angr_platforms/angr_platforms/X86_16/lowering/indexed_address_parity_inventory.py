"""Build a side-effect-free indexed-address collector migration inventory.

Layer: Types/Lowering diagnostics.
Responsibility: consume authoritative IR and Alias artifacts plus the current
late collectors, classify exact key relationships, and aggregate a migration
census without selecting evidence or changing generated C.
Consumes alias, widening, and typed facts; do not recover new semantics here.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not perform structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Protocol, cast

from ..alias.indexed_address_access_classification import (
    classify_indexed_alias_accesses_8616,
)
from ..alias.indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFailureKind8616,
)
from ..alias.indexed_address_copy_projection import project_indexed_address_copies_8616
from ..alias.indexed_address_projection import project_indexed_address_aliases_8616
from ..ir.indexed_address_contracts import IndexedAddressFailureKind8616
from ..ir.indexed_address_copy_evidence import collect_indexed_address_copy_evidence_8616
from ..ir.indexed_address_evidence import collect_indexed_address_evidence_8616
from ..ir.ssa_function import build_x86_16_function_ssa
from ..ir.vex_import import build_x86_16_ir_function_artifact
from ..pipeline.errors import PipelineHardError
from .indexed_address_collector_parity import (
    IndexedAddressCollectorKey8616,
    IndexedAddressCollectorParity8616,
    compare_indexed_address_collectors_8616,
)
from .indexed_address_parity_inventory_contracts import (
    IndexedAddressCollectorMismatch8616,
    IndexedAddressCollectorSide8616,
    IndexedAddressCopySite8616,
    IndexedAddressFunctionParityReport8616,
    IndexedAddressMismatchKind8616,
    IndexedAddressParityInventory8616,
    IndexedAddressParityInventoryStats8616,
)
from .segmented_global_loads import (
    recover_indexed_segmented_global_load_site_evidence_8616,
    recover_indexed_segmented_global_store_evidence_8616,
)


class _FunctionBoundary8616(Protocol):
    """Minimal dynamic angr function boundary needed by this diagnostic."""

    addr: object


def _key_order_8616(key: IndexedAddressCollectorKey8616) -> tuple[object, ...]:
    """Return deterministic primitive ordering for collector keys."""
    return (
        key.kind.value,
        key.space.value,
        key.base_offset,
        key.width,
        key.index_stack_offset,
        key.index_shift,
        key.instr_addr,
    )


def _mismatch_order_8616(
    mismatch: IndexedAddressCollectorMismatch8616,
) -> tuple[object, ...]:
    """Return deterministic primitive ordering for mismatch records."""
    return (mismatch.side.value, *_key_order_8616(mismatch.key))


def _keys_by_site_8616(
    keys: tuple[IndexedAddressCollectorKey8616, ...],
) -> dict[tuple[object, int], tuple[IndexedAddressCollectorKey8616, ...]]:
    """Group keys by exact access kind and machine instruction address."""
    grouped: defaultdict[tuple[object, int], list[IndexedAddressCollectorKey8616]] = defaultdict(list)
    for key in keys:
        grouped[(key.kind, key.instr_addr)].append(key)
    return {
        site: tuple(sorted(site_keys, key=_key_order_8616))
        for site, site_keys in grouped.items()
    }


def _classify_unmatched_key_8616(
    side: IndexedAddressCollectorSide8616,
    key: IndexedAddressCollectorKey8616,
    counterparts: tuple[IndexedAddressCollectorKey8616, ...],
    alias_failures_by_addr: Mapping[int, list[IndexedAddressAliasFailureKind8616]],
    ir_failures_by_addr: Mapping[int, list[IndexedAddressFailureKind8616]],
) -> IndexedAddressCollectorMismatch8616:
    """Classify one unmatched key against counterparts and typed refusals."""
    if counterparts:
        return IndexedAddressCollectorMismatch8616(
            side,
            IndexedAddressMismatchKind8616.IDENTITY_CONFLICT,
            key,
            counterparts,
        )
    if side is IndexedAddressCollectorSide8616.ALIAS:
        return IndexedAddressCollectorMismatch8616(
            side,
            IndexedAddressMismatchKind8616.ALIAS_ONLY_NO_LEGACY_CANDIDATE,
            key,
        )
    alias_failures = tuple(
        sorted(alias_failures_by_addr.get(key.instr_addr, ()), key=lambda item: item.value)
    )
    ir_failures = tuple(
        sorted(ir_failures_by_addr.get(key.instr_addr, ()), key=lambda item: item.value)
    )
    if alias_failures:
        return IndexedAddressCollectorMismatch8616(
            side,
            IndexedAddressMismatchKind8616.LEGACY_ONLY_ALIAS_REFUSED,
            key,
            alias_failures=alias_failures,
        )
    if ir_failures:
        return IndexedAddressCollectorMismatch8616(
            side,
            IndexedAddressMismatchKind8616.LEGACY_ONLY_IR_REFUSED,
            key,
            ir_failures=ir_failures,
        )
    return IndexedAddressCollectorMismatch8616(
        side,
        IndexedAddressMismatchKind8616.LEGACY_ONLY_NO_IR_CANDIDATE,
        key,
    )


def classify_indexed_address_mismatches_8616(
    alias_evidence: IndexedAddressAliasEvidence8616,
    parity: IndexedAddressCollectorParity8616,
) -> tuple[IndexedAddressCollectorMismatch8616, ...]:
    """Classify unmatched keys only from exact identities and typed refusals."""
    if not alias_evidence.closed or not parity.closed:
        raise PipelineHardError(
            "indexed-address mismatch classification requires closed evidence",
            layer="lowering",
        )
    if alias_evidence.function_addr != parity.function_addr:
        raise PipelineHardError(
            "indexed-address mismatch inputs belong to different functions",
            layer="lowering",
        )

    alias_keys_by_site = _keys_by_site_8616((*parity.matched, *parity.alias_only))
    legacy_keys_by_site = _keys_by_site_8616((*parity.matched, *parity.legacy_only))
    ir_failures_by_addr: defaultdict[int, list[IndexedAddressFailureKind8616]] = defaultdict(list)
    for ir_refusal in alias_evidence.source.refusals:
        ir_failures_by_addr[ir_refusal.instr_addr].append(ir_refusal.failure)
    alias_failures_by_addr: defaultdict[
        int, list[IndexedAddressAliasFailureKind8616]
    ] = defaultdict(list)
    for alias_refusal in alias_evidence.refusals:
        if alias_refusal.source_fact is not None:
            alias_failures_by_addr[alias_refusal.source_fact.instr_addr].append(alias_refusal.failure)

    mismatches: list[IndexedAddressCollectorMismatch8616] = []
    for side, unmatched, counterparts_by_site in (
        (IndexedAddressCollectorSide8616.ALIAS, parity.alias_only, legacy_keys_by_site),
        (IndexedAddressCollectorSide8616.LEGACY, parity.legacy_only, alias_keys_by_site),
    ):
        for key in unmatched:
            mismatches.append(
                _classify_unmatched_key_8616(
                    side,
                    key,
                    counterparts_by_site.get((key.kind, key.instr_addr), ()),
                    alias_failures_by_addr,
                    ir_failures_by_addr,
                )
            )
    result = tuple(sorted(mismatches, key=_mismatch_order_8616))
    if not all(mismatch.complete for mismatch in result):
        raise PipelineHardError(
            "indexed-address mismatch classification is incomplete",
            layer="lowering",
        )
    return result


def build_indexed_address_function_parity_report_8616(
    project: object,
    function: object,
) -> IndexedAddressFunctionParityReport8616:
    """Build one function report directly from IR, Alias, and legacy facts."""
    function_addr = cast(_FunctionBoundary8616, function).addr
    if not isinstance(function_addr, int) or function_addr < 0:
        raise PipelineHardError(
            "indexed-address inventory received a function without a valid address",
            layer="lowering",
        )
    ir_artifact = build_x86_16_ir_function_artifact(project, function)
    function_ssa = build_x86_16_function_ssa(ir_artifact)
    ir_evidence = collect_indexed_address_evidence_8616(function_ssa)
    alias_evidence = project_indexed_address_aliases_8616(ir_evidence)
    access_evidence = classify_indexed_alias_accesses_8616(alias_evidence)
    copy_evidence = collect_indexed_address_copy_evidence_8616(
        function_ssa,
        ir_evidence,
    )
    alias_copy_evidence = project_indexed_address_copies_8616(
        copy_evidence,
        alias_evidence,
        access_evidence,
    )
    parity = compare_indexed_address_collectors_8616(
        alias_evidence,
        recover_indexed_segmented_global_load_site_evidence_8616(project, function),
        recover_indexed_segmented_global_store_evidence_8616(project, function),
    )
    report = IndexedAddressFunctionParityReport8616(
        function_addr,
        ir_evidence.stats,
        alias_evidence.stats,
        access_evidence.stats,
        tuple(fact.role for fact in access_evidence.facts),
        copy_evidence.stats,
        alias_copy_evidence.stats,
        tuple(
            IndexedAddressCopySite8616(
                fact.source_copy.source.instr_addr,
                fact.source_copy.destination.instr_addr,
                fact.source.storage.base_offset,
                fact.destination.storage.base_offset,
            )
            for fact in alias_copy_evidence.facts
        ),
        parity,
        classify_indexed_address_mismatches_8616(alias_evidence, parity),
    )
    if not report.closed:
        raise PipelineHardError(
            "indexed-address function parity report is incomplete",
            layer="lowering",
        )
    return report


def build_indexed_address_parity_inventory_8616(
    project: object,
    functions: Iterable[object],
) -> IndexedAddressParityInventory8616:
    """Build a deterministic whole-program inventory without mutating codegen."""
    reports = tuple(
        sorted(
            (
                build_indexed_address_function_parity_report_8616(project, function)
                for function in functions
            ),
            key=lambda report: report.function_addr,
        )
    )
    inventory = IndexedAddressParityInventory8616(
        reports,
        IndexedAddressParityInventoryStats8616.from_reports(reports),
    )
    if not inventory.closed:
        raise PipelineHardError(
            "indexed-address whole-program parity inventory is incomplete",
            layer="lowering",
        )
    return inventory


__all__ = [
    "build_indexed_address_function_parity_report_8616",
    "build_indexed_address_parity_inventory_8616",
    "classify_indexed_address_mismatches_8616",
]
