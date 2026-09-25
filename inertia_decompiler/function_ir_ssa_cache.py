"""Persist exact raw IR and IR-stage SSA artifacts by function identity.

Layer: CLI/fallback/reporting orchestration.
Responsibility: restore and publish already-owned IR artifacts without
rebuilding VEX or SSA. This module does not recover or alter semantics.
"""

from __future__ import annotations

import binascii
import pickle
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactResolution8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactResolution8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)

from .cache import _load_cache_json, _store_cache_json
from .function_ir_ssa_cache_codec import (
    FunctionIRSSABundle8616,
    function_ir_ssa_bundle_from_record_8616,
    function_ir_ssa_bundle_record_8616,
)
from .function_ir_ssa_cache_identity import (
    function_addr_from_boundary_8616,
    function_ir_ssa_cache_key_8616,
)

FUNCTION_IR_SSA_CACHE_NAMESPACE_8616: str = "function_ir_ssa"


class FunctionIRSSACacheVerdict8616(StrEnum):
    """Typed outcome of one function cache operation."""

    HIT = "hit"
    MISS = "miss"
    REFUSED = "refused"
    STORED = "stored"


class FunctionIRSSACacheFailure8616(StrEnum):
    """Stable reason one cache operation could not materialize evidence."""

    FUNCTION_IDENTITY_INCOMPLETE = "function_identity_incomplete"
    ENTRY_NOT_FOUND = "entry_not_found"
    MALFORMED_ENTRY = "malformed_entry"
    INCOHERENT_ARTIFACTS = "incoherent_artifacts"
    ARTIFACT_NOT_REGISTERED = "artifact_not_registered"
    REGISTRY_CONFLICT = "registry_conflict"


@dataclass(frozen=True, slots=True)
class FunctionIRSSACacheResult8616:
    """One function cache outcome with optional restored artifacts."""

    function_addr: int
    verdict: FunctionIRSSACacheVerdict8616
    bundle: FunctionIRSSABundle8616 | None = None
    failure: FunctionIRSSACacheFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class FunctionIRSSACacheStats8616:
    """Closed cache evidence accounting for one function catalog."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every classified entry became a hit or refusal."""
        return bool(
            self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class FunctionIRSSACatalogResult8616:
    """Deterministic per-function outcomes and their closed counters."""

    results: tuple[FunctionIRSSACacheResult8616, ...]
    stats: FunctionIRSSACacheStats8616


def load_function_ir_ssa_cache_8616(
    cache_key: dict[str, object],
    function_addr: int,
) -> FunctionIRSSACacheResult8616:
    """Restore one coherent pair, refusing malformed or unsafe payloads."""
    record = _load_cache_json(FUNCTION_IR_SSA_CACHE_NAMESPACE_8616, cache_key)
    if record is None:
        return FunctionIRSSACacheResult8616(
            function_addr,
            FunctionIRSSACacheVerdict8616.MISS,
            failure=FunctionIRSSACacheFailure8616.ENTRY_NOT_FOUND,
        )
    try:
        bundle = function_ir_ssa_bundle_from_record_8616(record, function_addr)
    except (AttributeError, ImportError, binascii.Error, pickle.PickleError, TypeError, ValueError):
        return FunctionIRSSACacheResult8616(
            function_addr,
            FunctionIRSSACacheVerdict8616.REFUSED,
            failure=FunctionIRSSACacheFailure8616.MALFORMED_ENTRY,
        )
    return FunctionIRSSACacheResult8616(
        function_addr,
        FunctionIRSSACacheVerdict8616.HIT,
        bundle,
    )


def store_function_ir_ssa_cache_8616(
    cache_key: dict[str, object],
    bundle: FunctionIRSSABundle8616,
) -> FunctionIRSSACacheResult8616:
    """Persist one already-proven coherent raw IR/SSA pair."""
    function_addr = bundle.ir.function_addr
    try:
        record = function_ir_ssa_bundle_record_8616(bundle)
    except (pickle.PickleError, TypeError, ValueError):
        return FunctionIRSSACacheResult8616(
            function_addr,
            FunctionIRSSACacheVerdict8616.REFUSED,
            failure=FunctionIRSSACacheFailure8616.INCOHERENT_ARTIFACTS,
        )
    _store_cache_json(
        FUNCTION_IR_SSA_CACHE_NAMESPACE_8616,
        cache_key,
        record,
    )
    return FunctionIRSSACacheResult8616(
        function_addr,
        FunctionIRSSACacheVerdict8616.STORED,
        bundle,
    )


def _catalog_result_8616(
    results: Sequence[FunctionIRSSACacheResult8616],
) -> FunctionIRSSACatalogResult8616:
    """Build closed counters for deterministic per-function cache outcomes."""
    ordered = tuple(sorted(results, key=lambda item: item.function_addr))
    normalized = sum(
        result.failure
        is not FunctionIRSSACacheFailure8616.FUNCTION_IDENTITY_INCOMPLETE
        for result in ordered
    )
    classified = sum(
        result.verdict is not FunctionIRSSACacheVerdict8616.MISS
        for result in ordered
    )
    materialized = sum(
        result.verdict
        in {
            FunctionIRSSACacheVerdict8616.HIT,
            FunctionIRSSACacheVerdict8616.STORED,
        }
        for result in ordered
    )
    failures = sum(
        result.verdict is FunctionIRSSACacheVerdict8616.REFUSED
        for result in ordered
    )
    return FunctionIRSSACatalogResult8616(
        ordered,
        FunctionIRSSACacheStats8616(
            len(ordered),
            normalized,
            classified,
            materialized,
            failures,
        ),
    )


def hydrate_function_ir_ssa_catalog_8616(
    project: object,
    functions: Sequence[object],
) -> FunctionIRSSACatalogResult8616:
    """Publish every valid persisted pair into the owning IR registries."""
    results: list[FunctionIRSSACacheResult8616] = []
    for function in functions:
        function_addr = function_addr_from_boundary_8616(function)
        cache_key = function_ir_ssa_cache_key_8616(project, function)
        if cache_key is None:
            results.append(
                FunctionIRSSACacheResult8616(
                    function_addr,
                    FunctionIRSSACacheVerdict8616.MISS,
                    failure=FunctionIRSSACacheFailure8616.FUNCTION_IDENTITY_INCOMPLETE,
                )
            )
            continue
        loaded = load_function_ir_ssa_cache_8616(cache_key, function_addr)
        if loaded.bundle is None:
            results.append(loaded)
            continue
        ir_result = publish_function_ir_artifact_8616(project, loaded.bundle.ir)
        ssa_result = publish_function_ssa_artifact_8616(
            project,
            loaded.bundle.ssa,
            FunctionSSAArtifactStage8616.IR,
        )
        if (
            ir_result.verdict is not FunctionIRArtifactVerdict8616.PROVEN
            or ssa_result.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        ):
            results.append(
                FunctionIRSSACacheResult8616(
                    function_addr,
                    FunctionIRSSACacheVerdict8616.REFUSED,
                    failure=FunctionIRSSACacheFailure8616.REGISTRY_CONFLICT,
                )
            )
            continue
        results.append(loaded)
    return _catalog_result_8616(results)


def _hydrated_hit_matches_8616(
    hydrated: FunctionIRSSACacheResult8616 | None,
    ir_result: FunctionIRArtifactResolution8616,
    ssa_result: FunctionSSAArtifactResolution8616,
) -> bool:
    """Return True when a retained hydrated hit matches fresh artifacts."""
    return (
        hydrated is not None
        and hydrated.bundle is not None
        and ir_result.verdict is FunctionIRArtifactVerdict8616.PROVEN
        and ssa_result.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and ir_result.artifact == hydrated.bundle.ir
        and ssa_result.artifact == hydrated.bundle.ssa
        and ssa_result.stage is FunctionSSAArtifactStage8616.IR
    )


def store_function_ir_ssa_catalog_8616(
    project: object,
    functions: Sequence[object],
    *,
    already_hydrated: FunctionIRSSACatalogResult8616 | None = None,
) -> FunctionIRSSACatalogResult8616:
    """Persist rebuilt pairs while retaining exact pairs hydrated this run."""
    if already_hydrated is not None and not already_hydrated.stats.closed:
        raise ValueError("cannot retain hydrated IR/SSA cache with open accounting")
    hydrated_hits = {
        result.function_addr: result
        for result in (() if already_hydrated is None else already_hydrated.results)
        if result.verdict is FunctionIRSSACacheVerdict8616.HIT
        and result.bundle is not None
    }
    results: list[FunctionIRSSACacheResult8616] = []
    for function in functions:
        function_addr = function_addr_from_boundary_8616(function)
        ir_result = registered_function_ir_artifact_8616(project, function_addr)
        ssa_result = registered_function_ssa_artifact_8616(project, function_addr)
        hydrated = hydrated_hits.get(function_addr)
        if _hydrated_hit_matches_8616(hydrated, ir_result, ssa_result):
            results.append(hydrated)
            continue
        cache_key = function_ir_ssa_cache_key_8616(project, function)
        if cache_key is None:
            results.append(
                FunctionIRSSACacheResult8616(
                    function_addr,
                    FunctionIRSSACacheVerdict8616.MISS,
                    failure=FunctionIRSSACacheFailure8616.FUNCTION_IDENTITY_INCOMPLETE,
                )
            )
            continue
        if (
            ir_result.verdict is not FunctionIRArtifactVerdict8616.PROVEN
            or ir_result.artifact is None
            or ssa_result.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
            or ssa_result.artifact is None
            or ssa_result.stage is not FunctionSSAArtifactStage8616.IR
        ):
            results.append(
                FunctionIRSSACacheResult8616(
                    function_addr,
                    FunctionIRSSACacheVerdict8616.REFUSED,
                    failure=FunctionIRSSACacheFailure8616.ARTIFACT_NOT_REGISTERED,
                )
            )
            continue
        results.append(
            store_function_ir_ssa_cache_8616(
                cache_key,
                FunctionIRSSABundle8616(
                    ir_result.artifact,
                    ssa_result.artifact,
                ),
            )
        )
    return _catalog_result_8616(results)


__all__ = [
    "FUNCTION_IR_SSA_CACHE_NAMESPACE_8616",
    "FunctionIRSSABundle8616",
    "FunctionIRSSACacheFailure8616",
    "FunctionIRSSACacheResult8616",
    "FunctionIRSSACacheStats8616",
    "FunctionIRSSACacheVerdict8616",
    "FunctionIRSSACatalogResult8616",
    "function_ir_ssa_cache_key_8616",
    "hydrate_function_ir_ssa_catalog_8616",
    "load_function_ir_ssa_cache_8616",
    "store_function_ir_ssa_cache_8616",
    "store_function_ir_ssa_catalog_8616",
]
