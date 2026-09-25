"""Build independent Alias function evidence in bounded fork workers.

Layer: CLI/fallback/reporting orchestration.
Responsibility: schedule exact per-function IR/Alias work in isolated POSIX
workers, then republish returned raw IR and rebuild its deterministic IR-stage
SSA projection on the parent before assembling the authoritative Alias program
census. Execution is serial unless ``INERTIA_INDEXED_ALIAS_WORKERS`` explicitly
enables N-1 concurrency capped at three workers for a 2 GiB budget. This module
does not classify Alias facts or infer semantic evidence.
"""

from __future__ import annotations

import functools
import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr_platforms.X86_16.alias.indexed_address_program import (
    IndexedAliasFunctionEvidence8616,
    IndexedAliasFunctionRefusal8616,
    IndexedAliasFunctionSelection8616,
    IndexedAliasProgramEvidence8616,
    assemble_indexed_alias_program_evidence_8616,
    build_indexed_alias_function_evidence_8616,
    build_indexed_alias_program_evidence_8616,
)
from angr_platforms.X86_16.ir.core import IRFunctionArtifact
from angr_platforms.X86_16.ir.function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa

from .runtime_support import PreforkJobPool

log: logging.Logger = logging.getLogger(__name__)

_MAX_INDEXED_ALIAS_WORKERS_8616: int = 3
_INDEXED_ALIAS_WORKERS_ENV_8616: str = "INERTIA_INDEXED_ALIAS_WORKERS"


class _FunctionBlockInventory8616(Protocol):
    """Third-party function surface used only for scheduling priority."""

    block_addrs_set: object


class _FunctionAddressBoundary8616(Protocol):
    """Third-party function boundary with one canonical address."""

    addr: object


@dataclass(frozen=True, slots=True)
class _IndexedAliasFunctionBundle8616:
    """One worker's Alias result and its exact reusable raw IR."""

    result: IndexedAliasFunctionEvidence8616 | IndexedAliasFunctionRefusal8616
    raw_ir: IRFunctionArtifact | None


def indexed_alias_program_worker_count_8616(
    function_count: int,
    *,
    max_workers: int | None = None,
) -> int:
    """Return explicit bounded concurrency, or one worker by default."""
    if function_count <= 1:
        return 1
    available = max(1, (os.cpu_count() or 1) - 1)
    requested = max_workers
    if requested is None:
        configured = os.environ.get(_INDEXED_ALIAS_WORKERS_ENV_8616)
        if configured is None:
            return 1
        try:
            requested = int(configured)
        except ValueError:
            return 1
    requested = max(1, requested)
    return min(function_count, available, requested, _MAX_INDEXED_ALIAS_WORKERS_8616)


def indexed_alias_function_selection_8616(
    function: object,
) -> IndexedAliasFunctionSelection8616:
    """Normalize one discovered third-party function into a typed selection."""
    try:
        function_addr = cast(_FunctionAddressBoundary8616, function).addr
    except AttributeError as error:
        raise TypeError("discovered function has no canonical address") from error
    if not isinstance(function_addr, int) or function_addr < 0:
        raise TypeError("discovered function has an invalid canonical address")
    return IndexedAliasFunctionSelection8616(function_addr, function)


def _selection_cost_8616(selection: IndexedAliasFunctionSelection8616) -> int:
    """Return a deterministic block-count scheduling estimate."""
    function = selection.function
    if function is None:
        return 0
    try:
        block_addrs = cast(_FunctionBlockInventory8616, function).block_addrs_set
    except AttributeError:
        return 0
    try:
        return len(cast(Sequence[object], block_addrs))
    except TypeError:
        return 0


def _publish_parent_artifacts_8616(
    project: object,
    bundle: _IndexedAliasFunctionBundle8616,
) -> None:
    """Republish raw IR and rebuild deterministic IR-stage SSA on the parent."""
    if isinstance(bundle.result, IndexedAliasFunctionRefusal8616):
        if bundle.raw_ir is not None:
            raise ValueError("refused Alias function returned partial IR evidence")
        return
    if bundle.raw_ir is None:
        raise ValueError("materialized Alias function omitted reusable raw IR")
    raw_result = publish_function_ir_artifact_8616(project, bundle.raw_ir)
    if raw_result.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        raise ValueError("parallel raw IR publication conflicted on parent project")
    raw_ssa = build_x86_16_function_ssa(bundle.raw_ir)
    ssa_result = publish_function_ssa_artifact_8616(
        project,
        raw_ssa,
        FunctionSSAArtifactStage8616.IR,
    )
    if ssa_result.verdict is not FunctionSSAArtifactVerdict8616.PROVEN:
        raise ValueError("parallel IR-stage SSA publication conflicted on parent project")


def _indexed_alias_worker_8616(
    project: object,
    by_addr: dict[int, IndexedAliasFunctionSelection8616],
    payload: object,
) -> object:
    """Build one function using the fork-inherited immutable project view."""
    if not isinstance(payload, int):
        raise TypeError("parallel Alias worker payload must be an address")
    selection = by_addr[payload]
    result = build_indexed_alias_function_evidence_8616(project, selection)
    if isinstance(result, IndexedAliasFunctionRefusal8616):
        return _IndexedAliasFunctionBundle8616(result, None)
    raw = registered_function_ir_artifact_8616(project, payload)
    ssa = registered_function_ssa_artifact_8616(project, payload)
    if (
        raw.verdict is not FunctionIRArtifactVerdict8616.PROVEN
        or raw.artifact is None
        or ssa.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        or ssa.stage is not FunctionSSAArtifactStage8616.IR
        or ssa.artifact is None
    ):
        raise ValueError("parallel Alias worker did not retain exact raw IR/SSA")
    return _IndexedAliasFunctionBundle8616(result, raw.artifact)


def _run_parallel_bundles_8616(
    project: object,
    ordered: tuple[IndexedAliasFunctionSelection8616, ...],
    worker_count: int,
    by_addr: dict[int, IndexedAliasFunctionSelection8616],
) -> dict[int, _IndexedAliasFunctionBundle8616] | None:
    """Run the bounded worker pool; return per-address bundles or None."""
    jobs = [
        (selection.function_addr, selection.function_addr)
        for selection in sorted(
            ordered,
            key=lambda item: (-_selection_cost_8616(item), item.function_addr),
        )
    ]
    pool: PreforkJobPool | None = None
    try:
        pool = PreforkJobPool(
            max_workers=worker_count,
            worker_func=functools.partial(_indexed_alias_worker_8616, project, by_addr),
            name_prefix="indexed_alias",
        )
        bundles_by_addr: dict[int, _IndexedAliasFunctionBundle8616] = {}
        for job_id, payload in pool.run_unordered(jobs):
            if not isinstance(job_id, int) or not isinstance(
                payload, _IndexedAliasFunctionBundle8616
            ):
                raise RuntimeError(f"parallel Alias worker failed: {payload}")
            bundles_by_addr[job_id] = payload
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        log.warning("parallel indexed Alias census unavailable: %s", error)
        return None
    finally:
        if pool is not None:
            pool.shutdown()

    if set(bundles_by_addr) != set(by_addr):
        log.warning("parallel indexed Alias census returned an incomplete job set")
        return None
    return bundles_by_addr


def build_indexed_alias_program_evidence_bounded_8616(
    project: object,
    selections: Sequence[IndexedAliasFunctionSelection8616],
    *,
    max_workers: int | None = None,
) -> IndexedAliasProgramEvidence8616:
    """Build one closed Alias census with deterministic bounded fork workers."""
    ordered = tuple(sorted(selections, key=lambda item: item.function_addr))
    worker_count = indexed_alias_program_worker_count_8616(
        len(ordered),
        max_workers=max_workers,
    )
    if worker_count <= 1:
        return build_indexed_alias_program_evidence_8616(project, ordered)
    by_addr = {selection.function_addr: selection for selection in ordered}
    if len(by_addr) != len(ordered):
        return build_indexed_alias_program_evidence_8616(project, ordered)

    bundles_by_addr = _run_parallel_bundles_8616(project, ordered, worker_count, by_addr)
    if bundles_by_addr is None:
        return build_indexed_alias_program_evidence_8616(project, ordered)
    bundles = tuple(bundles_by_addr[selection.function_addr] for selection in ordered)
    try:
        for bundle in bundles:
            _publish_parent_artifacts_8616(project, bundle)
        return assemble_indexed_alias_program_evidence_8616(
            tuple(bundle.result for bundle in bundles),
            tuple(selection.function_addr for selection in ordered),
        )
    except (TypeError, ValueError) as error:
        log.warning("parallel indexed Alias evidence refused: %s", error)
        return build_indexed_alias_program_evidence_8616(project, ordered)


def build_discovered_indexed_alias_program_bounded_8616(
    project: object,
    functions: Sequence[object],
    *,
    max_workers: int | None = None,
) -> IndexedAliasProgramEvidence8616:
    """Build a bounded census from exact discovered function boundaries."""
    selections = tuple(indexed_alias_function_selection_8616(item) for item in functions)
    return build_indexed_alias_program_evidence_bounded_8616(
        project,
        selections,
        max_workers=max_workers,
    )


__all__ = [
    "build_discovered_indexed_alias_program_bounded_8616",
    "build_indexed_alias_program_evidence_bounded_8616",
    "indexed_alias_function_selection_8616",
    "indexed_alias_program_worker_count_8616",
]
