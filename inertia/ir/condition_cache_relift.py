"""Rebuild typed condition evidence without angr block-cache side effects.

Layer: IR.
Responsibility: force the custom x86-16 lifter over exact current-function
bytes and return an isolated ``ConditionIR`` cache artifact.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.

This is an IR migration boundary, not semantic recovery in Lowering.  The
custom frontend still records rich cross-block condition sources while lifting,
but angr may return a cached IRSB without rerunning those recording side
effects.  Until the complete cross-block condition source is carried directly
by ``IRFunctionArtifact``, consumers must use this exact-byte artifact instead
of treating an empty process-global cache entry as authoritative evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

import pyvex

from .condition_cache_relift_cache import ConditionReliftArtifactCache8616, ConditionReliftCacheRequest8616
from .condition_cache_relift_contracts import (
    ConditionCacheReliftArtifact8616,
    ConditionCacheReliftFailure8616,
    ConditionCacheReliftFailureReason8616,
    ConditionCacheReliftStats8616,
    ConditionReliftBlock8616,
)
from .condition_ir import ConditionFailure, ConditionIR, ConditionSource
from .condition_lift_capture import isolated_condition_lift_session_8616

__all__ = (
    "ConditionCacheReliftArtifact8616",
    "ConditionCacheReliftFailure8616",
    "ConditionCacheReliftFailureReason8616",
    "ConditionCacheReliftStats8616",
    "ConditionReliftBlock8616",
    "has_typed_condition_cache_evidence_8616",
    "relift_cached_project_blocks_8616",
    "relift_function_condition_cache_8616",
    "reset_lifter_condition_state_8616",
)


class _LoaderMemoryBoundary8616(Protocol):
    """Minimal third-party loader-memory surface needed for exact-byte relift."""

    def load(self, address: int, size: int) -> object:
        """Read one exact guest-memory range."""


class _LoaderBoundary8616(Protocol):
    """Minimal third-party loader surface needed for exact-byte relift."""

    memory: _LoaderMemoryBoundary8616


class _ProjectBoundary8616(Protocol):
    """Minimal third-party project surface needed for exact-byte relift."""

    arch: object
    loader: _LoaderBoundary8616


class _FactoryBoundary8616(Protocol):
    """Minimal third-party block factory used by narrow fallback fixtures."""

    def block(self, address: int, **kwargs: object) -> object:
        """Return or lift one third-party block boundary."""


class _FactoryProjectBoundary8616(Protocol):
    """Minimal project surface used when no exact loader boundary exists."""

    factory: _FactoryBoundary8616


_EXACT_RELIFT_CACHE_8616 = ConditionReliftArtifactCache8616[ConditionCacheReliftArtifact8616](max_entries=32)


def has_typed_condition_cache_evidence_8616(
    condition_cache: Mapping[int, object],
    pending_sources: Mapping[int, object],
    block_addr: int,
) -> bool:
    """Return whether a block has a typed condition or pending source fact."""
    block_evidence = condition_cache.get(block_addr)
    return bool(
        (
            isinstance(block_evidence, list)
            and any(isinstance(item, (ConditionIR, ConditionFailure)) for item in block_evidence)
        )
        or isinstance(pending_sources.get(block_addr), ConditionSource)
    )


def reset_lifter_condition_state_8616() -> None:
    """Reset path-sensitive custom-lifter state before a deterministic relift."""
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    Instruction_ANY._inertia_condition_reg_affine_state_8616.clear()
    Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616.clear()
    Instruction_ANY._inertia_condition_index_reg_state_8616.clear()
    Instruction_ANY._inertia_condition_reg_value_state_8616.clear()


def relift_cached_project_blocks_8616(project: object, block_addrs: tuple[int, ...]) -> None:
    """Relift blocks through a project factory when no loader boundary exists."""
    try:
        block_lifter = cast(_FactoryProjectBoundary8616, project).factory.block
    except AttributeError:
        return
    for block_addr in block_addrs:
        try:
            block_lifter(block_addr, opt_level=0)
        except TypeError:
            try:
                block_lifter(block_addr)
            except Exception:
                continue
        except Exception:
            continue


def _failure_detail_8616(error: BaseException) -> str:
    """Return deterministic diagnostic detail for a third-party boundary error."""
    text = str(error).strip()
    return f"{type(error).__name__}: {text}" if text else type(error).__name__


def _direct_lift_8616(data: bytes, address: int, arch: object) -> None:
    """Invoke pyvex directly so angr's IRSB cache cannot skip lifter effects."""
    cast(Any, pyvex).lift(
        data,
        address,
        arch,
        max_bytes=len(data),
        opt_level=0,
    )


def _load_exact_block_bytes_8616(
    memory: _LoaderMemoryBoundary8616,
    blocks: tuple[ConditionReliftBlock8616, ...],
    failures: list[ConditionCacheReliftFailure8616],
) -> tuple[tuple[ConditionReliftBlock8616, bytes], ...]:
    """Read valid exact block bytes while retaining every typed refusal."""
    loaded: list[tuple[ConditionReliftBlock8616, bytes]] = []
    for block in blocks:
        if block.address < 0 or block.size <= 0:
            failures.append(
                ConditionCacheReliftFailure8616(
                    block_addr=block.address,
                    reason=ConditionCacheReliftFailureReason8616.INVALID_BLOCK_RANGE,
                    detail=f"size={block.size}",
                )
            )
            continue
        try:
            data = bytes(cast(Any, memory.load(block.address, block.size)))
        except Exception as error:
            failures.append(
                ConditionCacheReliftFailure8616(
                    block_addr=block.address,
                    reason=ConditionCacheReliftFailureReason8616.BYTE_READ_FAILED,
                    detail=_failure_detail_8616(error),
                )
            )
            continue
        if len(data) != block.size:
            failures.append(
                ConditionCacheReliftFailure8616(
                    block_addr=block.address,
                    reason=ConditionCacheReliftFailureReason8616.BYTE_READ_FAILED,
                    detail=f"expected={block.size} actual={len(data)}",
                )
            )
            continue
        loaded.append((block, data))
    return tuple(loaded)


def relift_function_condition_cache_8616(
    project: object,
    blocks: tuple[ConditionReliftBlock8616, ...],
    expected_condition_blocks: frozenset[int],
) -> ConditionCacheReliftArtifact8616 | None:
    """Return isolated condition evidence from exact bytes, or no boundary.

    ``None`` means the supplied object is not a real angr project boundary; it
    lets narrow unit fixtures retain their factory-block fallback.  Once a real
    loader and architecture are available, every decode/lift/missing-evidence
    problem is retained as a typed refusal and must not fall back silently.
    """
    try:
        boundary = cast(_ProjectBoundary8616, project)
        memory = boundary.loader.memory
        arch = boundary.arch
    except AttributeError:
        return None

    ordered_blocks = tuple(sorted(set(blocks)))
    block_addresses = frozenset(block.address for block in ordered_blocks)
    normalized_expected = expected_condition_blocks & block_addresses
    failures: list[ConditionCacheReliftFailure8616] = [
        ConditionCacheReliftFailure8616(
            block_addr=address,
            reason=ConditionCacheReliftFailureReason8616.INVALID_BLOCK_RANGE,
            detail="expected condition owner is outside the exact function block inventory",
        )
        for address in sorted(expected_condition_blocks - block_addresses)
    ]
    if not expected_condition_blocks and all(
        block.address >= 0 and block.size > 0 for block in ordered_blocks
    ):
        return ConditionCacheReliftArtifact8616(
            conditions_by_block=tuple(
                (address, ()) for address in sorted(block_addresses)
            ),
            pending_sources_by_addr=(),
            failures=(),
            stats=ConditionCacheReliftStats8616(0, 0, 0, 0, 0),
        )
    loaded_blocks = _load_exact_block_bytes_8616(memory, ordered_blocks, failures)
    cache_request = ConditionReliftCacheRequest8616(
        block_bytes=tuple((block.address, block.size, data) for block, data in loaded_blocks),
        expected_condition_blocks=expected_condition_blocks,
    )
    lifted_blocks: set[int] = set()

    if not failures:
        cached = _EXACT_RELIFT_CACHE_8616.lookup(arch, cache_request)
        if cached is not None:
            return cached
    with isolated_condition_lift_session_8616() as capture:
        for block, data in loaded_blocks:
            try:
                _direct_lift_8616(data, block.address, arch)
            except Exception as error:
                failures.append(
                    ConditionCacheReliftFailure8616(
                        block_addr=block.address,
                        reason=ConditionCacheReliftFailureReason8616.VEX_LIFT_FAILED,
                        detail=_failure_detail_8616(error),
                    )
                )
                continue
            lifted_blocks.add(block.address)
            capture.record_successful_block(block.address)

        conditions_by_block = capture.conditions_by_block(block_addresses)
        failures.extend(capture.failures_by_block(block_addresses))
        materialized_blocks = {
            address
            for address, conditions in conditions_by_block
            if address in expected_condition_blocks and conditions
        }
        failed_block_addresses = {failure.block_addr for failure in failures}
        failures.extend(
            ConditionCacheReliftFailure8616(
                block_addr=address,
                reason=ConditionCacheReliftFailureReason8616.EXPECTED_CONDITION_MISSING,
            )
            for address in sorted(
                expected_condition_blocks
                - materialized_blocks
                - failed_block_addresses
            )
        )
        pending_sources = capture.pending_source_items()
    stats = ConditionCacheReliftStats8616(
        raw_fact_count=len(expected_condition_blocks),
        normalized_fact_count=len(normalized_expected),
        classified_fact_count=len(expected_condition_blocks & lifted_blocks),
        materialized_count=len(materialized_blocks),
        failure_count=len(failures),
    )
    artifact = ConditionCacheReliftArtifact8616(
        conditions_by_block=conditions_by_block,
        pending_sources_by_addr=pending_sources,
        failures=tuple(failures),
        stats=stats,
    )
    if all(
        failure.reason is ConditionCacheReliftFailureReason8616.EXPECTED_CONDITION_MISSING
        for failure in artifact.failures
    ):
        _EXACT_RELIFT_CACHE_8616.publish(arch, cache_request, artifact)
    return artifact
