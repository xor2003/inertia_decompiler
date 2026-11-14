# cython: language_level=3, infer_types=True
"""Capture typed condition evidence during an existing frontend lift.

Layer: IR.
Responsibility: isolate the custom frontend's class-scoped condition recorder
and expose only complete function-owned evidence to typed IR construction.
Incomplete captures are optimization misses and must fall back to exact-byte
relifting; they are never authoritative semantic evidence.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from .condition_cache_relift_contracts import (
    ConditionCacheReliftArtifact8616,
    ConditionCacheReliftFailure8616,
    ConditionCacheReliftFailureReason8616,
    ConditionCacheReliftStats8616,
)
from .condition_ir import ConditionFailure, ConditionIR, ConditionResult, ConditionSource
import dataclasses
import builtins

__all__ = (
    "ConditionLiftCaptureSession8616",
    "isolated_condition_lift_session_8616",
)


_CONDITION_LIFT_LOCK_8616 = threading.RLock()


@cython.dataclasses.dataclass()
class ConditionLiftCaptureSession8616:
    """Retain one isolated frontend lift's conditions and completed blocks."""

    condition_cache: object
    pending_sources: object
    _successful_blocks: object = field(default_factory=set, repr=False)

    @cython.ccall
    def record_successful_block(self, block_addr: cython.longlong) -> None:
        """Record that the existing block request returned a decoded block."""
        self._successful_blocks.add(block_addr)

    def conditions_by_block(
        self,
        block_addresses: object,
    ) -> tuple[tuple[cython.longlong, tuple[ConditionIR, ...]], ...]:
        """Project typed conditions onto an exact current-function inventory."""
        return tuple(
            (
                address,
                tuple(
                    condition
                    for condition in builtins.iter(self.condition_cache.get(address, ()))
                    if isinstance(condition, ConditionIR)
                ),
            )
            for address in builtins.iter(sorted(block_addresses))
        )

    def pending_source_items(self) -> tuple[tuple[cython.longlong, ConditionSource], ...]:
        """Return deterministic typed pending sources from this lift only."""
        return tuple(
            (address, source)
            for address, source in builtins.iter(sorted(tuple(self.pending_sources.items())))
            if isinstance(address, int) and isinstance(source, ConditionSource)
        )

    def failures_by_block(
        self, block_addresses: object,
    ) -> tuple[ConditionCacheReliftFailure8616, ...]:
        """Retain explicit recovery refusals within the current function only."""
        return tuple(
            ConditionCacheReliftFailure8616(
                block_addr=address,
                reason=ConditionCacheReliftFailureReason8616.CONDITION_RECOVERY_FAILED,
            )
            for address in builtins.iter(sorted(block_addresses))
            if any(isinstance(item, ConditionFailure) for item in builtins.iter(self.condition_cache.get(address, ())))
        )

    @cython.ccall
    def complete_artifact(
        self,
        block_addresses: object,
        expected_condition_blocks: object,
    ) -> ConditionCacheReliftArtifact8616 | None:
        """Return captured evidence only when every expected owner closes."""
        if not expected_condition_blocks <= block_addresses:
            return None
        conditions_by_block = self.conditions_by_block(block_addresses)
        materialized_blocks = {
            address
            for address, conditions in iter(conditions_by_block)
            if address in expected_condition_blocks and conditions
        }
        classified_blocks = expected_condition_blocks & self._successful_blocks
        failures = self.failures_by_block(block_addresses)
        stats = ConditionCacheReliftStats8616(
            raw_fact_count=len(expected_condition_blocks),
            normalized_fact_count=len(expected_condition_blocks),
            classified_fact_count=len(classified_blocks),
            materialized_count=len(materialized_blocks),
            failure_count=len(failures),
        )
        if not stats.complete:
            return None
        return ConditionCacheReliftArtifact8616(
            conditions_by_block=conditions_by_block,
            pending_sources_by_addr=self.pending_source_items(),
            failures=(),
            stats=stats,
        )


@contextmanager
def isolated_condition_lift_session_8616() -> Iterator[ConditionLiftCaptureSession8616]:
    """Isolate and restore all class-scoped frontend condition recorder state."""
    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

    with _CONDITION_LIFT_LOCK_8616:
        original_condition_cache = Instruction_ANY._inertia_module_condition_cache
        original_pending_sources = Instruction_ANY._inertia_pending_condition_sources_by_addr
        original_affine_state = Instruction_ANY._inertia_condition_reg_affine_state_8616
        original_affine_snapshots = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616
        original_index_state = Instruction_ANY._inertia_condition_index_reg_state_8616
        original_value_state = Instruction_ANY._inertia_condition_reg_value_state_8616
        condition_cache: dict[cython.longlong, list[ConditionResult]] = {}
        pending_sources: dict[cython.longlong, ConditionSource] = {}
        Instruction_ANY._inertia_module_condition_cache = condition_cache
        Instruction_ANY._inertia_pending_condition_sources_by_addr = pending_sources
        Instruction_ANY._inertia_condition_reg_affine_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = {}
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        try:
            yield ConditionLiftCaptureSession8616(condition_cache, pending_sources)
        finally:
            Instruction_ANY._inertia_module_condition_cache = original_condition_cache
            Instruction_ANY._inertia_pending_condition_sources_by_addr = original_pending_sources
            Instruction_ANY._inertia_condition_reg_affine_state_8616 = original_affine_state
            Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 = original_affine_snapshots
            Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state
            Instruction_ANY._inertia_condition_reg_value_state_8616 = original_value_state
