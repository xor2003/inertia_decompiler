# cython: language_level=3, infer_types=True
"""Retain exact-byte typed condition evidence on function IR artifacts.

Layer: IR.
Responsibility: normalize current-function byte ranges after block ownership,
relift typed branch conditions once, and keep their exact CFG owner in IR/SSA.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from .condition_cache_relift import (
    ConditionCacheReliftArtifact8616,
    ConditionReliftBlock8616,
    relift_function_condition_cache_8616,
)
from .condition_ir import ConditionIR, ConditionRegisterBindingIR, ConditionSource
from .core import IRBinaryValue, IRBlock, IRValue
import dataclasses
import operator


@cython.ccall
def _typed_value_data_8616(value: object) -> object:
    """Return deterministic diagnostic data without parsing rendered text."""
    if isinstance(value, (IRValue, IRBinaryValue)):
        return value.to_dict()
    if isinstance(value, ConditionRegisterBindingIR):
        return {
            "register_name": value.register_name,
            "value": _typed_value_data_8616(value.value),
        }
    if isinstance(value, (tuple, list)):
        return [_typed_value_data_8616(item) for item in iter(value)]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return {"unsupported_boundary_type": type(value).__name__}


@cython.ccall
def _condition_data_8616(condition: ConditionIR) -> dict[str, object]:
    """Serialize one owned typed condition for artifact diagnostics."""
    return {
        "op": condition.op,
        "lhs": _typed_value_data_8616(condition.lhs),
        "rhs": _typed_value_data_8616(condition.rhs),
        "width_bits": condition.width_bits,
        "source": list(condition.source),
        "src_insn": condition.src_insn,
        "block_addr": condition.block_addr,
        "producer_insn": condition.producer_insn,
        "taken_target": condition.taken_target,
        "fallthrough_target": condition.fallthrough_target,
        "operand_bind_insn": condition.operand_bind_insn,
        "producer_semantics": _typed_value_data_8616(
            condition.producer_semantics
        ),
        "register_bindings": [
            _typed_value_data_8616(binding)
            for binding in iter(condition.register_bindings)
        ],
    }


@cython.ccall
def _condition_source_data_8616(source: ConditionSource) -> dict[str, object]:
    """Serialize one pending typed condition source without dynamic access."""
    return {
        "kind": source.kind,
        "lhs": _typed_value_data_8616(source.lhs),
        "rhs": _typed_value_data_8616(source.rhs),
        "normalized_lhs": _typed_value_data_8616(source.normalized_lhs),
        "normalized_rhs": _typed_value_data_8616(source.normalized_rhs),
        "semantics": _typed_value_data_8616(source.semantics),
        "fallthrough_from_jcc": source.fallthrough_from_jcc,
        "width_bits": source.width_bits,
        "addr": source.addr,
        "block_addr": source.block_addr,
        "bind_operand_at_jcc": source.bind_operand_at_jcc,
        "register_bindings": [
            _typed_value_data_8616(binding)
            for binding in iter(source.register_bindings)
        ],
    }


@dataclasses.dataclass(frozen=True, )
class IRFunctionConditionArtifact8616:
    """Closed exact condition projection for one normalized IR function."""

    function_addr: cython.longlong
    block_ranges: object
    expected_condition_blocks: object
    source: ConditionCacheReliftArtifact8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every normalized conditional owner has evidence."""
        block_addrs = tuple(block.address for block in iter(self.block_ranges))
        condition_addrs = tuple(
            address for address, _items in iter(self.source.conditions_by_block)
        )
        materialized = {
            address
            for address, conditions in iter(self.source.conditions_by_block)
            if conditions
        }
        expected = set(self.expected_condition_blocks)
        return bool(
            self.function_addr >= 0
            and operator.eq(self.block_ranges, tuple(sorted(self.block_ranges)))
            and operator.eq(len(block_addrs), len(set(block_addrs)))
            and all(block.size > 0 for block in iter(self.block_ranges))
            and operator.eq(self.expected_condition_blocks, tuple(sorted(tuple(set(self.expected_condition_blocks)))))
            and expected <= set(block_addrs)
            and condition_addrs == block_addrs
            and self.source.failures == ()
            and self.source.stats.complete
            and operator.eq(self.source.stats.raw_fact_count, len(expected))
            and operator.eq(self.source.stats.materialized_count, len(expected))
            and expected == materialized
            and all(
                operator.eq(condition.block_addr, address)
                for address, conditions in iter(self.source.conditions_by_block)
                for condition in iter(conditions)
            )
        )

    def conditions_for_block(self, block_addr: cython.longlong) -> object:
        """Return exact typed conditions owned by one canonical block."""
        return next(
            (
                conditions
                for address, conditions in iter(self.source.conditions_by_block)
                if address == block_addr
            ),
            (),
        )

    def to_summary(self) -> dict[str, object]:
        """Return closed counter fields for the function IR summary."""
        stats = self.source.stats
        return {
            "condition_evidence_raw_fact_count": stats.raw_fact_count,
            "condition_evidence_normalized_fact_count": stats.normalized_fact_count,
            "condition_evidence_classified_fact_count": stats.classified_fact_count,
            "condition_evidence_materialized_count": stats.materialized_count,
            "condition_evidence_failure_count": stats.failure_count,
            "condition_evidence_complete": self.complete,
        }

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic diagnostic projection of the full artifact."""
        stats = self.source.stats
        return {
            "function_addr": self.function_addr,
            "block_ranges": [
                {"address": block.address, "size": block.size}
                for block in iter(self.block_ranges)
            ],
            "expected_condition_blocks": list(self.expected_condition_blocks),
            "conditions_by_block": [
                {
                    "block_addr": address,
                    "conditions": [
                        _condition_data_8616(condition)
                        for condition in iter(conditions)
                    ],
                }
                for address, conditions in iter(self.source.conditions_by_block)
            ],
            "pending_sources_by_addr": [
                {
                    "address": address,
                    "source": _condition_source_data_8616(source),
                }
                for address, source in iter(self.source.pending_sources_by_addr)
            ],
            "failures": [
                {
                    "block_addr": failure.block_addr,
                    "reason": failure.reason.value,
                    "detail": failure.detail,
                }
                for failure in iter(self.source.failures)
            ],
            "stats": {
                "raw_fact_count": stats.raw_fact_count,
                "normalized_fact_count": stats.normalized_fact_count,
                "classified_fact_count": stats.classified_fact_count,
                "materialized_count": stats.materialized_count,
                "failure_count": stats.failure_count,
            },
            "complete": self.complete,
        }


def _normalized_relift_blocks_8616(
    raw_blocks: object,
    blocks: object,
) -> tuple[ConditionReliftBlock8616, ...]:
    """Clip overlapping raw byte ranges to canonical IR block ownership."""
    next_addr: object
    raw: object
    address: object
    index: object
    raw_by_addr = {block.address: block for block in iter(raw_blocks)}
    ordered_addrs = tuple(sorted(block.addr for block in iter(blocks)))
    normalized: list[ConditionReliftBlock8616] = []
    for index, address in enumerate(ordered_addrs):
        raw = raw_by_addr.get(address)
        if raw is None:
            normalized.append(ConditionReliftBlock8616(address, 0))
            continue
        next_addr = (
            ordered_addrs[index + 1]
            if index + 1 < len(ordered_addrs)
            else None
        )
        size = raw.size
        if next_addr is not None and next_addr < address + size:
            size = next_addr - address
        normalized.append(ConditionReliftBlock8616(address, size))
    return tuple(normalized)


def build_ir_function_condition_artifact_8616(
    project: object,
    function_addr: cython.longlong,
    raw_blocks: object,
    blocks: object,
    captured_source: ConditionCacheReliftArtifact8616 | None = None,
) -> IRFunctionConditionArtifact8616 | None:
    """Build isolated typed conditions, reusing only a complete lift capture."""
    source: object
    normalized = _normalized_relift_blocks_8616(raw_blocks, blocks)
    expected = tuple(
        sorted(block.addr for block in iter(blocks) if len(block.successor_addrs) > 1)
    )
    block_addresses = tuple(block.address for block in iter(normalized))
    captured_addresses = (
        tuple(address for address, _conditions in iter(captured_source.conditions_by_block))
        if captured_source is not None
        else ()
    )
    if (
        captured_source is not None
        and captured_source.failures == ()
        and captured_source.stats.complete
        and captured_addresses == block_addresses
    ):
        captured_artifact = IRFunctionConditionArtifact8616(
            function_addr,
            normalized,
            expected,
            captured_source,
        )
        if captured_artifact.complete:
            return captured_artifact
    source = relift_function_condition_cache_8616(
        project,
        normalized,
        frozenset(expected),
    )
    if source is None:
        return None
    return IRFunctionConditionArtifact8616(
        function_addr,
        normalized,
        expected,
        source,
    )


__all__ = [
    "IRFunctionConditionArtifact8616",
    "build_ir_function_condition_artifact_8616",
]
