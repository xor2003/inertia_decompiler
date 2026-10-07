"""Validate final composite conditions against Structuring provenance.

Layer: Validation.
Responsibility: require one final logical condition to preserve every exact JCC
identity recorded when Structuring combined its ConditionIR facts.

This module compares typed identities and immutable precision evidence. It does
not recover predicates, traverse the CFG, mutate the C AST, or infer semantics
from rendered C or assembly.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

from inertia.ir.condition_ir import ConditionIR
from inertia.structuring.condition_chain_provenance import (
    ConditionChainProvenance8616,
    condition_chain_provenance_8616,
)


class ConditionChainValidationStatus8616(StrEnum):
    """Typed verdict for one final composite-condition identity check."""

    PROVEN = "proven"
    NO_PROVENANCE = "no_provenance"
    ROOT_MISMATCH = "root_mismatch"
    NOT_COMPOSITE = "not_composite"
    LEAF_IDENTITY_MISMATCH = "leaf_identity_mismatch"
    TYPED_FACT_MISMATCH = "typed_fact_mismatch"
    PRECISION_MISMATCH = "precision_mismatch"


@dataclass(frozen=True, slots=True)
class ConditionChainValidationResult8616:
    """Closed evidence for one composite-condition validation decision."""

    status: ConditionChainValidationStatus8616
    provenance: ConditionChainProvenance8616 | None = None
    leaf_jcc_addrs: tuple[int, ...] = ()

    @property
    def proven(self) -> bool:
        """Return whether all provenance, leaf, fact, and precision checks pass."""
        return self.status is ConditionChainValidationStatus8616.PROVEN


class _TaggedConditionNode8616(Protocol):
    """Third-party C condition tag boundary consumed by Validation."""

    tags: object


def _condition_jcc_addr_8616(condition: object) -> int | None:
    """Read one exact Structuring-owned JCC identity from a condition leaf."""
    surface = cast(_TaggedConditionNode8616, condition)
    try:
        tags = surface.tags
    except AttributeError:
        return None
    if not isinstance(tags, Mapping):
        return None
    jcc_addr = tags.get("ins_addr")
    return jcc_addr if isinstance(jcc_addr, int) else None


def _logical_leaf_jcc_addrs_8616(condition: object) -> tuple[int, ...] | None:
    """Return exact JCC identities for every terminal logical predicate."""
    if isinstance(condition, CBinaryOp) and condition.op in {
        "LogicalAnd",
        "LogicalOr",
    }:
        lhs = _logical_leaf_jcc_addrs_8616(condition.lhs)
        rhs = _logical_leaf_jcc_addrs_8616(condition.rhs)
        if lhs is None or rhs is None:
            return None
        return (*lhs, *rhs)
    jcc_addr = _condition_jcc_addr_8616(condition)
    return (jcc_addr,) if jcc_addr is not None else None


def validate_complete_condition_chain_8616(
    condition: object,
    *,
    root_jcc_addr: int,
    facts_by_jcc: Mapping[int, Mapping[tuple[object, ...], ConditionIR]],
    actual_fingerprint: str,
    precision_candidates: frozenset[str],
) -> ConditionChainValidationResult8616:
    """Validate exact leaf preservation for a precision-backed composite."""
    provenance = condition_chain_provenance_8616(condition)
    if provenance is None:
        return ConditionChainValidationResult8616(
            ConditionChainValidationStatus8616.NO_PROVENANCE
        )
    if not provenance.jcc_addrs or provenance.jcc_addrs[0] != root_jcc_addr:
        return ConditionChainValidationResult8616(
            ConditionChainValidationStatus8616.ROOT_MISMATCH,
            provenance,
        )
    leaf_jcc_addrs = _logical_leaf_jcc_addrs_8616(condition)
    if leaf_jcc_addrs is None or len(leaf_jcc_addrs) < 2:
        return ConditionChainValidationResult8616(
            ConditionChainValidationStatus8616.NOT_COMPOSITE,
            provenance,
            leaf_jcc_addrs or (),
        )
    if (
        len(set(leaf_jcc_addrs)) != len(leaf_jcc_addrs)
        or set(leaf_jcc_addrs) != set(provenance.jcc_addrs)
    ):
        return ConditionChainValidationResult8616(
            ConditionChainValidationStatus8616.LEAF_IDENTITY_MISMATCH,
            provenance,
            leaf_jcc_addrs,
        )
    if any(len(facts_by_jcc.get(jcc_addr, {})) != 1 for jcc_addr in provenance.jcc_addrs):
        return ConditionChainValidationResult8616(
            ConditionChainValidationStatus8616.TYPED_FACT_MISMATCH,
            provenance,
            leaf_jcc_addrs,
        )
    if actual_fingerprint not in precision_candidates:
        return ConditionChainValidationResult8616(
            ConditionChainValidationStatus8616.PRECISION_MISMATCH,
            provenance,
            leaf_jcc_addrs,
        )
    return ConditionChainValidationResult8616(
        ConditionChainValidationStatus8616.PROVEN,
        provenance,
        leaf_jcc_addrs,
    )


__all__ = [
    "ConditionChainValidationResult8616",
    "ConditionChainValidationStatus8616",
    "validate_complete_condition_chain_8616",
]
