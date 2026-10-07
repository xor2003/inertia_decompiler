"""Resolve exact register snapshots used by canonical frame carriers.

Layer: Types/Lowering.
Responsibility: prove same-instruction virtual temporaries copied directly
from BP or SP so canonical frame matching can consume their structured uses.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not follow cross-instruction definitions or infer register identity from
variable names, rendered C, assembly text, or sample-specific addresses.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Protocol

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CDirtyExpression, CTypeCast

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616

from .physical_registers import PhysicalRegisterView8616, physical_register_view_8616


class _FrameRegisterArchitecture8616(Protocol):
    """Architecture register map required by frame snapshot collection."""

    registers: Mapping[str, tuple[int, int]]


class _FrameRegisterProject8616(Protocol):
    """Project surface required by frame snapshot collection."""

    arch: _FrameRegisterArchitecture8616


@dataclass(frozen=True, slots=True, order=True)
class FrameVirtualCarrierIdentity8616:
    """Stable identity of one exact AIL virtual temporary."""

    varid: int
    bits: int


@dataclass(frozen=True, slots=True)
class FrameRegisterCarrierFact8616:
    """One unambiguous virtual temporary copied from BP or SP."""

    identity: FrameVirtualCarrierIdentity8616
    register: PhysicalRegisterView8616


@dataclass(frozen=True, slots=True)
class FrameRegisterCarrierResolution8616:
    """Closed evidence census and exact frame-register snapshot facts."""

    facts: tuple[FrameRegisterCarrierFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def resolve(self, value: object) -> PhysicalRegisterView8616 | None:
        """Resolve a direct register or one uniquely classified temporary."""
        direct = physical_register_view_8616(_unwrap_casts_8616(value))
        if direct is not None:
            return direct
        identity = _temporary_identity_8616(value)
        if identity is None:
            return None
        matches = tuple(fact.register for fact in self.facts if fact.identity == identity)
        return matches[0] if len(matches) == 1 else None

    def with_frame_proof(self, accepted: bool) -> FrameRegisterCarrierResolution8616:
        """Classify and consume candidates only after canonical frame proof."""
        classified = self.classified_fact_count if accepted else 0
        materialized = classified
        return replace(
            self,
            classified_fact_count=classified,
            materialized_count=materialized,
            failure_count=self.failure_count,
        )


def _unwrap_casts_8616(value: object) -> object:
    """Remove type-only wrappers from one structured expression."""
    while isinstance(value, CTypeCast):
        value = value.expr
    return value


def _temporary_identity_8616(value: object) -> FrameVirtualCarrierIdentity8616 | None:
    """Return one exact AIL temporary identity from a dirty C expression."""
    value = _unwrap_casts_8616(value)
    if not isinstance(value, CDirtyExpression) or not isinstance(value.dirty, VirtualVariable):
        return None
    dirty = value.dirty
    if dirty.category is not VirtualVariableCategory.TMP:
        return None
    return FrameVirtualCarrierIdentity8616(dirty.varid, dirty.bits)


def collect_frame_register_carriers_8616(
    root: object,
    project: _FrameRegisterProject8616,
    function_addr: int,
) -> FrameRegisterCarrierResolution8616:
    """Collect unique same-instruction BP/SP snapshots from structured C."""
    allowed = frozenset(
        PhysicalRegisterView8616(*register_span)
        for name in ("bp", "sp")
        if (register_span := project.arch.registers.get(name)) is not None
    )
    definitions: dict[FrameVirtualCarrierIdentity8616, list[PhysicalRegisterView8616]] = {}
    raw_count = 0
    normalized_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        tags = copy_structured_tags_8616(node.tags)
        if tags is None or tags.get("ins_addr") != function_addr:
            continue
        identity = _temporary_identity_8616(node.lhs)
        register = physical_register_view_8616(_unwrap_casts_8616(node.rhs))
        if identity is None or register is None or register not in allowed:
            continue
        raw_count += 1
        normalized_count += 1
        definitions.setdefault(identity, []).append(register)

    facts = tuple(
        FrameRegisterCarrierFact8616(identity, registers[0])
        for identity, registers in sorted(definitions.items())
        if len(registers) == 1
    )
    classified_count = len(facts)
    return FrameRegisterCarrierResolution8616(
        facts=facts,
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=0,
        failure_count=max(normalized_count - classified_count, 0),
    )


__all__ = [
    "FrameRegisterCarrierFact8616",
    "FrameRegisterCarrierResolution8616",
    "FrameVirtualCarrierIdentity8616",
    "collect_frame_register_carriers_8616",
]
