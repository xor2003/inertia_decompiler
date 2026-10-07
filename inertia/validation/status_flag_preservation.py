"""Bridge typed status-flag lift evidence into def-use validation.

Layer: Validation.
Responsibility: identify exact structured instruction sites where packed FLAGS
reads preserve architectural bits. Owns canonical equivalence checking and
validation diagnostics for this evidence. Do not mutate IR, rewrite emitted C,
recover semantics, or accept source/COD-backed proof. This module classifies
evidence only and does not infer behavior from rendered C or assembly text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.ir.status_flag_lift_context import resolve_status_flag_lift_artifact_8616


class _ArchBoundary8616(Protocol):
    """Third-party architecture register map used at the validation boundary."""

    registers: Mapping[str, tuple[int, int]]


class _ProjectBoundary8616(Protocol):
    """Third-party project fields consumed by this evidence bridge."""

    arch: _ArchBoundary8616


class _CFunctionBoundary8616(Protocol):
    """Third-party structured function identity."""

    addr: int


class _CodegenBoundary8616(Protocol):
    """Third-party codegen surface exposing the structured function."""

    cfunc: _CFunctionBoundary8616


@dataclass(frozen=True, slots=True)
class PackedStatusFlagPreservationEvidence8616:
    """Exact packed-FLAGS offset and instruction sites proven by the frontend."""

    register_offset: int
    instruction_addresses: frozenset[int]

    def covers_instruction(self, instruction_address: object) -> bool:
        """Return whether one structured node belongs to a proven partial write."""
        return isinstance(instruction_address, int) and instruction_address in self.instruction_addresses


def packed_status_flag_preservation_evidence_8616(
    project: object,
    codegen: object,
) -> PackedStatusFlagPreservationEvidence8616 | None:
    """Resolve immutable lift evidence for the current structured function."""
    try:
        project_boundary = cast(_ProjectBoundary8616, project)
        function_address = int(cast(_CodegenBoundary8616, codegen).cfunc.addr)
        flags_register = project_boundary.arch.registers.get("flags")
    except (AttributeError, TypeError, ValueError):
        return None
    if flags_register is None or not flags_register:
        return None
    register_offset = flags_register[0]
    if not isinstance(register_offset, int):
        return None
    resolution = resolve_status_flag_lift_artifact_8616(project, function_address)
    artifact = resolution.artifact if resolution is not None else None
    if os.environ.get("INERTIA_DEBUG_DEF_USE") == "1":
        logging.getLogger(__name__).warning(
            "packed-FLAGS evidence function=%#x source=%s sites=%d",
            function_address,
            resolution.source.value if resolution is not None else "missing",
            0 if artifact is None else len(artifact.packed_preservation_addresses),
        )
    if artifact is None:
        return None
    instruction_addresses = artifact.packed_preservation_addresses
    if not instruction_addresses:
        return None
    if artifact.original_linear_delta:
        instruction_addresses = instruction_addresses | frozenset(
            address - artifact.original_linear_delta
            for address in instruction_addresses
        )
    return PackedStatusFlagPreservationEvidence8616(register_offset, instruction_addresses)


__all__ = [
    "PackedStatusFlagPreservationEvidence8616",
    "packed_status_flag_preservation_evidence_8616",
]
