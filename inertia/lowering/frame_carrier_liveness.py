"""Refuse frame consumption when a scalar carrier remains externally observed.

Layer: Types/Lowering.
Responsibility: check the whole structured function before consuming a proven
canonical frame group. Machine frame tags prove ownership, not deadness.
This proof covers register/temporary values and owned runtime register state,
not reused stack objects: their memory lifetime belongs to the storage owner.
Consumes alias, widening, and typed facts. This is a conservative use check,
not general DCE: even an external write with the same identity refuses.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from angr.ailment.expression import VirtualVariable
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CDirtyExpression, CTypeCast, CVariable
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable, SimVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616

from .gp_register_state import runtime_gp_name_for_variable_8616
from .physical_registers import PhysicalRegisterView8616, physical_register_view_8616


class FrameCarrierUseVerdict8616(StrEnum):
    """Whether all scalar definitions are contained in the consumed group."""

    CLOSED = "closed"
    EXTERNAL_USE = "external_use"
    UNKNOWN_IDENTITY = "unknown_identity"


@dataclass(frozen=True, slots=True)
class FrameCarrierUseProof8616:
    """One atomic group-consumption decision without partial removal."""

    verdict: FrameCarrierUseVerdict8616
    candidate_count: int

    @property
    def complete(self) -> bool:
        """Return true only when no scalar definition has an external use."""
        return self.verdict is FrameCarrierUseVerdict8616.CLOSED


def _scalar_identity_8616(value: object) -> int | SimVariable | None:
    """Join dirty and recovered SSA views without merging distinct versions."""
    while isinstance(value, CTypeCast):
        value = value.expr
    if isinstance(value, CDirtyExpression) and isinstance(value.dirty, VirtualVariable):
        return value.dirty.varid
    if isinstance(value, CVariable):
        if isinstance(value.vvar_id, int):
            return value.vvar_id
        if isinstance(value.variable, SimVariable):
            return value.variable
    return None


def prove_frame_carrier_uses_8616(root: object, frame_addresses: frozenset[int]) -> FrameCarrierUseProof8616:
    """Require every scalar use to disappear with the entire frame group."""
    candidates = tuple(
        node for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and (tags := copy_structured_tags_8616(node.tags)) is not None
        and tags.get("ins_addr") in frame_addresses
    )
    definitions: set[int | SimVariable] = set()
    register_definitions: list[tuple[int | SimVariable, PhysicalRegisterView8616]] = []
    for candidate in candidates:
        lhs = candidate.lhs
        while isinstance(lhs, CTypeCast):
            lhs = lhs.expr
        if isinstance(lhs, CDirtyExpression) or (
            isinstance(lhs, CVariable) and (
                isinstance(lhs.variable, (SimRegisterVariable, SimTemporaryVariable))
                or runtime_gp_name_for_variable_8616(lhs.variable) is not None
            )
        ):
            identity = _scalar_identity_8616(lhs)
            if identity is None:
                return FrameCarrierUseProof8616(FrameCarrierUseVerdict8616.UNKNOWN_IDENTITY, len(candidates))
            definitions.add(identity)
            register = physical_register_view_8616(lhs)
            if register is not None:
                register_definitions.append((identity, register))
    excluded = {id(candidate) for candidate in candidates}
    for node in _iter_c_nodes_deep_8616(root, seen=excluded):
        identity = _scalar_identity_8616(node)
        if identity in definitions:
            return FrameCarrierUseProof8616(FrameCarrierUseVerdict8616.EXTERNAL_USE, len(candidates))
        register = physical_register_view_8616(node)
        if register is not None and any(
            not (isinstance(identity, int) and isinstance(defined, int))
            and register.reg_offset < source.reg_offset + source.width
            and source.reg_offset < register.reg_offset + register.width
            for defined, source in register_definitions
        ):
            return FrameCarrierUseProof8616(FrameCarrierUseVerdict8616.UNKNOWN_IDENTITY, len(candidates))
    return FrameCarrierUseProof8616(FrameCarrierUseVerdict8616.CLOSED, len(candidates))
