"""Lower proven packed-FLAGS entry dependencies to explicit runtime state.

Layer: Types/Lowering.
Responsibility: initialize exact packed-FLAGS SSA roots and inputs consumed by
updates whose frontend evidence proves preservation of architectural bits.

The live-in owner inventory is lowering evidence, not an unconditional DCE
root. Backward liveness retains an initializer while a proven consumer remains;
fixed-point cleanup may remove the initializer after its complete packed-FLAGS
chain becomes dead. Final projection replay rematerializes only still-consumed
live-ins.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.status_flag_lift_context import (
    StatusFlagLiftArtifact8616,
    active_status_flag_lift_artifact_8616,
    resolve_status_flag_lift_artifact_8616,
)
from ..semantics.expression_analysis import (
    VirtualValueIdentityKind8616,
    describe_virtual_value_identity_8616,
)
from .global_declarations import GlobalDeclarationCType8616, record_global_declaration_spec_8616
from .physical_registers import physical_register_view_8616

__all__ = ["PackedFlagsStateStats8616", "lower_packed_flags_live_in_8616"]

_RUNTIME_FLAGS_ADDRESS_8616 = 0x1_0018
_RUNTIME_FLAGS_NAME_8616 = "inertia_flags"


class _FlagsArch8616(Protocol):
    """Architecture register map consumed at the third-party boundary."""

    registers: Mapping[str, tuple[int, int]]


class _FlagsProject8616(Protocol):
    """Project architecture consumed by packed-FLAGS lowering."""

    arch: _FlagsArch8616


class _FlagsCFunction8616(Protocol):
    """Structured function surface mutated by packed-FLAGS lowering."""

    addr: int
    statements: object


class _FlagsCodegen8616(Protocol):
    """Dynamic codegen boundary consumed by packed-FLAGS lowering."""

    project: _FlagsProject8616 | None
    cfunc: _FlagsCFunction8616 | None
    _inertia_packed_flags_state_stats_8616: PackedFlagsStateStats8616
    _inertia_packed_flags_state_live_ins_8616: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class PackedFlagsStateStats8616:
    """Closed evidence counters for packed-FLAGS live-in materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _identity_8616(node: object) -> tuple[int, int, int, int | str] | None:
    """Return one exact structured register SSA identity."""
    if isinstance(node, structured_c.CDirtyExpression):
        view = physical_register_view_8616(node)
        identity = describe_virtual_value_identity_8616(node)
        if (
            view is None
            or identity is None
            or identity.kind is not VirtualValueIdentityKind8616.VARIABLE_ID
        ):
            return None
        return view.reg_offset, view.width, 0, identity.value
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not (
        isinstance(variable, SimRegisterVariable)
        and isinstance(variable.reg, int)
        and isinstance(variable.size, int)
        and isinstance(variable.region, int)
        and isinstance(variable.ident, (int, str))
    ):
        return None
    return variable.reg, variable.size, variable.region, variable.ident


def _flags_inputs_8616(
    root: object,
    flags_shape: tuple[int, int],
) -> dict[tuple[int, int, int, int | str], structured_c.CExpression]:
    """Return exact packed-FLAGS SSA identities read by one expression."""
    inputs: dict[tuple[int, int, int, int | str], structured_c.CExpression] = {}
    for node in _iter_c_nodes_deep_8616(root):
        identity = _identity_8616(node)
        if identity is not None and identity[:2] == flags_shape:
            inputs.setdefault(identity, node)
    return inputs


_FlagsIdentity8616 = tuple[int, int, int, int | str]


def _lift_candidates_8616(
    statements: structured_c.CStatement,
    artifact: StatusFlagLiftArtifact8616,
    flags_shape: tuple[int, int],
) -> dict[_FlagsIdentity8616, structured_c.CExpression]:
    """Collect FLAGS-input exemplars at artifact-covered instruction sites."""
    candidates: dict[_FlagsIdentity8616, structured_c.CExpression] = {}
    defined_identities: set[_FlagsIdentity8616] = set()
    definition_counts: dict[_FlagsIdentity8616, int] = {}
    self_dependent_roots: dict[_FlagsIdentity8616, structured_c.CExpression] = {}
    all_inputs: dict[_FlagsIdentity8616, structured_c.CExpression] = {}
    for node in _iter_c_nodes_deep_8616(statements):
        if not isinstance(node, structured_c.CAssignment):
            continue
        lhs_identity = _identity_8616(node.lhs)
        if lhs_identity is not None and lhs_identity[:2] == flags_shape:
            defined_identities.add(lhs_identity)
            definition_counts[lhs_identity] = definition_counts.get(lhs_identity, 0) + 1
        rhs_inputs = _flags_inputs_8616(node.rhs, flags_shape)
        all_inputs.update(rhs_inputs)
        if lhs_identity is not None and lhs_identity in rhs_inputs:
            self_dependent_roots.setdefault(lhs_identity, rhs_inputs[lhs_identity])
        instruction_addr = node.tags.get("ins_addr")
        if (
            not isinstance(instruction_addr, int)
            or not artifact.covers_packed_preservation_8616(instruction_addr)
        ):
            continue
        candidates.update(rhs_inputs)
    candidates.update(
        (identity, exemplar)
        for identity, exemplar in all_inputs.items()
        if identity not in defined_identities
    )
    candidates.update(
        (identity, exemplar)
        for identity, exemplar in self_dependent_roots.items()
        if definition_counts.get(identity) == 1
    )
    return candidates


def _existing_flag_identities_8616(
    statements: structured_c.CStatement,
) -> set[_FlagsIdentity8616 | None]:
    """Return identities already bound to a runtime FLAGS-state variable."""
    return {
        _identity_8616(node.lhs)
        for node in _iter_c_nodes_deep_8616(statements)
        if isinstance(node, structured_c.CAssignment)
        and isinstance(node.rhs, structured_c.CVariable)
        and isinstance(node.rhs.variable, SimMemoryVariable)
        and node.rhs.variable.category == "inertia_flags_state"
    }


def _materialize_flag_initializers_8616(
    codegen: object,
    cfunc: _FlagsCFunction8616,
    candidates: dict[_FlagsIdentity8616, structured_c.CExpression],
    existing: set[_FlagsIdentity8616 | None],
) -> int:
    """Insert runtime FLAGS initializers for candidates not already bound."""
    materialized = 0
    initializers: list[structured_c.CAssignment] = []
    for identity, exemplar in sorted(candidates.items(), key=lambda item: repr(item[0])):
        if identity in existing:
            continue
        lhs = copy.copy(exemplar)
        rhs = structured_c.CVariable(
            SimMemoryVariable(
                _RUNTIME_FLAGS_ADDRESS_8616,
                2,
                name=_RUNTIME_FLAGS_NAME_8616,
                region=cfunc.addr,
                category="inertia_flags_state",
            ),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        initializers.append(structured_c.CAssignment(lhs, rhs, codegen=codegen))
        materialized += 1
    if initializers:
        if isinstance(cfunc.statements, structured_c.CStatements):
            cfunc.statements.statements[0:0] = initializers
        else:
            cfunc.statements = structured_c.CStatements(
                [*initializers, cfunc.statements],
                codegen=codegen,
            )
    return materialized


def _flags_live_in_owners_8616(statements: structured_c.CStatement) -> tuple[object, ...]:
    """Collect owners of every runtime FLAGS-state assignment."""
    live_in_owners: list[object] = []
    for node in _iter_c_nodes_deep_8616(statements):
        if not (
            isinstance(node, structured_c.CAssignment)
            and isinstance(node.rhs, structured_c.CVariable)
            and isinstance(node.rhs.variable, SimMemoryVariable)
            and node.rhs.variable.category == "inertia_flags_state"
        ):
            continue
        live_in_owners.append(node.lhs)
        if isinstance(node.lhs, structured_c.CVariable) and isinstance(node.lhs.variable.ident, (int, str)):
            live_in_owners.append(node.lhs.variable.ident)
    return tuple(live_in_owners)


def _debug_packed_flags_8616(
    cfunc: _FlagsCFunction8616,
    artifact: StatusFlagLiftArtifact8616,
    flags_shape: tuple[int, int],
    candidates: dict[_FlagsIdentity8616, structured_c.CExpression],
    existing: set[_FlagsIdentity8616 | None],
    stats: PackedFlagsStateStats8616,
) -> None:
    """Emit the optional packed-FLAGS census dump for debugging."""
    logging.getLogger(__name__).warning(
        "[packed-flags-state] function=%#x sites=%s lift_candidates=%s candidates=%s existing=%s stats=%s assignments=%s",
        cfunc.addr,
        tuple(sorted(artifact.packed_preservation_addresses)),
        artifact.candidates,
        tuple(sorted(candidates, key=repr)),
        tuple(sorted((item for item in existing if item is not None), key=repr)),
        stats,
        tuple(
            (
                _identity_8616(node.lhs),
                node.tags.get("ins_addr"),
                tuple(sorted(_flags_inputs_8616(node.rhs, flags_shape), key=repr)),
            )
            for node in _iter_c_nodes_deep_8616(cfunc.statements)
            if isinstance(node, structured_c.CAssignment)
            and (_identity_8616(node.lhs) or (None, None))[:2] == flags_shape
        ),
    )


def lower_packed_flags_live_in_8616(codegen: object) -> bool:
    """Initialize proven packed-FLAGS update inputs from runtime FLAGS."""
    boundary = cast(_FlagsCodegen8616, codegen)
    boundary._inertia_packed_flags_state_live_ins_8616 = ()
    project = boundary.project
    cfunc = boundary.cfunc
    empty = PackedFlagsStateStats8616(0, 0, 0, 0, 0)
    if (
        project is None
        or cfunc is None
        or not isinstance(cfunc.statements, structured_c.CStatement)
    ):
        boundary._inertia_packed_flags_state_stats_8616 = empty
        return False
    shape = project.arch.registers.get("flags")
    artifact = active_status_flag_lift_artifact_8616(cfunc.addr)
    if artifact is None:
        resolution = resolve_status_flag_lift_artifact_8616(project, cfunc.addr)
        artifact = resolution.artifact if resolution is not None else None
    if shape is None or len(shape) < 2 or artifact is None:
        boundary._inertia_packed_flags_state_stats_8616 = empty
        return False
    flags_shape = shape[:2]
    statements = cfunc.statements
    candidates = _lift_candidates_8616(statements, artifact, flags_shape)
    existing = _existing_flag_identities_8616(statements)
    materialized = _materialize_flag_initializers_8616(
        codegen, cfunc, candidates, existing
    )
    if materialized:
        record_global_declaration_spec_8616(
            codegen,
            ctype=GlobalDeclarationCType8616.UNSIGNED_SHORT,
            name=_RUNTIME_FLAGS_NAME_8616,
            array_len=None,
        )
    boundary._inertia_packed_flags_state_live_ins_8616 = _flags_live_in_owners_8616(
        cfunc.statements
    )
    count = len(candidates)
    boundary._inertia_packed_flags_state_stats_8616 = PackedFlagsStateStats8616(
        count,
        count,
        count,
        materialized,
        count - materialized if not existing else 0,
    )
    if os.environ.get("INERTIA_DEBUG_PACKED_FLAGS") == "1":
        _debug_packed_flags_8616(
            cfunc,
            artifact,
            flags_shape,
            candidates,
            existing,
            boundary._inertia_packed_flags_state_stats_8616,
        )
    return materialized > 0
