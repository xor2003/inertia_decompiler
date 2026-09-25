"""Type register locals proven to be indirect near-call targets.

Layer: Types/Lowering.
Responsibility: consume typed callsite summaries for register-indirect near
calls, then keep the register carrier, its declaration, and scalar offset
assignments coherent as one near function-pointer value.
Consumes alias, widening, and typed facts.
Callsite summaries provide the typed call facts consumed here.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616
from ..pipeline.errors import PipelineHardError
from .callee_global_object_type_surface import cfunc_roots_8616
from .near_pointer_type import SimTypeNearPointer16_8616, near_pointer_type_8616
from .register_local_declarations import register_typed_register_local_8616
from .semantic_cast import CSemanticCast8616

__all__ = [
    "RegisterIndirectCallTargetStats8616",
    "materialize_register_indirect_call_target_types_8616",
]


class _ArchSurface8616(Protocol):
    """Architecture fields used to resolve one physical register."""

    registers: dict[str, tuple[int, int]]


class _ProjectSurface8616(Protocol):
    """Project fields required by the type materializer."""

    arch: Arch


class _CFunctionSurface8616(Protocol):
    """Structured function fields containing locals and the active AST."""

    variables_in_use: dict[object, structured_c.CVariable]


class _CodegenSurface8616(Protocol):
    """Owned callsite and result state on the dynamic codegen boundary."""

    project: _ProjectSurface8616
    cfunc: _CFunctionSurface8616
    _inertia_callsite_summary_inventory_8616: Mapping[int, CallsiteSummary8616]
    _inertia_register_indirect_call_target_stats_8616: RegisterIndirectCallTargetStats8616
    _inertia_codegen_decl_refresh_required_8616: bool


@dataclass(frozen=True, slots=True)
class RegisterIndirectCallTargetStats8616:
    """Closed evidence census for register-indirect call target typing."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class _RegisterIdentity8616:
    """Exact physical and SSA identity of one register carrier."""

    offset: int
    size: int
    ident: object
    region: object


def _register_identity_8616(variable: object) -> _RegisterIdentity8616 | None:
    """Return an exact register-storage identity at the angr boundary."""
    if not isinstance(variable, SimRegisterVariable):
        return None
    return _RegisterIdentity8616(variable.reg, variable.size, variable.ident, variable.region)


def _cvar_register_identity_8616(cvar: object) -> _RegisterIdentity8616 | None:
    """Prefer the unified identity carried by one structured register use."""
    if not isinstance(cvar, structured_c.CVariable):
        return None
    unified = cvar.unified_variable
    return _register_identity_8616(unified) or _register_identity_8616(cvar.variable)


def _summary_inventory_8616(codegen: _CodegenSurface8616) -> Mapping[int, CallsiteSummary8616]:
    """Read the typed exact-address summary inventory."""
    try:
        inventory = codegen._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return {}
    return inventory if isinstance(inventory, Mapping) else {}


def _register_shape_8616(arch: _ArchSurface8616, name: str) -> tuple[int, int] | None:
    """Resolve one exact architecture register name to offset and byte width."""
    shape = arch.registers.get(name.lower())
    if not isinstance(shape, tuple) or len(shape) < 2:
        return None
    offset, size = shape[:2]
    return (offset, size) if isinstance(offset, int) and isinstance(size, int) else None


def _function_pointer_type_8616(
    summary: CallsiteSummary8616,
    arch: Arch,
) -> SimTypeNearPointer16_8616:
    """Build the conservative near-call prototype proven at one callsite."""
    widths = summary.logical_arg_widths or summary.arg_widths
    args: list[SimType] = []
    for width in widths:
        scalar = {1: SimTypeChar(False), 2: SimTypeShort(False)}.get(width, SimTypeLong(False))
        args.append(cast(SimType, scalar.with_arch(arch)))
    return_type = cast(SimType, SimTypeShort(False).with_arch(arch))
    prototype = cast(
        SimType,
        SimTypeFunction(args, return_type, variadic=False).with_arch(arch),
    )
    return near_pointer_type_8616(prototype, arch)


def _typed_offset_cast_8616(
    codegen: object,
    rhs: object,
    pointer_type: SimTypeNearPointer16_8616,
) -> structured_c.CTypeCast | None:
    """Project one scalar near offset to a host-compilable function pointer."""
    if not isinstance(rhs, structured_c.CExpression):
        return None
    if isinstance(rhs, structured_c.CTypeCast) and isinstance(rhs.dst_type, SimTypeNearPointer16_8616):
        return rhs
    source_type = rhs.type
    if not isinstance(source_type, SimType):
        return None
    if isinstance(source_type, SimTypePointer) and isinstance(source_type.pts_to, SimTypeFunction):
        return CSemanticCast8616(source_type, pointer_type, rhs, codegen=codegen)
    wide_type = SimTypeLong(False)
    widened = CSemanticCast8616(source_type, wide_type, rhs, codegen=codegen)
    return CSemanticCast8616(wide_type, pointer_type, widened, codegen=codegen)


def _matching_declaration_8616(
    cfunc: _CFunctionSurface8616,
    identity: _RegisterIdentity8616,
) -> structured_c.CVariable | None:
    """Find the existing declaration for one exact register SSA identity."""
    matches = tuple(
        declaration
        for declaration in cfunc.variables_in_use.values()
        if _cvar_register_identity_8616(declaration) == identity
    )
    return matches[0] if len(matches) == 1 else None


def _proven_call_identity_8616(
    codegen: _CodegenSurface8616,
    call: structured_c.CFunctionCall,
    summary: CallsiteSummary8616,
) -> _RegisterIdentity8616 | None:
    """Prove the call's callee variable carries the exact register target."""
    target_source = summary.target_source
    if (
        not isinstance(target_source, tuple)
        or len(target_source) != 2
        or target_source[0] != "reg"
        or not isinstance(target_source[1], str)
        or not isinstance(call.callee_target, structured_c.CVariable)
    ):
        return None
    arch = cast(_ArchSurface8616, codegen.project.arch)
    expected_shape = _register_shape_8616(arch, target_source[1])
    identity = _cvar_register_identity_8616(call.callee_target)
    if expected_shape is None or identity is None or (identity.offset, identity.size) != expected_shape:
        return None
    if summary.arg_count is None or summary.arg_count != len(tuple(cast(Sequence[object], call.args or ()))):
        return None
    return identity


def _identity_census_8616(
    codegen: _CodegenSurface8616,
    identity: _RegisterIdentity8616,
) -> tuple[list[structured_c.CAssignment], list[structured_c.CVariable]]:
    """Collect every variable and assignment matching the register identity."""
    assignments: list[structured_c.CAssignment] = []
    variables: list[structured_c.CVariable] = []
    for root in cfunc_roots_8616(codegen.cfunc):
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, structured_c.CVariable) and _cvar_register_identity_8616(node) == identity:
                variables.append(node)
            if (
                isinstance(node, structured_c.CAssignment)
                and _cvar_register_identity_8616(node.lhs) == identity
            ):
                assignments.append(node)
    return assignments, variables


def _materialize_call_8616(
    codegen: _CodegenSurface8616,
    call: structured_c.CFunctionCall,
    summary: CallsiteSummary8616,
) -> tuple[bool, bool]:
    """Materialize one exact register-indirect target and its assignments."""
    identity = _proven_call_identity_8616(codegen, call, summary)
    if identity is None:
        return False, False

    pointer_type = _function_pointer_type_8616(summary, codegen.project.arch)
    assignments, variables = _identity_census_8616(codegen, identity)
    if not variables or not assignments:
        return False, False

    declaration = _matching_declaration_8616(codegen.cfunc, identity)
    if declaration is None:
        return False, False
    changed = False
    for variable in (*variables, declaration):
        if variable.variable_type != pointer_type:
            variable.variable_type = pointer_type
            changed = True
    for assignment in assignments:
        cast_rhs = _typed_offset_cast_8616(codegen, assignment.rhs, pointer_type)
        if cast_rhs is None:
            return False, False
        if cast_rhs is not assignment.rhs:
            assignment.rhs = cast_rhs
            changed = True
    changed = register_typed_register_local_8616(codegen, declaration) or changed
    return True, changed


def materialize_register_indirect_call_target_types_8616(codegen_raw: object) -> bool:
    """Type every exact register-indirect near-call carrier in structured C."""
    codegen = cast(_CodegenSurface8616, codegen_raw)
    try:
        roots = cfunc_roots_8616(codegen.cfunc)
    except AttributeError:
        return False
    inventory = _summary_inventory_8616(codegen)
    raw = normalized = classified = materialized = failures = 0
    changed = False
    seen_calls: set[int] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, structured_c.CFunctionCall) or id(node) in seen_calls:
                continue
            seen_calls.add(id(node))
            callsite_addr = structured_callsite_addr_8616(node)
            summary = inventory.get(callsite_addr) if isinstance(callsite_addr, int) else None
            if not isinstance(summary, CallsiteSummary8616) or summary.target_source is None:
                continue
            raw += 1
            target_source = summary.target_source
            if not isinstance(target_source, tuple) or len(target_source) != 2 or target_source[0] != "reg":
                failures += 1
                continue
            normalized += 1
            classified += 1
            succeeded, call_changed = _materialize_call_8616(codegen, node, summary)
            if succeeded:
                materialized += 1
                changed = call_changed or changed
            else:
                failures += 1

    stats = RegisterIndirectCallTargetStats8616(raw, normalized, classified, materialized, failures)
    codegen._inertia_register_indirect_call_target_stats_8616 = stats
    if classified > 0 and materialized == 0:
        raise PipelineHardError(
            "register-indirect call target facts were classified but not materialized",
            layer="types/lowering:register_indirect_call_targets",
        )
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed
