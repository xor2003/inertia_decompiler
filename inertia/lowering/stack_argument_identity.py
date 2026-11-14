# cython: language_level=3, infer_types=True
"""Canonicalize positive-BP argument storage after typed pointer lowering.

Layer: Types/Lowering.
Responsibility: join body stack variables to canonical argument variables using
alias identities, then keep angr declaration maps consistent with that join.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not infer arguments or pointer classes; it only consumes
prototype and alias facts already materialized by earlier pipeline owners.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia.alias.alias_model_impl import _stack_slot_identity_for_variable, _StackSlotIdentity
from inertia.lowering.c_ast_utils import _replace_c_children_8616

from .stack_declaration_identity import (
    body_declaration_owner_ids_8616,
    declaration_members_are_argument_owned_8616,
    prune_unreferenced_pre_argument_declarations_8616,
)
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_alias_8616,
)
import dataclasses
import operator
import builtins


class _ArgumentIdentityCFunction8616(Protocol):
    """Dynamic angr C-function fields consumed by argument identity lowering."""

    arg_list: Sequence[object] | None
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _ArgumentIdentityCodegen8616(Protocol):
    """Dynamic angr codegen fields used by argument identity lowering."""

    cfunc: _ArgumentIdentityCFunction8616 | None
    _inertia_arg_stack_identity_stats_8616: StackArgumentIdentityStats8616
    _inertia_arg_stack_identity_unified_8616: cython.longlong
    _inertia_codegen_decl_refresh_required_8616: cython.bint
    _inertia_return_selector_materialized_8616: cython.bint


@dataclasses.dataclass(frozen=True, )
class StackArgumentIdentityStats8616:
    """Closed evidence counts for one argument-storage identity pass."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@cython.ccall
def machine_bp_stack_identity_8616(
    codegen: object,
    variable: SimStackVariable,
) -> _StackSlotIdentity | None:
    """Project one Alias identity onto its authoritative machine-BP offset."""
    identity: object
    identity = _stack_slot_identity_for_variable(variable)
    if identity is None or identity.base != "bp":
        return None
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if not isinstance(bp_offset, int):
        return None
    return _StackSlotIdentity(identity.base, bp_offset, identity.width, identity.region)


@cython.ccall
def _machine_bp_stack_binding_identity_8616(
    codegen: object,
    variable: SimStackVariable,
    cvar: object,
) -> _StackSlotIdentity | None:
    """Bind an angr declaration-map key to its canonical projected C variable."""
    canonical_identity: object
    canonical_variable = (
        cvar.variable if isinstance(cvar, structured_c.CVariable) else None
    )
    if not isinstance(canonical_variable, SimStackVariable):
        return machine_bp_stack_identity_8616(codegen, variable)
    canonical_identity = machine_bp_stack_identity_8616(codegen, canonical_variable)
    if (
        canonical_identity is not None
        and canonical_variable is not variable
        and isinstance(canonical_variable.size, int)
        and operator.eq(canonical_variable.size, variable.size)
    ):
        record_stack_variable_coordinate_alias_8616(
            codegen,
            bp_offset=canonical_identity.offset,
            size=canonical_variable.size,
            variable=variable,
        )
    return machine_bp_stack_identity_8616(codegen, variable)


@cython.ccall
def _positive_stack_variable_8616(
    codegen: object,
    node: object,
) -> SimStackVariable | None:
    """Return a positive-BP stack variable exposed by one structured-C node."""
    identity: object
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if (
        not isinstance(variable, SimStackVariable)
        or not isinstance(variable.offset, int)
        or variable.base != "bp"
    ):
        return None
    identity = machine_bp_stack_identity_8616(codegen, variable)
    if identity is None or identity.offset < 4:
        return None
    return variable


@cython.ccall
def _indexed_stack_base_argument_offset_8616(node: object) -> int | None:
    """Return an exact positive argument offset from angr's stack-base view."""
    if not isinstance(node, structured_c.CIndexedVariable):
        return None
    base = node.variable
    index = node.index
    if (
        not isinstance(base, structured_c.CFakeVariable)
        or base.name != "stack_base"
        or not isinstance(index, structured_c.CConstant)
        or not isinstance(index.value, int)
        or index.value <= 0
    ):
        return None
    return index.value


@cython.ccall
def _mark_stack_identity_change_8616(
    codegen: _ArgumentIdentityCodegen8616,
) -> None:
    """Request declaration refresh after an owned stack-identity mutation."""
    codegen._inertia_codegen_decl_refresh_required_8616 = True
    try:
        unified_count = codegen._inertia_arg_stack_identity_unified_8616
    except AttributeError:
        unified_count = 0
    codegen._inertia_arg_stack_identity_unified_8616 = unified_count + 1


@cython.ccall
def _clone_argument_reference_8616(
    argument: structured_c.CVariable,
) -> structured_c.CVariable:
    """Clone one canonical argument reference for insertion into the C tree."""
    clone = structured_c.CVariable(
        argument.variable,
        variable_type=argument.variable_type,
        codegen=argument.codegen,
    )
    clone.tags = dict(argument.tags or {})
    return clone


@dataclasses.dataclass(frozen=True, )
class _ArgumentBoundary8616:
    """Normalized cfunc boundary pieces consumed by the identity pass."""

    cfunc: _ArgumentIdentityCFunction8616
    argument_list: object
    variables_in_use: object
    unified_local_vars: object


@cython.ccall
def _argument_boundary_8616(
    typed_codegen: _ArgumentIdentityCodegen8616,
) -> _ArgumentBoundary8616 | None:
    """Return the normalized boundary pieces, or None when unavailable."""
    cfunc: object
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return None
    if cfunc is None:
        return None
    # angr and focused codegen adapters may omit optional C-function indexes.
    # Normalize that dynamic boundary before applying owned identity contracts.
    try:
        argument_list = tuple(cfunc.arg_list or ())
    except AttributeError:
        argument_list = ()
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = None
    try:
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError:
        unified_local_vars = None
    try:
        if typed_codegen._inertia_return_selector_materialized_8616:
            return None
    except AttributeError:
        pass
    return _ArgumentBoundary8616(
        cfunc,
        argument_list,
        variables_in_use,
        unified_local_vars,
    )


@cython.ccall
def _canonical_arguments_8616(
    typed_codegen: _ArgumentIdentityCodegen8616,
    argument_list: object,
) -> tuple[
    dict[_StackSlotIdentity, structured_c.CVariable],
    dict[cython.longlong, structured_c.CVariable],
]:
    """Collect canonical argument references by identity and BP offset."""
    identity: object
    variable: object
    argument: object
    candidate: object
    arguments_by_identity: dict[_StackSlotIdentity, list[structured_c.CVariable]] = {}
    for candidate in argument_list:
        if not isinstance(candidate, structured_c.CVariable):
            continue
        variable = _positive_stack_variable_8616(typed_codegen, candidate)
        if variable is None:
            continue
        identity = machine_bp_stack_identity_8616(typed_codegen, variable)
        if identity is not None:
            arguments_by_identity.setdefault(identity, []).append(candidate)
    canonical_by_identity = {
        identity: arguments[0]
        for identity, arguments in builtins.iter(arguments_by_identity.items())
        if len(arguments) == 1
    }
    arguments_by_offset: dict[cython.longlong, list[structured_c.CVariable]] = {}
    for argument in canonical_by_identity.values():
        variable = _positive_stack_variable_8616(typed_codegen, argument)
        if variable is not None:
            identity = machine_bp_stack_identity_8616(typed_codegen, variable)
            if identity is not None:
                arguments_by_offset.setdefault(identity.offset, []).append(argument)
    canonical_by_offset = {
        offset: arguments[0]
        for offset, arguments in builtins.iter(arguments_by_offset.items())
        if len(arguments) == 1
    }
    return canonical_by_identity, canonical_by_offset


@cython.dataclasses.dataclass()
class _ArgumentUnification8616:
    """Mutable transform state for one argument-identity rewrite pass."""

    codegen: _ArgumentIdentityCodegen8616
    canonical_by_identity: Mapping[_StackSlotIdentity, structured_c.CVariable]
    canonical_by_offset: Mapping[cython.longlong, structured_c.CVariable]
    changed: cython.bint = False
    raw_count: cython.longlong = 0
    normalized_count: cython.longlong = 0
    classified_count: cython.longlong = 0
    materialized_count: cython.longlong = 0

    @cython.ccall
    def transform(self, node: object) -> object:
        """Rewrite one node to its canonical argument reference."""
        argument: object
        identity: object
        indexed_offset: object
        variable: object
        variable = _positive_stack_variable_8616(self.codegen, node)
        indexed_offset = _indexed_stack_base_argument_offset_8616(node)
        if variable is None and indexed_offset is None:
            return node
        self.raw_count += 1
        if variable is not None:
            identity = machine_bp_stack_identity_8616(self.codegen, variable)
            if identity is None:
                return node
            argument = self.canonical_by_identity.get(identity)
        else:
            argument = self.canonical_by_offset.get(cast(int, indexed_offset))
        self.normalized_count += 1
        if argument is None:
            return node
        self.classified_count += 1
        self.materialized_count += 1
        if variable is not None and variable is argument.variable:
            return node
        self.changed = True
        return _clone_argument_reference_8616(argument)


@cython.ccall
def _merge_variables_in_use_8616(
    typed_codegen: _ArgumentIdentityCodegen8616,
    variables_in_use: object,
    canonical_by_identity: Mapping[_StackSlotIdentity, structured_c.CVariable],
    canonical_variables: object,
) -> cython.bint:
    """Retarget or drop declaration-map entries bound to canonical arguments."""
    argument: object
    identity: object
    cvar: object
    variable: object
    changed = False
    for variable, cvar in tuple(variables_in_use.items()):
        if not isinstance(variable, SimStackVariable):
            continue
        identity = _machine_bp_stack_binding_identity_8616(
            typed_codegen,
            variable,
            cvar,
        )
        argument = (
            canonical_by_identity.get(identity) if identity is not None else None
        )
        if argument is None:
            continue
        if variable in canonical_variables:
            if cvar is not argument:
                variables_in_use[variable] = argument
                changed = True
            continue
        del variables_in_use[variable]
        changed = True
    return changed


def _merge_unified_local_vars_8616(
    typed_codegen: _ArgumentIdentityCodegen8616,
    unified_local_vars: object,
    canonical_by_identity: Mapping[_StackSlotIdentity, structured_c.CVariable],
    canonical_variables: object,
    statements: object,
) -> cython.bint:
    """Drop unified declaration entries proven argument-owned."""
    variable: object
    argument_variable_ids = frozenset(id(variable) for variable in iter(canonical_variables))
    body_variable_ids = body_declaration_owner_ids_8616(statements, argument_variable_ids)
    changed = False
    for variable in tuple(unified_local_vars):
        if not isinstance(variable, SimStackVariable):
            continue
        identity = machine_bp_stack_identity_8616(typed_codegen, variable)
        # Widening can replace declaration members while leaving a byte key.
        header_owned_members = id(variable) not in body_variable_ids and declaration_members_are_argument_owned_8616(
            unified_local_vars[variable], argument_variable_ids,
        )
        if identity in canonical_by_identity or header_owned_members:
            del unified_local_vars[variable]
            changed = True
    return changed


def unify_positive_bp_argument_identity_8616(
    codegen: object,
) -> cython.bint:
    """Join body references to exact canonical positive-BP argument storage."""
    boundary: object
    typed_codegen = cast(_ArgumentIdentityCodegen8616, codegen)
    boundary = _argument_boundary_8616(typed_codegen)
    if boundary is None:
        return False

    changed = bool(prune_unreferenced_pre_argument_declarations_8616(typed_codegen))

    canonical_by_identity, canonical_by_offset = _canonical_arguments_8616(
        typed_codegen,
        boundary.argument_list,
    )
    if not canonical_by_identity:
        typed_codegen._inertia_arg_stack_identity_stats_8616 = (
            StackArgumentIdentityStats8616()
        )
        if changed:
            _mark_stack_identity_change_8616(typed_codegen)
        return changed

    unification = _ArgumentUnification8616(
        typed_codegen,
        canonical_by_identity,
        canonical_by_offset,
    )
    if _replace_c_children_8616(boundary.cfunc.statements, unification.transform):
        unification.changed = True

    canonical_variables = frozenset(
        argument.variable for argument in builtins.iter(canonical_by_identity.values())
    )
    if isinstance(boundary.variables_in_use, dict):
        changed = (
            _merge_variables_in_use_8616(
                typed_codegen,
                boundary.variables_in_use,
                canonical_by_identity,
                canonical_variables,
            )
            or changed
        )

    if isinstance(boundary.unified_local_vars, dict):
        changed = (
            _merge_unified_local_vars_8616(
                typed_codegen,
                boundary.unified_local_vars,
                canonical_by_identity,
                canonical_variables,
                boundary.cfunc.statements,
            )
            or changed
        )

    failure_count = max(unification.classified_count - unification.materialized_count, 0)
    typed_codegen._inertia_arg_stack_identity_stats_8616 = (
        StackArgumentIdentityStats8616(
            raw_fact_count=unification.raw_count,
            normalized_fact_count=unification.normalized_count,
            classified_fact_count=unification.classified_count,
            materialized_count=unification.materialized_count,
            failure_count=failure_count,
        )
    )
    if unification.classified_count > 0 and unification.materialized_count == 0:
        raise RuntimeError(
            "argument stack identities were classified but not materialized"
        )
    changed = changed or unification.changed
    if changed:
        _mark_stack_identity_change_8616(typed_codegen)
    return changed


__all__ = [
    "StackArgumentIdentityStats8616",
    "machine_bp_stack_identity_8616",
    "unify_positive_bp_argument_identity_8616",
]
