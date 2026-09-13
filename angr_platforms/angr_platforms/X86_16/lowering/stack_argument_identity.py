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

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..alias.alias_model_impl import _stack_slot_identity_for_variable, _StackSlotIdentity
from ..c_ast_utils import _replace_c_children_8616
from .stack_declaration_identity import (
    body_declaration_owner_ids_8616,
    declaration_members_are_argument_owned_8616,
    prune_unreferenced_pre_argument_declarations_8616,
)
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_alias_8616,
)


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
    _inertia_arg_stack_identity_unified_8616: int
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_return_selector_materialized_8616: bool


@dataclass(frozen=True, slots=True)
class StackArgumentIdentityStats8616:
    """Closed evidence counts for one argument-storage identity pass."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def machine_bp_stack_identity_8616(
    codegen: object,
    variable: SimStackVariable,
) -> _StackSlotIdentity | None:
    """Project one Alias identity onto its authoritative machine-BP offset."""
    identity = _stack_slot_identity_for_variable(variable)
    if identity is None or identity.base != "bp":
        return None
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if not isinstance(bp_offset, int):
        return None
    return _StackSlotIdentity(identity.base, bp_offset, identity.width, identity.region)


def _machine_bp_stack_binding_identity_8616(
    codegen: object,
    variable: SimStackVariable,
    cvar: object,
) -> _StackSlotIdentity | None:
    """Bind an angr declaration-map key to its canonical projected C variable."""
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
        and canonical_variable.size == variable.size
    ):
        record_stack_variable_coordinate_alias_8616(
            codegen,
            bp_offset=canonical_identity.offset,
            size=canonical_variable.size,
            variable=variable,
        )
    return machine_bp_stack_identity_8616(codegen, variable)


def _positive_stack_variable_8616(
    codegen: object,
    node: object,
) -> SimStackVariable | None:
    """Return a positive-BP stack variable exposed by one structured-C node."""
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


def unify_positive_bp_argument_identity_8616(
    codegen: object,
) -> bool:
    """Join body references to exact canonical positive-BP argument storage."""
    typed_codegen = cast(_ArgumentIdentityCodegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return False
    if cfunc is None:
        return False
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
            return False
    except AttributeError:
        pass

    changed = bool(prune_unreferenced_pre_argument_declarations_8616(typed_codegen))

    arguments_by_identity: dict[object, list[structured_c.CVariable]] = {}
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
        for identity, arguments in arguments_by_identity.items()
        if len(arguments) == 1
    }
    arguments_by_offset: dict[int, list[structured_c.CVariable]] = {}
    for argument in canonical_by_identity.values():
        variable = _positive_stack_variable_8616(typed_codegen, argument)
        if variable is not None:
            identity = machine_bp_stack_identity_8616(typed_codegen, variable)
            if identity is not None:
                arguments_by_offset.setdefault(identity.offset, []).append(argument)
    canonical_by_offset = {
        offset: arguments[0]
        for offset, arguments in arguments_by_offset.items()
        if len(arguments) == 1
    }
    if not canonical_by_identity:
        typed_codegen._inertia_arg_stack_identity_stats_8616 = (
            StackArgumentIdentityStats8616()
        )
        if changed:
            _mark_stack_identity_change_8616(typed_codegen)
        return changed

    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    def transform(node: object) -> object:
        nonlocal raw_count, normalized_count, classified_count
        nonlocal materialized_count, changed
        variable = _positive_stack_variable_8616(typed_codegen, node)
        indexed_offset = _indexed_stack_base_argument_offset_8616(node)
        if variable is None and indexed_offset is None:
            return node
        raw_count += 1
        if variable is not None:
            identity = machine_bp_stack_identity_8616(typed_codegen, variable)
            if identity is None:
                return node
            argument = canonical_by_identity.get(identity)
        else:
            argument = canonical_by_offset.get(cast(int, indexed_offset))
        normalized_count += 1
        if argument is None:
            return node
        classified_count += 1
        materialized_count += 1
        if variable is not None and variable is argument.variable:
            return node
        changed = True
        return _clone_argument_reference_8616(argument)

    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True

    canonical_variables = {
        argument.variable for argument in canonical_by_identity.values()
    }
    if isinstance(variables_in_use, dict):
        for variable, cvar in tuple(variables_in_use.items()):
            if not isinstance(variable, SimStackVariable):
                continue
            identity = _machine_bp_stack_binding_identity_8616(
                typed_codegen,
                variable,
                cvar,
            )
            argument = canonical_by_identity.get(identity)
            if argument is None:
                continue
            if variable in canonical_variables:
                if cvar is not argument:
                    variables_in_use[variable] = argument
                    changed = True
                continue
            del variables_in_use[variable]
            changed = True

    if isinstance(unified_local_vars, dict):
        argument_variable_ids = frozenset(id(variable) for variable in canonical_variables)
        body_variable_ids = body_declaration_owner_ids_8616(cfunc.statements, argument_variable_ids)
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

    failure_count = max(classified_count - materialized_count, 0)
    typed_codegen._inertia_arg_stack_identity_stats_8616 = (
        StackArgumentIdentityStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        )
    )
    if classified_count > 0 and materialized_count == 0:
        raise RuntimeError(
            "argument stack identities were classified but not materialized"
        )
    if changed:
        _mark_stack_identity_change_8616(typed_codegen)
    return changed


__all__ = [
    "StackArgumentIdentityStats8616",
    "machine_bp_stack_identity_8616",
    "unify_positive_bp_argument_identity_8616",
]
