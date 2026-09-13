"""Clean stack declaration maps from exact storage-ownership evidence.

Layer: Types/Lowering.
Responsibility: reconcile stack declaration ownership with body and header
variables, using exact alias identity or already-bound formal argument members.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module does not infer arguments, locals, types, or semantics. It never
uses rendered C, assembly text, source names, or sample-specific addresses.
Unknown or overlapping storage is retained.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from ..alias.alias_model_impl import _stack_slot_identity_for_variable
from ..c_ast_utils import _iter_c_nodes_deep_8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

_FIRST_BP_ARGUMENT_OFFSET_8616: int = 4
_DECLARATION_ENTRY_FIELD_COUNT_8616: int = 2


class _StackSlotIdentityLike8616(Protocol):
    """Typed projection of the canonical Alias stack identity."""

    base: str
    offset: int
    width: int | None
    region: int | None

    def end_offset(self) -> int | None:
        """Return the exclusive ending byte offset when width is known."""
        ...


class _StackDeclarationCFunction8616(Protocol):
    """Dynamic angr C-function fields consumed by declaration cleanup."""

    arg_list: Sequence[object] | None
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _StackDeclarationCodegen8616(Protocol):
    """Dynamic angr codegen fields consumed by declaration cleanup."""

    cfunc: _StackDeclarationCFunction8616 | None
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_pre_argument_declaration_stats_8616: (
        PreArgumentStackDeclarationStats8616
    )
    _inertia_return_selector_materialized_8616: bool


class PreArgumentStackDeclarationDecision8616(Enum):
    """Typed ownership decision for one stack declaration-map entry."""

    OUTSIDE_PRE_ARGUMENT_RANGE = "outside_pre_argument_range"
    KEEP_BODY_OWNED = "keep_body_owned"
    KEEP_HEADER_OWNED = "keep_header_owned"
    REMOVE_UNREFERENCED = "remove_unreferenced"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class PreArgumentStackDeclarationStats8616:
    """Closed evidence counts for pre-argument declaration cleanup."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refusal_count: int = 0


def _stack_variable_8616(node: object) -> SimStackVariable | None:
    """Return exact stack storage exposed by one structured-C variable node."""
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    return variable if isinstance(variable, SimStackVariable) else None


def declaration_members_are_argument_owned_8616(
    entries: object, argument_variable_ids: frozenset[int],
) -> bool:
    """Recognize a stale declaration whose members all belong to one formal.

    This proves member ownership only. The caller must separately refuse a key
    still used by the body; byte/word proximity and matching names are not proof.
    """
    if not isinstance(entries, (list, tuple, set)) or not entries:
        return False
    owners: set[int] = set()
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != _DECLARATION_ENTRY_FIELD_COUNT_8616:
            return False
        variable = _stack_variable_8616(entry[0])
        if variable is None or id(variable) not in argument_variable_ids:
            return False
        owners.add(id(variable))
    return len(owners) == 1


def body_declaration_owner_ids_8616(
    root: object, argument_variable_ids: frozenset[int],
) -> frozenset[int]:
    """Keep physical and unified body owners, excluding stale formal indexes."""
    owners: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CVariable):
            continue
        owners.add(id(node.variable))
        if id(node.variable) not in argument_variable_ids and node.unified_variable is not None:
            owners.add(id(node.unified_variable))
    return frozenset(owners)


def _stack_identity_8616(
    variable: SimStackVariable,
) -> _StackSlotIdentityLike8616 | None:
    """Project the canonical Alias identity onto this typed consumer contract."""
    identity = _stack_slot_identity_for_variable(variable)
    return None if identity is None else cast(_StackSlotIdentityLike8616, identity)


def _stack_identities_in_tree_8616(
    root: object,
) -> frozenset[_StackSlotIdentityLike8616]:
    """Collect exact stack identities referenced by one structured-C tree."""
    identities: set[_StackSlotIdentityLike8616] = set()
    for node in _iter_c_nodes_deep_8616(root):
        variable = _stack_variable_8616(node)
        if variable is None:
            continue
        identity = _stack_identity_8616(variable)
        if identity is not None:
            identities.add(identity)
    return frozenset(identities)


def _stack_identities_overlap_8616(
    lhs: _StackSlotIdentityLike8616,
    rhs: _StackSlotIdentityLike8616,
) -> bool:
    """Return whether two exact stack ranges may own any common byte."""
    if lhs.base != rhs.base:
        return False
    if lhs.region is not None and rhs.region is not None and lhs.region != rhs.region:
        return False
    lhs_end = lhs.end_offset()
    rhs_end = rhs.end_offset()
    if lhs_end is None or rhs_end is None:
        return lhs == rhs
    return lhs.offset < rhs_end and rhs.offset < lhs_end


def _pre_argument_declaration_decision_8616(
    identity: _StackSlotIdentityLike8616,
    *,
    bp_offset: int | None,
    body_identities: frozenset[_StackSlotIdentityLike8616],
    header_identities: frozenset[_StackSlotIdentityLike8616],
) -> PreArgumentStackDeclarationDecision8616:
    """Classify in machine-BP coordinates; compare ownership in native storage coordinates."""
    if bp_offset is None:
        return PreArgumentStackDeclarationDecision8616.UNKNOWN_REFUSE
    if identity.base != "bp" or not 0 < bp_offset < _FIRST_BP_ARGUMENT_OFFSET_8616:
        return PreArgumentStackDeclarationDecision8616.OUTSIDE_PRE_ARGUMENT_RANGE
    if identity.width is None or bp_offset + identity.width > _FIRST_BP_ARGUMENT_OFFSET_8616:
        return PreArgumentStackDeclarationDecision8616.UNKNOWN_REFUSE
    if any(
        _stack_identities_overlap_8616(identity, owned)
        for owned in header_identities
    ):
        return PreArgumentStackDeclarationDecision8616.KEEP_HEADER_OWNED
    if any(
        _stack_identities_overlap_8616(identity, owned) for owned in body_identities
    ):
        return PreArgumentStackDeclarationDecision8616.KEEP_BODY_OWNED
    return PreArgumentStackDeclarationDecision8616.REMOVE_UNREFERENCED


def _declaration_variables_8616(
    *mappings: object,
) -> tuple[SimStackVariable, ...]:
    """Return unique stack declaration keys from dynamic angr maps."""
    declarations: dict[int, SimStackVariable] = {}
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        for variable in mapping:
            if isinstance(variable, SimStackVariable):
                declarations[id(variable)] = variable
    return tuple(declarations.values())


@dataclass(frozen=True, slots=True)
class _DeclarationSurface8616:
    """Snapshot the angr declaration maps and their ownership roots."""

    arguments: tuple[object, ...]
    statements: object
    variables_in_use: object
    unified_local_vars: object


def _declaration_surface_8616(codegen: object) -> _DeclarationSurface8616 | None:
    """Read the dynamic angr surface, refusing incomplete ownership roots."""
    typed_codegen = cast(_StackDeclarationCodegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return None
    if cfunc is None:
        return None
    try:
        if typed_codegen._inertia_return_selector_materialized_8616:
            return None
    except AttributeError:
        pass
    try:
        argument_list = tuple(cfunc.arg_list or ())
        statements = cfunc.statements
    except AttributeError:
        return None
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = None
    try:
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError:
        unified_local_vars = None
    return _DeclarationSurface8616(argument_list, statements, variables_in_use, unified_local_vars)


def _remove_declaration_variable_8616(variable: SimStackVariable, *mappings: object) -> bool:
    """Remove one classified declaration from every available map."""
    removed = False
    for mapping in mappings:
        if isinstance(mapping, dict) and variable in mapping:
            del mapping[variable]
            removed = True
    return removed


def prune_unreferenced_pre_argument_declarations_8616(codegen: object) -> bool:
    """Remove unowned BP control-slot declarations and retain uncertain views."""
    surface = _declaration_surface_8616(codegen)
    if surface is None:
        return False
    typed_codegen = cast(_StackDeclarationCodegen8616, codegen)
    variables_in_use = surface.variables_in_use
    unified_local_vars = surface.unified_local_vars

    body_identities = _stack_identities_in_tree_8616(surface.statements)
    header_identities = frozenset(
        identity
        for candidate in surface.arguments
        if (variable := _stack_variable_8616(candidate)) is not None
        if (identity := _stack_identity_8616(variable)) is not None
    )
    declarations = _declaration_variables_8616(
        variables_in_use,
        unified_local_vars,
    )
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0
    refusal_count = 0
    changed = False
    for variable in declarations:
        identity = _stack_identity_8616(variable)
        if identity is None:
            refusal_count += 1
            continue
        normalized_count += 1
        decision = _pre_argument_declaration_decision_8616(
            identity,
            bp_offset=machine_bp_offset_for_stack_variable_8616(codegen, variable),
            body_identities=body_identities,
            header_identities=header_identities,
        )
        if decision is PreArgumentStackDeclarationDecision8616.UNKNOWN_REFUSE:
            refusal_count += 1
            continue
        if decision is not PreArgumentStackDeclarationDecision8616.REMOVE_UNREFERENCED:
            continue
        classified_count += 1
        removed = _remove_declaration_variable_8616(variable, variables_in_use, unified_local_vars)
        if removed:
            materialized_count += 1
            changed = True
        else:
            failure_count += 1

    typed_codegen._inertia_pre_argument_declaration_stats_8616 = (
        PreArgumentStackDeclarationStats8616(
            raw_fact_count=len(declarations),
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
            refusal_count=refusal_count,
        )
    )
    if classified_count > 0 and materialized_count == 0:
        raise RuntimeError(
            "pre-argument stack declarations were classified but not materialized"
        )
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


__all__ = [
    "PreArgumentStackDeclarationDecision8616",
    "PreArgumentStackDeclarationStats8616",
    "body_declaration_owner_ids_8616",
    "declaration_members_are_argument_owned_8616",
    "prune_unreferenced_pre_argument_declarations_8616",
]
