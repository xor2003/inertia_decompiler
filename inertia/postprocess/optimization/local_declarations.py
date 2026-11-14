# cython: language_level=3, infer_types=True
"""Layer: Rewrite/Postprocess cleanup.

Responsibility: canonicalize declarations and retire DCE-proven unused declarations.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Consumes already-proven stack identity and type surfaces. This module may remove only
declaration duplicates with identical BP-relative storage, name, size, and type.
It may also retire declaration-only entries whose authoritative DCE keys have
no remaining body or argument references. Names alone never prove dead storage.
Unreferenced fixed scalar declarators may be retired after a complete body and
parameter inventory; opaque code, unknown types and uncertain aliases are kept.
It must not merge expressions, infer alias/type facts, or repair rendered C text.
"""

from __future__ import annotations
import typing
import cython

import os
import sys
from collections.abc import Callable
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBool, SimTypeChar, SimTypeFloat, SimTypeInt, SimTypeNum
from angr.sim_variable import SimRegisterVariable, SimStackVariable
import operator

_DeclarationKey8616 = tuple[str, int | str]
_UNIFIED_ENTRY_ARITY_8616: cython.longlong = 2


@cython.ccall
def _declaration_entry_keys_8616(
    entry: object, key_of: Callable[[structured_c.CVariable], _DeclarationKey8616],
) -> object:
    """Read exact keys from an angr variable or unified declaration entry."""
    candidate: object
    if isinstance(entry, structured_c.CVariable):
        return frozenset({key_of(entry)})
    if not isinstance(entry, (set, list, tuple)) or not entry:
        return None
    keys: set[_DeclarationKey8616] = set()
    for candidate in entry:
        if not isinstance(candidate, tuple) or operator.ne(len(candidate), _UNIFIED_ENTRY_ARITY_8616):
            return None
        cvar = candidate[0]
        if not isinstance(cvar, structured_c.CVariable):
            return None
        keys.add(key_of(cvar))
    return frozenset(keys)


@cython.ccall
def _declaration_maps_8616(codegen: object) -> tuple[object, object]:
    """Read optional third-party declaration maps without inventing surfaces."""
    cfunc: object
    try:
        cfunc = cast(_CodegenLike, codegen).cfunc
    except AttributeError:
        return None, None
    if cfunc is None:
        return None, None
    try:
        variables = cfunc.variables_in_use
    except AttributeError:
        variables = None
    try:
        unified = cfunc.unified_local_vars
    except AttributeError:
        unified = None
    return variables, unified


@cython.ccall
def prune_dce_proven_declarations_8616(
    codegen: object,
    *,
    dead_keys: object,
    key_of: Callable[[structured_c.CVariable], _DeclarationKey8616],
) -> cython.bint:
    """Consume DCE deletion keys after all surviving references are excluded."""
    entry: object
    mapping: object
    variable: object
    if not dead_keys:
        return False
    changed = False
    for mapping in _declaration_maps_8616(codegen):
        if not isinstance(mapping, dict):
            continue
        for variable, entry in tuple(mapping.items()):
            keys = _declaration_entry_keys_8616(entry, key_of)
            if keys and keys <= dead_keys:
                del mapping[variable]
                changed = True
    return changed

class _CFunctionLike(Protocol):
    """Third-party C function fields that own emitted local declarations."""

    variables_in_use: object
    unified_local_vars: object
    statements: object
    arg_list: object


class _CodegenLike(Protocol):
    """Third-party structured-codegen surface used by declaration cleanup."""

    cfunc: _CFunctionLike | None


@cython.ccall
def _scalar_declaration_nodes_8616(entry: object) -> object:
    """Accept only complete, fixed scalar declarators without initializer code."""
    item: object
    node: object
    if isinstance(entry, structured_c.CVariable):
        nodes = (entry,)
    elif isinstance(entry, (set, list, tuple)) and entry:
        collected: list[structured_c.CVariable] = []
        for item in entry:
            if not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], structured_c.CVariable):
                return None
            if operator.ne(item[1], item[0].variable_type):
                return None
            collected.append(item[0])
        nodes = tuple(collected)
    else:
        return None
    for node in nodes:
        value_type = node.variable_type
        if not isinstance(value_type, (SimTypeBool, SimTypeChar, SimTypeFloat, SimTypeInt, SimTypeNum)):
            return None
        try:
            size = value_type.size
        except (ValueError, TypeError):
            return None
        if not isinstance(size, int) or size <= 0:
            return None
    return nodes


def _declaration_references_8616(
    cfunc: _CFunctionLike,
) -> object:
    """Collect complete body/parameter references, keeping opaque code unknown."""
    identity: object
    node: object
    root: object
    from inertia.postprocess.decompiler_postprocess_utils import _iter_c_nodes_deep_8616
    from inertia.semantics.alias_query import describe_alias_storage

    try:
        arguments = cfunc.arg_list
        body = cfunc.statements
    except AttributeError:
        return None
    if not isinstance(arguments, (list, tuple)) or not isinstance(body, structured_c.CConstruct):
        return None
    if any(not isinstance(argument, structured_c.CConstruct) for argument in iter(arguments)):
        return None
    variables: set[cython.longlong] = set()
    storage: set[tuple[object, ...]] = set()
    any_reference = False
    unknown_storage = False
    for root in (body, ) + tuple(arguments):
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, (structured_c.CDirtyExpression, structured_c.CDirtyStatement)):
                return None
            if isinstance(node, structured_c.CVariable):
                any_reference = True
                variables.add(id(node.variable))
                variables.add(id(node.unified_variable))
                identity = describe_alias_storage(node).identity
                if identity is None:
                    unknown_storage = True
                else:
                    storage.add(identity)
    return variables, storage, any_reference, unknown_storage


def prune_unreferenced_scalar_declarations_8616(codegen: _CodegenLike) -> cython.bint:
    """Retire pure scalar declaration metadata after complete use exclusion.

    Parameters, body references and alias-equivalent storage remain declared.
    Arrays, pointer declarators, unknown types and opaque code remain unchanged.
    This changes no statements and derives no machine storage identity.
    """
    cfunc: object
    nodes: object
    references: object
    entry: object
    mapping: object
    variable: object
    from inertia.semantics.alias_query import describe_alias_storage

    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    references = _declaration_references_8616(cfunc)
    if references is None:
        return False
    variables, storage, any_reference, unknown_storage = references
    changed = False
    for mapping in _declaration_maps_8616(codegen):
        if not isinstance(mapping, dict):
            continue
        for variable, entry in tuple(mapping.items()):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable)) or id(variable) in variables:
                continue
            nodes = _scalar_declaration_nodes_8616(entry)
            if nodes is None or unknown_storage:
                continue
            identities = tuple(describe_alias_storage(node).identity for node in iter(nodes))
            if any(identity in storage or (identity is None and any_reference) for identity in iter(identities)):
                continue
            del mapping[variable]
            changed = True
    return changed


@cython.ccall
def _stack_declaration_identity(
    variable: object,
    cvar: object,
) -> object:
    """Return exact physical and emitted-name identity for one stack declaration."""
    if not isinstance(variable, SimStackVariable):
        return None
    if not isinstance(cvar, structured_c.CVariable):
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
        return None
    return (variable.base, variable.offset, variable.size, cvar.name)


@cython.ccall
def _unified_stack_declaration_identity(variable: object) -> object:
    """Return exact physical identity for one named unified stack declaration."""
    if not isinstance(variable, SimStackVariable):
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
        return None
    if not isinstance(variable.name, str) or not variable.name:
        return None
    return (variable.base, variable.offset, variable.size, variable.name)


@cython.ccall
def _unified_declaration_types(entries: object) -> object:
    """Return the complete declared type set or refuse malformed angr entries."""
    entry: object
    if not isinstance(entries, (list, set, tuple)):
        return None
    types: list[object] = []
    for entry in entries:
        if not isinstance(entry, tuple) or operator.ne(len(entry), _UNIFIED_ENTRY_ARITY_8616):
            return None
        types.append(entry[1])
    try:
        return frozenset(types)
    except TypeError:
        return None


@cython.ccall
def _dedupe_variables_in_use_8616(cfunc: _CFunctionLike, debug: cython.bint) -> cython.bint:
    """Drop duplicate variables_in_use entries sharing identity and C type."""
    canonical: object
    identity: object
    cvar: object
    variable: object
    variables_in_use = cfunc.variables_in_use
    if not isinstance(variables_in_use, dict):
        return False
    changed = False
    canonical_by_identity: dict[tuple[object, ...], structured_c.CVariable] = {}
    for variable, cvar in tuple(variables_in_use.items()):
        identity = _stack_declaration_identity(variable, cvar)
        if identity is None:
            continue
        if debug:
            print(
                "[local-declaration] "
                f"surface=variables_in_use identity={identity!r} type={cvar.variable_type!r} "
                f"variable={variable!r} unified={cvar.unified_variable!r}",
                file=sys.stderr,
                flush=True,
            )
        canonical = canonical_by_identity.get(identity)
        if canonical is None:
            canonical_by_identity[identity] = cvar
            continue
        if operator.ne(cvar.variable_type, canonical.variable_type):
            continue
        del variables_in_use[variable]
        changed = True
    return changed


@cython.ccall
def _dedupe_unified_local_vars_8616(cfunc: _CFunctionLike, debug: cython.bint) -> cython.bint:
    """Drop duplicate unified_local_vars entries sharing identity and types."""
    canonical_types: object
    declared_types: object
    identity: object
    entries: object
    variable: object
    unified_local_vars = cfunc.unified_local_vars
    if not isinstance(unified_local_vars, dict):
        return False
    changed = False
    canonical_unified: dict[tuple[object, ...], frozenset[object]] = {}
    for variable, entries in tuple(unified_local_vars.items()):
        identity = _unified_stack_declaration_identity(variable)
        declared_types = _unified_declaration_types(entries)
        if identity is None or declared_types is None:
            continue
        if debug:
            print(
                "[local-declaration] "
                f"surface=unified_local_vars identity={identity!r} types={declared_types!r} "
                f"variable={variable!r}",
                file=sys.stderr,
                flush=True,
            )
        canonical_types = canonical_unified.get(identity)
        if canonical_types is None:
            canonical_unified[identity] = declared_types
            continue
        if operator.ne(declared_types, canonical_types):
            continue
        del unified_local_vars[variable]
        changed = True
    return changed


@cython.ccall
def dedupe_equivalent_stack_local_declarations_8616(codegen: _CodegenLike) -> cython.bint:
    """Remove only exact duplicate stack declarations with equivalent C types."""
    cfunc: object
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    debug = os.environ.get("INERTIA_DEBUG_LOCAL_DECLARATIONS") == "1"
    changed = _dedupe_variables_in_use_8616(cfunc, debug)
    return _dedupe_unified_local_vars_8616(cfunc, debug) or changed


__all__ = ["dedupe_equivalent_stack_local_declarations_8616", "prune_dce_proven_declarations_8616", "prune_unreferenced_scalar_declarations_8616"]
