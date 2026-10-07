"""Maintain aggregate object types across angr C-AST replay surfaces.

Layer: Types/Lowering.
Responsibility: join replayed named types and exact stack-variable identities,
then keep expression and local-declaration type surfaces synchronized.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimStruct, SimType, TypeRef
from angr.sim_variable import SimStackVariable


class _CFunctionTypeSurface8616(Protocol):
    """Third-party CFunction fields that own emitted local declarations."""

    body: object
    statements: object
    variables_in_use: dict[object, CVariable]
    unified_local_vars: dict[object, set[tuple[CVariable, object]]]


def resolved_type_8616(type_: object) -> object:
    """Resolve one optional angr named type reference."""
    return type_.type if isinstance(type_, TypeRef) else type_


def is_named_struct_type_8616(type_: object, expected: SimStruct) -> bool:
    """Match one replayed angr struct by its owned registered type identity."""
    resolved = resolved_type_8616(type_)
    return isinstance(resolved, SimStruct) and resolved.name == expected.name


def same_stack_variable_8616(left: object, right: object) -> bool:
    """Return whether two values denote the same exact BP stack slot."""
    return (
        isinstance(left, SimStackVariable)
        and isinstance(right, SimStackVariable)
        and left.base == right.base
        and left.offset == right.offset
    )


def cfunc_roots_8616(cfunc_raw: object) -> tuple[object, ...]:
    """Return unique roots from the dynamic angr CFunction boundary."""
    cfunc = cast(_CFunctionTypeSurface8616, cfunc_raw)
    try:
        body = cfunc.body
    except AttributeError:
        body = None
    try:
        statements = cfunc.statements
    except AttributeError:
        statements = None
    roots: list[object] = []
    for root in (body, statements):
        if root is not None and all(root is not existing for existing in roots):
            roots.append(root)
    return tuple(roots)


def materialize_local_struct_declarations_8616(
    cfunc_raw: object,
    locals_: Sequence[SimStackVariable],
    registered_type: TypeRef,
    struct_type: SimStruct,
) -> bool:
    """Apply one proven local object type to all emitted declaration surfaces."""
    cfunc = cast(_CFunctionTypeSurface8616, cfunc_raw)
    changed = False
    for cvar in tuple(cfunc.variables_in_use.values()):
        if any(same_stack_variable_8616(cvar.variable, local) for local in locals_):  # noqa: SIM102
            if not is_named_struct_type_8616(cvar.variable_type, struct_type):
                cvar.variable_type = registered_type
                changed = True
    for variable, candidates in tuple(cfunc.unified_local_vars.items()):
        if not any(same_stack_variable_8616(variable, local) for local in locals_):
            continue
        updated: set[tuple[CVariable, object]] = set()
        for cvar, _variable_type in candidates:
            if not is_named_struct_type_8616(cvar.variable_type, struct_type):
                cvar.variable_type = registered_type
                changed = True
            updated.add((cvar, cast(SimType, registered_type)))
        if updated != candidates:
            cfunc.unified_local_vars[variable] = updated
            changed = True
    return changed


__all__ = [
    "cfunc_roots_8616",
    "is_named_struct_type_8616",
    "materialize_local_struct_declarations_8616",
    "same_stack_variable_8616",
]
