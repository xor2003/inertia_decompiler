"""Carry proven named C type definitions from Lowering to final rendering.

Layer: Types/Lowering.
Responsibility: persist complete named aggregate definitions already proven by
typed ABI or object-layout evidence. This module does not infer types from C
text, symbols, COD labels, or source names.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from inertia.lowering.codegen_metadata import get_codegen_sequence_attr, set_codegen_sequence_attr

__all__ = [
    "named_type_definitions_8616",
    "record_named_type_definitions_8616",
]


class _NamedTypeDefinitionOwner8616(Protocol):
    """Third-party codegen surface carrying Lowering-owned type definitions."""

    cfunc: object


def named_type_definitions_8616(codegen: object) -> tuple[str, ...]:
    """Return complete named aggregate definitions recorded by Lowering."""
    owner = cast(_NamedTypeDefinitionOwner8616, codegen)
    try:
        cfunc = owner.cfunc
    except AttributeError:
        return ()
    return tuple(
        str(definition)
        for definition in get_codegen_sequence_attr(
            codegen,
            cfunc,
            "_inertia_named_type_definitions_8616",
        )
    )


def record_named_type_definitions_8616(
    codegen: object,
    definitions: tuple[str, ...],
) -> bool:
    """Append complete named definitions and report whether metadata changed."""
    owner = cast(_NamedTypeDefinitionOwner8616, codegen)
    try:
        cfunc = owner.cfunc
    except AttributeError:
        return False
    normalized = tuple(
        "\n".join(line.rstrip() for line in definition.strip().splitlines())
        for definition in definitions
        if isinstance(definition, str) and definition.strip()
    )
    before = get_codegen_sequence_attr(
        codegen,
        cfunc,
        "_inertia_named_type_definitions_8616",
    )
    after = tuple(dict.fromkeys((*before, *normalized)))
    if after == before:
        return False
    set_codegen_sequence_attr(
        codegen,
        cfunc,
        "_inertia_named_type_definitions_8616",
        after,
    )
    return True
