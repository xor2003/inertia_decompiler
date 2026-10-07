"""Apply proven array extents to existing typed global declarations.

Layer: Types/Lowering.
Responsibility: replace only the array length of one already-materialized global
declaration while preserving its proven scalar, pointer, or aggregate element
type. This module does not infer names, types, storage identity, or bounds.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from .global_declarations import (
    GlobalDeclarationCodegen8616,
    initialize_global_declaration_specs_8616,
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)


class GlobalDeclarationExtentApplicationStatus8616(StrEnum):
    """Typed outcome of applying one exact array extent."""

    APPLIED = "applied"
    ALREADY_PRESENT = "already_present"
    DECLARATION_MISSING = "declaration_missing"
    DECLARATION_CONFLICT = "declaration_conflict"


@dataclass(frozen=True, slots=True)
class GlobalDeclarationExtentApplication8616:
    """One declaration name, extent, retained type, and application outcome."""

    status: GlobalDeclarationExtentApplicationStatus8616
    name: str
    array_len: int
    ctype: str | None

    @property
    def materialized(self) -> bool:
        """Return whether the exact extent is present after this application."""
        return self.status in {
            GlobalDeclarationExtentApplicationStatus8616.APPLIED,
            GlobalDeclarationExtentApplicationStatus8616.ALREADY_PRESENT,
        }


def apply_existing_global_array_extent_8616(
    codegen: object,
    *,
    name: str,
    array_len: int,
) -> GlobalDeclarationExtentApplication8616:
    """Strengthen one exact existing declaration without changing its C type."""
    if not name or array_len <= 0:
        raise ValueError("global array extent application requires a name and count")
    initialize_global_declaration_specs_8616(codegen)
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    matches = tuple(
        spec
        for spec in typed_codegen._inertia_global_declaration_specs_8616
        if spec[1] == name
    )
    if not matches:
        return GlobalDeclarationExtentApplication8616(
            GlobalDeclarationExtentApplicationStatus8616.DECLARATION_MISSING,
            name,
            array_len,
            None,
        )
    if len(matches) != 1 or not matches[0][0]:
        return GlobalDeclarationExtentApplication8616(
            GlobalDeclarationExtentApplicationStatus8616.DECLARATION_CONFLICT,
            name,
            array_len,
            None,
        )
    ctype, _old_name, old_array_len = matches[0]
    replace_global_declaration_spec_from_stronger_typed_evidence_8616(
        codegen,
        ctype=ctype,
        name=name,
        array_len=array_len,
    )
    status = (
        GlobalDeclarationExtentApplicationStatus8616.ALREADY_PRESENT
        if old_array_len == array_len
        else GlobalDeclarationExtentApplicationStatus8616.APPLIED
    )
    return GlobalDeclarationExtentApplication8616(status, name, array_len, ctype)


__all__ = [
    "GlobalDeclarationExtentApplication8616",
    "GlobalDeclarationExtentApplicationStatus8616",
    "apply_existing_global_array_extent_8616",
]
