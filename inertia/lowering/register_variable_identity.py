"""Project typed x86-16 register identities from structured C variables.

Layer: Types/Lowering.
Responsibility: normalize third-party Capstone and angr register-variable
identities without traversing or mutating the structured C AST.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable
from capstone.x86_const import (
    X86_REG_AX,
    X86_REG_BX,
    X86_REG_CX,
    X86_REG_DI,
    X86_REG_DX,
    X86_REG_SI,
)

__all__ = [
    "capstone_register_name_8616",
    "register_cvar_name_8616",
    "register_cvar_names_8616",
]

_CAPSTONE_REGISTER_NAMES_8616 = {
    X86_REG_AX: "ax",
    X86_REG_BX: "bx",
    X86_REG_CX: "cx",
    X86_REG_DX: "dx",
    X86_REG_SI: "si",
    X86_REG_DI: "di",
}
_REGISTER_OFFSET_NAMES_8616 = {
    0: "ax",
    2: "cx",
    4: "dx",
    6: "bx",
    12: "si",
    14: "di",
}


def capstone_register_name_8616(register_id: int) -> str | None:
    """Return the canonical word-register name for one Capstone identifier."""
    return _CAPSTONE_REGISTER_NAMES_8616.get(int(register_id))


def register_cvar_name_8616(value: object) -> str | None:
    """Return the canonical word-register name carried by one C variable."""
    while isinstance(value, structured_c.CTypeCast):
        value = value.expr
    if not isinstance(value, structured_c.CVariable):
        return None
    variable = value.variable
    if not isinstance(variable, SimRegisterVariable):
        return None
    for field_name in ("reg", "reg_offset", "offset"):
        # Dynamic boundary: angr changes SimRegisterVariable coordinates by release.
        coordinate = getattr(variable, field_name, None)
        if isinstance(coordinate, int) and coordinate in _REGISTER_OFFSET_NAMES_8616:
            return _REGISTER_OFFSET_NAMES_8616[coordinate]
    name = variable.name
    return name if isinstance(name, str) and name else None


def register_cvar_names_8616(variables: Iterable[object]) -> frozenset[str]:
    """Return every canonical register identity present in an AST inventory."""
    return frozenset(
        name
        for variable in variables
        if (name := register_cvar_name_8616(variable)) is not None
    )
