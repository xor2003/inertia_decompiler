"""Expose exact physical-register views from angr structured expressions.

Layer: Types/Lowering.
Responsibility: normalize third-party angr register carriers into one typed
physical register offset and width for lowering consumers.
Consumes alias, widening, and typed facts; it does not infer register identity
from variable names or rendered output.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import CDirtyExpression, CVariable
from angr.sim_variable import SimRegisterVariable

from ..ir.regs import REG16_OFFSET_MAP, REG32_OFFSET_MAP


@dataclass(frozen=True, slots=True)
class PhysicalRegisterView8616:
    """One exact byte range in the x86-16 architectural register file."""

    reg_offset: int
    width: int


def physical_register_offset_8616(value: object) -> int | None:
    """Return an explicit physical-register offset without requiring width."""
    if isinstance(value, CVariable) and isinstance(value.variable, SimRegisterVariable):
        variable = value.variable
        return variable.reg if isinstance(variable.reg, int) else None

    dirty = value.dirty if isinstance(value, CDirtyExpression) else value
    if isinstance(dirty, VirtualVariable):
        if dirty.category is VirtualVariableCategory.REGISTER and isinstance(dirty.oident, int):
            return dirty.oident
        return None

    for field_name in ("reg", "reg_offset", "parameter_reg_offset"):
        try:
            # Dynamic boundary: legacy angr dirty payloads vary across versions.
            field_value = getattr(dirty, field_name, None)
        except TypeError:
            continue
        if isinstance(field_value, int):
            return field_value
    return None


def physical_register_view_8616(value: object) -> PhysicalRegisterView8616 | None:
    """Return an exact register offset and width from an angr C or AIL carrier."""
    reg_offset = physical_register_offset_8616(value)
    if reg_offset is None:
        return None
    if isinstance(value, CVariable) and isinstance(value.variable, SimRegisterVariable):
        width = value.variable.size
        return PhysicalRegisterView8616(reg_offset, width) if isinstance(width, int) and width > 0 else None

    dirty = value.dirty if isinstance(value, CDirtyExpression) else value
    if isinstance(dirty, VirtualVariable):
        bits = dirty.bits
    else:
        # Dynamic boundary: legacy angr dirty payloads expose width by shape.
        bits = getattr(dirty, "bits", None)
    if not isinstance(bits, int) or bits <= 0 or bits % 8:
        return None
    return PhysicalRegisterView8616(reg_offset, bits // 8)


def physical_register_name_8616(value: object) -> str | None:
    """Return the width-correct storage name for an exact physical register view."""
    view = physical_register_view_8616(value)
    if view is None:
        return None
    names = REG32_OFFSET_MAP if view.width == 4 else REG16_OFFSET_MAP
    name = names.get(view.reg_offset)
    return name if isinstance(name, str) else None


__all__ = [
    "PhysicalRegisterView8616",
    "physical_register_name_8616",
    "physical_register_offset_8616",
    "physical_register_view_8616",
]
