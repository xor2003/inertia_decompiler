"""Preserve contained stack byte ranges when publishing variable associations.

Layer: Alias.
Responsibility: retain the displacement of an exact stack virtual-variable
range within its recovered storage owner. Unknown or non-contained ranges keep
their existing association; this does not infer frame coordinates or types.
Owns storage identity at the native variable-association boundary.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from angr.ailment.expression import Atom, VirtualVariable
from angr.sim_variable import SimStackVariable, SimVariable


class StackReferenceInvariantError8616(ValueError):
    """Reject a contradictory published displacement for a proven stack range."""

    def __init__(self, atom: VirtualVariable, variable: SimStackVariable, offset: int | None) -> None:
        """Retain the ranges and displacement for structured error reporting."""
        self.requested_range = (atom.stack_offset, atom.size)
        self.owner_range = (variable.offset, variable.size)
        self.displacement = offset
        super().__init__(
            f"Stack association invariant failed: requested={self.requested_range}, "
            f"owner={self.owner_range}, displacement={offset}; byte address or width changed"
        )


def validate_stack_reference_displacement_8616(
    atom: Atom | None, variable: SimVariable, offset: int | None,
) -> None:
    """Reject contradictory exact associations; leave unproven ranges refused."""
    if atom is None or not isinstance(atom, VirtualVariable) or not isinstance(variable, SimStackVariable):
        return
    if not atom.was_stack or variable.base != "bp" or not isinstance(variable.size, int):
        return
    start = atom.stack_offset
    owner_start = variable.offset
    if not isinstance(start, int) or not isinstance(owner_start, int) or atom.size <= 0:
        return
    contained = owner_start <= start and start + atom.size <= owner_start + variable.size
    if contained and owner_start + (offset or 0) != start:
        raise StackReferenceInvariantError8616(atom, variable, offset)


def stack_reference_displacement_8616(
    atom: Atom | None,
    variable: SimVariable,
    offset: int | None,
) -> int | None:
    """Project an exact contained byte range in angr's shared stack coordinates."""
    if atom is None:
        return offset
    if not (
        isinstance(atom, VirtualVariable)
        and atom.was_stack
        and isinstance(variable, SimStackVariable)
        and variable.base == "bp"
        and isinstance(atom.stack_offset, int)
        and isinstance(variable.offset, int)
        and isinstance(variable.size, int)
    ):
        return offset
    displacement = atom.stack_offset - variable.offset
    if atom.size <= 0 or displacement < 0 or displacement + atom.size > variable.size:
        return offset
    return displacement or None
