"""Install exact stack-subrange association at angr's publication boundary.

Layer: Frontend/Alias adapter.
Responsibility: dispatch x86-16 access offsets to their Alias-owned projection
before angr records instruction, statement and atom indexes. Other targets
delegate unchanged. No C rewriting or frame-coordinate guessing is allowed.
"""

from __future__ import annotations

from angr.ailment.expression import Atom
from angr.code_location import CodeLocation
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
from angr.sim_variable import SimVariable

from .alias.stack_reference_offsets import (
    StackReferenceInvariantError8616,
    stack_reference_displacement_8616,
    validate_stack_reference_displacement_8616,
)


def _checked_offset_8616(
    manager: VariableManagerInternal, location: CodeLocation,
    variable: SimVariable, offset: int | None, atom: Atom | None,
) -> int | None:
    """Validate before publication and report the responsible function/access."""
    kb = manager.manager._kb
    if kb is None or kb._project is None or kb._project.arch.name != "86_16":
        return offset
    projected = stack_reference_displacement_8616(atom, variable, offset)
    try:
        validate_stack_reference_displacement_8616(atom, variable, projected)
    except StackReferenceInvariantError8616 as exc:
        exc.add_note(f"function={manager.func_addr!r}, access={location!r}")
        raise
    return projected


def apply_stack_reference_compatibility_8616() -> None:
    """Install the architecture-scoped variable registration adapter once."""
    original = VariableManagerInternal.record_variable
    if original.__name__ == "_record_stack_reference_8616":
        return

    def _record_stack_reference_8616(
        self: VariableManagerInternal,
        location: CodeLocation,
        variable: SimVariable,
        offset: int | None,
        overwrite: bool = False,
        atom: Atom | None = None,
    ) -> None:
        """Publish the exact displacement consistently in all native indexes."""
        offset = _checked_offset_8616(self, location, variable, offset, atom)
        original(self, location, variable, offset, overwrite=overwrite, atom=atom)

    VariableManagerInternal.record_variable = _record_stack_reference_8616
    original_access = VariableManagerInternal._record_variable_access

    def _record_stack_access_8616(
        self: VariableManagerInternal,
        sort: int,
        variable: SimVariable,
        offset: int | None,
        location: CodeLocation,
        overwrite: bool = False,
        atom: Atom | None = None,
    ) -> None:
        """Keep durable read/write/reference records coherent with their indexes."""
        offset = _checked_offset_8616(self, location, variable, offset, atom)
        original_access(self, sort, variable, offset, location, overwrite=overwrite, atom=atom)

    VariableManagerInternal._record_variable_access = _record_stack_access_8616
