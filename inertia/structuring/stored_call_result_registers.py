"""Classify structured register carriers for stored call results.

Layer: Structuring.
Responsibility: prove that a structured assignment destination covers the
typed return register named by one callsite summary.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Physical angr register variables and the explicit runtime GP state emitted by
Types/Lowering are accepted through their authoritative typed projections.
Names, rendered C, and unowned memory variables are not evidence.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616

from inertia.lowering.gp_register_state import (
    runtime_gp_live_in_name_8616,
    runtime_gp_name_for_variable_8616,
)
from inertia.lowering.physical_registers import physical_register_view_8616


class _ArchSurface8616(Protocol):
    """Third-party architecture register lookup used at the AST boundary."""

    def get_register_offset(self, name: str) -> int:
        """Return the byte offset of one architectural register."""


class _ProjectSurface8616(Protocol):
    """Third-party project fields required by register matching."""

    arch: _ArchSurface8616


class _CodegenSurface8616(Protocol):
    """Third-party codegen fields required by register matching."""

    project: _ProjectSurface8616


def is_stored_call_return_register_destination_8616(
    codegen: object,
    expression: object,
    summary: CallsiteSummary8616,
    width: int,
) -> bool:
    """Prove that one structured lvalue covers the summary return register."""
    register_name = summary.return_register
    if not isinstance(register_name, str) or ":" in register_name:
        return False
    if isinstance(expression, CVariable):
        runtime_parent = runtime_gp_name_for_variable_8616(expression.variable)
        runtime_width = expression.variable.size
        if runtime_parent is not None:
            return (
                runtime_parent == runtime_gp_live_in_name_8616(register_name)
                and isinstance(runtime_width, int)
                and runtime_width >= width
            )
    view = physical_register_view_8616(expression)
    if view is None:
        return False
    boundary = cast(_CodegenSurface8616, codegen)
    try:
        register_offset = int(boundary.project.arch.get_register_offset(register_name))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    view_offset = int(view.reg_offset)
    view_width = int(view.width)
    return view_offset <= register_offset and view_offset + view_width >= register_offset + width


__all__ = ("is_stored_call_return_register_destination_8616",)
