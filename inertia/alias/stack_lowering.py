"""Legacy import bridge for stack-lowering helpers.

Layer: Alias.
Responsibility: owns storage identity only; this module exists to preserve old import paths
while forwarding to the canonical lowering implementation.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from inertia.lowering.stack_lowering import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
    run_stack_lowering_pass_8616,
)

__all__ = (
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_materialize_stack_cvar_at_offset",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "run_stack_lowering_pass_8616",
)
