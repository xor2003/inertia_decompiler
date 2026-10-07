"""Layer: Rewrite/Postprocess cleanup.

Responsibility: identify already-proven local storage for conservative liveness consumers.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
Unknown identity must make callers preserve code.
"""

from __future__ import annotations

from collections.abc import Hashable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable

type LocalLivenessKey8616 = tuple[str, Hashable]

__all__ = [
    "LocalLivenessKey8616",
    "local_liveness_key_8616",
    "stack_storage_liveness_key_8616",
]


def stack_storage_liveness_key_8616(
    node: structured_c.CVariable,
) -> LocalLivenessKey8616 | None:
    """Return physical BP-relative identity for a proven stack variable."""
    variable = node.variable
    if not isinstance(variable, SimStackVariable):
        return None
    if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
        return None
    return ("stack_storage", (variable.base, variable.offset, variable.size))


def local_liveness_key_8616(
    node: structured_c.CVariable,
) -> LocalLivenessKey8616 | None:
    """Return a stable local-storage key or refuse when angr metadata is incomplete."""
    variable = node.variable
    if isinstance(variable, SimStackVariable):
        if not isinstance(variable.offset, int) or not isinstance(variable.size, int):
            return None
        return (
            "stack_slot",
            (variable.region, variable.base, variable.offset, variable.size),
        )
    if not isinstance(variable, SimRegisterVariable):
        return None
    if not isinstance(variable.reg, int) or not isinstance(variable.size, int):
        return None
    if isinstance(variable.ident, str) and variable.ident:
        return (
            "register_ssa",
            (variable.region, variable.ident, variable.reg, variable.size),
        )
    if isinstance(variable.name, str) and variable.name:
        return (
            "register_name",
            (variable.region, variable.name, variable.reg, variable.size),
        )
    return (
        "register_storage",
        (variable.region, variable.reg, variable.size),
    )
