"""Layer: Recovery metadata.

Responsibility: carry side metadata on codegen objects without changing semantics.
Forbidden: using metadata writes as proof, recovery, or validation acceptance.
Dynamic attribute boundary: getattr/setattr use here is limited to third-party
angr/codegen compatibility objects and optional diagnostic metadata.
"""

from __future__ import annotations

import contextlib
import typing
from enum import Enum

if typing.TYPE_CHECKING:
    from angr.sim_variable import SimStackVariable

__all__ = [
    "GlobalDeclarationArrayExtent8616",
    "GlobalDeclarationArrayLength8616",
    "append_codegen_sequence_attr",
    "get_codegen_sequence_attr",
    "get_codegen_side_metadata",
    "set_codegen_sequence_attr",
    "snapshot_stack_local_candidates_8616",
]


def snapshot_stack_local_candidates_8616(codegen: object) -> dict[int, tuple[SimStackVariable, object]]:
    """Retain native stack declarations by object identity, excluding arguments.

    This copies existing declaration metadata only; it supplies no Alias proof
    and does not classify storage or authorize removal of any stack effect.
    """
    from angr.analyses.decompiler.structured_codegen.c import CFunction
    from angr.sim_variable import SimStackVariable

    # Native code generators expose different roots; require the C contract.
    function = getattr(codegen, "cfunc", None)
    if not isinstance(function, CFunction):
        raise TypeError("Stack declaration snapshot requires a native CFunction")
    argument_ids = {id(argument.variable) for argument in function.arg_list}
    return {
        id(variable): (variable, declaration)
        for variable, declaration in function.variables_in_use.items()
        if isinstance(variable, SimStackVariable) and id(variable) not in argument_ids
    }


class GlobalDeclarationArrayExtent8616(Enum):
    """Typed non-numeric array extent carried from Lowering to rendering."""

    UNKNOWN = "unknown"


type GlobalDeclarationArrayLength8616 = (
    int | GlobalDeclarationArrayExtent8616 | None
)


def get_codegen_side_metadata(codegen: object) -> dict[str, object]:
    """Return the mutable recovery metadata side map attached to a codegen object.

    Dynamic attribute boundary: codegen is a third-party angr/codegen
    compatibility object that intentionally carries optional diagnostic metadata.
    """
    metadata = getattr(codegen, "_inertia_recovery_metadata", None)
    if isinstance(metadata, dict):
        return metadata
    metadata = {}
    typing.cast(typing.Any, codegen)._inertia_recovery_metadata = metadata
    return metadata


def get_codegen_sequence_attr(codegen: object, cfunc: object, name: str) -> tuple[str, ...]:
    """Read a string sequence side attribute from codegen, falling back to cfunc.

    Dynamic attribute boundary: these are third-party angr/codegen
    compatibility objects that intentionally carry optional diagnostic metadata.
    """
    value = getattr(codegen, name, None)
    if isinstance(value, (tuple, list)):
        return tuple(str(item) for item in value)
    value = getattr(cfunc, name, None)
    if isinstance(value, (tuple, list)):
        return tuple(str(item) for item in value)
    return ()


def append_codegen_sequence_attr(codegen: object, cfunc: object, name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    """Append unique string values to a codegen/cfunc side metadata sequence.

    Dynamic attribute boundary: these are third-party angr/codegen
    compatibility objects that intentionally carry optional diagnostic metadata.
    """
    merged: list[str] = list(get_codegen_sequence_attr(codegen, cfunc, name))
    for value in values:
        if value not in merged:
            merged.append(value)
    return set_codegen_sequence_attr(codegen, cfunc, name, tuple(merged))


def set_codegen_sequence_attr(codegen: object, cfunc: object, name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    """Replace a string sequence on both transient codegen metadata owners.

    angr may replace the codegen wrapper while retaining the structured C
    function. Mirroring lowering artifacts onto both boundaries keeps them
    available without making CLI rendering rediscover semantics.
    """
    merged_tuple = tuple(dict.fromkeys(values))
    setattr(codegen, name, merged_tuple)
    with contextlib.suppress(Exception):
        setattr(cfunc, name, merged_tuple)
    return merged_tuple
