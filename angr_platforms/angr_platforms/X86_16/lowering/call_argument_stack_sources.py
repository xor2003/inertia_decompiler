"""Select proven stack objects for call-argument source materialization.

Layer: Types/Lowering.
Responsibility: resolve call sources to typed BP-stack objects and distinguish
outgoing carriers by their machine-BP coordinates and complete PUSH widths.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

The selector consumes objects already materialized by lowering, including
objects created earlier in the same call pass.  It must not infer arguments
from rendered C, assembly text, symbol names, or compiler-specific shapes.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping
from enum import Enum
from typing import Final, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CExpression, CVariable
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsitePushSourceKind8616
from .stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from .stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
    stack_variable_coordinate_registry_8616,
)

_PUSH_WIDTHS: Final = frozenset({16, 32})
_OUTGOING_CARRIER_MAX_BP_OFFSET: Final = 2


class PushStoreWidthVerdict8616(Enum):
    """Whether a typed lvalue has a complete architectural PUSH width."""

    COMPLETE_WIDTH = "complete_width"
    PARTIAL_REFUSE = "partial_refuse"
    UNKNOWN_REFUSE = "unknown_refuse"


def classify_push_store_width_8616(lvalue: object) -> PushStoreWidthVerdict8616:
    """Refuse partial/unknown stores without changing their memory effects.

    Width is necessary, not sufficient: PUSH identity, alias storage and reaching
    definitions must independently establish ownership by a call argument.
    """
    if not isinstance(lvalue, CExpression):
        return PushStoreWidthVerdict8616.UNKNOWN_REFUSE
    try:
        store_type = lvalue.type
        if store_type is None:
            return PushStoreWidthVerdict8616.UNKNOWN_REFUSE
        width = store_type.size
    except (AttributeError, TypeError, ValueError):
        # Native codegen can expose missing or architecture-unbound types.
        return PushStoreWidthVerdict8616.UNKNOWN_REFUSE
    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        return PushStoreWidthVerdict8616.UNKNOWN_REFUSE
    if width in _PUSH_WIDTHS:
        return PushStoreWidthVerdict8616.COMPLETE_WIDTH
    return PushStoreWidthVerdict8616.PARTIAL_REFUSE


class _CallArgumentCFunction8616(Protocol):
    """Third-party C function surface needed for stack-object selection."""

    arg_list: list[object] | tuple[object, ...]
    statements: object
    variables_in_use: Mapping[object, object]


class _CallArgumentCodegen8616(Protocol):
    """Third-party structured-codegen surface needed by this lowering pass."""

    cfunc: _CallArgumentCFunction8616


def _stack_name_preference_8616(name: str | None) -> int:
    """Rank evidence-bearing names above anonymous temporary carriers."""
    if not name:
        return 0
    if name.startswith(("vvar_", "tmp_", "ir_", "s_", "stack_bp_", "stack_sp_")):
        return 1
    if name.startswith(("local_", "arg_")):
        return 3
    return 4


def iter_stack_cvariable_candidates_8616(
    codegen: object,
    synthetic_stack_cvars: Mapping[int, CVariable],
) -> Iterator[CVariable]:
    """Yield lowering-created and angr-owned stack variables once, in stable order."""
    boundary = cast(_CallArgumentCodegen8616, codegen)
    try:
        cfunc = boundary.cfunc
    except AttributeError:
        return

    yielded: set[int] = set()

    def _yield_candidate(value: object) -> Iterator[CVariable]:
        if not isinstance(value, CVariable) or not isinstance(value.variable, SimStackVariable):
            return
        marker = id(value)
        if marker in yielded:
            return
        yielded.add(marker)
        yield value

    for cvar in synthetic_stack_cvars.values():
        yield from _yield_candidate(cvar)

    for candidate in _native_stack_candidates_8616(cfunc):
        yield from _yield_candidate(candidate)


def _native_stack_candidates_8616(cfunc: _CallArgumentCFunction8616) -> Iterator[object]:
    """Read native declaration and body inventories without assuming completeness."""
    try:
        arguments = cfunc.arg_list
    except AttributeError:
        arguments = ()
    yield from arguments or ()

    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = {}
    if isinstance(variables_in_use, Mapping):
        yield from variables_in_use.values()

    try:
        root = cfunc.statements
    except AttributeError:
        root = None
    if root is not None:
        yield from _iter_c_nodes_deep_8616(root)


def containing_stack_cvariable_8616(
    codegen: object,
    synthetic_stack_cvars: Mapping[int, CVariable],
    *,
    offset: int,
    size_hint: int = 1,
) -> CVariable | None:
    """Select a proven object extent, not merely its angr backing allocation.

    ``size_hint`` bounds the containing object's size; it is not a read width
    starting at ``offset``. Callers may request addresses inside that object.
    """
    minimum_size = max(size_hint, 1)
    canonical = stack_cvar_for_machine_bp_range_8616(codegen, offset, minimum_size)
    if isinstance(canonical, CVariable) and isinstance(canonical.variable, SimStackVariable):
        return canonical
    owner = stack_variable_coordinate_registry_8616(codegen).containing_bp_range(offset, 1)
    if (
        owner is not None and owner.size >= minimum_size
        and isinstance(owner.cvar, CVariable) and isinstance(owner.cvar.variable, SimStackVariable)
    ):
        return owner.cvar
    best: CVariable | None = None
    best_score: tuple[int, int, int, int, int] | None = None
    for cvar in iter_stack_cvariable_candidates_8616(codegen, synthetic_stack_cvars):
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable):
            continue
        base_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        size = variable.size
        if variable.base != "bp" or not isinstance(base_offset, int) or not isinstance(size, int):
            continue
        if size < minimum_size or not (base_offset <= offset < base_offset + size):
            continue
        name_preference = _stack_name_preference_8616(variable.name or cvar.name)
        if name_preference <= 1:
            continue
        score = (
            int(base_offset == offset),
            int(size == minimum_size),
            -abs(base_offset - offset),
            -abs(size - minimum_size),
            name_preference,
        )
        if best_score is None or score > best_score:
            best = cvar
            best_score = score

    return best


def call_argument_source_requires_exact_address_identity_8616(source: object) -> bool:
    """Return whether one typed push source requires exact stack-address identity."""
    if not isinstance(source, tuple) or not source or not isinstance(source[0], str):
        return False
    try:
        kind = CallsitePushSourceKind8616(source[0])
    except ValueError:
        return False
    return kind in {
        CallsitePushSourceKind8616.BP_ADDRESS,
        CallsitePushSourceKind8616.BP_INDEX_ADDRESS,
    }


def materialize_call_argument_stack_cvariable_8616(
    codegen: object,
    synthetic_stack_cvars: MutableMapping[int, CVariable],
    *,
    machine_bp_offset: int,
    size_hint: int = 1,
    preferred_name: str | None = None,
) -> CVariable | None:
    """Resolve or materialize one call source through a proven stack coordinate.

    Callsite summaries use machine ``SS:BP`` displacements while angr stores
    ``SimStackVariable.offset`` in entry-SP coordinates. A missing projection
    therefore refuses materialization instead of treating equal integers from
    those two domains as the same storage slot.
    """
    minimum_size = max(size_hint, 1)
    existing = containing_stack_cvariable_8616(
        codegen,
        synthetic_stack_cvars,
        offset=machine_bp_offset,
        size_hint=minimum_size,
    )
    if existing is not None:
        synthetic_stack_cvars[machine_bp_offset] = existing
        return existing
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
        codegen,
        machine_bp_offset,
        minimum_size,
    )
    if entry_sp_offset is None:
        return None
    materialized = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        entry_sp_offset,
        minimum_size,
        machine_bp_offset=machine_bp_offset,
        preferred_name=preferred_name,
    )
    if not isinstance(materialized, CVariable) or not isinstance(
        materialized.variable, SimStackVariable
    ):
        return None
    synthetic_stack_cvars[machine_bp_offset] = materialized
    return materialized


def outgoing_call_stack_carrier_offset_8616(
    codegen: object,
    expression: object,
) -> int | None:
    """Return the machine-BP offset only for an outgoing call-stack carrier."""
    bp_offset = call_argument_stack_variable_offset_8616(codegen, expression)
    return bp_offset if isinstance(bp_offset, int) and 0 <= bp_offset <= _OUTGOING_CARRIER_MAX_BP_OFFSET else None


def call_argument_stack_variable_offset_8616(
    codegen: object,
    expression: object,
) -> int | None:
    """Return a direct call argument's proven machine-BP storage offset."""
    if not isinstance(expression, CVariable):
        return None
    variable = expression.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return None
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return bp_offset if isinstance(bp_offset, int) else None
