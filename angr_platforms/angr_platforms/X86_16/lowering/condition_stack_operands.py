"""Layer: Types/Lowering.

Responsibility: lower typed ConditionIR stack operands onto proven stack storage.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Signedness evidence belongs to the condition operation, so conflicting signedness
is represented as a typed expression view instead of a second stack declaration.
This module must not infer storage from rendered C or create overlapping aliases
when an exact BP-relative object already exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

from .condition_stack_projection_contracts import (
    ConditionStackProjectionFact8616,
    condition_stack_projection_tags_8616,
)
from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
    stack_variable_coordinate_registry_8616,
)


class _ProjectLike(Protocol):
    """Project surface required to bind angr C types."""

    arch: object


class _CFunctionLike(Protocol):
    """C function storage surfaces used by typed operand lowering."""

    addr: int | None
    arg_list: object
    variables_in_use: object
    unified_local_vars: object


class _CodegenLike(Protocol):
    """Structured-codegen surface used by typed operand lowering."""

    project: _ProjectLike
    cfunc: _CFunctionLike | None


def _cfunc_for_codegen(codegen: object) -> _CFunctionLike | None:
    """Read the optional C function at the explicit third-party codegen boundary."""
    try:
        return cast(_CodegenLike, codegen).cfunc
    except AttributeError:
        return None


def _variables_in_use(cfunc: object) -> object:
    """Read the optional angr declaration map without inventing a fallback contract."""
    try:
        return cast(_CFunctionLike, cfunc).variables_in_use
    except AttributeError:
        return None


def _unified_local_vars(cfunc: object) -> object:
    """Read the optional angr unified-local map at the dynamic boundary."""
    try:
        return cast(_CFunctionLike, cfunc).unified_local_vars
    except AttributeError:
        return None


def _cfunc_addr(cfunc: object) -> int | None:
    """Read the optional function region used for newly materialized storage."""
    try:
        return cast(_CFunctionLike, cfunc).addr
    except AttributeError:
        return None


def _condition_integer_type(codegen: object, size: int, *, signed: bool) -> SimType:
    """Return an architecture-bound integer type for one condition operand."""
    if size == 1:
        type_ = SimTypeChar(signed)
    elif size == 4:
        type_ = SimTypeLong(signed)
    else:
        type_ = SimTypeShort(signed)
    return type_.with_arch(cast(_CodegenLike, codegen).project.arch)


def _matches_stack_storage(
    codegen: object,
    variable: object,
    *,
    base: str,
    offset: int,
    size: int,
) -> bool:
    """Match an exact machine stack identity across projected C coordinates."""
    if not isinstance(variable, SimStackVariable) or variable.base != base or variable.size != size:
        return False
    storage_offset = (
        machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if base == "bp"
        else variable.offset if isinstance(variable.offset, int) else None
    )
    return storage_offset == offset


def _existing_stack_cvar(
    codegen: object,
    cfunc: _CFunctionLike,
    *,
    base: str,
    offset: int,
    size: int,
) -> structured_c.CVariable | None:
    """Resolve an exact stack declaration by its canonical C variable value."""
    variables_in_use = _variables_in_use(cfunc)
    if isinstance(variables_in_use, dict):
        for cvar in variables_in_use.values():
            if isinstance(cvar, structured_c.CVariable) and _matches_stack_storage(
                codegen,
                cvar.variable,
                base=base,
                offset=offset,
                size=size,
            ):
                return cvar
    unified_local_vars = _unified_local_vars(cfunc)
    if isinstance(unified_local_vars, dict):
        for entries in unified_local_vars.values():
            if not isinstance(entries, (list, set, tuple)):
                continue
            for entry in entries:
                if not (isinstance(entry, tuple) and entry):
                    continue
                cvar = entry[0]
                if isinstance(cvar, structured_c.CVariable) and _matches_stack_storage(
                    codegen,
                    cvar.variable,
                    base=base,
                    offset=offset,
                    size=size,
                ):
                    return cvar
    return None


def _existing_wide_stack_cvar(
    codegen: object,
    cfunc: _CFunctionLike,
    *,
    base: str,
    offset: int,
    size: int,
) -> structured_c.CVariable | None:
    """Resolve a proven wide owner containing one word slice."""
    if size != 2:
        return None
    candidates: list[structured_c.CVariable] = []
    variables_in_use = _variables_in_use(cfunc)
    if isinstance(variables_in_use, dict):
        candidates.extend(
            cvar for cvar in variables_in_use.values() if isinstance(cvar, structured_c.CVariable)
        )
    try:
        arg_list = cfunc.arg_list
    except AttributeError:
        arg_list = None
    if isinstance(arg_list, (list, tuple)):
        candidates.extend(cvar for cvar in arg_list if isinstance(cvar, structured_c.CVariable))

    for cvar in candidates:
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable):
            continue
        if variable.base != base or variable.size != 4:
            continue
        variable_offset = (
            machine_bp_offset_for_stack_variable_8616(codegen, variable)
            if base == "bp"
            else variable.offset
        )
        if not isinstance(variable_offset, int) or offset not in {variable_offset, variable_offset + 2}:
            continue
        return cvar
    return None


def _wide_stack_word_projection(
    codegen: object,
    declaration: structured_c.CVariable,
    *,
    offset: int,
    signed: bool,
    prefer_word_view: bool = False,
) -> structured_c.CExpression | None:
    """Project a proven low/high word without declaring an overlapping object."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant

    variable = declaration.variable
    if not isinstance(variable, SimStackVariable) or variable.size != 4:
        return None
    owner_offset = (
        machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if variable.base == "bp"
        else variable.offset
    )
    if not isinstance(owner_offset, int):
        return None
    shift = offset - owner_offset
    if shift not in {0, 2}:
        return None
    projection_tags = condition_stack_projection_tags_8616(
        declaration.tags,
        ConditionStackProjectionFact8616(
            base=variable.base,
            owner_offset=owner_offset,
            owner_size=variable.size,
            view_offset=offset,
            view_size=2,
        ),
    )
    word_type = _condition_integer_type(codegen, 2, signed=signed)
    direct_word_view = prefer_word_view and shift == 0
    view = structured_c.CVariable(
        variable,
        unified_variable=declaration.unified_variable,
        # A high-word shift must still read the complete wide storage value.
        variable_type=word_type if direct_word_view else declaration.variable_type,
        codegen=codegen,
        tags=projection_tags,
    )
    projected: structured_c.CExpression = view
    if direct_word_view:
        return view
    if shift == 2:
        projected = CBinaryOp(
            "Shr",
            projected,
            CConstant(16, word_type, codegen=codegen),
            codegen=codegen,
            tags=projection_tags,
        )
    projected = CBinaryOp(
        "And",
        projected,
        CConstant(0xFFFF, word_type, codegen=codegen),
        codegen=codegen,
        tags=projection_tags,
    )
    if signed:
        return CSemanticCast8616(
            declaration.variable_type,
            word_type,
            projected,
            codegen=codegen,
            tags=projection_tags,
        )
    return projected


def project_contained_stack_integer_view_8616(
    codegen: object,
    declaration: structured_c.CVariable,
    *,
    owner_bp_offset: int,
    offset: int,
    size: int,
    signed: bool,
    tags: Mapping[str, object] | None,
) -> structured_c.CExpression | None:
    """Project one proven integer subrange without declaring new storage."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant

    variable = declaration.variable
    if not isinstance(variable, SimStackVariable) or not isinstance(variable.size, int):
        return None
    byte_delta = offset - owner_bp_offset
    if byte_delta < 0 or byte_delta + size > variable.size:
        return None
    owner_type = declaration.variable_type or _condition_integer_type(
        codegen,
        variable.size,
        signed=False,
    )
    target_type = _condition_integer_type(codegen, size, signed=signed)
    projection_tags = condition_stack_projection_tags_8616(
        tags or declaration.tags,
        ConditionStackProjectionFact8616(
            base=variable.base,
            owner_offset=owner_bp_offset,
            owner_size=variable.size,
            view_offset=offset,
            view_size=size,
        ),
    )
    view: structured_c.CExpression = structured_c.CVariable(
        variable,
        unified_variable=declaration.unified_variable,
        variable_type=owner_type,
        codegen=codegen,
        tags=dict(declaration.tags or {}),
    )
    if byte_delta:
        view = CBinaryOp(
            "Shr",
            view,
            CConstant(byte_delta * 8, owner_type, codegen=codegen),
            codegen=codegen,
            tags=projection_tags,
        )
    if size < variable.size:
        view = CBinaryOp(
            "And",
            view,
            CConstant((1 << (size * 8)) - 1, owner_type, codegen=codegen),
            codegen=codegen,
            tags=projection_tags,
        )
    if signed:
        return CSemanticCast8616(
            owner_type,
            target_type,
            view,
            codegen=codegen,
            tags=projection_tags,
        )
    return view


def _register_cvar_8616(
    cfunc: _CFunctionLike,
    variable: SimStackVariable,
    declaration: structured_c.CVariable,
) -> None:
    """Register one fresh stack declaration on both codegen variable maps."""
    variables_in_use = _variables_in_use(cfunc)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = declaration
    unified_local_vars = _unified_local_vars(cfunc)
    if isinstance(unified_local_vars, dict):
        unified_local_vars[variable] = {(declaration, declaration.variable_type)}


def _wider_storage_view_8616(
    codegen: object,
    cfunc: _CFunctionLike | None,
    *,
    base: str,
    offset: int,
    size: int,
    name: str,
    signed: bool,
    tags: Mapping[str, object] | None,
    prefer_signed_local_storage: bool,
    storage_size: int | None,
) -> structured_c.CExpression | None:
    """Project the narrower view from a proven wider stack storage owner."""
    if cfunc is None or not isinstance(storage_size, int) or storage_size <= size:
        return None
    storage_declaration = _existing_stack_cvar(
        codegen,
        cfunc,
        base=base,
        offset=offset,
        size=storage_size,
    )
    if storage_declaration is None:
        storage_variable = SimStackVariable(
            offset,
            storage_size,
            base=base,
            name=name,
            region=_cfunc_addr(cfunc),
        )
        storage_declaration = structured_c.CVariable(
            storage_variable,
            variable_type=_condition_integer_type(codegen, storage_size, signed=False),
            codegen=codegen,
            tags=dict(tags or {}),
        )
        _register_cvar_8616(cfunc, storage_variable, storage_declaration)
    return _wide_stack_word_projection(
        codegen,
        storage_declaration,
        offset=offset,
        signed=signed,
        prefer_word_view=(prefer_signed_local_storage and base == "bp" and offset > 0),
    )


def _bp_declaration_or_contained_view_8616(
    codegen: object,
    offset: int,
    size: int,
    signed: bool,
    tags: Mapping[str, object] | None,
) -> tuple[structured_c.CVariable | None, structured_c.CExpression | None]:
    """Return a BP declaration or a contained view inside a wider owner."""
    projected = stack_cvar_for_machine_bp_range_8616(codegen, offset, size)
    if isinstance(projected, structured_c.CVariable):
        return projected, None
    owner = stack_variable_coordinate_registry_8616(codegen).containing_bp_range(
        offset,
        size,
    )
    if (
        owner is not None
        and owner.size > size
        and isinstance(owner.cvar, structured_c.CVariable)
    ):
        contained_view = project_contained_stack_integer_view_8616(
            codegen,
            owner.cvar,
            owner_bp_offset=owner.bp_offset,
            offset=offset,
            size=size,
            signed=signed,
            tags=tags,
        )
        if contained_view is not None:
            return None, contained_view
    return None, None


def _existing_wide_projection_8616(
    codegen: object,
    cfunc: _CFunctionLike,
    *,
    base: str,
    offset: int,
    size: int,
    signed: bool,
    prefer_signed_local_storage: bool,
) -> structured_c.CExpression | None:
    """Project a word view from an existing wider stack declaration."""
    wide_declaration = _existing_wide_stack_cvar(
        codegen,
        cfunc,
        base=base,
        offset=offset,
        size=size,
    )
    if wide_declaration is None:
        return None
    return _wide_stack_word_projection(
        codegen,
        wide_declaration,
        offset=offset,
        signed=signed,
        prefer_word_view=(prefer_signed_local_storage and base == "bp" and offset > 0),
    )


def _register_stack_declaration_8616(
    codegen: object,
    cfunc: _CFunctionLike | None,
    *,
    base: str,
    offset: int,
    size: int,
    name: str,
    signed: bool,
    tags: Mapping[str, object] | None,
) -> structured_c.CVariable:
    """Create and register one fresh stack declaration for the view."""
    variable = SimStackVariable(
        offset,
        size,
        base=base,
        name=name,
        region=_cfunc_addr(cfunc) if cfunc is not None else None,
    )
    declaration = structured_c.CVariable(
        variable,
        variable_type=_condition_integer_type(codegen, size, signed=signed),
        codegen=codegen,
        tags=dict(tags or {}),
    )
    if cfunc is not None:
        _register_cvar_8616(cfunc, variable, declaration)
    return declaration


def _signed_stack_view_8616(
    codegen: object,
    declaration: structured_c.CVariable,
    size: int,
    signed: bool,
    tags: Mapping[str, object] | None,
) -> structured_c.CExpression:
    """Return the declaration view, semantically cast when signedness differs."""
    current_type = declaration.variable_type
    target_type = _condition_integer_type(codegen, size, signed=signed)
    view = structured_c.CVariable(
        declaration.variable,
        unified_variable=declaration.unified_variable,
        variable_type=current_type or target_type,
        codegen=codegen,
        tags=dict(tags or declaration.tags),
    )
    current_signed = current_type.signed if isinstance(current_type, (SimTypeChar, SimTypeShort, SimTypeLong)) else None
    if current_signed is None or bool(current_signed) == signed:
        return view
    return CSemanticCast8616(
        current_type,
        target_type,
        view,
        codegen=codegen,
        tags=dict(tags or declaration.tags),
    )


def materialize_typed_condition_stack_operand_8616(
    codegen: object,
    *,
    base: str,
    offset: int,
    size: int,
    name: str,
    signed: bool,
    tags: Mapping[str, object] | None = None,
    preferred: structured_c.CVariable | None = None,
    prefer_signed_local_storage: bool = False,
    storage_size: int | None = None,
) -> structured_c.CExpression | None:
    """Return a typed expression view over one exact BP-relative stack object.

    ``storage_size`` preserves a wider object proven by the IR while the
    condition consumes a narrower typed view.  The wider declaration is the
    storage owner; the returned expression is only a word projection.  This
    prevents condition width from silently narrowing a live stack object.
    """
    if size <= 0:
        return None
    cfunc = _cfunc_for_codegen(codegen)

    projected = _wider_storage_view_8616(
        codegen,
        cfunc,
        base=base,
        offset=offset,
        size=size,
        name=name,
        signed=signed,
        tags=tags,
        prefer_signed_local_storage=prefer_signed_local_storage,
        storage_size=storage_size,
    )
    if projected is not None:
        return projected

    declaration = preferred
    if declaration is not None and not _matches_stack_storage(
        codegen,
        declaration.variable,
        base=base,
        offset=offset,
        size=size,
    ):
        declaration = None
    if declaration is None and base == "bp":
        declaration, contained_view = _bp_declaration_or_contained_view_8616(
            codegen,
            offset,
            size,
            signed,
            tags,
        )
        if contained_view is not None:
            return contained_view
    if declaration is None and cfunc is not None:
        declaration = _existing_stack_cvar(codegen, cfunc, base=base, offset=offset, size=size)
    if declaration is None and cfunc is not None and size == 2:
        projected = _existing_wide_projection_8616(
            codegen,
            cfunc,
            base=base,
            offset=offset,
            size=size,
            signed=signed,
            prefer_signed_local_storage=prefer_signed_local_storage,
        )
        if projected is not None:
            return projected
    if declaration is None:
        declaration = _register_stack_declaration_8616(
            codegen,
            cfunc,
            base=base,
            offset=offset,
            size=size,
            name=name,
            signed=signed,
            tags=tags,
        )

    return _signed_stack_view_8616(codegen, declaration, size, signed, tags)


__all__ = [
    "materialize_typed_condition_stack_operand_8616",
    "project_contained_stack_integer_view_8616",
]
