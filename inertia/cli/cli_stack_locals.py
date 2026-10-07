"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable


class _ArchLike(Protocol):
    """Architecture surface needed to size stack references."""

    byte_width: int


class _ProjectLike(Protocol):
    """Project surface needed by stack-local materialization."""

    arch: _ArchLike


class _CFunctionLike(Protocol):
    """Structured C function surface needed by stack-local materialization."""

    addr: int
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _CodegenLike(Protocol):
    """Codegen surface needed by stack-local materialization."""

    cfunc: _CFunctionLike | None


def _stack_type_for_size(size: int) -> SimType:
    return SimTypeChar(False) if size == 1 else SimTypeShort(False)



def _same_stack_slot_8616(candidate: object, target_base: object, target_offset: object) -> bool:
    """Return whether a candidate variable aliases the target stack slot."""
    return (
        isinstance(candidate, SimStackVariable)
        # Dynamic codegen boundary: stack variable identity comes from angr SimVariable fields.
        and getattr(candidate, "base", None) == target_base
        # Dynamic codegen boundary: stack variable identity comes from angr SimVariable fields.
        and getattr(candidate, "offset", None) == target_offset
    )


def _promote_stack_view_8616(
    candidate_var: object,
    candidate_cvar: structured_c.CVariable,
    *,
    target_base: object,
    target_offset: object,
    size: int,
    type_: SimType,
) -> bool:
    """Widen one stack-slot view and retype its CVariable."""
    if not isinstance(candidate_var, SimStackVariable) or not _same_stack_slot_8616(
        candidate_var, target_base, target_offset,
    ):
        return False
    changed = False
    if candidate_var.size < size:
        candidate_var.size = size
        changed = True
    # Dynamic codegen boundary: angr CVariable type metadata is optional.
    if getattr(candidate_cvar, "variable_type", None) != type_:
        candidate_cvar.variable_type = type_
        changed = True
    return changed


def _grow_unified_size_8616(unified: object, size: int) -> bool:
    """Grow an optional unified-variable size."""
    # Dynamic codegen boundary: unified variable size is optional codegen metadata.
    if unified is None or getattr(unified, "size", 0) >= size:
        return False
    try:
        unified.size = size
        return True
    except Exception:
        return False


def _promote_tracked_views_8616(
    cfunc: _CFunctionLike,
    *,
    target_base: object,
    target_offset: object,
    size: int,
    type_: SimType,
) -> bool:
    """Promote matching tracked views in variables_in_use."""
    changed = False
    variables_in_use = cfunc.variables_in_use
    if isinstance(variables_in_use, dict):
        for tracked_var, tracked in list(variables_in_use.items()):
            if isinstance(tracked, structured_c.CVariable):
                changed |= _promote_stack_view_8616(
                    tracked_var, tracked,
                    target_base=target_base, target_offset=target_offset,
                    size=size, type_=type_,
                )
    return changed


def _retype_unified_entries_8616(
    cfunc: _CFunctionLike,
    *,
    target_base: object,
    target_offset: object,
    type_: SimType,
) -> bool:
    """Retype unified-local entries for the target stack slot."""
    unified_locals = cfunc.unified_local_vars
    if not isinstance(unified_locals, dict):
        return False
    for tracked_var, cvar_and_vartypes in list(unified_locals.items()):
        if not _same_stack_slot_8616(tracked_var, target_base, target_offset):
            continue
        changed = False
        new_entries = set()
        for tracked_cvar, _vartype in cvar_and_vartypes:
            # Dynamic codegen boundary: angr CVariable type metadata is optional.
            if getattr(tracked_cvar, "variable_type", None) != type_:
                tracked_cvar.variable_type = type_
                changed = True
            new_entries.add((tracked_cvar, type_))
        if new_entries != cvar_and_vartypes:
            unified_locals[tracked_var] = new_entries
            changed = True
        return changed
    return False


def _promote_direct_stack_cvariable(
    codegen: _CodegenLike, cvar: structured_c.CVariable, size: int, type_: SimType
) -> bool:
    # Dynamic codegen boundary: angr CVariable nodes expose optional SimVariable payloads.
    variable = getattr(cvar, "variable", None)
    if variable is None:
        return False
    # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
    target_base = getattr(variable, "base", None)
    # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
    target_offset = getattr(variable, "offset", None)

    changed = _promote_stack_view_8616(
        variable, cvar,
        target_base=target_base, target_offset=target_offset,
        size=size, type_=type_,
    )

    # Dynamic codegen boundary: unified variables are optional codegen metadata.
    unified = getattr(cvar, "unified_variable", None)
    changed |= _grow_unified_size_8616(unified, size)

    cfunc = codegen.cfunc
    if cfunc is None:
        return changed
    changed |= _promote_tracked_views_8616(
        cfunc, target_base=target_base, target_offset=target_offset, size=size, type_=type_,
    )
    changed |= _retype_unified_entries_8616(
        cfunc, target_base=target_base, target_offset=target_offset, type_=type_,
    )
    return changed


def _stack_object_name_8616(offset: int) -> str:
    """Return the conventional name for a stack object at one offset."""
    if offset >= 0:
        return f"arg_{offset:x}"
    return f"local_{-offset:x}"


def _stack_local_name_or_existing_8616(offset: int, *names: str | None) -> str:
    """Return the first stable existing name, else the conventional one."""
    for name in names:
        if isinstance(name, str) and name and not re.fullmatch(r"(?:v\d+|vvar_\d+)", name):
            return name
    return _stack_object_name_8616(offset)


@dataclass
class _SsStackAttachment8616:
    """Mutable run state for SS stack-reference attachment."""

    project: _ProjectLike
    codegen: _CodegenLike
    cfunc: _CFunctionLike
    match_ss_stack_reference: Callable[[object, _ProjectLike], tuple[SimStackVariable, structured_c.CVariable, int] | None]
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], structured_c.CVariable]
    created: dict[tuple[int, int], structured_c.CVariable] = field(default_factory=dict)
    promoted: set[tuple[int, int]] = field(default_factory=set)

    def transform(self, node: object) -> object:
        """Replace one matched SS stack reference with a promoted CVariable."""
        matched = self.match_ss_stack_reference(node, self.project)
        if matched is None:
            return node
        stack_var, ref_cvar, extra_offset = matched

        # Dynamic codegen boundary: angr C AST node type metadata is optional.
        type_ = getattr(node, "type", None)
        if type_ is None:
            return node

        # Dynamic codegen boundary: concrete angr SimType instances expose size.
        bits = getattr(type_, "size", None)
        size = max((bits // self.project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)
        final_offset = stack_var.offset + extra_offset
        promoted_offset = final_offset

        if size >= 4:
            resolved_cvar = self.resolve_stack_cvar_at_offset(self.codegen, final_offset)
            # Dynamic codegen boundary: resolved CVariable payloads are supplied by angr codegen.
            resolved_variable = getattr(resolved_cvar, "variable", None)
            if isinstance(resolved_variable, SimStackVariable):
                # Dynamic codegen boundary: SimStackVariable offset is supplied by angr.
                resolved_offset = getattr(resolved_variable, "offset", None)
                if resolved_offset == final_offset:
                    _promote_direct_stack_cvariable(self.codegen, resolved_cvar, size, type_)
                    key = (final_offset, size)
                    self.promoted.add(key)
                    existing = self.created.get(key)
                    if existing is not None:
                        return existing
                    self.created[key] = resolved_cvar
                    return resolved_cvar

        key = (promoted_offset, size)
        self.promoted.add(key)
        existing = self.created.get(key)
        if existing is not None:
            return existing
        if extra_offset == 0:
            local_name = _stack_local_name_or_existing_8616(
                promoted_offset,
                # Dynamic codegen boundary: names on CVariable/SimVariable payloads are optional.
                getattr(ref_cvar, "name", None),
                # Dynamic codegen boundary: names on CVariable/SimVariable payloads are optional.
                getattr(stack_var, "name", None),
            )
        else:
            local_name = _stack_object_name_8616(promoted_offset)

        cvar = structured_c.CVariable(
            SimStackVariable(
                promoted_offset,
                size,
                # Dynamic codegen boundary: SimStackVariable base is supplied by angr.
                base=getattr(stack_var, "base", "bp"),
                name=local_name,
                region=self.cfunc.addr,
            ),
            variable_type=type_,
            codegen=self.codegen,
        )
        self.created[key] = cvar
        return cvar


def _resize_promoted_vars_in_use_8616(
    cfunc: _CFunctionLike,
    promoted: set[tuple[int, int]],
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> bool:
    """Resize/retype tracked variables covering promoted stack slots."""
    changed = False
    variables_in_use = cfunc.variables_in_use
    for variable, cvar in variables_in_use.items() if isinstance(variables_in_use, dict) else ():
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
        offset = getattr(variable, "offset", None)
        matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
        if not matching:
            continue
        size = max(matching)
        target_type = _stack_type_for_size(size)
        # Dynamic codegen boundary: SimVariable size is supplied by angr.
        if getattr(variable, "size", 0) < size:
            variable.size = size
            changed = True
        # Dynamic codegen boundary: CVariable type metadata is optional.
        if getattr(cvar, "variable_type", None) != target_type:
            cvar.variable_type = target_type
            changed = True
        # Dynamic codegen boundary: unified variables are optional codegen metadata.
        unified = getattr(cvar, "unified_variable", None)
        changed |= _grow_unified_size_8616(unified, size)
    return changed


def _retype_promoted_unified_8616(
    cfunc: _CFunctionLike,
    promoted: set[tuple[int, int]],
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> bool:
    """Retype unified-local entries covering promoted stack slots."""
    changed = False
    unified_locals = cfunc.unified_local_vars
    if not isinstance(unified_locals, dict):
        return False
    for variable, cvar_and_vartypes in list(unified_locals.items()):
        identity = stack_slot_identity_for_variable(variable)
        if identity is None:
            continue
        # Dynamic codegen boundary: SimVariable subclasses differ in available stack fields.
        offset = getattr(variable, "offset", None)
        matching = [size for promoted_offset, size in promoted if promoted_offset == offset]
        if not matching:
            continue
        size = max(matching)
        target_type = _stack_type_for_size(size)
        new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
        if new_entries != cvar_and_vartypes:
            unified_locals[variable] = new_entries
            changed = True
    return changed


def _attach_ss_stack_variables(
    project: _ProjectLike,
    codegen: _CodegenLike,
    *,
    match_ss_stack_reference: Callable[[object, _ProjectLike], tuple[SimStackVariable, structured_c.CVariable, int] | None],
    resolve_stack_cvar_at_offset: Callable[[_CodegenLike, int], structured_c.CVariable],
    replace_c_children: Callable[[object, Callable[[object], object]], bool],
    stack_slot_identity_for_variable: Callable[[object], object | None],
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    attachment = _SsStackAttachment8616(
        project=project,
        codegen=codegen,
        cfunc=cfunc,
        match_ss_stack_reference=match_ss_stack_reference,
        resolve_stack_cvar_at_offset=resolve_stack_cvar_at_offset,
    )

    root = cfunc.statements
    new_root = attachment.transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if replace_c_children(root, attachment.transform):
        changed = True

    changed |= _resize_promoted_vars_in_use_8616(
        cfunc, attachment.promoted, stack_slot_identity_for_variable,
    )
    changed |= _retype_promoted_unified_8616(
        cfunc, attachment.promoted, stack_slot_identity_for_variable,
    )
    return changed
