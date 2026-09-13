"""Materialize stack variables from alias-proven stack facts.

Layer: Types/Lowering.
Responsibility: consumes alias, widening, and typed facts to bind stable SS/BP
stack accesses to real variables before final C emission.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
import logging
import os
import typing
from collections.abc import Iterable, Mapping
from typing import Any, Protocol, cast, overload

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from ..alias.alias_model_impl import AliasStorageFacts
from ..analysis.stack_frame_ir import FrameAccessArtifact, StackFrameSlot
from ..annotations import ANNOTATION_KEY, annotate_function
from ..pipeline.errors import PipelineHardError
from .stack_lowering_result import (
    StackLoweringResult,
    StackLoweringStatus,
    StackSlotFailure,
)
from .stack_variable_binding import (
    StackVariableBinding,
    build_stack_variable_bindings_8616,
)
from .stack_variable_coordinates import (
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from .stack_variable_display_names import (
    apply_stack_variable_projection_name_8616,
    generated_stack_variable_name_8616,
)

__all__ = [
    "attach_cod_stack_alias_annotations_8616",
    "build_stack_variable_bindings_from_alias_facts_8616",
    "canonical_stack_offset_8616",
    "lower_stack_accesses_from_alias_facts_8616",
]

log: logging.Logger = logging.getLogger(__name__)


class _StackSlotIdentityLike(Protocol):
    base: str
    offset: int
    width: int | None


def _dynamic_boundary_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Dynamic angr/codegen boundary: read optional project, C AST, or metadata attributes."""
    return getattr(obj, name, default)


def _stack_slot_identity_from_fact_8616(fact: AliasStorageFacts) -> _StackSlotIdentityLike | None:
    """Return the owned stack-slot identity carried by an alias fact."""
    identity = fact.identity
    if not isinstance(identity, tuple) or len(identity) < 2 or identity[0] != "stack":
        return None
    return cast(_StackSlotIdentityLike, identity[1])


def _typed_bp_frame_slots_8616(
    codegen: object,
    required_ranges: frozenset[tuple[int, int]] | None = None,
) -> tuple[StackFrameSlot, ...]:
    """Return typed SS:BP slots in the materializer's explicit evidence scope."""
    artifact = _dynamic_boundary_attr_8616(codegen, "_inertia_vex_ir_frame")
    if not isinstance(artifact, FrameAccessArtifact):
        return ()
    return tuple(
        slot
        for slot in artifact.slots
        if slot.base == "bp" and slot.role in {"local", "arg"} and slot.size > 0
        and (required_ranges is None or (slot.offset, slot.size) in required_ranges)
    )


def _binding_covers_frame_slot_8616(binding: StackVariableBinding, slot: StackFrameSlot) -> bool:
    """Return whether one alias-proven binding covers the typed frame-slot byte range."""
    binding_offset = _canonical_stack_offset_8616(binding.bp_offset)
    slot_offset = _canonical_stack_offset_8616(slot.offset)
    if not isinstance(binding_offset, int) or not isinstance(slot_offset, int):
        return False
    binding_size = max(binding.size, 1)
    slot_size = max(slot.size, 1)
    return binding_offset <= slot_offset and binding_offset + binding_size >= slot_offset + slot_size


def _unbound_typed_frame_slots_8616(
    bindings: Iterable[StackVariableBinding],
    slots: Iterable[StackFrameSlot],
) -> tuple[StackFrameSlot, ...]:
    """Return typed BP frame slots not covered by any alias-proven binding."""
    binding_tuple = tuple(bindings)
    return tuple(slot for slot in slots if not any(_binding_covers_frame_slot_8616(binding, slot) for binding in binding_tuple))


def attach_cod_stack_alias_annotations_8616(project: object, func_addr: int, cod_metadata: object) -> bool:
    """Attach COD BP stack aliases as lowering-owned stack-name evidence.

    COD aliases are optional naming evidence, not a source-body oracle.  This
    bridge records them as normalized stack slots before decompiler recovery so
    the stack/prototype lowering path can consume the same structured
    ``stack_vars`` map as other metadata sources.
    """
    stack_aliases = _dynamic_boundary_attr_8616(cod_metadata, "stack_aliases")
    if not isinstance(stack_aliases, dict) or not stack_aliases:
        return False
    kb = _dynamic_boundary_attr_8616(project, "kb")
    functions = _dynamic_boundary_attr_8616(kb, "functions")
    if functions is None:
        return False
    try:
        function_for_addr = _dynamic_boundary_attr_8616(functions, "function")
        if not callable(function_for_addr):
            return False
        func = function_for_addr(addr=func_addr, create=True)
    except Exception:
        return False
    if func is None:
        return False
    info = _dynamic_boundary_attr_8616(func, "info")
    if not isinstance(info, dict):
        info = {}
        typing.cast(typing.Any, func).info = info
    annotations = info.setdefault(
        ANNOTATION_KEY,
        {
            "stack_vars": {},
            "global_vars": {},
            "source_lines": (),
            "source_return_lines": (),
        },
    )
    if not isinstance(annotations, dict):
        return False
    stack_vars = annotations.setdefault("stack_vars", {})
    if not isinstance(stack_vars, dict):
        return False
    normalized_specs: dict[int, dict[str, object]] = {}
    for bp_disp, alias in sorted(stack_aliases.items()):
        if not isinstance(bp_disp, int) or not isinstance(alias, str) or not alias:
            continue
        stack_offset = bp_disp - 2 if bp_disp > 0 else bp_disp
        spec: dict[str, object] = {"name": alias}
        normalized_specs[stack_offset] = spec
    if not normalized_specs:
        return False
    changed = any(
        not isinstance(stack_vars.get(offset), dict) or stack_vars.get(offset, {}).get("name") != spec["name"]
        for offset, spec in normalized_specs.items()
    )
    annotate_function(
        project,
        func_addr,
        stack_vars=cast(dict[int, str | dict[str, object]], normalized_specs),
    )
    return changed


def canonical_stack_offset_8616(offset: object) -> object:
    """Normalize integer 16-bit stack offsets while preserving unknown values."""
    if not isinstance(offset, int):
        return offset
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


@overload
def _canonical_stack_offset_8616(offset: int) -> int: ...


@overload
def _canonical_stack_offset_8616(offset: object) -> object: ...


def _canonical_stack_offset_8616(offset: object) -> object:
    """Compatibility wrapper for internal typed stack-lowering callers."""
    return canonical_stack_offset_8616(offset)


def build_stack_variable_bindings_from_alias_facts_8616(
    alias_facts: list[object],
) -> list[StackVariableBinding]:
    """Build stack variable bindings from typed alias storage facts."""

    def _impl() -> list[StackVariableBinding]:
        """Build StackVariableBinding list from alias storage facts.

        Only stack-space facts with proven BP base are accepted.
        Naming: offset < 0 → local_N, offset > 0 → arg_N, offset == 0 → frame_base.

        Returns empty list if no stack facts exist.
        """
        address_sizes: dict[int, int] = {}
        preferred_names: dict[int, str] = {}

        for fact in alias_facts:
            if not isinstance(fact, AliasStorageFacts):
                continue
            slot = _stack_slot_identity_from_fact_8616(fact)
            if slot is None or slot.base != "bp":
                continue

            offset = _canonical_stack_offset_8616(slot.offset)
            width = slot.width

            if not isinstance(offset, int):
                continue

            size = width if isinstance(width, int) and width > 0 else 1
            current_size = address_sizes.get(offset)
            if current_size is None or size > current_size:
                address_sizes[offset] = size

            if offset < 0:
                name = f"local_{abs(offset):x}"
            elif offset > 0:
                name = f"arg_{abs(offset):x}"
            else:
                name = "frame_base"
            preferred_names[offset] = name

        if not address_sizes:
            return []

        return cast(
            list[Any],
            build_stack_variable_bindings_8616(
                sorted(address_sizes.items()),
                preferred_names=preferred_names,
            ),
        )

    return _impl()


def _stack_object_name(offset: int, codegen: object | None = None) -> str:
    offset = _canonical_stack_offset_8616(offset)
    if not isinstance(offset, int):
        return "arg_0"

    arg_offsets: set[int] = set()
    cfunc = _dynamic_boundary_attr_8616(codegen, "cfunc") if codegen is not None else None
    if cfunc is not None:
        arg_list = _dynamic_boundary_attr_8616(cfunc, "arg_list", ())
        if not isinstance(arg_list, Iterable):
            arg_list = ()
        for arg in arg_list:
            arg_var = _dynamic_boundary_attr_8616(arg, "variable")
            if isinstance(arg_var, SimStackVariable):
                arg_offset = _canonical_stack_offset_8616(_dynamic_boundary_attr_8616(arg_var, "offset"))
                if isinstance(arg_offset, int):
                    arg_offsets.add(arg_offset)

    if offset in arg_offsets:
        return f"arg_{offset:x}"

    if offset >= 0:
        return f"local_{offset:x}"
    return f"local_{-offset:x}"


def _stack_type_for_size(size: int, *, codegen: object | None = None) -> SimType:
    """Return one exact-width unsigned scalar type or refuse unsupported widths."""
    scalar_types: dict[int, SimType] = {
        1: SimTypeChar(signed=False),
        2: SimTypeShort(signed=False),
        4: SimTypeLong(signed=False),
    }
    try:
        t = scalar_types[size]
    except KeyError as exc:
        raise ValueError(f"unsupported scalar stack width {size}") from exc
    if codegen is not None:
        project = _dynamic_boundary_attr_8616(codegen, "project")
        cfunc = _dynamic_boundary_attr_8616(codegen, "cfunc")
        arch = _dynamic_boundary_attr_8616(project, "arch") or _dynamic_boundary_attr_8616(cfunc, "arch")
        if isinstance(arch, Arch):
            t = t.with_arch(arch)
    return t


def _promote_direct_stack_cvariable(
    codegen: object,
    cvar: object,
    size: int,
    target_type: SimType,
    *,
    preserve_existing_type: bool = False,
) -> None:
    """Update the type and size on an existing stack CVariable."""
    if cvar is not None:
        current_type = _dynamic_boundary_attr_8616(cvar, "variable_type")
        if not preserve_existing_type and not isinstance(current_type, SimTypePointer):  # noqa: SIM102
            if isinstance(cvar, structured_c.CVariable):
                cvar.variable_type = target_type
        variables = (
            _dynamic_boundary_attr_8616(cvar, "variable"),
            _dynamic_boundary_attr_8616(cvar, "unified_variable"),
        )
        for variable in variables:
            if isinstance(variable, SimStackVariable) and (
                not isinstance(variable.size, int) or variable.size < size
            ):
                variable.size = size


def _apply_stack_binding_name_8616(cvar: object, preferred_name: str | None) -> str | None:
    if not isinstance(preferred_name, str) or not preferred_name:
        return None
    variable = _dynamic_boundary_attr_8616(cvar, "variable")
    current_names = (
        _dynamic_boundary_attr_8616(variable, "name"),
        _dynamic_boundary_attr_8616(cvar, "name"),
        _dynamic_boundary_attr_8616(_dynamic_boundary_attr_8616(cvar, "unified_variable"), "name"),
    )
    if any(isinstance(name, str) and name and not generated_stack_variable_name_8616(name) for name in current_names):
        return None
    changed_name = None
    if isinstance(variable, SimStackVariable) and _dynamic_boundary_attr_8616(variable, "name") != preferred_name:
        variable.name = preferred_name
        changed_name = preferred_name
    if _dynamic_boundary_attr_8616(cvar, "name") != preferred_name:
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, cvar).name = preferred_name
            changed_name = preferred_name
    unified = _dynamic_boundary_attr_8616(cvar, "unified_variable")
    if unified is not None and _dynamic_boundary_attr_8616(unified, "name") != preferred_name:
        typing.cast(typing.Any, unified).name = preferred_name
        changed_name = preferred_name
    return changed_name


def _arg_cvar_at_stack_offset_8616(codegen: object, offset: int) -> object | None:
    """Return an existing argument at one canonical entry-SP offset."""
    cfunc = _dynamic_boundary_attr_8616(codegen, "cfunc")
    if cfunc is None:
        return None
    arg_list = _dynamic_boundary_attr_8616(cfunc, "arg_list", ())
    if not isinstance(arg_list, Iterable):
        arg_list = ()
    registry = stack_variable_coordinate_registry_8616(codegen)
    for arg in tuple(arg_list):
        if not isinstance(arg, structured_c.CVariable) or not isinstance(arg.variable, SimStackVariable):
            continue
        projection = registry.for_variable(arg.variable)
        # Native argument objects can retain BP-relative offsets after their
        # exact entry-SP projection is published. Never reinterpret that view.
        entry_offset = projection.entry_sp_offset if projection is not None else arg.variable.offset
        if _canonical_stack_offset_8616(entry_offset) == offset:
            return cast(object, arg)
    return None


def _register_stack_cvar_surface_8616(codegen: object, cvar: object, target_type: object) -> None:
    """Register a stack CVariable in codegen metadata without replacing stronger args."""
    variable = _dynamic_boundary_attr_8616(cvar, "variable")
    if not isinstance(variable, SimStackVariable):
        return
    cfunc = _dynamic_boundary_attr_8616(codegen, "cfunc")
    variables_in_use = _dynamic_boundary_attr_8616(cfunc, "variables_in_use")
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified_locals = _dynamic_boundary_attr_8616(cfunc, "unified_local_vars")
    if isinstance(unified_locals, dict):
        unified_locals[variable] = {(cvar, _dynamic_boundary_attr_8616(cvar, "variable_type") or target_type)}


def materialize_stack_cvar_at_offset_from_facts_8616(
    codegen: object,
    offset: int,
    size: int = 2,
    *,
    machine_bp_offset: int | None = None,
    preferred_name: str | None = None,
    publish_machine_bp: bool = True,
) -> object | None:
    """Register a stack CVariable from an exact entry-SP projection.

    ``offset`` is angr's entry-SP coordinate. ``machine_bp_offset`` records the
    originating SS:BP displacement when Alias and frame evidence supplied one;
    legacy callers default to an identity projection. A native entry-SP access
    without BP-frame proof must disable publication of that machine relation.
    """

    def _impl() -> object | None:
        nonlocal offset
        cfunc = _dynamic_boundary_attr_8616(codegen, "cfunc")
        if cfunc is None:
            return None
        offset = _canonical_stack_offset_8616(offset)
        if not isinstance(offset, int):
            return None
        bp_offset = _canonical_stack_offset_8616(machine_bp_offset)
        if machine_bp_offset is None:
            bp_offset = offset
        if not isinstance(bp_offset, int):
            return None
        binding_name = preferred_name
        if bp_offset < 0 and generated_stack_variable_name_8616(binding_name):
            binding_name = _stack_object_name(bp_offset, codegen=codegen)

        def _record(cvar: object) -> object:
            if isinstance(binding_name, str) and binding_name:
                apply_stack_variable_projection_name_8616(
                    codegen,
                    cvar=cvar,
                    entry_sp_offset=offset,
                    size=size,
                    name=binding_name,
                )
            variable = _dynamic_boundary_attr_8616(cvar, "variable")
            if isinstance(variable, SimStackVariable) and publish_machine_bp:
                record_stack_variable_coordinate_projection_8616(
                    codegen,
                    variable=variable,
                    cvar=cvar,
                    bp_offset=bp_offset,
                    entry_sp_offset=offset,
                    size=size,
                    display_name=binding_name,
                )
            return cvar

        target_type = _stack_type_for_size(size, codegen=codegen)
        if offset >= 2:
            arg_cvar = _arg_cvar_at_stack_offset_8616(codegen, offset)
            if isinstance(arg_cvar, structured_c.CVariable):
                _promote_direct_stack_cvariable(
                    codegen,
                    arg_cvar,
                    size,
                    target_type,
                    preserve_existing_type=True,
                )
                _apply_stack_binding_name_8616(arg_cvar, binding_name)
                _register_stack_cvar_surface_8616(codegen, arg_cvar, target_type)
                return _record(cast(object, arg_cvar))

        # Reconcile every regenerated view at this exact storage start. angr may
        # rebuild byte variables after an earlier Alias-proven word projection.
        variables_in_use = _dynamic_boundary_attr_8616(cfunc, "variables_in_use")
        if isinstance(variables_in_use, dict):
            matches = [
                (var, cvar)
                for var, cvar in variables_in_use.items()
                if isinstance(var, SimStackVariable)
                and _canonical_stack_offset_8616(var.offset) == offset
                and (not isinstance(var.size, int) or var.size <= size)
            ]
            if matches:
                canonical_var, canonical_cvar = min(
                    matches,
                    key=lambda item: (
                        item[0].size != size,
                        not isinstance(item[0].size, int) or item[0].size < size,
                        str(item[0].name or ""),
                    ),
                )
                for _variable, candidate_cvar in matches:
                    _promote_direct_stack_cvariable(codegen, candidate_cvar, size, target_type)
                    _apply_stack_binding_name_8616(candidate_cvar, binding_name)
                    _register_stack_cvar_surface_8616(codegen, candidate_cvar, target_type)
                if isinstance(canonical_var, SimStackVariable):
                    recorded = _record(cast(object, canonical_cvar))
                    for variable, _candidate_cvar in matches:
                        if variable is canonical_var or not publish_machine_bp:
                            continue
                        record_stack_variable_coordinate_alias_8616(
                            codegen,
                            bp_offset=bp_offset,
                            size=size,
                            variable=variable,
                        )
                    return recorded

        variable = SimStackVariable(
            offset,
            size,
            base="bp",
            name=binding_name or _stack_object_name(offset),
            region=_dynamic_boundary_attr_8616(cfunc, "addr"),
        )
        cvar = structured_c.CVariable(variable, variable_type=target_type, codegen=codegen)
        _apply_stack_binding_name_8616(cvar, binding_name)

        if isinstance(variables_in_use, dict):
            variables_in_use[variable] = cvar

        unified_locals = _dynamic_boundary_attr_8616(cfunc, "unified_local_vars")
        if isinstance(unified_locals, dict):
            unified_locals[variable] = {(cvar, target_type)}

        stack_local_candidates = _dynamic_boundary_attr_8616(codegen, "_inertia_stack_local_declaration_candidates")
        if isinstance(stack_local_candidates, dict):
            stack_local_candidates[id(variable)] = (variable, cvar)

        sort_local_vars = _dynamic_boundary_attr_8616(cfunc, "sort_local_vars")
        if callable(sort_local_vars):
            with contextlib.suppress(Exception):
                sort_local_vars()

        return _record(cast(object, cvar))

    return _impl()


def lower_stack_accesses_from_alias_facts_8616(
    codegen: object,
    alias_facts: list[object],
    *,
    required_bp_ranges: frozenset[tuple[int, int]] | None = None,
    entry_sp_offsets_by_bp_range: Mapping[tuple[int, int], int] | None = None,
) -> StackLoweringResult:
    """Lower alias-proven BP facts into proven angr entry-SP CVariable surfaces."""

    def _impl() -> StackLoweringResult:
        """Primary stack lowering: consume alias facts, not linear expression patterns.

        Rules:
        - Only consume alias facts
        - No regex on generated C
        - No linear expression guessing
        - If facts exist but variables cannot be materialized, report failure

        Materialization means registering real SimStackVariable + CVariable objects
        in codegen.cfunc.variables_in_use. Creating StackVariableBinding metadata is
        NOT materialization.
        """
        bindings = build_stack_variable_bindings_from_alias_facts_8616(alias_facts)
        typed_frame_slots = _typed_bp_frame_slots_8616(codegen, required_bp_ranges)
        unbound_typed_frame_slots = _unbound_typed_frame_slots_8616(bindings, typed_frame_slots)
        stable_stack_fact_count = len(
            [
                fact
                for fact in alias_facts
                if isinstance(fact, AliasStorageFacts)
                and isinstance(fact.identity, tuple)
                and len(fact.identity) >= 2
                and fact.identity[0] == "stack"
            ]
        )
        stable_bp_fact_count = len(
            [
                fact
                for fact in alias_facts
                if isinstance(fact, AliasStorageFacts)
                and (slot := _stack_slot_identity_from_fact_8616(fact)) is not None
                and slot.base == "bp"
            ]
        )
        debug_stats = {
            "stable_stack_fact_count": stable_stack_fact_count,
            "stable_bp_fact_count": stable_bp_fact_count,
            "stack_binding_count": len(bindings),
            "stack_slot_candidates": len(bindings),
            "stack_slot_bindings": len(bindings),
            "stack_slot_materialized": 0,
            "stack_slot_failed": 0,
            "typed_frame_raw_fact_count": len(typed_frame_slots),
            "typed_frame_normalized_fact_count": len(typed_frame_slots),
            "typed_frame_classified_fact_count": len(typed_frame_slots),
            "typed_frame_bound_count": len(typed_frame_slots) - len(unbound_typed_frame_slots),
            "typed_frame_failure_count": len(unbound_typed_frame_slots),
        }
        typing.cast(typing.Any, codegen)._inertia_stack_lowering_debug = debug_stats
        typing.cast(typing.Any, codegen)._inertia_stack_variable_bindings = tuple(bindings)
        if unbound_typed_frame_slots:
            raise PipelineHardError(
                "typed BP frame slots not covered by alias-proven stack bindings",
                layer="stack_lowering",
                details={"unbound_slots": [slot.to_dict() for slot in unbound_typed_frame_slots]},
            )
        if os.environ.get("INERTIA_DEBUG_STACK_FACTS"):
            log.warning(
                "[stack-lowering] bindings=%d stable_stack=%d stable_bp=%d",
                len(bindings),
                stable_stack_fact_count,
                stable_bp_fact_count,
            )
            for binding in bindings[:16]:
                log.warning("[stack-lowering] binding=%r", binding)

        if not bindings:
            return StackLoweringResult(
                status=StackLoweringStatus.OK,
                failures=[],
                materialized=[],
                diagnostics=[
                    "stack_lowering_source=alias_facts bindings=0 materialized=0",
                    f"stable_stack_fact_count={stable_stack_fact_count}",
                    f"stable_bp_fact_count={stable_bp_fact_count}",
                ],
            )

        typing.cast(typing.Any, codegen)._inertia_stack_bindings = bindings
        typing.cast(typing.Any, codegen)._inertia_stack_lowering_source = "alias_facts"
        typing.cast(typing.Any, codegen)._inertia_semantic_stack_binding_count = len(bindings)

        materialized_count = 0
        failures_list: list[StackSlotFailure] = []
        materialized: list[tuple[int, str]] = []

        for binding in bindings:
            offset = _canonical_stack_offset_8616(binding.bp_offset)
            size = binding.size if binding.size > 0 else 2
            try:
                if not isinstance(offset, int):
                    raise TypeError(f"invalid stack binding offset {binding.bp_offset!r}")
                materialization_offset: int | None
                if entry_sp_offsets_by_bp_range is None:
                    existing_projection = stack_variable_coordinate_registry_8616(
                        codegen
                    ).for_bp_range(offset, size)
                    materialization_offset = (
                        existing_projection.entry_sp_offset
                        if existing_projection is not None
                        else offset
                    )
                else:
                    materialization_offset = entry_sp_offsets_by_bp_range.get(
                        (offset, size)
                    )
                if not isinstance(materialization_offset, int):
                    raise TypeError(
                        f"missing entry-SP projection for BP range {(offset, size)!r}"
                    )

                cvar = materialize_stack_cvar_at_offset_from_facts_8616(
                    codegen,
                    materialization_offset,
                    size,
                    machine_bp_offset=offset,
                    preferred_name=binding.var_name,
                )
                materialized_name = _dynamic_boundary_attr_8616(
                    _dynamic_boundary_attr_8616(cvar, "variable"), "name"
                ) or _dynamic_boundary_attr_8616(
                    cvar, "name"
                )
                materialized_count += 1
                materialized.append(
                    (int(offset), str(materialized_name or _stack_object_name(int(offset), codegen=codegen)))
                )
            except Exception as exc:
                fallback_offset = _canonical_stack_offset_8616(binding.bp_offset)
                if not isinstance(fallback_offset, int):
                    fallback_offset = 0
                failures_list.append(
                    StackSlotFailure(
                        offset=fallback_offset,
                        size=size,
                        reason=str(exc),
                    )
                )
                log.debug(
                    "stage=stack_lowering_from_facts function=%#x offset=%r failed: %s",
                    _dynamic_boundary_attr_8616(_dynamic_boundary_attr_8616(codegen, "cfunc"), "addr", -1) or -1,
                    fallback_offset,
                    exc,
                )

        typing.cast(typing.Any, codegen)._inertia_semantic_stack_materialized_count = materialized_count
        debug_stats["stack_slot_materialized"] = materialized_count
        debug_stats["stack_slot_failed"] = len(failures_list)

        # ── Update STACK lane contract counters ──
        # AGENTS rule: bindings are NOT materialization.
        # bound = number of StackVariableBindings created
        # materialized = number of SimStackVariables registered in variables_in_use
        lane = _dynamic_boundary_attr_8616(codegen, "_inertia_stack_lane")
        if lane is not None:
            typing.cast(typing.Any, lane).bound = len(bindings)
            typing.cast(typing.Any, lane).materialized = materialized_count

        # ── HARD CONTRACT: bindings > 0 && materialized == 0 → PipelineHardError ──
        if len(bindings) > 0 and materialized_count == 0:
            raise PipelineHardError(
                "stable stack slots not materialized",
                layer="stack_lowering",
            )

        ok = len(failures_list) == 0

        return StackLoweringResult(
            status=StackLoweringStatus.OK if ok else StackLoweringStatus.PARTIAL,
            failures=failures_list,
            materialized=materialized,
            diagnostics=[
                f"stack_lowering_source=alias_facts bindings={len(bindings)} materialized={materialized_count}",
                f"stable_stack_fact_count={stable_stack_fact_count}",
                f"stable_bp_fact_count={stable_bp_fact_count}",
            ],
        )

    return _impl()
