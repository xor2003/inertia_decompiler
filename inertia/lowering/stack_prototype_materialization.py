# cython: language_level=3, infer_types=True
"""Layer: Types/Lowering.

Responsibility: materialize stack-prototype facts before rewrite.
Consumes alias, widening, and typed facts from structured stack-slot annotations
already attached to function metadata, then turns positive BP slots into codegen
argument variables and a typed function prototype.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import cython

import contextlib
import itertools
import os
import re
import sys
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, TypeGuard, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable, SimVariable

from inertia.frontend.x86_16.calling_convention_compat import collect_wide_stack_argument_width_evidence_8616
from inertia.lowering.annotations import ANNOTATION_KEY, stack_layout_annotation_specs_8616
from inertia.widening.stack_argument_widths import WideStackArgumentWidthEvidence8616
from inertia.widening.widening_rules import collect_bp_stack_access_widths_from_instructions_8616

from .authoritative_function_prototypes import authoritative_function_prototype_8616
from .callee_argument_width_evidence import (
    CalleeArgumentWidthEvidence8616,
    CalleeArgumentWidthVerdict8616,
    collect_callee_argument_width_evidence_8616,
)
from .interprocedural_storage_transaction import (
    accepted_stack_input_layout_8616,
    function_storage_resolution_8616,
)
from .stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from .stack_lowering_from_facts import canonical_stack_offset_8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    publish_selected_stack_cvar_projection_8616,
    refresh_stack_variable_coordinate_cvar_8616,
)
from .wide_stack_argument_views import (
    WideStackArgumentOwner8616,
    materialize_wide_stack_argument_subviews_8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "FunctionParameterWidthFact8616",
    "align_pointer_flags_to_stack_argument_widths_8616",
    "materialize_annotated_stack_prototype_8616",
    "materialize_exact_trailing_stack_argument_8616",
    "reconcile_callsite_interface_declarations_8616",
    "reconcile_exact_stack_argument_prototype_8616",
]


@cython.ccall
def align_pointer_flags_to_stack_argument_widths_8616(
    source_pointer_flags: object,
    argument_offsets: object,
    argument_widths: Mapping[cython.longlong, cython.longlong],
) -> object:
    """Align physical stack-word classes with logical typed arguments."""
    offset: object
    if operator.eq(len(source_pointer_flags), len(argument_offsets)):
        return source_pointer_flags
    if len(source_pointer_flags) < len(argument_offsets):
        return ()
    aligned: list[cython.bint] = []
    source_index = 0
    for offset in argument_offsets:
        width = max(2, argument_widths.get(offset, 2))
        word_count = max(1, (width + 1) // 2)
        next_source_index = source_index + word_count
        if next_source_index > len(source_pointer_flags):
            return ()
        aligned.append(any(source_pointer_flags[source_index:next_source_index]))
        source_index = next_source_index
    return tuple(aligned) if operator.eq(source_index, len(source_pointer_flags)) else ()


class _PrototypeFunction8616(Protocol):
    """Function metadata written at the dynamic third-party angr boundary."""

    info: object
    prototype: object
    prototype_source: PrototypeSource
    is_prototype_guessed: cython.bint


@cython.ccall
def _prototype_source_8616(function: _PrototypeFunction8616) -> PrototypeSource:
    """Read provenance across legacy third-party Function test adapters."""
    try:
        return function.prototype_source
    except AttributeError:
        return (
            PrototypeSource.GUESSED
            if function.is_prototype_guessed
            else PrototypeSource.USER
        )


@cython.ccall
def _raise_prototype_source_8616(
    function: _PrototypeFunction8616,
    source: PrototypeSource,
) -> cython.bint:
    """Raise explicit provenance without invoking angr's legacy bool setter."""
    try:
        current = function.prototype_source
        legacy_adapter = False
    except AttributeError:
        current = _prototype_source_8616(function)
        legacy_adapter = True
    if current >= source:
        return False
    function.prototype_source = source
    if legacy_adapter:
        function.is_prototype_guessed = source < PrototypeSource.CCA_DECOMPILER
    return True


class _StackPrototypeCodegen8616(Protocol):
    """Codegen metadata written at the dynamic third-party angr boundary."""

    cfunc: object
    next_ident: Callable[[str], str]
    next_node_idx: Callable[[], cython.longlong]
    _inertia_annotated_stack_prototype_materialized_8616: cython.longlong
    _inertia_authoritative_zero_arg_prototype_8616: cython.bint
    _inertia_callsite_summaries: object
    _inertia_callee_argument_width_evidence_8616: CalleeArgumentWidthEvidence8616
    _inertia_codegen_decl_refresh_required_8616: cython.bint
    _inertia_function_parameter_width_facts_8616: object
    _inertia_stack_prototype_width_stats_8616: StackPrototypeWidthStats8616
    _inertia_wide_stack_argument_width_evidence_8616: WideStackArgumentWidthEvidence8616


class _StackPrototypeCFunction8616(Protocol):
    """C-function fields consumed after the dynamic codegen entry boundary."""

    addr: cython.longlong
    arg_list: object
    functy: object
    unified_local_vars: object
    variables_in_use: object


class _ProjectArch8616(Protocol):
    """Project fields exposed after the dynamic third-party entry boundary."""

    arch: object
    kb: _KnowledgeBase8616


class _ArchBytes8616(Protocol):
    """Target architecture field that defines the C ABI word size."""

    bytes: cython.longlong


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base surface required by stack prototype lowering."""

    functions: _FunctionManager8616


class _FunctionManager8616(Protocol):
    """angr function-manager surface required by stack prototype lowering."""

    def function(self, *, addr: cython.longlong, create: cython.bint) -> object:
        """Return an existing function by address."""
        ...


class _SizedType8616(Protocol):
    """Third-party type surface used to query an architecture-sized width."""

    size: cython.longlong


class _ArchBindableType8616(Protocol):
    """Third-party type surface used to bind an architecture."""

    def with_arch(self, arch: object) -> object:
        """Return this type bound to ``arch``."""
        ...


class _CallsiteSummary8616(Protocol):
    """Typed callsite fields consumed from the semantics layer."""

    arg_widths: object
    push_arg_sources: object


@dataclasses.dataclass(frozen=True)
class StackPrototypeWidthStats8616:
    """Evidence accounting for exact stack-slot argument-width constraints."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, order=True, )
class FunctionParameterWidthFact8616:
    """Exact binary/IR-backed width of one positive BP function parameter."""

    stack_offset: cython.longlong
    width_bytes: cython.longlong


@cython.ccall
def _debug_parameter_width_facts_8616(
    phase: object,
    facts: object,
) -> None:
    """Log parameter-width fact lifecycle when prototype diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") != "1":
        return
    print(
        f"[dbg-x87-proto] parameter_width_facts phase={phase} facts={facts!r}",
        file=sys.stderr,
        flush=True,
    )


@cython.ccall
def _function_for_codegen_8616(project: object, codegen: object) -> object | None:
    """Return metadata through the dynamic third-party angr project/codegen boundary."""
    cfunc: object
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return None
    func_addr = cast(_StackPrototypeCFunction8616, cfunc).addr
    if not isinstance(func_addr, int):
        return None
    with contextlib.suppress(Exception):
        return cast(_ProjectArch8616, project).kb.functions.function(addr=func_addr, create=False)
    return None


def positive_stack_specs_8616(func: object) -> tuple[tuple[cython.longlong, str | None], ...]:
    """Return positive stack annotations in canonical machine-BP coordinates."""
    spec: object
    spec_name: object
    raw_offset: object
    info = cast(_PrototypeFunction8616, func).info
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
    if not isinstance(annotations, Mapping):
        return ()
    stack_specs = stack_layout_annotation_specs_8616(annotations)
    positive_offsets = sorted(offset for offset in iter(stack_specs) if isinstance(offset, int) and offset > 0)
    if not positive_offsets:
        return ()
    normalized = positive_offsets[0] == 2
    entries: list[tuple[cython.longlong, str | None]] = []
    for raw_offset in positive_offsets:
        spec = stack_specs.get(raw_offset)
        name: object = None
        if isinstance(spec, str):
            name = spec
        elif isinstance(spec, Mapping):
            spec_name = spec.get("name")
            if isinstance(spec_name, str):
                name = spec_name
        if isinstance(name, str) and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            name = None
        entries.append((raw_offset + 2 if normalized else raw_offset, name))
    return tuple(entries)


@cython.ccall
def _existing_stack_cvars_by_offset_8616(codegen: object) -> object:
    """Read stack C variables through the dynamic third-party angr codegen boundary."""
    cfunc: object
    cvar: object
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return {}
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars: dict[cython.longlong, structured_c.CVariable] = {}
    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, Mapping):
        for cvar in variables_in_use.values():
            _collect_stack_cvar_by_offset_8616(codegen, cvar, cvars)
    for cvar in typed_cfunc.arg_list or ():
        _collect_stack_cvar_by_offset_8616(codegen, cvar, cvars)
    return cvars


@cython.ccall
def _collect_stack_cvar_by_offset_8616(
    codegen: object,
    cvar: object,
    cvars: object,
) -> None:
    """Record one stack C variable under its machine BP offset."""
    if not isinstance(cvar, structured_c.CVariable):
        return
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable):
        return
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if isinstance(offset, int):
        cvars.setdefault(offset, cvar)


def _iter_existing_stack_cvars_at_offset_8616(codegen: object, offset: cython.longlong) -> tuple[structured_c.CVariable, ...]:
    """Iterate stack C variables through the dynamic third-party angr codegen boundary."""
    cfunc: object
    cvar: object
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return ()
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars: list[structured_c.CVariable] = []
    seen: set[cython.longlong] = set()

    def _append(cvar: object) -> None:
        """Read stack variables through the dynamic third-party angr boundary."""
        if not isinstance(cvar, structured_c.CVariable):
            return
        variable = cvar.variable
        if (
            not isinstance(variable, SimStackVariable)
            or operator.ne(machine_bp_offset_for_stack_variable_8616(codegen, variable), offset)
        ):
            return
        identity = id(cvar)
        if identity in seen:
            return
        seen.add(identity)
        cvars.append(cvar)

    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, Mapping):
        for cvar in variables_in_use.values():
            _append(cvar)
    for cvar in typed_cfunc.arg_list or ():
        _append(cvar)
    return tuple(cvars)


@cython.ccall
def _apply_arg_cvar_surface_8616(cvar: structured_c.CVariable, *, name: object, variable_type: object) -> cython.bint:
    """Apply argument surface updates across the dynamic third-party angr C AST boundary."""
    unified_variable: object
    changed = False
    variable = cvar.variable
    if isinstance(variable, SimStackVariable) and operator.ne(variable.name, name):
        variable.name = name
        changed = True
    if operator.ne(cvar.variable_type, variable_type):
        typing.cast(typing.Any, cvar).variable_type = variable_type
        changed = True
    unified_variable = cvar.unified_variable
    if unified_variable is not None and operator.ne(unified_variable.name, name):
        unified_variable.name = name
        changed = True
    return changed


@cython.ccall
def _is_generated_argument_name_8616(name: object) -> cython.bint:
    """Return whether a parameter name is an Inertia/angr placeholder."""
    return isinstance(name, str) and bool(
        re.fullmatch(r"(?:arg_[0-9a-fA-F]+|arg_n[0-9a-fA-F]+|a[0-9]+)", name)
    )


@cython.ccall
def _reconciled_positive_arg_name_8616(
    variable: SimStackVariable,
    prototype_name: object,
    bp_offset: cython.longlong,
) -> object:
    """Replace provisional local names once a positive BP slot is proven an argument."""
    candidate: object
    variable_name = variable.name
    for candidate in (prototype_name, variable_name):
        if _is_usable_arg_name_8616(candidate):
            return candidate
    return f"arg_{bp_offset:x}" if bp_offset >= 0 else f"arg_n{abs(bp_offset):x}"


@cython.ccall
def _is_usable_arg_name_8616(candidate: object) -> TypeGuard[str]:
    """Return whether a candidate is a concrete, non-generated argument name."""
    if not isinstance(candidate, str) or not candidate:
        return False
    return (
        candidate != "local"
        and not candidate.startswith("local_")
        and not _is_generated_argument_name_8616(candidate)
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate) is not None
    )


def _exact_incoming_argument_selection_8616(
    arg_cvars: object,
    incoming_layout: Mapping[cython.longlong, cython.longlong],
    body_access_widths: Mapping[cython.longlong, cython.longlong],
    codegen: object,
) -> object:
    """Select codegen arguments matching one closed incoming stack layout.

    Surplus codegen parameters are removable only when every accepted input
    has one exact BP owner and every decoded positive-BP body access is covered
    by the accepted ranges. Missing owners, overlaps, or out-of-layout accesses
    refuse the projection without mutating codegen.
    """
    _width: object
    offset: object
    layout = tuple(sorted(tuple(incoming_layout.items())))
    if not layout or any(offset < 4 or width <= 0 for offset, width in iter(layout)):
        return None
    if any(right_offset < left_offset + left_width for (left_offset, left_width), (right_offset, _) in builtins.iter(itertools.pairwise(layout))):
        return None
    cvar_offsets = tuple(
        canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, cvar.variable))
        if isinstance(cvar.variable, SimStackVariable)
        else None
        for cvar in iter(arg_cvars)
    )
    selected: list[cython.longlong] = []
    for offset, _width in layout:
        matching = tuple(index for index, cvar_offset in builtins.iter(enumerate(cvar_offsets)) if cvar_offset == offset)
        if len(matching) != 1:
            return None
        selected.append(matching[0])
    if operator.ne(len(set(selected)), len(selected)):
        return None
    positive_accesses = tuple(
        (offset, width)
        for offset, width in builtins.iter(body_access_widths.items())
        if offset >= 4 and width > 0
    )
    if any(
        not any(
            argument_offset <= access_offset
            and access_offset + access_width <= argument_offset + argument_width
            for argument_offset, argument_width in iter(layout)
        )
        for access_offset, access_width in iter(positive_accesses)
    ):
        return None
    return tuple(selected)


@cython.ccall
def _abi_word_size_8616(arch: object | None) -> cython.longlong:
    """Return the target C ABI word size, independent of VEX register width."""
    try:
        width = cast(_ArchBytes8616, arch).bytes
    except AttributeError:
        width = None
    return width if isinstance(width, int) and width > 0 else 2


@cython.ccall
def _type_size_bytes_8616(
    type_: object,
    *,
    arch: object | None = None,
    default: cython.longlong = 2,
) -> cython.longlong:
    """Read one x86-16 ABI type width at the dynamic angr type boundary.

    ``Arch86_16.bits`` is intentionally 32 for VEX compatibility, while its C
    ABI word is 16 bits. An angr ``SimTypeInt`` therefore occupies
    ``arch.bytes`` here; explicit ``SimTypeLong`` values retain their 32-bit
    size.
    """
    if isinstance(type_, SimTypeInt) and not isinstance(type_, SimTypeLong):
        return _abi_word_size_8616(arch)
    try:
        bits = cast(_SizedType8616, type_).size
    except (AttributeError, ValueError):
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


@cython.ccall
def _exact_stack_slot_width_8616(
    codegen: object,
    offset: cython.longlong,
    *,
    arch: object,
) -> int | None:
    """Return the binary-derived width of an exact C stack slot."""
    cvar: object
    cvar = _existing_stack_cvars_by_offset_8616(codegen).get(offset)
    if cvar is None or not isinstance(cvar.variable, SimStackVariable):
        return None
    return _exact_typed_cvar_width_8616(cvar, arch)


@cython.ccall
def _exact_typed_cvar_width_8616(cvar: structured_c.CVariable, arch: object) -> int | None:
    """Return an exact argument width from its typed stack storage.

    Pointer ``size`` follows ``Arch86_16.bits`` and is therefore not a near/far
    pointer ABI discriminator. The exact ``SimStackVariable`` width remains the
    binary-owned storage fact for non-integer arguments.
    """
    variable_type = cvar.variable_type
    if not isinstance(variable_type, SimType):
        return None
    if isinstance(variable_type, SimTypeInt) and not isinstance(variable_type, (SimTypeChar, SimTypeLong)):
        return _abi_word_size_8616(arch)
    variable = cvar.variable
    if not isinstance(variable_type, (SimTypeChar, SimTypeInt)):
        if isinstance(variable, SimStackVariable) and isinstance(variable.size, int) and variable.size > 0:
            return variable.size
        return None
    bound_type = _with_arch_8616(variable_type, arch)
    try:
        bits = cast(_SizedType8616, bound_type).size
    except (AttributeError, ValueError):
        return None
    if not isinstance(bits, int) or bits <= 0:
        return None
    return max(1, (bits + 7) // 8)


@cython.ccall
def _parameter_width_fact_8616(
    codegen: object, cvar: structured_c.CVariable, arg_type: SimType, arch: object,
    body_widths: Mapping[cython.longlong, cython.longlong], incoming_widths: Mapping[cython.longlong, cython.longlong], callsite_widths: Mapping[cython.longlong, cython.longlong],
) -> FunctionParameterWidthFact8616 | None:
    """Resolve one proposed argument range without changing its storage or type."""
    width: object
    if not isinstance(arg_type, SimType):
        return None
    variable = cvar.variable
    if not isinstance(variable, SimStackVariable) or not isinstance(variable.size, int) or variable.size <= 0:
        return None
    offset = canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, variable))
    if not isinstance(offset, int):
        return None
    width = _exact_typed_cvar_width_8616(cvar, arch)
    if isinstance(arg_type, (SimTypeChar, SimTypeInt, SimTypeLong)):
        width = body_widths.get(offset, incoming_widths.get(offset, callsite_widths.get(offset, width)))
    return None if width is None else FunctionParameterWidthFact8616(offset, width)


@cython.ccall
def _arg_stack_object_widths_8616(cfunc: object) -> object:
    """Positive-BP arg_list object extents for grouped-width reconciliation."""
    cvar: object
    widths: dict[cython.longlong, cython.longlong] = {}
    for cvar in tuple(cast(_StackPrototypeCFunction8616, cfunc).arg_list or ()):
        variable = cvar.variable
        if (
            isinstance(variable, SimStackVariable)
            and isinstance(variable.offset, int)
            and isinstance(variable.size, int)
            and variable.offset >= 4
            and variable.size > 0
        ):
            widths[variable.offset] = variable.size
    return widths


@cython.ccall
def _bp_source_width_8616(source: object, width: object) -> cython.bint:
    """Return whether one typed callsite source is a positive BP slice."""
    if not (
        isinstance(source, tuple)
        and len(source) >= 2
        and source[0] == "bp"
        and isinstance(source[1], int)
    ):
        return False
    return source[1] >= 4 and isinstance(width, int) and width > 0


def _collect_summary_source_widths_8616(
    summary: _CallsiteSummary8616,
    stack_object_widths: object,
    widths_by_offset: object,
    grouped_widths_by_offset: object,
) -> None:
    """Accumulate per-offset and fully-tiled object widths from one summary."""
    source: object
    object_offset: object
    object_width: object
    offset: object
    width: object
    source_slices: set[tuple[cython.longlong, cython.longlong]] = set()
    for source, width in zip(tuple(summary.push_arg_sources or ()), tuple(summary.arg_widths or ()), strict=False):
        if source is not None and _bp_source_width_8616(source, width):
            widths_by_offset.setdefault(source[1], set()).add(width)
            source_slices.add((source[1], width))
    for object_offset, object_width in stack_object_widths.items():
        object_end = object_offset + object_width
        contained = sorted(
            (offset, width)
            for offset, width in iter(source_slices)
            if object_offset <= offset and offset + width <= object_end
        )
        cursor = object_offset
        for offset, width in contained:
            if offset != cursor:
                break
            cursor += width
        if cursor == object_end and len(contained) > 1:
            grouped_widths_by_offset.setdefault(object_offset, set()).add(object_width)


@cython.ccall
def _callsite_stack_arg_widths_8616(codegen: object) -> object:
    """Return unambiguous BP-source widths from typed callsite summaries."""
    cfunc: object
    summary_value: object
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    try:
        summaries = typed_codegen._inertia_callsite_summaries
    except AttributeError:
        return {}
    if not isinstance(summaries, Mapping):
        return {}
    cfunc = typed_codegen.cfunc
    stack_object_widths = _arg_stack_object_widths_8616(cfunc) if cfunc is not None else {}
    widths_by_offset: dict[cython.longlong, set[cython.longlong]] = {}
    grouped_widths_by_offset: dict[cython.longlong, set[cython.longlong]] = {}
    for summary_value in summaries.values():
        _collect_summary_source_widths_8616(
            cast(_CallsiteSummary8616, summary_value),
            stack_object_widths,
            widths_by_offset,
            grouped_widths_by_offset,
        )
    widths = {
        offset: next(iter(widths))
        for offset, widths in builtins.iter(widths_by_offset.items())
        if len(widths) == 1
    }
    widths.update(
        {
            offset: next(iter(grouped_widths))
            for offset, grouped_widths in builtins.iter(grouped_widths_by_offset.items())
            if len(grouped_widths) == 1
        }
    )
    return widths


@cython.ccall
def _normalized_header_arg_widths_8616(
    codegen: object,
    entries: object,
    *,
    arch: object,
) -> tuple[cython.longlong, ...]:
    """Return widths when the entire angr header omits the return-address word."""
    _name: object
    cvar: object
    expected_offset: object
    cfunc = cast(_StackPrototypeCFunction8616, cast(_StackPrototypeCodegen8616, codegen).cfunc)
    arg_list = tuple(cfunc.arg_list or ())
    if operator.ne(len(arg_list), len(entries)):
        return ()
    widths: list[cython.longlong] = []
    for cvar, (expected_offset, _name) in zip(arg_list, entries, strict=False):
        variable = cvar.variable
        if (
            not isinstance(variable, SimStackVariable)
            or operator.ne(variable.offset + 2, expected_offset)
            or not isinstance(variable.size, int)
            or variable.size <= 0
        ):
            return ()
        logical_width = _exact_typed_cvar_width_8616(cvar, arch) or 0
        widths.append(max(2, variable.size, logical_width))
    return tuple(widths)


@cython.ccall
def _annotated_stack_object_widths_8616(
    entries: object,
) -> object:
    """Derive exact 2/4-byte object widths from adjacent structured BP starts."""
    _name: object
    index: object
    offset: object
    widths: dict[cython.longlong, cython.longlong] = {}
    for index, (offset, _name) in enumerate(entries[:-1]):
        next_offset = entries[index + 1][0]
        distance = next_offset - offset
        if distance in {2, 4}:
            widths[offset] = distance
    return widths


@cython.ccall
def _constrain_scalar_arg_type_to_stack_slot_8616(
    arg_type: SimType,
    *,
    slot_width: object,
    arch: object,
) -> tuple[SimType, cython.bint, cython.bint]:
    """Materialize a scalar type from exact non-overlapping stack storage."""
    if isinstance(arg_type, SimTypePointer):
        return arg_type, False, False
    if slot_width is None:
        return arg_type, False, False
    type_width = _type_size_bytes_8616(arg_type, arch=arch)
    if operator.eq(type_width, slot_width):
        return arg_type, False, False
    if not isinstance(arg_type, (SimTypeChar, SimTypeInt, SimTypeLong)):
        return arg_type, False, True
    if slot_width == 2 and type_width > slot_width:
        materialized = SimTypeShort(signed=arg_type.signed, label=arg_type.label)
    elif slot_width == 4 and type_width < slot_width:
        materialized = SimTypeLong(signed=arg_type.signed, label=arg_type.label)
    else:
        return arg_type, False, True
    return cast(SimType, _with_arch_8616(materialized, arch)), True, False


@cython.ccall
def _ensure_arg_cvar_8616(
    *,
    codegen: object,
    offset: cython.longlong,
    name: object,
    variable_type: object,
    width: cython.longlong,
) -> tuple[structured_c.CVariable | None, cython.bint]:
    """Materialize a BP argument variable through the dynamic third-party angr codegen boundary."""
    cfunc: object
    cvar: object
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return None, False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars_by_offset = _existing_stack_cvars_by_offset_8616(codegen)
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
        codegen,
        offset,
        width,
    )
    cvar = cvars_by_offset.get(offset)
    if (
        cvar is not None
        and isinstance(entry_sp_offset, int)
        and operator.ne(cast(SimStackVariable, cvar.variable).offset, entry_sp_offset)
    ):
        cvar = None
    changed = False
    if cvar is None:
        if not callable(typed_codegen.next_ident) or not callable(typed_codegen.next_node_idx):
            return None, False
        func_addr = typed_cfunc.addr
        stack_var = SimStackVariable(
            entry_sp_offset if isinstance(entry_sp_offset, int) else offset,
            width,
            base="bp",
            name=name,
            region=func_addr,
        )
        cvar = structured_c.CVariable(stack_var, variable_type=variable_type, codegen=codegen)
        variables_in_use = typed_cfunc.variables_in_use
        if isinstance(variables_in_use, dict):
            variables_in_use[stack_var] = cvar
        unified = typed_cfunc.unified_local_vars
        if isinstance(unified, dict):
            unified[stack_var] = {(cvar, variable_type)}
        changed = True
    variable = cvar.variable
    if isinstance(variable, SimStackVariable) and operator.ne(variable.size, width):
        variable.size = width
        changed = True
    changed = _apply_arg_cvar_surface_8616(cvar, name=name, variable_type=variable_type) or changed
    publish_selected_stack_cvar_projection_8616(
        codegen,
        cvar,
        bp_offset=offset,
        size=width,
        entry_sp_offset=entry_sp_offset,
    )
    return cvar, changed


@cython.ccall
def _prune_stack_slots_covered_by_wide_args_8616(
    codegen: object,
    owned_ranges: Mapping[cython.longlong, cython.longlong],
    owner_variables: object,
    retained_variables: object = frozenset(),
) -> cython.bint:
    """Prune stack slots through the dynamic third-party angr codegen boundary."""
    cfunc: object
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    covered_offsets = {
        covered
        for base_offset, width in builtins.iter(owned_ranges.items())
        if width > 2
        for covered in range(base_offset + 2, base_offset + width, 2)
    }
    if not covered_offsets:
        return False
    changed = _prune_covered_stack_variables_8616(
        codegen,
        typed_cfunc.variables_in_use,
        owner_variables,
        retained_variables,
        covered_offsets,
    )
    changed = _prune_covered_stack_variables_8616(
        codegen,
        typed_cfunc.unified_local_vars,
        owner_variables,
        retained_variables,
        covered_offsets,
    ) or changed
    return changed


@cython.ccall
def _prune_covered_stack_variables_8616(
    codegen: object,
    variables: object,
    owner_variables: object,
    retained_variables: object,
    covered_offsets: object,
) -> cython.bint:
    """Drop non-owned stack variables covered by proven wide-argument ranges."""
    variable: object
    if not isinstance(variables, dict):
        return False
    changed = False
    for variable in tuple(variables):
        if variable in owner_variables or variable in retained_variables or not isinstance(variable, SimStackVariable):
            continue
        if machine_bp_offset_for_stack_variable_8616(codegen, variable) in covered_offsets:
            del variables[variable]
            changed = True
    return changed


@cython.ccall
def _with_arch_8616(type_: object, arch: object) -> object:
    """Attach architecture through the dynamic third-party angr type boundary."""
    with contextlib.suppress(Exception):
        return cast(_ArchBindableType8616, type_).with_arch(arch)
    return type_


@cython.ccall
def _prototype_equivalent_8616(left: object, right: object) -> cython.bint:
    """Compare prototypes through the dynamic third-party angr type boundary."""
    if left is right:
        return True
    if left is None or right is None:
        return False
    with contextlib.suppress(Exception):
        return bool(operator.eq(left, right))
    return False


@cython.ccall
def materialize_exact_trailing_stack_argument_8616(
    project: object,
    codegen: object,
    *,
    candidate: structured_c.CVariable,
    stack_offset: cython.longlong,
    argument_type: SimType,
    width: cython.longlong,
) -> structured_c.CVariable | None:
    """Append one evidence-proven contiguous trailing BP argument.

    The caller owns the semantic proof for the candidate storage and type. This
    consumer updates the interface only when the existing argument list and
    prototype agree, all existing arguments occupy contiguous BP slots starting
    at ``BP+4``, and the candidate is exactly the next slot. Gaps, overlaps,
    malformed interfaces, and authoritative zero-argument contracts are
    refused without mutation.
    """
    arg_names: object
    gate: object
    sibling: object
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    gate = _trailing_stack_arg_gate_8616(typed_codegen, candidate, stack_offset, width)
    if gate is None:
        return None
    typed_cfunc, prototype, _prototype_args, existing_args, candidate_variable = gate

    name = f"arg_{stack_offset:x}"
    candidate_variable.size = width
    _apply_arg_cvar_surface_8616(candidate, name=name, variable_type=argument_type)
    for sibling in _iter_existing_stack_cvars_at_offset_8616(codegen, stack_offset):
        _apply_arg_cvar_surface_8616(sibling, name=name, variable_type=argument_type)
    typed_cfunc.arg_list = [*existing_args, candidate]

    arg_names = _trailing_arg_names_8616(prototype, existing_args)
    if arg_names is None:
        return None
    _publish_trailing_arg_prototype_8616(
        project,
        typed_codegen,
        typed_cfunc,
        prototype,
        argument_type,
        tuple(arg_names) + (name,),
    )
    return candidate


@cython.ccall
def _trailing_stack_arg_gate_8616(
    typed_codegen: _StackPrototypeCodegen8616,
    candidate: structured_c.CVariable,
    stack_offset: cython.longlong,
    width: cython.longlong,
) -> object:
    """Validate the contiguous trailing-slot contract; return context or refuse."""
    cfunc: object
    existing: object
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return None
    try:
        if typed_codegen._inertia_authoritative_zero_arg_prototype_8616:
            return None
    except AttributeError:
        pass
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    prototype = typed_cfunc.functy
    if not isinstance(prototype, SimTypeFunction) or width <= 0:
        return None
    prototype_args = tuple(prototype.args or ())
    existing_args = tuple(typed_cfunc.arg_list or ())
    if operator.ne(len(existing_args), len(prototype_args)):
        return None
    candidate_variable = candidate.variable
    if (
        not isinstance(candidate_variable, SimStackVariable)
        or operator.ne(candidate_variable.offset, stack_offset)
        or stack_offset < 4
    ):
        return None
    expected_offset = 4
    for existing in existing_args:
        variable = existing.variable
        if (
            not isinstance(variable, SimStackVariable)
            or not isinstance(variable.offset, int)
            or not isinstance(variable.size, int)
            or variable.size <= 0
            or operator.ne(variable.offset, expected_offset)
        ):
            return None
        expected_offset += max(2, variable.size)
    if stack_offset != expected_offset:
        return None
    return typed_cfunc, prototype, prototype_args, existing_args, candidate_variable


@cython.ccall
def _trailing_arg_names_8616(
    prototype: SimTypeFunction,
    existing_args: object,
) -> object:
    """Prototype arg names, recovered from variable names when the arity drifts."""
    existing: object
    arg_names = tuple(prototype.arg_names or ())
    if operator.eq(len(arg_names), len(existing_args)):
        return arg_names
    recovered_names: list[str] = []
    for existing in existing_args:
        variable = existing.variable
        if not isinstance(variable, SimStackVariable) or not isinstance(variable.offset, int):
            return None
        recovered_names.append(variable.name or f"arg_{variable.offset:x}")
    return tuple(recovered_names)


@cython.ccall
def _publish_trailing_arg_prototype_8616(
    project: object,
    typed_codegen: _StackPrototypeCodegen8616,
    typed_cfunc: _StackPrototypeCFunction8616,
    prototype: SimTypeFunction,
    argument_type: SimType,
    arg_names: object,
) -> None:
    """Publish the extended prototype to the cfunc and owning angr function."""
    func: object
    arch = cast(_ProjectArch8616, project).arch
    new_prototype = SimTypeFunction(
        list(tuple(prototype.args or ())) + [argument_type],
        prototype.returnty,
        arg_names=arg_names,
        variadic=prototype.variadic,
    )
    new_prototype = cast(SimTypeFunction, _with_arch_8616(new_prototype, arch))
    typed_cfunc.functy = new_prototype
    func = _function_for_codegen_8616(project, typed_codegen)
    if func is not None:
        cast(_PrototypeFunction8616, func).prototype = new_prototype
    typed_codegen._inertia_codegen_decl_refresh_required_8616 = True


@cython.ccall
def _materialize_annotated_zero_arg_prototype_8616(
    *,
    project: object,
    codegen: object,
    func: object,
    prototype: SimTypeFunction,
) -> cython.bint:
    """Materialize an explicit zero-argument annotation as the authoritative typed contract."""
    arch: object
    cfunc: object
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    typed_func = cast(_PrototypeFunction8616, func)
    arch = cast(_ProjectArch8616, project).arch
    new_proto = _with_arch_8616(prototype, arch) if arch is not None else prototype
    changed = False
    if typed_cfunc.arg_list:
        typed_cfunc.arg_list = []
        changed = True
    if not _prototype_equivalent_8616(typed_func.prototype, new_proto):
        typed_func.prototype = new_proto
        changed = True
    if _raise_prototype_source_8616(typed_func, PrototypeSource.USER):
        changed = True
    if not _prototype_equivalent_8616(typed_cfunc.functy, new_proto):
        typed_cfunc.functy = new_proto
        changed = True
    typed_codegen._inertia_authoritative_zero_arg_prototype_8616 = True
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


@dataclasses.dataclass(frozen=True, )
class _ReconcileEvidence8616:
    """Typed width evidence collected before per-argument reconciliation."""

    callsite_widths: object
    incoming_widths: object
    body_widths: object
    body_access_widths: Mapping[cython.longlong, cython.longlong]
    wide_evidence: WideStackArgumentWidthEvidence8616
    incoming_width_evidence: CalleeArgumentWidthEvidence8616


@cython.ccall
def _reconcile_width_evidence_8616(
    project: object,
    codegen: object,
    typed_cfunc: _StackPrototypeCFunction8616,
    func: object,
) -> _ReconcileEvidence8616:
    """Collect callsite, incoming, wide, and body width evidence once."""
    accepted_layout: object
    callsite_widths = _callsite_stack_arg_widths_8616(codegen)
    incoming_width_evidence = (
        CalleeArgumentWidthEvidence8616(-1, CalleeArgumentWidthVerdict8616.UNKNOWN)
        if func is None
        else collect_callee_argument_width_evidence_8616(project, typed_cfunc.addr)
    )
    accepted_layout = accepted_stack_input_layout_8616(project, typed_cfunc.addr)
    incoming_widths = dict(accepted_layout) if accepted_layout is not None else (
        dict(incoming_width_evidence.widths_by_offset)
        if incoming_width_evidence.closes_census
        else {}
    )
    wide_evidence = (
        WideStackArgumentWidthEvidence8616(0, 0, ())
        if func is None
        else collect_wide_stack_argument_width_evidence_8616(project, func)
    )
    body_widths = dict.fromkeys(wide_evidence.classified_offsets, 4)
    body_access_widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)
    return _ReconcileEvidence8616(
        callsite_widths,
        incoming_widths,
        body_widths,
        body_access_widths,
        wide_evidence,
        incoming_width_evidence,
    )


@cython.ccall
def _conflicting_body_offsets_8616(
    body_widths: Mapping[cython.longlong, cython.longlong],
    incoming_widths: Mapping[cython.longlong, cython.longlong],
    callsite_widths: Mapping[cython.longlong, cython.longlong],
) -> set[cython.longlong]:
    """Body-decoded widths that contradict incoming or callsite evidence."""
    return {
        offset
        for offset, width in builtins.iter(body_widths.items())
        if (offset in incoming_widths and operator.ne(incoming_widths[offset], width))
        or (
            not incoming_widths
            and offset in callsite_widths
            and operator.ne(callsite_widths[offset], width)
        )
    }


@dataclasses.dataclass(frozen=True, )
class _ReconcileArgResult8616:
    """Per-argument reconciliation outcome shared back to the caller."""

    reconciled: SimType
    name: object
    failed: cython.bint
    wide_offset: int | None
    changed: cython.bint
    debug_row: object


@cython.ccall
def _reconcile_one_arg_8616(
    codegen: object,
    arg_type: SimType,
    cvar: structured_c.CVariable,
    fact: FunctionParameterWidthFact8616,
    prototype_name: object,
    body_widths: Mapping[cython.longlong, cython.longlong],
    arch: object,
) -> _ReconcileArgResult8616:
    """Reconcile one argument surface, type, size, and coordinate binding."""
    variable = cast(SimStackVariable, cvar.variable)
    canonical_offset = fact.stack_offset
    exact_width = fact.width_bytes
    reconciled_name = _reconciled_positive_arg_name_8616(
        variable,
        prototype_name,
        canonical_offset,
    )
    changed = _apply_arg_cvar_surface_8616(
        cvar,
        name=reconciled_name,
        variable_type=cvar.variable_type,
    )
    reconciled, materialized, failed = _constrain_scalar_arg_type_to_stack_slot_8616(
        arg_type,
        slot_width=exact_width,
        arch=arch,
    )
    wide_offset = (
        canonical_offset
        if not failed and canonical_offset in body_widths and operator.eq(exact_width, body_widths[canonical_offset])
        else None
    )
    reconciled_width = _type_size_bytes_8616(reconciled, arch=arch)
    if (
        materialized
        or isinstance(reconciled, SimTypePointer)
        or reconciled_width == exact_width
    ) and operator.ne(cvar.variable_type, reconciled):
        typing.cast(typing.Any, cvar).variable_type = reconciled
        changed = True
    debug_row = (
        canonical_offset,
        variable.size,
        repr(arg_type),
        repr(cvar.variable_type),
        exact_width,
        materialized,
        failed,
    )
    if (
        not failed
        and reconciled_width == exact_width
        and operator.ne(variable.size, exact_width)
    ):
        variable.size = exact_width
        changed = True
    if not failed:
        refresh_stack_variable_coordinate_cvar_8616(codegen, cvar)
    return _ReconcileArgResult8616(
        reconciled, reconciled_name, failed, wide_offset, changed, debug_row
    )


def _select_incoming_args_8616(
    typed_codegen: _StackPrototypeCodegen8616,
    codegen: object,
    args: object,
    arg_cvars: object,
    prototype_names: object,
    evidence: _ReconcileEvidence8616,
    original_arg_count: cython.longlong,
) -> object:
    """Prune args to the closed incoming layout; refuse ambiguous selections."""
    selection: object
    if not evidence.incoming_widths:
        return args, arg_cvars, prototype_names, 0
    selection = _exact_incoming_argument_selection_8616(
        arg_cvars,
        evidence.incoming_widths,
        evidence.body_access_widths,
        codegen,
    )
    if selection is None:
        typed_codegen._inertia_wide_stack_argument_width_evidence_8616 = evidence.wide_evidence
        typed_codegen._inertia_stack_prototype_width_stats_8616 = StackPrototypeWidthStats8616(
            raw_fact_count=original_arg_count,
            normalized_fact_count=original_arg_count,
            failure_count=1,
        )
        return None
    return (
        tuple(args[index] for index in iter(selection)),
        tuple(arg_cvars[index] for index in iter(selection)),
        tuple(
            prototype_names[index] if index < len(prototype_names) else None
            for index in iter(selection)
        ),
        original_arg_count - len(selection),
    )


@cython.ccall
def _reconcile_width_facts_8616(
    codegen: object,
    typed_codegen: _StackPrototypeCodegen8616,
    args: object,
    arg_cvars: object,
    arch: object,
    evidence: _ReconcileEvidence8616,
) -> object:
    """Compute per-argument width facts; refuse conflicting layouts."""
    fact: object
    arg_type: object
    cvar: object
    conflicting_offsets = _conflicting_body_offsets_8616(
        evidence.body_widths, evidence.incoming_widths, evidence.callsite_widths
    )
    if conflicting_offsets:
        typed_codegen._inertia_wide_stack_argument_width_evidence_8616 = evidence.wide_evidence
        typed_codegen._inertia_stack_prototype_width_stats_8616 = StackPrototypeWidthStats8616(
            raw_fact_count=len(arg_cvars),
            normalized_fact_count=len(arg_cvars),
            failure_count=len(conflicting_offsets),
        )
        return None
    width_facts: list[FunctionParameterWidthFact8616] = []
    for arg_type, cvar in zip(args, arg_cvars, strict=True):
        fact = _parameter_width_fact_8616(
            codegen, cvar, arg_type, arch, evidence.body_widths, evidence.incoming_widths, evidence.callsite_widths,
        )
        if fact is None:
            return None
        width_facts.append(fact)
    proposed_layout = {fact.stack_offset: fact.width_bytes for fact in iter(width_facts)}
    if operator.ne(_exact_incoming_argument_selection_8616(
        arg_cvars, proposed_layout, evidence.body_access_widths, codegen,
    ), tuple(range(len(arg_cvars)))):
        return None
    return width_facts


@cython.dataclasses.dataclass()
class _ReconciledArgs8616:
    """Accumulated per-argument reconciliation results."""

    reconciled_args: object
    reconciled_names: object
    debug_rows: object
    materialized_wide_offsets: object
    classified_count: cython.longlong
    failure_count: cython.longlong
    changed: cython.bint


@cython.ccall
def _reconcile_args_8616(
    codegen: object,
    args: object,
    arg_cvars: object,
    width_facts: object,
    prototype_names: object,
    body_widths: Mapping[cython.longlong, cython.longlong],
    arch: object,
) -> _ReconciledArgs8616:
    """Reconcile every argument surface and collect stats/debug rows."""
    arg_type: object
    cvar: object
    fact: object
    index: object
    state = _ReconciledArgs8616([], [], [], set(), 0, 0, False)
    for index, (arg_type, cvar, fact) in enumerate(zip(args, arg_cvars, width_facts, strict=True)):
        result = _reconcile_one_arg_8616(
            codegen,
            arg_type,
            cvar,
            fact,
            prototype_names[index] if index < len(prototype_names) else None,
            body_widths,
            arch,
        )
        state.reconciled_names.append(result.name)
        state.reconciled_args.append(result.reconciled)
        state.classified_count += int(not result.failed)
        state.failure_count += int(result.failed)
        if result.wide_offset is not None:
            state.materialized_wide_offsets.add(result.wide_offset)
        state.changed = result.changed or state.changed
        state.debug_rows.append(result.debug_row)
    return state


@cython.ccall
def reconcile_exact_stack_argument_prototype_8616(project: object, codegen: object) -> cython.bint:
    """Reconcile a prototype with exact typed argument C variables.

    Resolve native entry-SP variables through the authoritative BP registry.
    Only constrain numeric types when every argument has one exact,
    non-overlapping stack slot; unresolved or unsupported shapes are refused.
    """
    cfunc: object
    selected: object
    storage_resolution: object
    width_facts: object
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    prototype = typed_cfunc.functy
    if not isinstance(prototype, SimTypeFunction):
        return False
    args = tuple(prototype.args or ())
    arg_cvars = tuple(typed_cfunc.arg_list or ())
    if not args or operator.ne(len(args), len(arg_cvars)):
        return False
    original_arg_count = len(arg_cvars)
    prototype_names = tuple(prototype.arg_names or ())
    arch = cast(_ProjectArch8616, project).arch
    func = _function_for_codegen_8616(project, codegen)
    evidence = _reconcile_width_evidence_8616(project, codegen, typed_cfunc, func)
    typed_codegen._inertia_callee_argument_width_evidence_8616 = evidence.incoming_width_evidence
    storage_resolution = function_storage_resolution_8616(project, typed_cfunc.addr)
    if storage_resolution is not None and storage_resolution.contract is None:
        return False
    wide_evidence = evidence.wide_evidence
    selected = _select_incoming_args_8616(
        typed_codegen,
        codegen,
        args,
        arg_cvars,
        prototype_names,
        evidence,
        original_arg_count,
    )
    if selected is None:
        return False
    args, arg_cvars, prototype_names, pruned_arg_count = selected
    width_facts = _reconcile_width_facts_8616(
        codegen,
        typed_codegen,
        args,
        arg_cvars,
        arch,
        evidence,
    )
    if width_facts is None:
        return False
    reconciled = _reconcile_args_8616(
        codegen, args, arg_cvars, width_facts, prototype_names, evidence.body_widths, arch
    )
    materialized_wide_offsets = reconciled.materialized_wide_offsets
    reconciled_names = reconciled.reconciled_names
    reconciled_args = reconciled.reconciled_args
    debug_rows = reconciled.debug_rows
    classified_count = reconciled.classified_count
    failure_count = reconciled.failure_count
    changed = reconciled.changed
    parameter_width_facts = tuple(width_facts)
    typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
    materialized_wide_evidence = wide_evidence.with_materialized_count(len(materialized_wide_offsets))
    typed_codegen._inertia_wide_stack_argument_width_evidence_8616 = materialized_wide_evidence
    failure_count += max(
        0,
        materialized_wide_evidence.classified_fact_count - materialized_wide_evidence.materialized_count,
    )
    _debug_parameter_width_facts_8616("reconcile", parameter_width_facts)
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
        print(f"[dbg-x87-proto] reconcile_stack_proto rows={tuple(debug_rows)!r}", file=sys.stderr, flush=True)
    typed_codegen._inertia_stack_prototype_width_stats_8616 = StackPrototypeWidthStats8616(
        raw_fact_count=original_arg_count,
        normalized_fact_count=original_arg_count,
        classified_fact_count=classified_count + pruned_arg_count,
        materialized_count=classified_count + pruned_arg_count,
        failure_count=failure_count,
    )
    if failure_count or classified_count == 0:
        return False
    return _publish_reconciled_prototype_8616(
        typed_codegen,
        typed_cfunc,
        func,
        prototype,
        arg_cvars,
        width_facts,
        reconciled_args,
        reconciled_names,
        arch,
        pruned_arg_count,
        changed,
    )


def _publish_reconciled_prototype_8616(
    typed_codegen: _StackPrototypeCodegen8616,
    typed_cfunc: _StackPrototypeCFunction8616,
    func: object,
    prototype: SimTypeFunction,
    arg_cvars: object,
    width_facts: object,
    reconciled_args: object,
    reconciled_names: object,
    arch: object,
    pruned_arg_count: cython.longlong,
    changed: cython.bint,
) -> cython.bint:
    """Publish the reconciled prototype, wide subviews, and pruned arg list."""
    if pruned_arg_count:
        typed_cfunc.arg_list = list(arg_cvars)
        changed = True
    new_prototype = SimTypeFunction(
        reconciled_args,
        prototype.returnty,
        arg_names=tuple(reconciled_names),
        variadic=prototype.variadic,
    )
    new_prototype = cast(SimTypeFunction, _with_arch_8616(new_prototype, arch))
    cfunc_names = (
        tuple(typed_cfunc.functy.arg_names or ())
        if isinstance(typed_cfunc.functy, SimTypeFunction)
        else ()
    )
    if (
        not _prototype_equivalent_8616(typed_cfunc.functy, new_prototype)
        or operator.ne(cfunc_names, tuple(reconciled_names))
    ):
        typed_cfunc.functy = new_prototype
        changed = True
    if func is not None:
        typed_func = cast(_PrototypeFunction8616, func)
        function_names = (
            tuple(typed_func.prototype.arg_names or ())
            if isinstance(typed_func.prototype, SimTypeFunction)
            else ()
        )
        if (
            not _prototype_equivalent_8616(typed_func.prototype, new_prototype)
            or operator.ne(function_names, tuple(reconciled_names))
        ):
            typed_func.prototype = new_prototype
            changed = True
        if _raise_prototype_source_8616(
            typed_func,
            PrototypeSource.CCA_DECOMPILER,
        ):
            changed = True
    subview_owners = tuple(
        WideStackArgumentOwner8616(fact.stack_offset, fact.width_bytes, cvar)
        for cvar, fact in builtins.iter(zip(arg_cvars, width_facts, strict=True))
    )
    changed = materialize_wide_stack_argument_subviews_8616(typed_codegen, subview_owners).changed or changed
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


@cython.ccall
def reconcile_callsite_interface_declarations_8616(project: object, codegen: object) -> cython.bint:
    """Run the owned publication, prototype, helper, and declaration lifecycle."""
    from .interprocedural_storage_pipeline import publish_and_reconcile_callsite_interfaces_8616

    return bool(publish_and_reconcile_callsite_interfaces_8616(project, codegen))


def materialize_annotated_stack_prototype_8616(
    project: object,
    codegen: object,
    *,
    fallback_to_positive_bp: cython.bint = True,
) -> cython.bint:
    """Materialize positive BP stack annotations as typed codegen arguments.

    Structured annotations take precedence. Without them, optionally replay
    the binary positive-BP owner after stack-coordinate facts are available.
    The codegen, function, C AST, and prototype objects cross a dynamic
    third-party angr boundary; owned Inertia state is written via typed protocol
    casts.
    """
    cfunc: object
    func: object
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    func = _function_for_codegen_8616(project, codegen)
    if func is None:
        return False
    info = cast(_PrototypeFunction8616, func).info
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
    annotated_prototype = annotations.get("prototype") if isinstance(annotations, Mapping) else None
    if (
        isinstance(annotated_prototype, SimTypeFunction)
        and not tuple(annotated_prototype.args or ())
        and not annotated_prototype.variadic
    ):
        return _materialize_annotated_zero_arg_prototype_8616(
            project=project,
            codegen=codegen,
            func=func,
            prototype=annotated_prototype,
        )
    entries = positive_stack_specs_8616(func)
    if not entries:
        if not fallback_to_positive_bp:
            return False
        from .positive_bp_arguments import materialize_positive_bp_arguments_8616

        return bool(materialize_positive_bp_arguments_8616(project, codegen))
    arch = cast(_ArchBytes8616 | None, cast(_ProjectArch8616, project).arch)
    typed_func = cast(_PrototypeFunction8616, func)
    authoritative_prototype = authoritative_function_prototype_8616(
        project,
        func,
        argument_count=len(entries),
    )
    current_proto = authoritative_prototype or typed_cfunc.functy or typed_func.prototype
    current_args, current_arg_names, return_type, variadic = _current_prototype_surface_8616(current_proto)
    current_surfaces_by_offset = _current_arg_surfaces_8616(
        codegen, typed_cfunc, current_args, current_arg_names
    )
    entry_ctx = _AnnotatedEntryCtx8616(
        codegen=typed_codegen,
        arch=arch,
        current_surfaces_by_offset=current_surfaces_by_offset,
        current_args=tuple(current_args),
        current_arg_names=current_arg_names,
        annotated_names=tuple(name for _offset, name in iter(entries)),
        normalized_header_widths=_normalized_header_arg_widths_8616(codegen, entries, arch=arch),
        annotated_object_widths=_annotated_stack_object_widths_8616(entries),
    )
    outcome = _materialize_annotated_entries_8616(entry_ctx, entries)
    return _commit_annotated_materialization_8616(
        typed_codegen,
        typed_cfunc,
        typed_func,
        codegen,
        outcome,
        return_type,
        variadic,
        arch,
    )


@cython.ccall
def _current_prototype_surface_8616(
    current_proto: object,
) -> tuple[list[SimType], tuple[str | None, ...], SimType, cython.bint]:
    """Decompose the current prototype surface, defaulting when absent."""
    return_type: object
    if isinstance(current_proto, SimTypeFunction):
        current_args = list(current_proto.args or ())
        current_arg_names = tuple(current_proto.arg_names or ())
        return_type = current_proto.returnty
        variadic = current_proto.variadic
    else:
        current_args = []
        current_arg_names = ()
        return_type = None
        variadic = False
    if return_type is None or (isinstance(return_type, SimTypeBottom) and return_type.label != "void"):
        return_type = SimTypeShort(False)
    return current_args, current_arg_names, return_type, variadic


@cython.dataclasses.dataclass()
class _AnnotatedMaterialization8616:
    """Accumulated annotated-entry materialization results."""

    arg_cvars: object
    arg_types: object
    arg_names: object
    owned_ranges: object
    owner_variables: object
    wide_argument_owners: object
    width_stats: StackPrototypeWidthStats8616
    width_facts: object
    changed: cython.bint


@cython.ccall
def _materialize_annotated_entries_8616(
    ctx: _AnnotatedEntryCtx8616,
    entries: object,
) -> _AnnotatedMaterialization8616:
    """Materialize all annotated entries, accumulating stats and evidence."""
    index: object
    maybe_name: object
    offset: object
    arg_cvars: list[structured_c.CVariable] = []
    arg_types: list[SimType] = []
    arg_names: list[str] = []
    owned_ranges: dict[cython.longlong, cython.longlong] = {}
    owner_variables: set[SimStackVariable] = set()
    wide_argument_owners: list[WideStackArgumentOwner8616] = []
    width_stats = StackPrototypeWidthStats8616()
    width_facts: list[FunctionParameterWidthFact8616] = []
    changed = False
    for index, (offset, maybe_name) in enumerate(entries):
        result = _materialize_annotated_entry_8616(ctx, index, offset, maybe_name, arg_names)
        if result.width_fact is not None:
            width_facts.append(result.width_fact)
        width_stats = StackPrototypeWidthStats8616(
            raw_fact_count=width_stats.raw_fact_count + result.raw_width_fact,
            normalized_fact_count=width_stats.normalized_fact_count + result.normalized_width_fact,
            classified_fact_count=width_stats.classified_fact_count + int(result.width_classified),
            materialized_count=width_stats.materialized_count + int(result.width_classified),
            failure_count=width_stats.failure_count + int(result.width_failure),
        )
        if result.cvar is None:
            continue
        changed = result.changed or changed
        owned_ranges[offset] = result.width
        if isinstance(result.variable, SimStackVariable):
            owner_variables.add(result.variable)
        wide_argument_owners.append(WideStackArgumentOwner8616(offset, result.width, result.cvar))
        arg_cvars.append(result.cvar)
        arg_types.append(result.arg_type)
        arg_names.append(result.name)
    return _AnnotatedMaterialization8616(
        arg_cvars,
        arg_types,
        arg_names,
        owned_ranges,
        owner_variables,
        wide_argument_owners,
        width_stats,
        width_facts,
        changed,
    )


@cython.ccall
def _commit_annotated_materialization_8616(
    typed_codegen: _StackPrototypeCodegen8616,
    typed_cfunc: _StackPrototypeCFunction8616,
    typed_func: _PrototypeFunction8616,
    codegen: object,
    outcome: _AnnotatedMaterialization8616,
    return_type: object,
    variadic: cython.bint,
    arch: object,
) -> cython.bint:
    """Publish stats, subviews, pruning, and the annotated prototype."""
    changed = outcome.changed
    typed_codegen._inertia_stack_prototype_width_stats_8616 = outcome.width_stats
    parameter_width_facts = tuple(outcome.width_facts)
    typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
    if not outcome.arg_cvars:
        _debug_parameter_width_facts_8616("materialize-empty", parameter_width_facts)
        return changed
    _debug_parameter_width_facts_8616("materialize", parameter_width_facts)
    if outcome.width_stats.classified_fact_count > 0 and outcome.width_stats.materialized_count == 0:
        raise RuntimeError("stack prototype width evidence was classified but not materialized")
    subview_result = materialize_wide_stack_argument_subviews_8616(codegen, tuple(outcome.wide_argument_owners))
    changed = subview_result.changed or changed
    changed = _prune_stack_slots_covered_by_wide_args_8616(
        codegen,
        outcome.owned_ranges,
        outcome.owner_variables,
        frozenset(subview_result.retained_variables),
    ) or changed
    return _publish_annotated_prototype_8616(
        typed_codegen,
        typed_cfunc,
        typed_func,
        outcome.arg_cvars,
        outcome.arg_types,
        outcome.arg_names,
        return_type,
        variadic,
        arch,
        changed,
    )


@cython.ccall
def _current_arg_surfaces_8616(
    codegen: object,
    typed_cfunc: _StackPrototypeCFunction8616,
    current_args: object,
    current_arg_names: object,
) -> object:
    """Map existing positive-BP args to their current type/name surfaces."""
    current_cvar: object
    physical_index: object
    surfaces: dict[cython.longlong, tuple[SimType, str | None]] = {}
    for physical_index, current_cvar in enumerate(typed_cfunc.arg_list):
        if physical_index >= len(current_args):
            break
        current_variable = current_cvar.variable
        current_type = current_args[physical_index]
        if not isinstance(current_variable, SimStackVariable) or not isinstance(current_type, SimType):
            continue
        machine_bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, current_variable)
        if not isinstance(machine_bp_offset, int):
            continue
        current_name = current_arg_names[physical_index] if physical_index < len(current_arg_names) else None
        surfaces.setdefault(machine_bp_offset, (current_type, current_name))
    return surfaces


@dataclasses.dataclass(frozen=True, )
class _AnnotatedEntryCtx8616:
    """Read-only annotation context shared by per-entry materialization."""

    codegen: _StackPrototypeCodegen8616
    arch: _ArchBytes8616 | None
    current_surfaces_by_offset: Mapping[cython.longlong, tuple[SimType, str | None]]
    current_args: object
    current_arg_names: object
    annotated_names: object
    normalized_header_widths: object
    annotated_object_widths: Mapping[cython.longlong, cython.longlong]


@dataclasses.dataclass(frozen=True, )
class _AnnotatedEntryResult8616:
    """One materialized annotated entry shared back to the materializer."""

    cvar: structured_c.CVariable | None
    variable: SimVariable | None
    arg_type: SimType
    name: object
    width: cython.longlong
    changed: cython.bint
    raw_width_fact: cython.longlong
    normalized_width_fact: cython.longlong
    width_classified: cython.bint
    width_failure: cython.bint
    width_fact: FunctionParameterWidthFact8616 | None


@cython.ccall
def _annotated_entry_name_8616(
    ctx: _AnnotatedEntryCtx8616,
    index: cython.longlong,
    offset: cython.longlong,
    maybe_name: object,
    current_surface: object,
) -> object:
    """Pick the proven prototype, annotated, or generated argument name."""
    prototype_name = (
        current_surface[1]
        if current_surface is not None
        else ctx.current_arg_names[index] if index < len(ctx.current_arg_names) else None
    )
    if _is_usable_arg_name_8616(prototype_name) and ctx.current_arg_names.count(prototype_name) == 1:
        return prototype_name
    if (
        _is_usable_annotated_name_8616(maybe_name)
        and ctx.annotated_names.count(maybe_name) == 1
    ):
        return cast(str, maybe_name)
    return f"arg_{offset:x}"


@cython.ccall
def _is_usable_annotated_name_8616(candidate: object) -> cython.bint:
    """Return whether an annotated name is a concrete C identifier."""
    if not isinstance(candidate, str) or not candidate:
        return False
    return (
        candidate != "local"
        and not candidate.startswith("local_")
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate) is not None
    )


def _annotated_entry_arg_type_8616(
    ctx: _AnnotatedEntryCtx8616,
    index: cython.longlong,
    offset: cython.longlong,
    slot_width: int | None,
    current_surface: object,
) -> SimType:
    """Resolve the annotated entry type, honoring exact existing surfaces."""
    arg_type = (
        current_surface[0]
        if current_surface is not None
        else ctx.current_args[index] if index < len(ctx.current_args) else SimTypeShort(False)
    )
    if ctx.arch is not None:
        arg_type = _with_arch_8616(arg_type, ctx.arch)
    if not isinstance(arg_type, SimType):
        arg_type = SimTypeShort(False)
    exact_existing_types = tuple(
        cvar.variable_type
        for cvar in builtins.iter(_iter_existing_stack_cvars_at_offset_8616(ctx.codegen, offset))
        if isinstance(cvar.variable_type, SimType)
        and (
            operator.eq(_exact_typed_cvar_width_8616(cvar, ctx.arch), slot_width)
            or (
                isinstance(cvar.variable_type, SimTypeChar)
                and isinstance(slot_width, int)
                and (_exact_typed_cvar_width_8616(cvar, ctx.arch) or 0) < slot_width
            )
        )
    )
    if operator.ne(_type_size_bytes_8616(arg_type, arch=ctx.arch), slot_width) and exact_existing_types and all(
        operator.eq(candidate, exact_existing_types[0]) for candidate in iter(exact_existing_types[1:])
    ):
        arg_type = exact_existing_types[0]
    return arg_type


@cython.ccall
def _materialize_annotated_entry_8616(
    ctx: _AnnotatedEntryCtx8616,
    index: cython.longlong,
    offset: cython.longlong,
    maybe_name: object,
    arg_names: object,
) -> _AnnotatedEntryResult8616:
    """Materialize one annotated entry's name, type, width fact, and cvar."""
    current_surface: object
    cvar: object
    slot_width: object
    value_width: object
    sibling_cvar: object
    current_surface = ctx.current_surfaces_by_offset.get(offset)
    name = _annotated_entry_name_8616(ctx, index, offset, maybe_name, current_surface)
    slot_width = (
        ctx.normalized_header_widths[index]
        if index < len(ctx.normalized_header_widths)
        else ctx.annotated_object_widths.get(offset)
    )
    if slot_width is None:
        slot_width = _exact_stack_slot_width_8616(ctx.codegen, offset, arch=ctx.arch)
    arg_type = _annotated_entry_arg_type_8616(ctx, index, offset, slot_width, current_surface)
    value_width = (
        _type_size_bytes_8616(arg_type, arch=ctx.arch)
        if isinstance(arg_type, SimTypeChar)
        else slot_width
    )
    raw_width_fact = int(value_width is not None)
    normalized_width_fact = int(isinstance(value_width, int) and value_width > 0)
    width_fact = (
        FunctionParameterWidthFact8616(stack_offset=offset, width_bytes=value_width)
        if normalized_width_fact and isinstance(value_width, int)
        else None
    )
    arg_type, _, width_failure = _constrain_scalar_arg_type_to_stack_slot_8616(
        arg_type,
        slot_width=value_width,
        arch=ctx.arch,
    )
    width_classified = bool(normalized_width_fact and not width_failure)
    width = (
        slot_width
        if isinstance(slot_width, int) and slot_width > 0
        else max(2, _type_size_bytes_8616(arg_type, arch=ctx.arch))
    )
    cvar, cvar_changed = _ensure_arg_cvar_8616(
        codegen=ctx.codegen,
        offset=offset,
        name=name,
        variable_type=arg_type,
        width=width,
    )
    if cvar is None:
        return _AnnotatedEntryResult8616(
            None, None, arg_type, name, width, False,
            raw_width_fact, normalized_width_fact, width_classified, width_failure, width_fact,
        )
    variable = cvar.variable
    if isinstance(variable, SimStackVariable):
        name = _reconciled_positive_arg_name_8616(
            variable,
            name,
            offset,
        )
    if name in arg_names:
        name = f"arg_{offset:x}"
    cvar_changed = (
        _apply_arg_cvar_surface_8616(
            cvar,
            name=name,
            variable_type=arg_type,
        )
        or cvar_changed
    )
    for sibling_cvar in _iter_existing_stack_cvars_at_offset_8616(ctx.codegen, offset):
        cvar_changed = _apply_arg_cvar_surface_8616(sibling_cvar, name=name, variable_type=arg_type) or cvar_changed
    return _AnnotatedEntryResult8616(
        cvar, variable, arg_type, name, width, cvar_changed,
        raw_width_fact, normalized_width_fact, width_classified, width_failure, width_fact,
    )


def _publish_annotated_prototype_8616(
    typed_codegen: _StackPrototypeCodegen8616,
    typed_cfunc: _StackPrototypeCFunction8616,
    typed_func: _PrototypeFunction8616,
    arg_cvars: object,
    arg_types: object,
    arg_names: object,
    return_type: object,
    variadic: cython.bint,
    arch: object,
    changed: cython.bint,
) -> cython.bint:
    """Publish the annotated arg list and prototype across angr boundaries."""
    existing_args = list(typed_cfunc.arg_list or ())
    if operator.ne(len(existing_args), len(arg_cvars)) or any(existing is not desired for existing, desired in builtins.iter(zip(existing_args, arg_cvars, strict=False))):
        typed_cfunc.arg_list = arg_cvars
        changed = True
    new_proto = SimTypeFunction(arg_types, return_type, arg_names=arg_names, variadic=variadic)
    if arch is not None:
        new_proto = _with_arch_8616(new_proto, arch)
    function_names = (
        tuple(typed_func.prototype.arg_names or ())
        if isinstance(typed_func.prototype, SimTypeFunction)
        else ()
    )
    if not _prototype_equivalent_8616(typed_func.prototype, new_proto) or operator.ne(function_names, tuple(arg_names)):
        typed_func.prototype = new_proto
        _raise_prototype_source_8616(
            typed_func,
            PrototypeSource.CCA_DECOMPILER,
        )
        changed = True
    cfunc_names = (
        tuple(typed_cfunc.functy.arg_names or ())
        if isinstance(typed_cfunc.functy, SimTypeFunction)
        else ()
    )
    if not _prototype_equivalent_8616(typed_cfunc.functy, new_proto) or operator.ne(cfunc_names, tuple(arg_names)):
        typed_cfunc.functy = new_proto
        changed = True
    try:
        materialized_count = typed_codegen._inertia_annotated_stack_prototype_materialized_8616
    except AttributeError:
        materialized_count = 0
    typed_codegen._inertia_annotated_stack_prototype_materialized_8616 = max(
        int(materialized_count or 0),
        len(arg_cvars),
    )
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed
