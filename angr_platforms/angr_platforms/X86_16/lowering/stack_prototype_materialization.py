"""Layer: Types/Lowering.

Responsibility: materialize stack-prototype facts before rewrite.
Consumes alias, widening, and typed facts from structured stack-slot annotations
already attached to function metadata, then turns positive BP slots into codegen
argument variables and a typed function prototype.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import re
import sys
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

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
from angr.sim_variable import SimStackVariable

from ..annotations import ANNOTATION_KEY
from ..calling_convention_compat import collect_wide_stack_argument_width_evidence_8616
from ..widening.stack_argument_widths import WideStackArgumentWidthEvidence8616
from ..widening.widening_rules import collect_bp_stack_access_widths_from_instructions_8616
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

__all__ = [
    "FunctionParameterWidthFact8616",
    "align_pointer_flags_to_stack_argument_widths_8616",
    "materialize_annotated_stack_prototype_8616",
    "materialize_exact_trailing_stack_argument_8616",
    "reconcile_callsite_interface_declarations_8616",
    "reconcile_exact_stack_argument_prototype_8616",
]


def align_pointer_flags_to_stack_argument_widths_8616(
    source_pointer_flags: tuple[bool, ...],
    argument_offsets: tuple[int, ...],
    argument_widths: Mapping[int, int],
) -> tuple[bool, ...]:
    """Align physical stack-word classes with logical typed arguments."""
    if len(source_pointer_flags) == len(argument_offsets):
        return source_pointer_flags
    if len(source_pointer_flags) < len(argument_offsets):
        return ()
    aligned: list[bool] = []
    source_index = 0
    for offset in argument_offsets:
        width = max(2, argument_widths.get(offset, 2))
        word_count = max(1, (width + 1) // 2)
        next_source_index = source_index + word_count
        if next_source_index > len(source_pointer_flags):
            return ()
        aligned.append(any(source_pointer_flags[source_index:next_source_index]))
        source_index = next_source_index
    return tuple(aligned) if source_index == len(source_pointer_flags) else ()


class _PrototypeFunction8616(Protocol):
    """Function metadata written at the dynamic third-party angr boundary."""

    info: object
    prototype: object
    prototype_source: PrototypeSource
    is_prototype_guessed: bool


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


def _raise_prototype_source_8616(
    function: _PrototypeFunction8616,
    source: PrototypeSource,
) -> bool:
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
    next_node_idx: Callable[[], int]
    _inertia_annotated_stack_prototype_materialized_8616: int
    _inertia_authoritative_zero_arg_prototype_8616: bool
    _inertia_callsite_summaries: object
    _inertia_callee_argument_width_evidence_8616: CalleeArgumentWidthEvidence8616
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_function_parameter_width_facts_8616: tuple[FunctionParameterWidthFact8616, ...]
    _inertia_stack_prototype_width_stats_8616: StackPrototypeWidthStats8616
    _inertia_wide_stack_argument_width_evidence_8616: WideStackArgumentWidthEvidence8616


class _StackPrototypeCFunction8616(Protocol):
    """C-function fields consumed after the dynamic codegen entry boundary."""

    addr: int
    arg_list: list[structured_c.CVariable]
    functy: object
    unified_local_vars: object
    variables_in_use: object


class _ProjectArch8616(Protocol):
    """Project fields exposed after the dynamic third-party entry boundary."""

    arch: object
    kb: _KnowledgeBase8616


class _ArchBytes8616(Protocol):
    """Target architecture field that defines the C ABI word size."""

    bytes: int


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base surface required by stack prototype lowering."""

    functions: _FunctionManager8616


class _FunctionManager8616(Protocol):
    """angr function-manager surface required by stack prototype lowering."""

    def function(self, *, addr: int, create: bool) -> object:
        """Return an existing function by address."""
        ...


class _SizedType8616(Protocol):
    """Third-party type surface used to query an architecture-sized width."""

    size: int


class _ArchBindableType8616(Protocol):
    """Third-party type surface used to bind an architecture."""

    def with_arch(self, arch: object) -> object:
        """Return this type bound to ``arch``."""
        ...


class _CallsiteSummary8616(Protocol):
    """Typed callsite fields consumed from the semantics layer."""

    arg_widths: tuple[int, ...]
    push_arg_sources: tuple[tuple[str, int] | None, ...]


@dataclass(frozen=True)
class StackPrototypeWidthStats8616:
    """Evidence accounting for exact stack-slot argument-width constraints."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, order=True, slots=True)
class FunctionParameterWidthFact8616:
    """Exact binary/IR-backed width of one positive BP function parameter."""

    stack_offset: int
    width_bytes: int


def _debug_parameter_width_facts_8616(
    phase: str,
    facts: tuple[FunctionParameterWidthFact8616, ...],
) -> None:
    """Log parameter-width fact lifecycle when prototype diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") != "1":
        return
    print(
        f"[dbg-x87-proto] parameter_width_facts phase={phase} facts={facts!r}",
        file=sys.stderr,
        flush=True,
    )


def _function_for_codegen_8616(project: object, codegen: object) -> object | None:
    """Return metadata through the dynamic third-party angr project/codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return None
    func_addr = cast(_StackPrototypeCFunction8616, cfunc).addr
    if not isinstance(func_addr, int):
        return None
    with contextlib.suppress(Exception):
        return cast(_ProjectArch8616, project).kb.functions.function(addr=func_addr, create=False)
    return None


def positive_stack_specs_8616(func: object) -> tuple[tuple[int, str | None], ...]:
    """Return positive stack annotations in canonical machine-BP coordinates."""
    info = cast(_PrototypeFunction8616, func).info
    annotations = info.get(ANNOTATION_KEY) if isinstance(info, Mapping) else None
    if not isinstance(annotations, Mapping):
        return ()
    stack_specs = annotations.get("stack_vars")
    if not isinstance(stack_specs, Mapping):
        return ()
    positive_offsets = sorted(offset for offset in stack_specs if isinstance(offset, int) and offset > 0)
    if not positive_offsets:
        return ()
    normalized = positive_offsets[0] == 2
    entries: list[tuple[int, str | None]] = []
    for raw_offset in positive_offsets:
        spec = stack_specs.get(raw_offset)
        name: str | None = None
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


def _existing_stack_cvars_by_offset_8616(codegen: object) -> dict[int, structured_c.CVariable]:
    """Read stack C variables through the dynamic third-party angr codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return {}
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars: dict[int, structured_c.CVariable] = {}
    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, Mapping):
        for cvar in variables_in_use.values():
            if not isinstance(cvar, structured_c.CVariable):
                continue
            variable = cvar.variable
            if not isinstance(variable, SimStackVariable):
                continue
            offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
            if isinstance(offset, int):
                cvars.setdefault(offset, cvar)
    for cvar in typed_cfunc.arg_list or ():
        if not isinstance(cvar, structured_c.CVariable):
            continue
        variable = cvar.variable
        if not isinstance(variable, SimStackVariable):
            continue
        offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if isinstance(offset, int):
            cvars.setdefault(offset, cvar)
    return cvars


def _iter_existing_stack_cvars_at_offset_8616(codegen: object, offset: int) -> tuple[structured_c.CVariable, ...]:
    """Iterate stack C variables through the dynamic third-party angr codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return ()
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    cvars: list[structured_c.CVariable] = []
    seen: set[int] = set()

    def _append(cvar: object) -> None:
        """Read stack variables through the dynamic third-party angr boundary."""
        if not isinstance(cvar, structured_c.CVariable):
            return
        variable = cvar.variable
        if (
            not isinstance(variable, SimStackVariable)
            or machine_bp_offset_for_stack_variable_8616(codegen, variable) != offset
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


def _apply_arg_cvar_surface_8616(cvar: structured_c.CVariable, *, name: str, variable_type: object) -> bool:
    """Apply argument surface updates across the dynamic third-party angr C AST boundary."""
    changed = False
    variable = cvar.variable
    if isinstance(variable, SimStackVariable) and variable.name != name:
        variable.name = name
        changed = True
    if cvar.variable_type != variable_type:
        typing.cast(typing.Any, cvar).variable_type = variable_type
        changed = True
    unified_variable = cvar.unified_variable
    if unified_variable is not None and unified_variable.name != name:
        unified_variable.name = name
        changed = True
    return changed


def _is_generated_argument_name_8616(name: object) -> bool:
    """Return whether a parameter name is an Inertia/angr placeholder."""
    return isinstance(name, str) and bool(
        re.fullmatch(r"(?:arg_[0-9a-fA-F]+|arg_n[0-9a-fA-F]+|a[0-9]+)", name)
    )


def _reconciled_positive_arg_name_8616(
    variable: SimStackVariable,
    prototype_name: str | None,
    bp_offset: int,
) -> str:
    """Replace provisional local names once a positive BP slot is proven an argument."""
    variable_name = variable.name
    for candidate in (prototype_name, variable_name):
        if (
            isinstance(candidate, str)
            and candidate
            and candidate != "local"
            and not candidate.startswith("local_")
            and not _is_generated_argument_name_8616(candidate)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate) is not None
        ):
            return candidate
    return f"arg_{bp_offset:x}" if bp_offset >= 0 else f"arg_n{abs(bp_offset):x}"


def _exact_incoming_argument_selection_8616(
    arg_cvars: tuple[structured_c.CVariable, ...],
    incoming_layout: Mapping[int, int],
    body_access_widths: Mapping[int, int],
    codegen: object,
) -> tuple[int, ...] | None:
    """Select codegen arguments matching one closed incoming stack layout.

    Surplus codegen parameters are removable only when every accepted input
    has one exact BP owner and every decoded positive-BP body access is covered
    by the accepted ranges. Missing owners, overlaps, or out-of-layout accesses
    refuse the projection without mutating codegen.
    """
    layout = tuple(sorted(incoming_layout.items()))
    if not layout or any(offset < 4 or width <= 0 for offset, width in layout):
        return None
    if any(right_offset < left_offset + left_width for (left_offset, left_width), (right_offset, _) in itertools.pairwise(layout)):
        return None
    cvar_offsets = tuple(
        canonical_stack_offset_8616(machine_bp_offset_for_stack_variable_8616(codegen, cvar.variable))
        if isinstance(cvar.variable, SimStackVariable)
        else None
        for cvar in arg_cvars
    )
    selected: list[int] = []
    for offset, _width in layout:
        matching = tuple(index for index, cvar_offset in enumerate(cvar_offsets) if cvar_offset == offset)
        if len(matching) != 1:
            return None
        selected.append(matching[0])
    if len(set(selected)) != len(selected):
        return None
    positive_accesses = tuple(
        (offset, width)
        for offset, width in body_access_widths.items()
        if offset >= 4 and width > 0
    )
    if any(
        not any(
            argument_offset <= access_offset
            and access_offset + access_width <= argument_offset + argument_width
            for argument_offset, argument_width in layout
        )
        for access_offset, access_width in positive_accesses
    ):
        return None
    return tuple(selected)


def _abi_word_size_8616(arch: object | None) -> int:
    """Return the target C ABI word size, independent of VEX register width."""
    try:
        width = cast(_ArchBytes8616, arch).bytes
    except AttributeError:
        width = None
    return width if isinstance(width, int) and width > 0 else 2


def _type_size_bytes_8616(
    type_: object,
    *,
    arch: object | None = None,
    default: int = 2,
) -> int:
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


def _exact_stack_slot_width_8616(
    codegen: object,
    offset: int,
    *,
    arch: object,
) -> int | None:
    """Return the binary-derived width of an exact C stack slot."""
    cvar = _existing_stack_cvars_by_offset_8616(codegen).get(offset)
    if cvar is None or not isinstance(cvar.variable, SimStackVariable):
        return None
    return _exact_typed_cvar_width_8616(cvar, arch)


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


def _parameter_width_fact_8616(
    codegen: object, cvar: structured_c.CVariable, arg_type: SimType, arch: object,
    body_widths: Mapping[int, int], incoming_widths: Mapping[int, int], callsite_widths: Mapping[int, int],
) -> FunctionParameterWidthFact8616 | None:
    """Resolve one proposed argument range without changing its storage or type."""
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


def _callsite_stack_arg_widths_8616(codegen: object) -> dict[int, int]:
    """Return unambiguous BP-source widths from typed callsite summaries."""
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
    try:
        summaries = typed_codegen._inertia_callsite_summaries
    except AttributeError:
        return {}
    if not isinstance(summaries, Mapping):
        return {}
    cfunc = typed_codegen.cfunc
    stack_object_widths: dict[int, int] = {}
    if cfunc is not None:
        for cvar in tuple(cast(_StackPrototypeCFunction8616, cfunc).arg_list or ()):
            variable = cvar.variable
            if (
                isinstance(variable, SimStackVariable)
                and isinstance(variable.offset, int)
                and isinstance(variable.size, int)
                and variable.offset >= 4
                and variable.size > 0
            ):
                stack_object_widths[variable.offset] = variable.size
    widths_by_offset: dict[int, set[int]] = {}
    grouped_widths_by_offset: dict[int, set[int]] = {}
    for summary_value in summaries.values():
        summary = cast(_CallsiteSummary8616, summary_value)
        source_slices: set[tuple[int, int]] = set()
        for source, width in zip(tuple(summary.push_arg_sources or ()), tuple(summary.arg_widths or ()), strict=False):
            if (
                isinstance(source, tuple)
                and len(source) >= 2
                and source[0] == "bp"
                and isinstance(source[1], int)
                and source[1] >= 4
                and isinstance(width, int)
                and width > 0
            ):
                widths_by_offset.setdefault(source[1], set()).add(width)
                source_slices.add((source[1], width))
        for object_offset, object_width in stack_object_widths.items():
            object_end = object_offset + object_width
            contained = sorted(
                (offset, width)
                for offset, width in source_slices
                if object_offset <= offset and offset + width <= object_end
            )
            cursor = object_offset
            for offset, width in contained:
                if offset != cursor:
                    break
                cursor += width
            if cursor == object_end and len(contained) > 1:
                grouped_widths_by_offset.setdefault(object_offset, set()).add(object_width)
    widths = {
        offset: next(iter(widths))
        for offset, widths in widths_by_offset.items()
        if len(widths) == 1
    }
    widths.update(
        {
            offset: next(iter(grouped_widths))
            for offset, grouped_widths in grouped_widths_by_offset.items()
            if len(grouped_widths) == 1
        }
    )
    return widths


def _normalized_header_arg_widths_8616(
    codegen: object,
    entries: tuple[tuple[int, str | None], ...],
    *,
    arch: object,
) -> tuple[int, ...]:
    """Return widths when the entire angr header omits the return-address word."""
    cfunc = cast(_StackPrototypeCFunction8616, cast(_StackPrototypeCodegen8616, codegen).cfunc)
    arg_list = tuple(cfunc.arg_list or ())
    if len(arg_list) != len(entries):
        return ()
    widths: list[int] = []
    for cvar, (expected_offset, _name) in zip(arg_list, entries, strict=False):
        variable = cvar.variable
        if (
            not isinstance(variable, SimStackVariable)
            or variable.offset + 2 != expected_offset
            or not isinstance(variable.size, int)
            or variable.size <= 0
        ):
            return ()
        logical_width = _exact_typed_cvar_width_8616(cvar, arch) or 0
        widths.append(max(2, variable.size, logical_width))
    return tuple(widths)


def _annotated_stack_object_widths_8616(
    entries: tuple[tuple[int, str | None], ...],
) -> dict[int, int]:
    """Derive exact 2/4-byte object widths from adjacent structured BP starts."""
    widths: dict[int, int] = {}
    for index, (offset, _name) in enumerate(entries[:-1]):
        next_offset = entries[index + 1][0]
        distance = next_offset - offset
        if distance in {2, 4}:
            widths[offset] = distance
    return widths


def _constrain_scalar_arg_type_to_stack_slot_8616(
    arg_type: SimType,
    *,
    slot_width: int | None,
    arch: object,
) -> tuple[SimType, bool, bool]:
    """Materialize a scalar type from exact non-overlapping stack storage."""
    if isinstance(arg_type, SimTypePointer):
        return arg_type, False, False
    if slot_width is None:
        return arg_type, False, False
    type_width = _type_size_bytes_8616(arg_type, arch=arch)
    if type_width == slot_width:
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


def _ensure_arg_cvar_8616(
    *,
    codegen: object,
    offset: int,
    name: str,
    variable_type: object,
    width: int,
) -> tuple[structured_c.CVariable | None, bool]:
    """Materialize a BP argument variable through the dynamic third-party angr codegen boundary."""
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
        and cast(SimStackVariable, cvar.variable).offset != entry_sp_offset
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
    if isinstance(variable, SimStackVariable) and variable.size != width:
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


def _prune_stack_slots_covered_by_wide_args_8616(
    codegen: object,
    owned_ranges: Mapping[int, int],
    owner_variables: set[SimStackVariable],
    retained_variables: frozenset[SimStackVariable] = frozenset(),
) -> bool:
    """Prune stack slots through the dynamic third-party angr codegen boundary."""
    cfunc = cast(_StackPrototypeCodegen8616, codegen).cfunc
    if cfunc is None:
        return False
    typed_cfunc = cast(_StackPrototypeCFunction8616, cfunc)
    covered_offsets = {
        covered
        for base_offset, width in owned_ranges.items()
        if width > 2
        for covered in range(base_offset + 2, base_offset + width, 2)
    }
    if not covered_offsets:
        return False
    changed = False
    variables_in_use = typed_cfunc.variables_in_use
    if isinstance(variables_in_use, dict):
        for variable in tuple(variables_in_use):
            if variable in owner_variables or variable in retained_variables or not isinstance(variable, SimStackVariable):
                continue
            if machine_bp_offset_for_stack_variable_8616(codegen, variable) in covered_offsets:
                del variables_in_use[variable]
                changed = True
    unified = typed_cfunc.unified_local_vars
    if isinstance(unified, dict):
        for variable in tuple(unified):
            if variable in owner_variables or variable in retained_variables or not isinstance(variable, SimStackVariable):
                continue
            if machine_bp_offset_for_stack_variable_8616(codegen, variable) in covered_offsets:
                del unified[variable]
                changed = True
    return changed


def _with_arch_8616(type_: object, arch: object) -> object:
    """Attach architecture through the dynamic third-party angr type boundary."""
    with contextlib.suppress(Exception):
        return cast(_ArchBindableType8616, type_).with_arch(arch)
    return type_


def _prototype_equivalent_8616(left: object, right: object) -> bool:
    """Compare prototypes through the dynamic third-party angr type boundary."""
    if left is right:
        return True
    if left is None or right is None:
        return False
    with contextlib.suppress(Exception):
        return bool(left == right)
    return False


def materialize_exact_trailing_stack_argument_8616(
    project: object,
    codegen: object,
    *,
    candidate: structured_c.CVariable,
    stack_offset: int,
    argument_type: SimType,
    width: int,
) -> structured_c.CVariable | None:
    """Append one evidence-proven contiguous trailing BP argument.

    The caller owns the semantic proof for the candidate storage and type. This
    consumer updates the interface only when the existing argument list and
    prototype agree, all existing arguments occupy contiguous BP slots starting
    at ``BP+4``, and the candidate is exactly the next slot. Gaps, overlaps,
    malformed interfaces, and authoritative zero-argument contracts are
    refused without mutation.
    """
    typed_codegen = cast(_StackPrototypeCodegen8616, codegen)
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
    if len(existing_args) != len(prototype_args):
        return None
    candidate_variable = candidate.variable
    if (
        not isinstance(candidate_variable, SimStackVariable)
        or candidate_variable.offset != stack_offset
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
            or variable.offset != expected_offset
        ):
            return None
        expected_offset += max(2, variable.size)
    if stack_offset != expected_offset:
        return None

    name = f"arg_{stack_offset:x}"
    candidate_variable.size = width
    _apply_arg_cvar_surface_8616(candidate, name=name, variable_type=argument_type)
    for sibling in _iter_existing_stack_cvars_at_offset_8616(codegen, stack_offset):
        _apply_arg_cvar_surface_8616(sibling, name=name, variable_type=argument_type)
    typed_cfunc.arg_list = [*existing_args, candidate]

    arg_names = tuple(prototype.arg_names or ())
    if len(arg_names) != len(existing_args):
        recovered_names: list[str] = []
        for existing in existing_args:
            variable = existing.variable
            if not isinstance(variable, SimStackVariable) or not isinstance(variable.offset, int):
                return None
            recovered_names.append(variable.name or f"arg_{variable.offset:x}")
        arg_names = tuple(recovered_names)
    arch = cast(_ProjectArch8616, project).arch
    new_prototype = SimTypeFunction(
        [*prototype_args, argument_type],
        prototype.returnty,
        arg_names=(*arg_names, name),
        variadic=prototype.variadic,
    )
    new_prototype = cast(SimTypeFunction, _with_arch_8616(new_prototype, arch))
    typed_cfunc.functy = new_prototype
    func = _function_for_codegen_8616(project, codegen)
    if func is not None:
        cast(_PrototypeFunction8616, func).prototype = new_prototype
    typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return candidate


def _materialize_annotated_zero_arg_prototype_8616(
    *,
    project: object,
    codegen: object,
    func: object,
    prototype: SimTypeFunction,
) -> bool:
    """Materialize an explicit zero-argument annotation as the authoritative typed contract."""
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


def reconcile_exact_stack_argument_prototype_8616(project: object, codegen: object) -> bool:
    """Reconcile a prototype with exact typed argument C variables.

    Resolve native entry-SP variables through the authoritative BP registry.
    Only constrain numeric types when every argument has one exact,
    non-overlapping stack slot; unresolved or unsupported shapes are refused.
    """
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
    if not args or len(args) != len(arg_cvars):
        return False
    original_arg_count = len(arg_cvars)
    prototype_names = tuple(prototype.arg_names or ())
    arch = cast(_ProjectArch8616, project).arch
    reconciled_args: list[SimType] = []
    classified_count = 0
    failure_count = 0
    callsite_widths = _callsite_stack_arg_widths_8616(codegen)
    func = _function_for_codegen_8616(project, codegen)
    incoming_width_evidence = (
        CalleeArgumentWidthEvidence8616(-1, CalleeArgumentWidthVerdict8616.UNKNOWN)
        if func is None
        else collect_callee_argument_width_evidence_8616(project, typed_cfunc.addr)
    )
    typed_codegen._inertia_callee_argument_width_evidence_8616 = incoming_width_evidence
    storage_resolution = function_storage_resolution_8616(project, typed_cfunc.addr)
    if storage_resolution is not None and storage_resolution.contract is None:
        return False
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
    pruned_arg_count = 0
    if incoming_widths:
        selection = _exact_incoming_argument_selection_8616(
            arg_cvars,
            incoming_widths,
            body_access_widths,
            codegen,
        )
        if selection is None:
            typed_codegen._inertia_wide_stack_argument_width_evidence_8616 = wide_evidence
            typed_codegen._inertia_stack_prototype_width_stats_8616 = StackPrototypeWidthStats8616(
                raw_fact_count=original_arg_count,
                normalized_fact_count=original_arg_count,
                failure_count=1,
            )
            return False
        args = tuple(args[index] for index in selection)
        arg_cvars = tuple(arg_cvars[index] for index in selection)
        prototype_names = tuple(
            prototype_names[index] if index < len(prototype_names) else None
            for index in selection
        )
        pruned_arg_count = original_arg_count - len(arg_cvars)
    conflicting_offsets = {
        offset
        for offset, width in body_widths.items()
        if (offset in incoming_widths and incoming_widths[offset] != width)
        or (
            not incoming_widths
            and offset in callsite_widths
            and callsite_widths[offset] != width
        )
    }
    if conflicting_offsets:
        typed_codegen._inertia_wide_stack_argument_width_evidence_8616 = wide_evidence
        typed_codegen._inertia_stack_prototype_width_stats_8616 = StackPrototypeWidthStats8616(
            raw_fact_count=len(arg_cvars),
            normalized_fact_count=len(arg_cvars),
            failure_count=len(conflicting_offsets),
        )
        return False
    width_facts: list[FunctionParameterWidthFact8616] = []
    for arg_type, cvar in zip(args, arg_cvars, strict=True):
        fact = _parameter_width_fact_8616(
            codegen, cvar, arg_type, arch, body_widths, incoming_widths, callsite_widths,
        )
        if fact is None:
            return False
        width_facts.append(fact)
    proposed_layout = {fact.stack_offset: fact.width_bytes for fact in width_facts}
    if _exact_incoming_argument_selection_8616(
        arg_cvars, proposed_layout, body_access_widths, codegen,
    ) != tuple(range(len(arg_cvars))):
        return False
    materialized_wide_offsets: set[int] = set()
    reconciled_names: list[str] = []
    debug_rows: list[tuple[object, ...]] = []
    changed = False
    for index, (arg_type, cvar, fact) in enumerate(zip(args, arg_cvars, width_facts, strict=True)):
        variable = cast(SimStackVariable, cvar.variable)
        canonical_offset = fact.stack_offset
        exact_width = fact.width_bytes
        reconciled_name = _reconciled_positive_arg_name_8616(
            variable,
            prototype_names[index] if index < len(prototype_names) else None,
            canonical_offset,
        )
        reconciled_names.append(reconciled_name)
        changed = (
            _apply_arg_cvar_surface_8616(
                cvar,
                name=reconciled_name,
                variable_type=cvar.variable_type,
            )
            or changed
        )
        reconciled, materialized, failed = _constrain_scalar_arg_type_to_stack_slot_8616(
            arg_type,
            slot_width=exact_width,
            arch=arch,
        )
        reconciled_args.append(reconciled)
        classified_count += int(not failed)
        failure_count += int(failed)
        if not failed and canonical_offset in body_widths and exact_width == body_widths[canonical_offset]:
            materialized_wide_offsets.add(canonical_offset)
        reconciled_width = _type_size_bytes_8616(reconciled, arch=arch)
        if (
            materialized
            or isinstance(reconciled, SimTypePointer)
            or reconciled_width == exact_width
        ) and cvar.variable_type != reconciled:
            typing.cast(typing.Any, cvar).variable_type = reconciled
            changed = True
        debug_rows.append(
            (
                canonical_offset,
                variable.size,
                repr(arg_type),
                repr(cvar.variable_type),
                exact_width,
                materialized,
                failed,
            )
        )
        if (
            not failed
            and reconciled_width == exact_width
            and variable.size != exact_width
        ):
            variable.size = exact_width
            changed = True
        if not failed:
            refresh_stack_variable_coordinate_cvar_8616(codegen, cvar)
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
        or cfunc_names != tuple(reconciled_names)
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
            or function_names != tuple(reconciled_names)
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
        for cvar, fact in zip(arg_cvars, width_facts, strict=True)
    )
    changed = materialize_wide_stack_argument_subviews_8616(codegen, subview_owners).changed or changed
    if changed:
        typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def reconcile_callsite_interface_declarations_8616(project: object, codegen: object) -> bool:
    """Run the owned publication, prototype, helper, and declaration lifecycle."""
    from .interprocedural_storage_pipeline import publish_and_reconcile_callsite_interfaces_8616

    return bool(publish_and_reconcile_callsite_interfaces_8616(project, codegen))


def materialize_annotated_stack_prototype_8616(
    project: object,
    codegen: object,
    *,
    fallback_to_positive_bp: bool = True,
) -> bool:
    """Materialize positive BP stack annotations as typed codegen arguments.

    Structured annotations take precedence. Without them, optionally replay
    the binary positive-BP owner after stack-coordinate facts are available.
    The codegen, function, C AST, and prototype objects cross a dynamic
    third-party angr boundary; owned Inertia state is written via typed protocol
    casts.
    """
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
    arch = cast(_ProjectArch8616, project).arch
    typed_func = cast(_PrototypeFunction8616, func)
    authoritative_prototype = authoritative_function_prototype_8616(
        project,
        func,
        argument_count=len(entries),
    )
    current_proto = authoritative_prototype or typed_cfunc.functy or typed_func.prototype
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
    current_surfaces_by_offset: dict[int, tuple[SimType, str | None]] = {}
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
        current_surfaces_by_offset.setdefault(machine_bp_offset, (current_type, current_name))
    if return_type is None or (isinstance(return_type, SimTypeBottom) and return_type.label != "void"):
        return_type = SimTypeShort(False)
    arg_cvars: list[structured_c.CVariable] = []
    arg_types: list[SimType] = []
    arg_names: list[str] = []
    owned_ranges: dict[int, int] = {}
    owner_variables: set[SimStackVariable] = set()
    wide_argument_owners: list[WideStackArgumentOwner8616] = []
    width_stats = StackPrototypeWidthStats8616()
    width_facts: list[FunctionParameterWidthFact8616] = []
    normalized_header_widths = _normalized_header_arg_widths_8616(codegen, entries, arch=arch)
    annotated_object_widths = _annotated_stack_object_widths_8616(entries)
    annotated_names = tuple(name for _offset, name in entries)
    changed = False
    for index, (offset, maybe_name) in enumerate(entries):
        current_surface = current_surfaces_by_offset.get(offset)
        prototype_name = (
            current_surface[1]
            if current_surface is not None
            else current_arg_names[index] if index < len(current_arg_names) else None
        )
        prototype_name_is_unique = bool(
            isinstance(prototype_name, str)
            and prototype_name
            and prototype_name != "local"
            and not prototype_name.startswith("local_")
            and not _is_generated_argument_name_8616(prototype_name)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prototype_name)
            is not None
            and current_arg_names.count(prototype_name) == 1
        )
        annotated_name_is_unique = bool(
            isinstance(maybe_name, str)
            and maybe_name
            and maybe_name != "local"
            and not maybe_name.startswith("local_")
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", maybe_name) is not None
            and annotated_names.count(maybe_name) == 1
        )
        name: str
        if prototype_name_is_unique:
            name = cast(str, prototype_name)
        elif annotated_name_is_unique:
            name = cast(str, maybe_name)
        else:
            name = f"arg_{offset:x}"
        arg_type = (
            current_surface[0]
            if current_surface is not None
            else current_args[index] if index < len(current_args) else SimTypeShort(False)
        )
        if arch is not None:
            arg_type = _with_arch_8616(arg_type, arch)
        if not isinstance(arg_type, SimType):
            arg_type = SimTypeShort(False)
        slot_width = (
            normalized_header_widths[index]
            if index < len(normalized_header_widths)
            else annotated_object_widths.get(offset)
        )
        if slot_width is None:
            slot_width = _exact_stack_slot_width_8616(codegen, offset, arch=arch)
        exact_existing_types = tuple(
            cvar.variable_type
            for cvar in _iter_existing_stack_cvars_at_offset_8616(codegen, offset)
            if isinstance(cvar.variable_type, SimType)
            and (
                _exact_typed_cvar_width_8616(cvar, arch) == slot_width
                or (
                    isinstance(cvar.variable_type, SimTypeChar)
                    and isinstance(slot_width, int)
                    and (_exact_typed_cvar_width_8616(cvar, arch) or 0) < slot_width
                )
            )
        )
        if _type_size_bytes_8616(arg_type, arch=arch) != slot_width and exact_existing_types and all(
            candidate == exact_existing_types[0] for candidate in exact_existing_types[1:]
        ):
            arg_type = exact_existing_types[0]
        value_width = (
            _type_size_bytes_8616(arg_type, arch=arch)
            if isinstance(arg_type, SimTypeChar)
            else slot_width
        )
        raw_width_fact = int(value_width is not None)
        normalized_width_fact = int(isinstance(value_width, int) and value_width > 0)
        if normalized_width_fact:
            assert isinstance(value_width, int)
            width_facts.append(
                FunctionParameterWidthFact8616(
                    stack_offset=offset,
                    width_bytes=value_width,
                )
            )
        arg_type, _, width_failure = _constrain_scalar_arg_type_to_stack_slot_8616(
            arg_type,
            slot_width=value_width,
            arch=arch,
        )
        width_classified = bool(normalized_width_fact and not width_failure)
        width_stats = StackPrototypeWidthStats8616(
            raw_fact_count=width_stats.raw_fact_count + raw_width_fact,
            normalized_fact_count=width_stats.normalized_fact_count + normalized_width_fact,
            classified_fact_count=width_stats.classified_fact_count + int(width_classified),
            materialized_count=width_stats.materialized_count + int(width_classified),
            failure_count=width_stats.failure_count + int(width_failure),
        )
        width = (
            slot_width
            if isinstance(slot_width, int) and slot_width > 0
            else max(2, _type_size_bytes_8616(arg_type, arch=arch))
        )
        cvar, cvar_changed = _ensure_arg_cvar_8616(
            codegen=codegen,
            offset=offset,
            name=name,
            variable_type=arg_type,
            width=width,
        )
        if cvar is None:
            continue
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
        for sibling_cvar in _iter_existing_stack_cvars_at_offset_8616(codegen, offset):
            cvar_changed = _apply_arg_cvar_surface_8616(sibling_cvar, name=name, variable_type=arg_type) or cvar_changed
        changed = cvar_changed or changed
        owned_ranges[offset] = width
        if isinstance(variable, SimStackVariable):
            owner_variables.add(variable)
        wide_argument_owners.append(WideStackArgumentOwner8616(offset, width, cvar))
        arg_cvars.append(cvar)
        arg_types.append(arg_type)
        arg_names.append(name)
    if not arg_cvars:
        typed_codegen._inertia_stack_prototype_width_stats_8616 = width_stats
        parameter_width_facts = tuple(width_facts)
        typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
        _debug_parameter_width_facts_8616("materialize-empty", parameter_width_facts)
        return changed
    typed_codegen._inertia_stack_prototype_width_stats_8616 = width_stats
    parameter_width_facts = tuple(width_facts)
    typed_codegen._inertia_function_parameter_width_facts_8616 = parameter_width_facts
    _debug_parameter_width_facts_8616("materialize", parameter_width_facts)
    if width_stats.classified_fact_count > 0 and width_stats.materialized_count == 0:
        raise RuntimeError("stack prototype width evidence was classified but not materialized")
    subview_result = materialize_wide_stack_argument_subviews_8616(codegen, tuple(wide_argument_owners))
    changed = subview_result.changed or changed
    changed = _prune_stack_slots_covered_by_wide_args_8616(
        codegen,
        owned_ranges,
        owner_variables,
        frozenset(subview_result.retained_variables),
    ) or changed
    existing_args = list(typed_cfunc.arg_list or ())
    if len(existing_args) != len(arg_cvars) or any(existing is not desired for existing, desired in zip(existing_args, arg_cvars, strict=False)):
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
    if not _prototype_equivalent_8616(typed_func.prototype, new_proto) or function_names != tuple(arg_names):
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
    if not _prototype_equivalent_8616(typed_cfunc.functy, new_proto) or cfunc_names != tuple(arg_names):
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
