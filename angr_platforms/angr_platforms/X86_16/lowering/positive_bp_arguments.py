"""Materialize binary-derived positive-BP storage as function arguments.

Layer: Types/Lowering.
Responsibility: convert structured angr positive-BP stack variables into one
canonical near/far argument interface before argument-identity unification.
Consumes alias, widening, and typed facts from binary-derived C-AST storage.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import (
    SimType,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..calling_convention_compat import (
    collect_bp_word_stack_access_offsets_8616,
    collect_wide_stack_argument_width_evidence_8616,
)
from .argument_frame_base import proven_first_argument_machine_bp_offset_8616
from .authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    publish_authoritative_function_prototype_8616,
)
from .callee_argument_interface import (
    CalleeArgumentInterfaceDecision8616,
    reconcile_callee_argument_interface_8616,
)
from .callee_argument_width_evidence import collect_callee_argument_width_evidence_8616
from .function_pointer_parameters import materialized_function_pointer_slots_8616
from .live_stack_word_inputs import collect_live_stack_word_inputs_8616
from .near_return_address_arguments import prune_near_return_address_argument_8616
from .positive_bp_argument_plan import (
    PositiveBpArgumentPlan8616,
    PositiveBpArgumentPlanDecision8616,
    PositiveBpArgumentPlanEntry8616,
    complete_positive_bp_argument_plan_8616,
    complete_positive_bp_body_word_access_plan_8616,
)
from .stack_c_ast_matching import _stack_variable_read_offsets_8616
from .stack_frame_projection import (
    entry_sp_offset_for_machine_bp_range_8616,
    machine_bp_owner_for_entry_sp_view_8616,
)
from .stack_prototype_layout import (
    StackPrototypeArgument8616,
    stack_prototype_argument_layout_8616,
)
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    publish_selected_stack_cvar_projection_8616,
)
from .stack_variable_display_names import generated_stack_variable_name_8616


class _PositiveBpCFunction8616(Protocol):
    """angr C-function fields consumed at the dynamic Lowering boundary."""

    addr: int
    arg_list: Sequence[object] | None
    functy: object
    prototype: object
    statements: object
    unified_local_vars: object
    variables_in_use: object


class _PositiveBpCodegen8616(Protocol):
    """angr codegen fields consumed and updated by this Lowering pass."""

    cfunc: _PositiveBpCFunction8616 | None
    _inertia_authoritative_zero_arg_prototype_8616: bool
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_positive_bp_argument_stats_8616: PositiveBpArgumentStats8616
    _inertia_return_selector_materialized_8616: bool


class _FunctionSurface8616(Protocol):
    """angr function metadata updated with the recovered binary ABI."""

    prototype: object
    prototype_source: PrototypeSource
    is_prototype_guessed: bool


@dataclass(frozen=True, slots=True)
class PositiveBpArgumentStats8616:
    """Closed evidence counts for one positive-BP interface materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _candidate_width_8616(candidate: structured_c.CVariable) -> int:
    """Return the ABI storage width proven by one stack variable."""
    size = candidate.variable.size
    return max(2, size if isinstance(size, int) and size > 0 else 2)


def _optional_arg_list_8616(cfunc: object) -> tuple[object, ...]:
    """Read angr's optional argument surface at the dynamic boundary."""
    try:
        return tuple(cast(_PositiveBpCFunction8616, cfunc).arg_list or ())
    except AttributeError:
        return ()


def _canonical_argument_name_8616(
    candidate: structured_c.CVariable,
    bp_offset: int,
    *,
    entry_sp_offset: int | None,
) -> str:
    """Keep names only when their storage coordinate remains authoritative."""
    variable = cast(SimStackVariable, candidate.variable)
    name = variable.name or candidate.name
    projected_entry_sp_view = (
        isinstance(entry_sp_offset, int)
        and variable.offset == entry_sp_offset
        and entry_sp_offset != bp_offset
    )
    if (
        not projected_entry_sp_view
        and isinstance(name, str)
        and not generated_stack_variable_name_8616(name)
    ):
        return name
    return f"arg_{bp_offset:x}"


def _function_for_codegen_8616(project: object, address: int) -> _FunctionSurface8616 | None:
    """Resolve an existing angr function through its dynamic project boundary."""
    try:
        project_dynamic = cast(Any, project)
        function = project_dynamic.kb.functions.function(addr=address, create=False)
    except (AttributeError, KeyError):
        return None
    return cast(_FunctionSurface8616, function) if function is not None else None


def _existing_interface_matches_8616(
    codegen: object,
    cfunc: _PositiveBpCFunction8616,
    desired: Sequence[structured_c.CVariable],
) -> bool:
    """Return whether angr already owns the exact contiguous BP interface."""
    prototype = cfunc.functy if isinstance(cfunc.functy, SimTypeFunction) else cfunc.prototype
    if not isinstance(prototype, SimTypeFunction):
        return False
    first_argument_bp_offset = proven_first_argument_machine_bp_offset_8616(codegen)
    existing = tuple(cfunc.arg_list or ())
    if not existing:
        # A typed interface can precede its CVariable materialization. Require
        # exact ABI storage before preserving those types over body defaults.
        try:
            layout = stack_prototype_argument_layout_8616(
                prototype,
                cast(Any, codegen).project.arch,
                first_argument_bp_offset=first_argument_bp_offset,
            )
        except AttributeError:
            return False
        return bool(layout) and len(layout) == len(desired) and all(
            isinstance(wanted.variable, SimStackVariable)
            and machine_bp_offset_for_stack_variable_8616(codegen, wanted.variable) == slot.offset
            and isinstance(wanted.variable.size, int)
            and wanted.variable.size > 0
            and max(2, wanted.variable.size) == slot.storage_width
            for slot, wanted in zip(layout, desired, strict=False)
        )
    if len(existing) != len(desired) or len(tuple(prototype.args or ())) != len(desired):
        return False
    cursor = first_argument_bp_offset
    for current, wanted in zip(existing, desired, strict=False):
        if not isinstance(current, structured_c.CVariable):
            return False
        current_variable = current.variable
        wanted_variable = wanted.variable
        if not (
            isinstance(current_variable, SimStackVariable)
            and isinstance(wanted_variable, SimStackVariable)
        ):
            return False
        if (
            machine_bp_offset_for_stack_variable_8616(codegen, current_variable) != cursor
            or machine_bp_offset_for_stack_variable_8616(codegen, wanted_variable) != cursor
            or not isinstance(current_variable.size, int)
            or current_variable.size <= 0
        ):
            return False
        cursor += max(2, current_variable.size)
    return True


def _portable_word_argument_type_8616(project: object, argument_type: SimType) -> SimType:
    """Keep signedness while spelling a 16-bit integer portably as short."""
    if not isinstance(argument_type, SimTypeInt) or isinstance(argument_type, SimTypeShort):
        return argument_type
    try:
        if argument_type.size != 16:
            return argument_type
    except ValueError:
        return argument_type
    normalized = SimTypeShort(argument_type.signed)
    try:
        project_dynamic = cast(Any, project)
        return cast(SimType, normalized.with_arch(project_dynamic.arch))
    except AttributeError:
        return normalized


def _argument_type_for_proven_stack_width_8616(
    project: object,
    argument_type: SimType,
    *,
    proven_width: int | None,
) -> SimType:
    """Apply an exact decoded stack-access width to one scalar argument type."""
    if (
        proven_width == 4
        and isinstance(argument_type, (SimTypeInt, SimTypeChar))
        and not isinstance(argument_type, SimTypeLong)
    ):
        wide_type = SimTypeLong(argument_type.signed)
        try:
            project_dynamic = cast(Any, project)
            return cast(SimType, wide_type.with_arch(project_dynamic.arch))
        except AttributeError:
            return wide_type
    if proven_width == 2 and isinstance(argument_type, SimTypeChar):
        word_type = SimTypeShort(argument_type.signed)
        try:
            project_dynamic = cast(Any, project)
            return cast(SimType, word_type.with_arch(project_dynamic.arch))
        except AttributeError:
            return word_type
    return _portable_word_argument_type_8616(project, argument_type)


def _merge_existing_and_body_argument_type_8616(
    existing_type: SimType,
    entry: PositiveBpArgumentPlanEntry8616,
) -> SimType:
    """Accept body-proven pointer class without replacing an owned pointee."""
    if (
        entry.cvar is not None
        and isinstance(entry.argument_type, SimTypePointer)
        and not isinstance(existing_type, SimTypePointer)
    ):
        return entry.argument_type
    return existing_type


def materialize_positive_bp_arguments_8616(project: object, codegen: object) -> bool:
    """Build one contiguous argument interface from proven BP stack storage.

    Arguments begin at the proven near/far frame base. Contained byte/word
    views are folded into their wider owner; a gap ends recovery. Closed
    pointer facts constrain individual slots, not the full argument census.
    """
    run = _prepare_positive_bp_run_8616(project, codegen)
    if run is None:
        return False
    return_address_result = prune_near_return_address_argument_8616(
        run.project,
        run.codegen,
        run.function,
    )
    run.existing_arg_list = _optional_arg_list_8616(run.cfunc)
    run.changed = bool(return_address_result.changed)

    _collect_positive_bp_candidates_8616(run)
    run.raw_count = (
        sum(len(bucket) for bucket in run.candidates.values())
        + len(run.word_access_offsets)
        + len(run.wide_argument_offsets)
    )
    run.normalized_count = len(
        set(run.candidates).union(run.word_access_offsets, run.wide_argument_offsets)
    )
    read_offsets = _stack_variable_read_offsets_8616(run.cfunc.statements)
    layout_by_offset, authoritative_layout_end = _function_layout_8616(run)
    body_plan_entries = _body_plan_entries_8616(
        run,
        layout_by_offset,
        authoritative_layout_end,
        read_offsets,
    )

    eligible_word_access_offsets = tuple(
        offset
        for offset in run.word_access_offsets
        if authoritative_layout_end is None or offset < authoritative_layout_end
    )
    body_plan_entries = list(
        complete_positive_bp_body_word_access_plan_8616(
            tuple(body_plan_entries),
            eligible_word_access_offsets,
            default_argument_type=SimTypeShort(False),
            wide_access_offsets=run.wide_argument_offsets,
            first_argument_offset=run.first_argument_bp_offset,
        )
    )
    candidate_count = len(body_plan_entries)
    if not body_plan_entries:
        return _positive_bp_no_plan_result_8616(run)

    argument_plan = complete_positive_bp_argument_plan_8616(
        tuple(body_plan_entries),
        collect_callee_argument_width_evidence_8616(run.project, run.cfunc.addr),
        default_argument_type=SimTypeShort(False),
    )
    if argument_plan.decision is PositiveBpArgumentPlanDecision8616.REFUSE:
        _refuse_stats_8616(
            run,
            failure_count=max(candidate_count, argument_plan.evidence.failure_count),
        )
        return run.changed
    candidate_count = len(argument_plan.entries)
    interface_result = reconcile_callee_argument_interface_8616(
        run.project,
        run.codegen,
        candidate_count=candidate_count,
    )
    if (
        interface_result.decision is not CalleeArgumentInterfaceDecision8616.ACCEPT
        and argument_plan.decision
        is not PositiveBpArgumentPlanDecision8616.BODY_CALLER_PHYSICAL
    ):
        _refuse_stats_8616(run, failure_count=candidate_count)
        return run.changed or bool(interface_result.changed)

    existing_args = run.existing_arg_list
    if (
        candidate_count < len(existing_args)
        and not interface_result.evidence.closes_census
        and (
            run.function is None
            or run.function.prototype_source >= PrototypeSource.SIGNATURES
        )
    ):
        _refuse_stats_8616(run, failure_count=len(existing_args) - candidate_count)
        return run.changed or bool(interface_result.changed)

    interface = _desired_candidates_8616(
        run,
        argument_plan,
        body_plan_entries,
        existing_args,
    )
    classified_count = candidate_count

    current_prototype = (
        run.cfunc.functy
        if isinstance(run.cfunc.functy, SimTypeFunction)
        else run.cfunc.prototype
    )
    preserve_existing_types = _existing_interface_matches_8616(
        run.codegen,
        run.cfunc,
        interface.desired,
    )
    authoritative_prototype = authoritative_function_prototype_8616(
        run.project,
        run.function,
        argument_count=candidate_count,
        minimum_source=PrototypeSource.SIGNATURES,
    )
    if authoritative_prototype is not None:
        _apply_authoritative_argument_names_8616(interface, authoritative_prototype)
    selected_prototype = authoritative_prototype or current_prototype
    return_type = (
        selected_prototype.returnty
        if isinstance(selected_prototype, SimTypeFunction)
        else SimTypeShort(False)
    )
    variadic = (
        selected_prototype.variadic
        if isinstance(selected_prototype, SimTypeFunction)
        else False
    )
    source_types = _positive_bp_source_types_8616(
        authoritative_prototype,
        preserve_existing_types,
        current_prototype,
        argument_plan,
        interface.desired,
    )
    # Plan entries already own machine-BP coordinates. Candidate variables may
    # still use entry-SP offsets until the projections below are published.
    argument_types = (
        source_types
        if authoritative_prototype is not None
        else [
            _argument_type_for_proven_stack_width_8616(
                run.project,
                argument_type,
                proven_width=(
                    entry.width
                    if entry.bp_offset in run.word_access_offsets
                    or entry.bp_offset in run.wide_argument_offsets
                    else None
                ),
            )
            for entry, argument_type in zip(
                argument_plan.entries,
                source_types,
                strict=True,
            )
        ]
    )
    _publish_selected_projections_8616(
        run,
        interface,
        argument_types,
        argument_plan,
    )
    new_prototype = SimTypeFunction(
        argument_types,
        return_type,
        arg_names=interface.desired_names,
        variadic=variadic,
    )
    try:
        project_dynamic = cast(Any, run.project)
        new_prototype = cast(
            SimTypeFunction, new_prototype.with_arch(project_dynamic.arch)
        )
    except AttributeError:
        pass

    run.changed = (
        run.changed
        or len(existing_args) != len(interface.desired)
        or any(
            current is not wanted
            for current, wanted in zip(existing_args, interface.desired, strict=False)
        )
    )
    if run.changed:
        run.cfunc.arg_list = interface.desired
    run.changed = _publish_new_prototype_8616(run, new_prototype) or run.changed
    run.changed = (
        _prune_stale_stack_arguments_8616(run, interface.desired_variables)
        or run.changed
    )

    run.codegen._inertia_positive_bp_argument_stats_8616 = (
        PositiveBpArgumentStats8616(
            raw_fact_count=run.raw_count,
            normalized_fact_count=run.normalized_count,
            classified_fact_count=classified_count,
            materialized_count=len(interface.desired),
        )
    )
    if run.changed:
        run.codegen._inertia_codegen_decl_refresh_required_8616 = True
    return run.changed



@dataclass(slots=True)
class _PositiveBpRun8616:
    """Captured run state for one positive-BP interface materialization."""

    project: object
    codegen: _PositiveBpCodegen8616
    cfunc: _PositiveBpCFunction8616
    function: _FunctionSurface8616 | None
    first_argument_bp_offset: int
    word_access_offsets: frozenset[int]
    word_access_ranges: frozenset[tuple[int, int]]
    wide_argument_offsets: frozenset[int]
    variables_in_use: object
    unified_local_vars: object
    existing_arg_list: tuple[object, ...] = ()
    candidates: dict[int, list[structured_c.CVariable]] = field(default_factory=dict)
    body_variable_ids: set[int] = field(default_factory=set)
    raw_count: int = 0
    normalized_count: int = 0
    changed: bool = False


@dataclass(slots=True)
class _DesiredInterface8616:
    """Desired argument surface built from one completed plan."""

    desired: list[structured_c.CVariable] = field(default_factory=list)
    desired_names: list[str] = field(default_factory=list)
    desired_entry_sp_offsets: list[int | None] = field(default_factory=list)
    desired_variables: set[SimStackVariable] = field(default_factory=set)


def _prepare_positive_bp_run_8616(
    project: object,
    codegen: object,
) -> _PositiveBpRun8616 | None:
    """Capture codegen inputs for the pass or refuse early."""
    typed_codegen = cast(_PositiveBpCodegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return None
    if cfunc is None:
        return None
    # angr and focused codegen adapters may omit optional C-function indexes.
    # Capture that dynamic boundary once; owned lowering state remains explicit.
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = None
    try:
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError:
        unified_local_vars = None
    try:
        if typed_codegen._inertia_authoritative_zero_arg_prototype_8616:
            return None
    except AttributeError:
        pass
    first_argument_bp_offset = proven_first_argument_machine_bp_offset_8616(codegen)
    function = _function_for_codegen_8616(project, cfunc.addr)
    word_access_offsets = frozenset(
        collect_bp_word_stack_access_offsets_8616(project, function)
        if function is not None
        else ()
    )
    word_access_offsets |= collect_live_stack_word_inputs_8616(
        codegen, cfunc.statements
    ).offsets
    wide_argument_offsets = frozenset(
        collect_wide_stack_argument_width_evidence_8616(
            project,
            function,
        ).classified_offsets
        if function is not None
        else ()
    )
    try:
        if typed_codegen._inertia_return_selector_materialized_8616:
            return None
    except AttributeError:
        pass
    return _PositiveBpRun8616(
        project=project,
        codegen=typed_codegen,
        cfunc=cfunc,
        function=function,
        first_argument_bp_offset=first_argument_bp_offset,
        word_access_offsets=word_access_offsets,
        word_access_ranges=frozenset((offset, 2) for offset in word_access_offsets),
        wide_argument_offsets=wide_argument_offsets,
        variables_in_use=variables_in_use,
        unified_local_vars=unified_local_vars,
    )


def _positive_bp_candidate_offset_8616(
    run: _PositiveBpRun8616,
    candidate: structured_c.CVariable,
) -> int | None:
    """Resolve an initial angr stack view through exact argument evidence."""
    variable = candidate.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return None
    projected = machine_bp_owner_for_entry_sp_view_8616(
        run.codegen,
        variable,
        run.word_access_ranges,
    )
    return (
        projected
        if isinstance(projected, int)
        else machine_bp_offset_for_stack_variable_8616(run.codegen, variable)
    )


def _collect_positive_bp_candidate_8616(
    run: _PositiveBpRun8616,
    candidate: object,
    *,
    body: bool,
) -> None:
    """Collect one positive-BP candidate without duplicating object identity."""
    if not isinstance(candidate, structured_c.CVariable):
        return
    variable = candidate.variable
    bp_offset = _positive_bp_candidate_offset_8616(run, candidate)
    if (
        not isinstance(variable, SimStackVariable)
        or not isinstance(bp_offset, int)
        or bp_offset < run.first_argument_bp_offset
    ):
        return
    bucket = run.candidates.setdefault(bp_offset, [])
    if all(existing is not candidate for existing in bucket):
        bucket.append(candidate)
    if body:
        run.body_variable_ids.add(id(variable))


def _collect_positive_bp_candidates_8616(run: _PositiveBpRun8616) -> None:
    """Collect candidates from the body and both angr argument surfaces."""
    for node in _iter_c_nodes_deep_8616(run.cfunc.statements):
        _collect_positive_bp_candidate_8616(run, node, body=True)
    if isinstance(run.variables_in_use, dict):
        for cvar in tuple(run.variables_in_use.values()):
            _collect_positive_bp_candidate_8616(run, cvar, body=False)
    for cvar in run.existing_arg_list:
        _collect_positive_bp_candidate_8616(run, cvar, body=False)


def _function_layout_8616(
    run: _PositiveBpRun8616,
) -> tuple[dict[int, StackPrototypeArgument8616], int | None]:
    """Resolve the authoritative prototype argument layout keyed by BP offset."""
    try:
        project_arch = cast(Any, run.project).arch
        function_layout = (
            stack_prototype_argument_layout_8616(
                run.function.prototype,
                project_arch,
                first_argument_bp_offset=run.first_argument_bp_offset,
            )
            if run.function is not None
            and not run.function.is_prototype_guessed
            and run.function.prototype_source >= PrototypeSource.SIGNATURES
            else ()
        )
    except AttributeError:
        function_layout = ()
    layout_by_offset = {argument.offset: argument for argument in function_layout}
    for argument in materialized_function_pointer_slots_8616(
        run.codegen, cast(Any, run.project).arch
    ):
        layout_by_offset.setdefault(argument.offset, argument)
    authoritative_layout_end = (
        function_layout[-1].offset + function_layout[-1].storage_width
        if function_layout
        and run.function is not None
        and run.function.prototype_source >= PrototypeSource.SIGNATURES
        else None
    )
    return layout_by_offset, authoritative_layout_end


def _canonical_body_candidate_8616(
    body_bucket: list[structured_c.CVariable],
    body_owner_starts: tuple[structured_c.CVariable, ...],
    existing_for_offset: tuple[object, ...],
    entry_sp_offset: int | None,
) -> structured_c.CVariable:
    """Pick the canonical candidate for one proven BP slot."""
    if (
        isinstance(entry_sp_offset, int)
        and body_owner_starts
        and len(existing_for_offset) == 1
    ):
        return cast(structured_c.CVariable, existing_for_offset[0])
    if body_owner_starts:
        return max(body_owner_starts, key=_candidate_width_8616)
    if len(existing_for_offset) == 1:
        return cast(structured_c.CVariable, existing_for_offset[0])
    return max(body_bucket, key=_candidate_width_8616)


def _body_plan_entries_8616(
    run: _PositiveBpRun8616,
    layout_by_offset: dict[int, StackPrototypeArgument8616],
    authoritative_layout_end: int | None,
    read_offsets: frozenset[int],
) -> list[PositiveBpArgumentPlanEntry8616]:
    """Walk contiguous proven BP slots and build one plan entry each."""
    body_plan_entries: list[PositiveBpArgumentPlanEntry8616] = []
    cursor = run.first_argument_bp_offset
    for offset in sorted(run.candidates):
        if offset < cursor:
            continue
        if authoritative_layout_end is not None and offset >= authoritative_layout_end:
            break
        if offset != cursor:
            break
        bucket = run.candidates[offset]
        body_bucket = [
            item for item in bucket if id(item.variable) in run.body_variable_ids
        ]
        if not body_bucket:
            break
        if not any(
            cast(SimStackVariable, item.variable).offset in read_offsets
            for item in body_bucket
        ):
            break
        layout_argument = layout_by_offset.get(offset)
        width = (
            layout_argument.storage_width
            if layout_argument is not None
            else max(_candidate_width_8616(item) for item in body_bucket)
        )
        entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
            run.codegen,
            offset,
            width,
        )
        existing_for_offset = tuple(
            item
            for item in run.existing_arg_list
            if isinstance(item, structured_c.CVariable)
            and isinstance(item.variable, SimStackVariable)
            and _positive_bp_candidate_offset_8616(run, item) == offset
            and _candidate_width_8616(item) >= width
        )
        body_owner_starts = tuple(
            item
            for item in body_bucket
            if not isinstance(entry_sp_offset, int)
            or cast(SimStackVariable, item.variable).offset == entry_sp_offset
        )
        canonical = _canonical_body_candidate_8616(
            body_bucket,
            body_owner_starts,
            existing_for_offset,
            entry_sp_offset,
        )
        name = _canonical_argument_name_8616(
            canonical,
            offset,
            entry_sp_offset=entry_sp_offset,
        )
        argument_type = (
            layout_argument.argument_type
            if layout_argument is not None
            else canonical.variable_type
            if isinstance(canonical.variable_type, SimType)
            else SimTypeShort(False)
        )
        body_plan_entries.append(
            PositiveBpArgumentPlanEntry8616(
                bp_offset=offset,
                width=width,
                name=name,
                argument_type=argument_type,
                cvar=canonical,
            )
        )
        cursor += width
    return body_plan_entries


def _refuse_stats_8616(run: _PositiveBpRun8616, *, failure_count: int = 0) -> None:
    """Publish refusal stats preserving raw/normalized evidence counts."""
    run.codegen._inertia_positive_bp_argument_stats_8616 = (
        PositiveBpArgumentStats8616(
            raw_fact_count=run.raw_count,
            normalized_fact_count=run.normalized_count,
            failure_count=failure_count,
        )
    )


def _positive_bp_no_plan_result_8616(run: _PositiveBpRun8616) -> bool:
    """Reconcile the interface when no body plan entries survived."""
    interface_result = reconcile_callee_argument_interface_8616(
        run.project,
        run.codegen,
        candidate_count=len(run.existing_arg_list),
    )
    _refuse_stats_8616(run)
    return run.changed or bool(interface_result.changed)


def _reusable_existing_candidate_8616(
    run: _PositiveBpRun8616,
    entry: PositiveBpArgumentPlanEntry8616,
    entry_sp_offset: int | None,
    existing_args: tuple[object, ...],
) -> structured_c.CVariable | None:
    """Reuse a uniquely matching existing argument when one exists."""
    reusable = tuple(
        existing
        for existing in existing_args
        if isinstance(existing, structured_c.CVariable)
        and isinstance(existing.variable, SimStackVariable)
        and machine_bp_offset_for_stack_variable_8616(
            run.codegen, existing.variable
        )
        == entry.bp_offset
        and _candidate_width_8616(existing) == entry.width
        and (
            not isinstance(entry_sp_offset, int)
            or existing.variable.offset == entry_sp_offset
        )
    )
    return cast(structured_c.CVariable, reusable[0]) if len(reusable) == 1 else None


def _fresh_argument_candidate_8616(
    run: _PositiveBpRun8616,
    entry: PositiveBpArgumentPlanEntry8616,
    entry_sp_offset: int | None,
) -> structured_c.CVariable:
    """Build a fresh stack argument variable for an unowned slot."""
    return structured_c.CVariable(
        SimStackVariable(
            entry_sp_offset if isinstance(entry_sp_offset, int) else entry.bp_offset,
            entry.width,
            base="bp",
            name=entry.name,
            region=run.cfunc.addr,
        ),
        variable_type=entry.argument_type,
        codegen=run.codegen,
    )


def _desired_candidates_8616(
    run: _PositiveBpRun8616,
    argument_plan: PositiveBpArgumentPlan8616,
    body_plan_entries: list[PositiveBpArgumentPlanEntry8616],
    existing_args: tuple[object, ...],
) -> _DesiredInterface8616:
    """Materialize the desired argument list from the completed plan."""
    interface = _DesiredInterface8616()
    body_coordinate_deltas = {
        entry_sp_offset - entry.bp_offset
        for entry in body_plan_entries
        for entry_sp_offset in (
            entry_sp_offset_for_machine_bp_range_8616(
                run.codegen,
                entry.bp_offset,
                entry.width,
            ),
        )
        if isinstance(entry_sp_offset, int)
    }
    body_coordinate_delta = (
        next(iter(body_coordinate_deltas))
        if len(body_coordinate_deltas) == 1
        else None
    )
    for entry in argument_plan.entries:
        entry_sp_offset = (
            entry.bp_offset + body_coordinate_delta
            if isinstance(body_coordinate_delta, int)
            else entry_sp_offset_for_machine_bp_range_8616(
                run.codegen,
                entry.bp_offset,
                entry.width,
            )
        )
        candidate = entry.cvar
        if candidate is None:
            candidate = _reusable_existing_candidate_8616(
                run, entry, entry_sp_offset, existing_args
            )
        if candidate is None:
            candidate = _fresh_argument_candidate_8616(run, entry, entry_sp_offset)
        variable = cast(SimStackVariable, candidate.variable)
        variable.size = entry.width
        variable.name = entry.name
        candidate.variable_type = entry.argument_type
        interface.desired.append(candidate)
        interface.desired_names.append(entry.name)
        interface.desired_entry_sp_offsets.append(entry_sp_offset)
        interface.desired_variables.add(variable)
    return interface


def _apply_authoritative_argument_names_8616(
    interface: _DesiredInterface8616,
    authoritative_prototype: SimTypeFunction,
) -> None:
    """Overlay authoritative prototype names onto the desired surface."""
    authoritative_names = tuple(authoritative_prototype.arg_names or ())
    for index, candidate in enumerate(interface.desired):
        if index >= len(authoritative_names):
            break
        authoritative_name = authoritative_names[index]
        if isinstance(authoritative_name, str) and authoritative_name:
            cast(SimStackVariable, candidate.variable).name = authoritative_name
            interface.desired_names[index] = authoritative_name


def _positive_bp_source_types_8616(
    authoritative_prototype: SimTypeFunction | None,
    preserve_existing_types: bool,
    current_prototype: object,
    argument_plan: PositiveBpArgumentPlan8616,
    desired: list[structured_c.CVariable],
) -> list[SimType]:
    """Pick the source argument types for the rebuilt prototype."""
    if authoritative_prototype is not None:
        return list(authoritative_prototype.args or ())
    if preserve_existing_types and isinstance(current_prototype, SimTypeFunction):
        current_types = list(current_prototype.args or ())
        return [
            _merge_existing_and_body_argument_type_8616(current_types[index], entry)
            for index, entry in enumerate(argument_plan.entries)
        ]
    return [cast(SimType, candidate.variable_type) for candidate in desired]


def _publish_selected_projections_8616(
    run: _PositiveBpRun8616,
    interface: _DesiredInterface8616,
    argument_types: list[SimType],
    argument_plan: PositiveBpArgumentPlan8616,
) -> None:
    """Publish the selected machine-BP projection on each argument."""
    for candidate, argument_type, entry, entry_sp_offset in zip(
        interface.desired,
        argument_types,
        argument_plan.entries,
        interface.desired_entry_sp_offsets,
        strict=True,
    ):
        candidate.variable_type = argument_type
        variable = cast(SimStackVariable, candidate.variable)
        publish_selected_stack_cvar_projection_8616(
            run.codegen,
            candidate,
            bp_offset=entry.bp_offset,
            size=variable.size,
            entry_sp_offset=entry_sp_offset,
        )


def _publish_new_prototype_8616(
    run: _PositiveBpRun8616,
    new_prototype: SimTypeFunction,
) -> bool:
    """Install the prototype on the cfunc surfaces and the function."""
    changed = False
    cfunc = run.cfunc
    if (
        cfunc.functy != new_prototype
        or not isinstance(cfunc.functy, SimTypeFunction)
        or tuple(cfunc.functy.arg_names or ()) != tuple(new_prototype.arg_names or ())
    ):
        cfunc.functy = new_prototype
        changed = True
    try:
        if (
            cfunc.prototype != new_prototype
            or not isinstance(cfunc.prototype, SimTypeFunction)
            or tuple(cfunc.prototype.arg_names or ())
            != tuple(new_prototype.arg_names or ())
        ):
            cfunc.prototype = new_prototype
            changed = True
    except AttributeError:
        pass
    function = run.function
    if function is not None:
        function.prototype = new_prototype
        if function.prototype_source < PrototypeSource.CCA_DECOMPILER:
            function.prototype_source = PrototypeSource.CCA_DECOMPILER
        publish_authoritative_function_prototype_8616(
            run.project,
            cfunc.addr,
            new_prototype,
            source=function.prototype_source,
        )
    return changed


def _prune_stale_stack_arguments_8616(
    run: _PositiveBpRun8616,
    desired_variables: set[SimStackVariable],
) -> bool:
    """Drop stale stack locals displaced by the materialized arguments."""
    changed = False
    if isinstance(run.variables_in_use, dict):
        for variable in tuple(run.variables_in_use):
            if not isinstance(variable, SimStackVariable):
                continue
            bp_offset = machine_bp_offset_for_stack_variable_8616(
                run.codegen, variable
            )
            if (
                isinstance(bp_offset, int)
                and bp_offset >= 4
                and variable not in desired_variables
                and id(variable) not in run.body_variable_ids
            ):
                del run.variables_in_use[variable]
                changed = True
    if isinstance(run.unified_local_vars, dict):
        for variable in tuple(run.unified_local_vars):
            if isinstance(variable, SimStackVariable) and variable in desired_variables:
                del run.unified_local_vars[variable]
                changed = True
    return changed


__all__ = ["PositiveBpArgumentStats8616", "materialize_positive_bp_arguments_8616"]
