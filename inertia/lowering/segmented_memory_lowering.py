# cython: language_level=3, infer_types=True
"""Apply runtime segmented-memory lowering for proven address forms.

Layer: Types/Lowering.
Responsibility: runtime lowering for proven segmented-memory expressions.
Consumes alias, widening, and typed facts to convert segmented memory carriers
into runtime helper calls or materialized stack/global accesses.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic attribute access in this module is limited to the angr structured-C and
codegen boundary, where upstream classes expose version-dependent attributes.
"""

from __future__ import annotations
import cython

import builtins
import contextlib
import functools
import typing
from collections.abc import Callable, MutableMapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from archinfo import Arch

from inertia.ir.core import MemSpace
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616, _same_c_expression_8616
from inertia.pipeline.contracts import SemanticLaneState
from inertia.structuring.string_io_loop_carriers import materialize_string_io_loop_carriers_8616
from inertia.widening.segmented_load_identity import SegmentedLoadIdentity8616, segmented_load_tags_8616

from .assignment_lvalue_casts import normalize_scalar_assignment_lvalues_8616
from .authoritative_function_prototypes import publish_codegen_function_prototype_8616
from .balanced_memory_stack_restore import materialize_balanced_immediate_register_restores_8616
from .direction_flag_state import lower_direction_flag_state_8616
from .gp_register_state import (
    GPRegisterStateLoweringStats8616,
    lower_architectural_gp_register_state_8616,
)
from .gp_stack_restore import materialize_gp_stack_restores_8616
from .linear_global_decomposition_cache import (
    LinearGlobalDecompositionCache8616,
    LinearGlobalDecompositionCacheStats8616,
)
from .near_pointer_argument import (
    NearPointerArgumentFact8616,
    collect_near_pointer_argument_facts_8616,
)
from .near_pointer_index_binding import bind_byte_pointer_index_8616
from .near_pointer_type import SimTypeNearPointer16_8616, near_pointer_type_8616, with_near_pointer_parameter_8616
from .packed_flags_state import lower_packed_flags_live_in_8616
from .physical_registers import physical_register_name_8616
from .pointer_store_consumption import (
    PointerStoreConsumptionEvidence8616,
    PointerStoreConsumptionFailure8616,
    prove_pointer_store_consumption_8616,
    prove_pointer_store_source_preservation_8616,
)
from .positive_bp_arguments import materialize_positive_bp_arguments_8616
from .real_mode_linear import (
    RealModeLinearStackAccess8616,
    _decompose_linear_global_terms_8616,
    _has_stack_storage_evidence_for_displacement_8616,
    _known_bp_stack_offsets_8616,
    _segment_base_name_8616,
    _single_assignment_rhs_8616,
    _single_assignment_rhs_for_virtual_name_8616,
    _stack_offset_from_expr_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from .segment_access_policy import (
    instruction_addrs_from_node_8616,
    may_lower_codegen_access_to_entry_ds_object_8616,
)
from .segment_register_state import (
    SegmentRegisterStateLoweringStats8616,
    lower_architectural_segment_register_state_8616,
    runtime_segment_name_for_variable_8616,
    runtime_segment_push_source_cvar_8616,
)
from .stack_argument_identity import unify_positive_bp_argument_identity_8616
from .stack_lowering_from_facts import _canonical_stack_offset_8616
from .stack_pointer_snapshot import (
    StackPointerSnapshotStats8616,
    StackPointerSnapshotTracker8616,
)
from .stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
    materialize_exact_trailing_stack_argument_8616,
)
from .stack_value_projection import normalize_pointer_scalar_temporaries_8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
import dataclasses
import operator
DirectSegmentedGlobalLoadEvidence8616 = typing.TypeVar("DirectSegmentedGlobalLoadEvidence8616")
DirectSegmentedGlobalStoreEvidence8616 = typing.TypeVar("DirectSegmentedGlobalStoreEvidence8616")

_CarrierKey8616 = typing.TypeAliasType("_CarrierKey8616", tuple[str, int | str])


class _AngrFunctionTypeBoundary8616(Protocol):
    """Typed view of dynamic angr function-type metadata at the codegen boundary."""

    args: Sequence[object] | None


class _AngrFunctionMetadataBoundary8616(Protocol):
    """Typed prototype field on the dynamic angr function boundary."""

    prototype: object


class _AngrCFunctionBoundary8616(Protocol):
    """Typed view of dynamic angr C function state at the codegen boundary."""

    addr: cython.longlong
    arg_list: Sequence[object] | None
    functy: _AngrFunctionTypeBoundary8616
    statements: object


@cython.ccall
def _replace_cfunc_statements_root_8616(cfunc: _AngrCFunctionBoundary8616, root: object) -> None:
    """Replace the supported structured-C statements root."""
    cfunc.statements = root


class _AngrProjectBoundary8616(Protocol):
    """Typed view of dynamic angr project state at the codegen boundary."""

    arch: Arch


class _AngrCodegenBoundary8616(Protocol):
    """Typed view of dynamic angr codegen state used by this lowering pass."""

    cfunc: _AngrCFunctionBoundary8616 | None
    project: _AngrProjectBoundary8616 | None
    _func: object | None
    _inertia_assignment_maps: object | None
    _inertia_segment_register_state_lowering_stats_8616: SegmentRegisterStateLoweringStats8616
    _inertia_gp_register_state_lowering_stats_8616: GPRegisterStateLoweringStats8616
    _inertia_stack_offset_cache: object
    _inertia_near_pointer_argument_classified_offsets_8616: object
    _inertia_near_pointer_argument_facts_8616: object
    _inertia_near_pointer_argument_materialized_offsets_8616: object
    _inertia_near_pointer_argument_refusals_8616: object
    _inertia_near_pointer_argument_stats_8616: NearPointerArgumentStats8616
    _inertia_stack_pointer_snapshot_stats_8616: StackPointerSnapshotStats8616
    _inertia_linear_global_decomposition_cache_stats_8616: LinearGlobalDecompositionCacheStats8616
    _inertia_final_codegen_projection_replayer_8616: Callable[[object], cython.bint]
    _inertia_segmented_access_width_lane_8616: SemanticLaneState
    _inertia_semantic_lanes_8616: object


@dataclasses.dataclass(frozen=True, )
class SegmentedMemoryExpr:
    """Proven segmented-memory access recovered from structured C expressions."""

    space: object
    segment_expr: object
    offset_expr: object
    width_bits: cython.longlong
    access: object


def _reset_segmented_access_width_lane_8616(
    codegen: _AngrCodegenBoundary8616,
) -> SemanticLaneState:
    """Start one closed evidence lane for IR-backed segmented access widths."""
    lane = SemanticLaneState(name="segmented_access_width")
    codegen._inertia_segmented_access_width_lane_8616 = lane
    try:
        existing = codegen._inertia_semantic_lanes_8616
    except AttributeError:
        existing = ()
    retained = tuple(
        item
        for item in iter(existing)
        if isinstance(item, SemanticLaneState) and operator.ne(item.name, lane.name)
    )
    codegen._inertia_semantic_lanes_8616 = (*retained, lane)
    return lane


@cython.ccall
def _segmented_access_width_lane_8616(
    codegen: _AngrCodegenBoundary8616,
) -> SemanticLaneState:
    """Return the active typed width-projection lane, creating it when needed."""
    try:
        lane = codegen._inertia_segmented_access_width_lane_8616
    except AttributeError:
        return _reset_segmented_access_width_lane_8616(codegen)
    if not isinstance(lane, SemanticLaneState):
        return _reset_segmented_access_width_lane_8616(codegen)
    return lane


def _logical_segmented_access_width_bits_8616(
    expr: object,
    matched: SegmentedMemoryExpr,
    codegen: _AngrCodegenBoundary8616,
) -> int | None:
    """Constrain C width without promoting an execution slice to its operand."""
    cfunc: object
    project: object
    space: object
    source_addrs = instruction_addrs_from_node_8616(expr)
    cfunc = codegen.cfunc
    project = codegen.project
    if not source_addrs or cfunc is None or project is None:
        return None
    function_addr = cfunc.addr
    if not isinstance(function_addr, int):
        return None
    resolution = registered_function_ssa_artifact_8616(project, function_addr)
    if (
        resolution.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
        or resolution.artifact is None
        or resolution.artifact.logical_memory is None
        or not resolution.artifact.logical_memory.closed
    ):
        return None
    space = {
        "DS": MemSpace.DS,
        "ES": MemSpace.ES,
        "SS": MemSpace.SS,
    }.get(matched.space)
    if space is None:
        return None
    candidates = tuple(
        access
        for access in iter(resolution.artifact.logical_memory.accesses)
        if access.key.insn_addr in source_addrs and access.address.space is space
    )
    if not candidates:
        return None
    widths = frozenset(int(access.address.size) * 8 for access in iter(candidates))
    # Site and segment alone do not prove consumption of the complete operand.
    if len(widths) == 1 and next(iter(widths)) > matched.width_bits:
        return None
    lane = _segmented_access_width_lane_8616(codegen)
    lane.raw += 1
    lane.normalized += 1
    lane.classified += 1
    if len(widths) != 1:
        lane.failures += 1
        return None
    lane.materialized += 1
    lane.verified += 1
    return next(iter(widths))


class NearPointerArgumentRefusalReason8616(StrEnum):
    """Typed reasons a binary-proven pointer argument cannot be materialized."""

    MISSING_FUNCTION_PROTOTYPE = "missing_function_prototype"
    NO_CANONICAL_ARGUMENT = "no_canonical_argument"
    AMBIGUOUS_CANONICAL_ARGUMENT = "ambiguous_canonical_argument"
    INTERFACE_CARDINALITY_MISMATCH = "interface_cardinality_mismatch"


@dataclasses.dataclass(frozen=True, )
class NearPointerArgumentRefusal8616:
    """Structured interface evidence for one refused pointer argument."""

    reason: NearPointerArgumentRefusalReason8616
    stack_offset: cython.longlong
    argument_count: cython.longlong
    argument_match_count: cython.longlong
    prototype_argument_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class NearPointerArgumentStats8616:
    """Closed evidence counters for near-pointer argument materialization."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    refusals: tuple[NearPointerArgumentRefusal8616, ...] = ()


@cython.ccall
def _record_near_pointer_argument_refusal_8616(
    codegen: _AngrCodegenBoundary8616,
    *,
    reason: NearPointerArgumentRefusalReason8616,
    stack_offset: cython.longlong,
    argument_count: cython.longlong,
    argument_match_count: cython.longlong,
    prototype_argument_count: cython.longlong,
) -> None:
    """Record one deduplicated typed refusal at the dynamic codegen boundary."""
    refusal = NearPointerArgumentRefusal8616(
        reason=reason,
        stack_offset=stack_offset,
        argument_count=argument_count,
        argument_match_count=argument_match_count,
        prototype_argument_count=prototype_argument_count,
    )
    if refusal not in codegen._inertia_near_pointer_argument_refusals_8616:
        codegen._inertia_near_pointer_argument_refusals_8616.append(refusal)


@cython.ccall
def _strip_casts_8616(node: object) -> object:
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


@cython.ccall
def _dynamic_angr_attr_8616(obj: object, name: object, default: object | None = None) -> object | None:
    """Read version-dependent attributes at the dynamic angr/codegen boundary."""
    return builtins.getattr(obj, name, default)


@cython.ccall
def _dynamic_angr_setattr_8616(obj: object, name: object, value: object) -> None:
    """Write version-dependent attributes at the dynamic angr/codegen boundary."""
    builtins.setattr(obj, name, value)


@cython.ccall
def _dynamic_angr_int_attr_8616(obj: object, name: object, default: cython.longlong = 0) -> cython.longlong:
    """Read integer metadata at the dynamic angr/codegen boundary."""
    value = _dynamic_angr_attr_8616(obj, name, default)
    return value if isinstance(value, int) else default


@cython.ccall
def _dynamic_angr_sequence_attr_8616(obj: object, name: object) -> Sequence[object]:
    """Read sequence metadata at the dynamic angr/codegen boundary."""
    value = _dynamic_angr_attr_8616(obj, name, ())
    return value if isinstance(value, (list, tuple)) else ()


@cython.ccall
def _bump_codegen_counter_8616(codegen: object, name: object, amount: cython.longlong = 1) -> None:
    """Update an ad-hoc metric at the dynamic angr codegen boundary."""
    _dynamic_angr_setattr_8616(codegen, name, _dynamic_angr_int_attr_8616(codegen, name) + amount)


@cython.ccall
def _constant_value_8616(node: object) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


@cython.ccall
def _zero_plus_pointer_arg_8616(
    expr: object,
    codegen: _AngrCodegenBoundary8616 | None,
) -> structured_c.CVariable | None:
    expr = _strip_casts_8616(expr)
    if isinstance(expr, structured_c.CVariable) and _is_near_pointer_arg_cvar_8616(expr, codegen):
        return expr
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None
    if _constant_value_8616(expr.lhs) == 0:
        return _zero_plus_pointer_arg_8616(expr.rhs, codegen)
    if _constant_value_8616(expr.rhs) == 0:
        return _zero_plus_pointer_arg_8616(expr.lhs, codegen)
    return None


@cython.ccall
def _zero_plus_cvar_8616(expr: object) -> structured_c.CVariable | None:
    """Return the sole C variable in an expression with only additive zeros."""
    expr = _strip_casts_8616(expr)
    if isinstance(expr, structured_c.CVariable):
        return expr
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None
    if _constant_value_8616(expr.lhs) == 0:
        return _zero_plus_cvar_8616(expr.rhs)
    if _constant_value_8616(expr.rhs) == 0:
        return _zero_plus_cvar_8616(expr.lhs)
    return None


@cython.ccall
def _scaled_index_for_access_width_8616(
    expr: object,
    access_width_bytes: cython.longlong,
) -> structured_c.CExpression | None:
    """Return an index only when its byte scale exactly matches the access width."""
    expr = _strip_casts_8616(expr)
    if access_width_bytes == 1 and isinstance(expr, structured_c.CExpression):
        return expr
    if access_width_bytes <= 0 or not isinstance(expr, structured_c.CBinaryOp):
        return None
    if expr.op == "Shl":
        shift = _constant_value_8616(expr.rhs)
        if isinstance(shift, int) and shift >= 0 and operator.eq(1 << shift, access_width_bytes):
            return expr.lhs
        return None
    if expr.op != "Mul":
        return None
    if operator.eq(_constant_value_8616(expr.lhs), access_width_bytes):
        return expr.rhs
    if operator.eq(_constant_value_8616(expr.rhs), access_width_bytes):
        return expr.lhs
    return None


@cython.ccall
def _cvar_plus_scaled_index_8616(
    expr: object,
    access_width_bytes: cython.longlong,
) -> object:
    """Match one C variable plus an index scaled by the exact element width."""
    base: object
    index: object
    base_expr: object
    index_expr: object
    expr = _strip_casts_8616(expr)
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Add":
        return None
    for base_expr, index_expr in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
        base = _zero_plus_cvar_8616(base_expr)
        index = _scaled_index_for_access_width_8616(index_expr, access_width_bytes)
        if base is not None and index is not None:
            return base, index
    return None


@cython.ccall
def _stack_offset_for_cvar_8616(
    cvar: object,
    codegen: object,
) -> int | None:
    """Return one stack variable's machine-BP coordinate."""
    variable: object
    if not isinstance(cvar, structured_c.CVariable):
        return None
    for variable in (cvar.variable, cvar.unified_variable):
        offset = _dynamic_angr_attr_8616(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and isinstance(offset, int):
            if codegen is not None:
                bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
                if isinstance(bp_offset, int):
                    return bp_offset
            return offset
    return None


@cython.ccall
def _near_pointer_arg_type_8616(
    cvar: object,
    codegen: object,
) -> SimTypePointer | None:
    """Return the canonical pointer type for one proven argument storage identity."""
    arg: object
    index: object
    if not isinstance(cvar, structured_c.CVariable):
        return None
    if isinstance(cvar.variable_type, SimTypePointer):
        return cvar.variable_type
    if codegen is None or codegen.cfunc is None:
        return None
    cfunc = codegen.cfunc
    arg_list = tuple(cfunc.arg_list or ())
    prototype_args = tuple(_dynamic_angr_sequence_attr_8616(cfunc.functy, "args"))
    cvar_offset = _stack_offset_for_cvar_8616(cvar, codegen)
    matches: list[SimTypePointer] = []
    for index, arg in enumerate(arg_list):
        if not isinstance(arg, structured_c.CVariable):
            continue
        same_object = arg is cvar
        same_offset = (
            isinstance(cvar_offset, int)
            and operator.eq(_stack_offset_for_cvar_8616(arg, codegen), cvar_offset)
        )
        if not same_object and not same_offset:
            continue
        proto_type = prototype_args[index] if index < len(prototype_args) else None
        if isinstance(arg.variable_type, SimTypePointer):
            matches.append(arg.variable_type)
        elif isinstance(proto_type, SimTypePointer):
            matches.append(proto_type)
    return matches[0] if len(matches) == 1 else None


@cython.ccall
def _is_near_pointer_arg_cvar_8616(cvar: object, codegen: _AngrCodegenBoundary8616 | None) -> cython.bint:
    """Return whether a C variable joins to one canonical near-pointer argument."""
    return _near_pointer_arg_type_8616(cvar, codegen) is not None


@cython.ccall
def _pointer_element_width_bits_8616(pointer_type: SimTypePointer) -> int | None:
    """Return the pointee width in bits when angr exposes a complete type."""
    try:
        width = pointer_type.pts_to.size
    except (AttributeError, ValueError):
        return None
    return width if isinstance(width, int) and width > 0 else None


@cython.ccall
def _active_function_for_codegen_8616(codegen: _AngrCodegenBoundary8616) -> object | None:
    """Resolve the current angr function at the dynamic project boundary."""
    function: object
    if codegen.cfunc is None or codegen.project is None:
        return None
    try:
        if codegen._func is not None:
            return codegen._func
    except AttributeError:
        pass
    try:
        function = typing.cast(typing.Any, codegen.project).kb.functions.get(codegen.cfunc.addr)
        return function
    except (AttributeError, KeyError, TypeError):
        return None


@cython.ccall
def _materialize_near_pointer_gate_8616(
    matched: SegmentedMemoryExpr, codegen: object
) -> cython.bint:
    """Only DS accesses on a live codegen+cfunc+project can materialize."""
    return not (
        matched.space != "DS"
        or codegen is None
        or codegen.cfunc is None
        or codegen.project is None
    )


def _canonical_cvar_for_stack_offset_8616(
    matched: SegmentedMemoryExpr,
    codegen: _AngrCodegenBoundary8616,
    proven_stack_offset: object,
) -> object:
    """Resolve the canonical cvar and proven stack offset for ``matched``."""
    cfunc: object
    cvar: object
    indexed: object
    cvar = _zero_plus_cvar_8616(matched.offset_expr)
    if cvar is None and matched.width_bits % 8 == 0:
        indexed = _cvar_plus_scaled_index_8616(
            matched.offset_expr,
            matched.width_bits // 8,
        )
        if indexed is not None:
            cvar, _index = indexed
    stack_offset = _stack_offset_for_cvar_8616(cvar, codegen)
    if proven_stack_offset is not None:
        if isinstance(stack_offset, int) and operator.ne(stack_offset, proven_stack_offset):
            return None
        stack_offset = proven_stack_offset
        cfunc = codegen.cfunc
        if cfunc is None:
            return None
        canonical_matches = tuple(
            argument
            for argument in builtins.iter(tuple(cfunc.arg_list or ()))
            if isinstance(argument, structured_c.CVariable)
            and operator.eq(_stack_offset_for_cvar_8616(argument, codegen), stack_offset)
        )
        if len(canonical_matches) != 1:
            return None
        cvar = canonical_matches[0]
    if cvar is None or not isinstance(stack_offset, int):
        return None
    return cvar, stack_offset


def _near_pointer_matching_facts_8616(
    matched: SegmentedMemoryExpr,
    codegen: _AngrCodegenBoundary8616,
    stack_offset: cython.longlong,
    segment_identity_proven: cython.bint,
) -> object:
    """Return dereference facts matching offset+width, gated by DS proof."""
    try:
        facts = codegen._inertia_near_pointer_argument_facts_8616
    except AttributeError:
        return None
    matching_facts = tuple(
        fact
        for fact in iter(facts)
        if operator.eq(fact.stack_offset, stack_offset) and operator.eq(fact.access_width_bytes * 8, matched.width_bits)
    )
    if not matching_facts:
        return None
    if not segment_identity_proven and not may_lower_codegen_access_to_entry_ds_object_8616(
        codegen,
        matched,
        instruction_addrs=frozenset(fact.dereference_ins_addr for fact in iter(matching_facts)),
        segment_register="ds",
        offset=None,
        width=matched.width_bits // 8,
    ):
        return None
    return matching_facts


@cython.ccall
def _materialize_missing_argument_8616(
    codegen: _AngrCodegenBoundary8616,
    cvar: structured_c.CVariable,
    stack_offset: cython.longlong,
    pointer_type: SimTypeNearPointer16_8616,
    arguments: object,
    prototype_args: object,
) -> object:
    """Materialize a trailing stack argument when no canonical match exists."""
    cfunc: object
    materialized_argument: object
    materialized_argument = materialize_exact_trailing_stack_argument_8616(
        codegen.project,
        codegen,
        candidate=cvar,
        stack_offset=stack_offset,
        argument_type=pointer_type,
        width=2,
    )
    if materialized_argument is None:
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.NO_CANONICAL_ARGUMENT,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=0,
            prototype_argument_count=len(prototype_args),
        )
        return None
    cfunc = codegen.cfunc
    if cfunc is None:
        return None
    arguments = tuple(cfunc.arg_list or ())
    argument_matches = _argument_matches_for_offset_8616(arguments, codegen, stack_offset)
    typed_prototype = cast(SimTypeFunction, cfunc.functy)
    prototype_args = tuple(typed_prototype.args or ())
    return arguments, argument_matches, typed_prototype, prototype_args


@cython.ccall
def _commit_near_pointer_argument_8616(
    codegen: _AngrCodegenBoundary8616,
    cvar: structured_c.CVariable,
    argument: structured_c.CVariable,
    argument_index: cython.longlong,
    pointer_type: SimTypeNearPointer16_8616,
    typed_prototype: SimTypeFunction,
    stack_offset: cython.longlong,
) -> cython.bint:
    """Apply the pointer type to the cvar, argument, and prototypes."""
    active_function: object
    canonical_prototype: object
    cfunc: object
    project: object
    updated_prototype: object
    cfunc = codegen.cfunc
    project = codegen.project
    if cfunc is None or project is None:
        return False
    codegen._inertia_near_pointer_argument_classified_offsets_8616.add(stack_offset)
    cvar.variable_type = pointer_type
    argument.variable_type = pointer_type
    if isinstance(cvar.variable, SimStackVariable):
        cvar.variable.size = 2
    if isinstance(argument.variable, SimStackVariable):
        argument.variable.size = 2
    updated_prototype = with_near_pointer_parameter_8616(
        typed_prototype, argument_index, pointer_type, project.arch
    )
    if updated_prototype is None:
        return False
    cfunc.functy = updated_prototype
    active_function = _active_function_for_codegen_8616(codegen)
    if active_function is not None:
        typed_function = cast(_AngrFunctionMetadataBoundary8616, active_function)
        try:
            function_prototype = typed_function.prototype
        except AttributeError:
            function_prototype = None
        canonical_prototype = with_near_pointer_parameter_8616(
            function_prototype, argument_index, pointer_type, project.arch
        )
        if canonical_prototype is not None:
            typed_function.prototype = canonical_prototype
    codegen._inertia_near_pointer_argument_materialized_offsets_8616.add(stack_offset)
    publish_codegen_function_prototype_8616(codegen.project, codegen)
    return True


@cython.ccall
def _near_pointer_type_8616(
    matched: SegmentedMemoryExpr, codegen: _AngrCodegenBoundary8616
) -> SimTypeNearPointer16_8616 | None:
    """Represent the proven unsigned load width, including C byte signedness."""
    pointee_type: object
    project: object
    pointee_type = {
        # Angr renders an unlabeled SimTypeChar as plain char even when its
        # signed flag is false. Preserve the byte-load range in emitted C.
        8: SimTypeChar(False, label="unsigned char"),
        16: SimTypeShort(False),
        32: SimTypeLong(False),
    }.get(matched.width_bits)
    if pointee_type is None:
        return None
    project = codegen.project
    if project is None:
        return None
    return near_pointer_type_8616(pointee_type, project.arch)


@cython.ccall
def _argument_cardinality_gate_8616(
    codegen: _AngrCodegenBoundary8616,
    stack_offset: cython.longlong,
    arguments: object,
    argument_matches: object,
    prototype_args: object,
) -> cython.bint:
    """Refuse when argument matching is ambiguous or interface sizes differ."""
    if len(argument_matches) != 1:
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.AMBIGUOUS_CANONICAL_ARGUMENT,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=len(argument_matches),
            prototype_argument_count=len(prototype_args),
        )
        return False
    if operator.ne(len(arguments), len(prototype_args)):
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.INTERFACE_CARDINALITY_MISMATCH,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=1,
            prototype_argument_count=len(prototype_args),
        )
        return False
    return True


def _argument_matches_for_offset_8616(
    arguments: object,
    codegen: _AngrCodegenBoundary8616,
    stack_offset: cython.longlong,
) -> tuple[tuple[cython.longlong, object], ...]:
    """Enumerate ``arg_list`` entries whose stack offset equals ``stack_offset``."""
    return tuple(
        (index, argument)
        for index, argument in builtins.iter(enumerate(arguments))
        if isinstance(argument, structured_c.CVariable)
        and operator.eq(_stack_offset_for_cvar_8616(argument, codegen), stack_offset)
    )


@cython.ccall
def _typed_prototype_or_refuse_8616(
    codegen: _AngrCodegenBoundary8616,
    stack_offset: cython.longlong,
    arguments: object,
    argument_matches: object,
) -> SimTypeFunction | None:
    """Return the function prototype, or record a missing-prototype refusal."""
    cfunc: object
    cfunc = codegen.cfunc
    prototype = cfunc.functy if cfunc is not None else None
    if not isinstance(prototype, SimTypeFunction):
        _record_near_pointer_argument_refusal_8616(
            codegen,
            reason=NearPointerArgumentRefusalReason8616.MISSING_FUNCTION_PROTOTYPE,
            stack_offset=stack_offset,
            argument_count=len(arguments),
            argument_match_count=len(argument_matches),
            prototype_argument_count=0,
        )
        return None
    return cast(SimTypeFunction, prototype)


@cython.ccall
def _materialize_binary_proven_near_pointer_argument_8616(
    matched: SegmentedMemoryExpr,
    codegen: _AngrCodegenBoundary8616 | None,
    *,
    segment_identity_proven: cython.bint = False,
    proven_stack_offset: int | None = None,
) -> structured_c.CVariable | None:
    """Promote only the BP argument proven by binary register-indirect use."""
    matching_facts: object
    materialized: object
    pointer_type: object
    resolved: object
    typed_prototype: object
    if not _materialize_near_pointer_gate_8616(matched, codegen):
        return None
    codegen = cast(_AngrCodegenBoundary8616, codegen)
    cfunc = cast(_AngrCFunctionBoundary8616, codegen.cfunc)
    resolved = _canonical_cvar_for_stack_offset_8616(matched, codegen, proven_stack_offset)
    if resolved is None:
        return None
    cvar, stack_offset = resolved
    matching_facts = _near_pointer_matching_facts_8616(
        matched, codegen, stack_offset, segment_identity_proven
    )
    if matching_facts is None:
        return None
    arguments = tuple(cfunc.arg_list or ())
    argument_matches = _argument_matches_for_offset_8616(arguments, codegen, stack_offset)
    typed_prototype = _typed_prototype_or_refuse_8616(
        codegen, stack_offset, arguments, argument_matches
    )
    if typed_prototype is None:
        return None
    prototype_args: tuple[SimType, ...] = tuple(typed_prototype.args or ())
    pointer_type = _near_pointer_type_8616(matched, codegen)
    if pointer_type is None:
        return None
    if not argument_matches:
        materialized = _materialize_missing_argument_8616(
            codegen, cvar, stack_offset, pointer_type, arguments, prototype_args
        )
        if materialized is None:
            return None
        arguments, argument_matches, typed_prototype, prototype_args = materialized
    if not _argument_cardinality_gate_8616(
        codegen, stack_offset, arguments, argument_matches, prototype_args
    ):
        return None
    argument_index, argument = argument_matches[0]
    if not _commit_near_pointer_argument_8616(
        codegen, cvar, argument, argument_index, pointer_type, typed_prototype, stack_offset
    ):
        return None
    return cvar


@cython.ccall
def _rematerialize_binary_proven_near_pointer_types_8616(
    codegen: _AngrCodegenBoundary8616,
) -> cython.bint:
    """Restore pointer parameter types after prior lowering consumed helper AST."""
    access_width: object
    cfunc: object
    argument: object
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    try:
        arguments = tuple(cfunc.arg_list or ())
        pointer_facts = codegen._inertia_near_pointer_argument_facts_8616
    except AttributeError:
        # Dynamic angr/codegen boundary: pointer replay is optional when the
        # codegen has no argument or evidence surface.
        return False
    changed = False
    for argument in arguments:
        if not isinstance(argument, structured_c.CVariable):
            continue
        stack_offset = _stack_offset_for_cvar_8616(argument, codegen)
        widths = {
            fact.access_width_bytes
            for fact in iter(pointer_facts)
            if operator.eq(fact.stack_offset, stack_offset)
        }
        if len(widths) != 1 or not widths <= {1, 2, 4}:
            continue
        access_width = next(iter(widths))
        matched = SegmentedMemoryExpr(
            space="DS",
            segment_expr=argument,
            offset_expr=argument,
            width_bits=access_width * 8,
            access="read",
        )
        changed = (
            _materialize_binary_proven_near_pointer_argument_8616(matched, codegen)
            is not None
        ) or changed
    return changed


def _lower_binary_proven_pointer_argument_helpers_8616(
    codegen: _AngrCodegenBoundary8616,
) -> cython.bint:
    """Lower DS runtime helpers whose offsets are binary-proven pointer arguments."""
    if codegen.cfunc is None or codegen.project is None:
        return False
    changed = False

    def transform(node: object) -> object:
        args: object
        pointer_access: object
        width_bytes: object
        nonlocal changed
        helper_name = _runtime_segment_helper_name_8616(node)
        width_bytes = _runtime_segment_helper_width_8616(helper_name)
        args = _runtime_segment_helper_args_8616(node)
        if width_bytes is None or args is None:
            return node
        if _segment_base_name_8616(args[0], codegen.project, codegen=codegen) != "ds":
            return node
        matched = SegmentedMemoryExpr(
            space="DS",
            segment_expr=args[0],
            offset_expr=args[1],
            width_bits=width_bytes * 8,
            access="read",
        )
        pointer_access = _near_pointer_arg_access_8616(
            matched,
            codegen,
            provenance_node=node,
        )
        if pointer_access is None:
            return node
        changed = True
        return pointer_access

    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True
    return changed


@cython.ccall
def _carrier_store_roots_8616(
    cfunc: object,
) -> tuple[dict[cython.longlong, structured_c.CStatements], dict[cython.longlong, object]]:
    """Collect ``CStatements`` roots plus all cfunc roots for consumption proof."""
    root: object
    attribute: object
    node: object
    roots_by_id: dict[cython.longlong, structured_c.CStatements] = {}
    function_roots: dict[cython.longlong, object] = {}
    for attribute in ("body", "statements", "stmt"):
        root = builtins.getattr(cfunc, attribute, None)
        if root is None:
            continue
        function_roots[id(root)] = root
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, structured_c.CStatements):
                roots_by_id[id(node)] = node
    return roots_by_id, function_roots


@cython.dataclasses.dataclass
class _CarrierSetup8616:
    """Proven pointer-carrier setup assignment facts."""

    setup: structured_c.CAssignment
    carrier: object
    pointer: object
    pointer_type: object
    stack_offset: cython.longlong
    carrier_key: _CarrierKey8616


@cython.dataclasses.dataclass
class _CarrierUse8616:
    """Proven helper-store use facts for one candidate statement."""

    use: structured_c.CAssignment
    use_index: cython.longlong
    helper_width: cython.longlong
    helper_args: object
    byte_index: cython.longlong
    matching_facts: object
    proven_width: cython.longlong
    source_addrs: object


@cython.dataclasses.dataclass
class _CarrierStoreCtx8616:
    """Context for typed-pointer register-carrier store consumption."""

    codegen: _AngrCodegenBoundary8616
    project: _AngrProjectBoundary8616
    facts: object
    function_roots: object


@cython.ccall
def _carrier_setup_gate_8616(
    setup: object, codegen: _AngrCodegenBoundary8616
) -> _CarrierSetup8616 | None:
    """Gate: ``setup`` copies a proven pointer argument into a register carrier."""
    carrier_key: object
    pointer_type: object
    if not isinstance(setup, structured_c.CAssignment):
        return None
    carrier = _strip_casts_8616(setup.lhs)
    pointer = _strip_casts_8616(setup.rhs)
    carrier_variable = carrier.variable if isinstance(carrier, structured_c.CVariable) else None
    if not isinstance(carrier_variable, SimRegisterVariable):
        return None
    if not isinstance(pointer, structured_c.CVariable):
        return None
    pointer_type = _near_pointer_arg_type_8616(pointer, codegen)
    stack_offset = _stack_offset_for_cvar_8616(pointer, codegen)
    if pointer_type is None or not isinstance(stack_offset, int):
        return None
    carrier_key = _carrier_key_8616(carrier)
    if carrier_key is None:
        return None
    return _CarrierSetup8616(
        setup=setup,
        carrier=carrier,
        pointer=pointer,
        pointer_type=pointer_type,
        stack_offset=stack_offset,
        carrier_key=carrier_key,
    )


@cython.ccall
def _carrier_use_shape_ok_8616(
    ctx: _CarrierStoreCtx8616,
    carrier_uses: object,
    helper_width: object,
    helper_args: object,
    carrier_key: _CarrierKey8616,
    pointer_width_bits: object,
) -> cython.bint:
    """True when the helper-store shape can carry a proven byte index."""
    return (
        len(carrier_uses) == 1
        and helper_width is not None
        and helper_args is not None
        and _segment_base_name_8616(helper_args[0], ctx.project, codegen=ctx.codegen) == "ds"
        and _pointer_store_byte_index_8616(helper_args[1], carrier_key) is not None
        and pointer_width_bits is not None
        and pointer_width_bits >= helper_width * 8
    )


def _carrier_use_gate_8616(
    ctx: _CarrierStoreCtx8616,
    use: structured_c.CAssignment,
    use_index: cython.longlong,
    carrier_uses: object,
    setup_rec: _CarrierSetup8616,
) -> _CarrierUse8616 | None:
    """Gate: ``use`` is a proven DS helper store through the carrier."""
    byte_index: object
    helper_args: object
    helper_width: object
    helper_name = _runtime_segment_helper_name_8616(use.lhs)
    helper_width = _runtime_segment_helper_width_8616(helper_name)
    helper_args = _runtime_segment_helper_args_8616(use.lhs)
    pointer_width_bits = _pointer_element_width_bits_8616(setup_rec.pointer_type)
    if not _carrier_use_shape_ok_8616(
        ctx, carrier_uses, helper_width, helper_args, setup_rec.carrier_key, pointer_width_bits
    ):
        return None
    if helper_args is None or helper_width is None:
        return None
    matching_facts = tuple(
        fact
        for fact in iter(ctx.facts)
        if operator.eq(fact.stack_offset, setup_rec.stack_offset)
        and fact.access_width_bytes >= helper_width
    )
    if not matching_facts:
        return None
    source_addrs = instruction_addrs_from_node_8616(use.lhs)
    if source_addrs and not any(
        fact.dereference_ins_addr in source_addrs for fact in iter(matching_facts)
    ):
        return None
    byte_index = _pointer_store_byte_index_8616(helper_args[1], setup_rec.carrier_key)
    if byte_index is None or byte_index < 0:
        return None
    proven_width = max(fact.access_width_bytes for fact in iter(matching_facts))
    if operator.ne(_pointer_element_width_bits_8616(setup_rec.pointer_type), proven_width * 8):
        return None
    return _CarrierUse8616(
        use=use,
        use_index=use_index,
        helper_width=helper_width,
        helper_args=helper_args,
        byte_index=byte_index,
        matching_facts=matching_facts,
        proven_width=proven_width,
        source_addrs=source_addrs,
    )


def _extend_carrier_store_pair_8616(
    ctx: _CarrierStoreCtx8616,
    statements: object,
    use_index: cython.longlong,
    helper_width: cython.longlong,
    byte_index: cython.longlong,
    carrier_key: _CarrierKey8616,
    matching_facts: object,
) -> object:
    """Extend a byte-store pair with the adjacent ``byte_index + 1`` store."""
    pair_args: object
    pair: list[tuple[structured_c.CAssignment, cython.longlong, cython.longlong]] = []
    for pair_index in range(use_index + 1, min(use_index + 2, len(statements))):
        pair_statement = statements[pair_index]
        if not isinstance(pair_statement, structured_c.CAssignment):
            break
        pair_args = _runtime_segment_helper_args_8616(pair_statement.lhs)
        pair_width = _runtime_segment_helper_width_8616(
            _runtime_segment_helper_name_8616(pair_statement.lhs)
        )
        if pair_args is None or pair_width != helper_width:
            continue
        if _segment_base_name_8616(pair_args[0], ctx.project, codegen=ctx.codegen) != "ds":
            break
        next_index = _pointer_store_byte_index_8616(pair_args[1], carrier_key)
        if operator.ne(next_index, byte_index + 1):
            continue
        pair_source_addrs = instruction_addrs_from_node_8616(pair_statement.lhs)
        if pair_source_addrs and not any(
            fact.dereference_ins_addr in pair_source_addrs
            for fact in iter(matching_facts)
        ):
            break
        pair.append((pair_statement, pair_index, next_index))
        break
    return pair


@cython.ccall
def _carrier_consumption_ok_8616(
    ctx: _CarrierStoreCtx8616,
    setup_rec: _CarrierSetup8616,
    consumption_stores: object,
    intervening: object,
) -> tuple[PointerStoreConsumptionEvidence8616, cython.bint]:
    """Prove the carrier store is consumed or its source preserved."""
    consumption = prove_pointer_store_consumption_8616(
        tuple(ctx.function_roots.values()), setup_rec.setup, setup_rec.carrier, setup_rec.pointer,
        consumption_stores, intervening,
    )
    if not consumption.complete and (
        consumption.failure is not PointerStoreConsumptionFailure8616.UNCONSUMED_REGISTER
        or not prove_pointer_store_source_preservation_8616(
            setup_rec.carrier, setup_rec.pointer, consumption_stores, intervening,
        ).source_preserved
    ):
        return consumption, False
    return consumption, True


@cython.ccall
def _mixed_projection_store_ok_8616(
    low_lhs: object,
    pointer: object,
    use_facts: _CarrierUse8616,
    low_source_addrs: object,
    fact_addrs: object,
    word_source: object,
) -> cython.bint:
    """True when the low-byte store is a proven adjacent indexed write."""
    return (
        isinstance(low_lhs, structured_c.CIndexedVariable)
        and _same_c_expression_8616(low_lhs.variable, pointer)
        and operator.eq(_constant_value_8616(low_lhs.index), use_facts.byte_index // use_facts.proven_width)
        and bool(use_facts.source_addrs)
        and bool(low_source_addrs)
        and bool(use_facts.source_addrs & low_source_addrs & fact_addrs)
        and word_source is not None
    )


def _apply_mixed_projection_store_8616(
    ctx: _CarrierStoreCtx8616,
    statements: object,
    setup_rec: _CarrierSetup8616,
    use_facts: _CarrierUse8616,
    consumption: object,
) -> object:
    """Apply the mixed-projection merge; return consumed indexes or None."""
    use_index = use_facts.use_index
    use = use_facts.use
    low_use = statements[use_index - 1] if use_index > 0 else None
    if not isinstance(low_use, structured_c.CAssignment):
        return None
    low_lhs = _strip_casts_8616(low_use.lhs)
    low_source_addrs = instruction_addrs_from_node_8616(low_lhs)
    fact_addrs = frozenset(
        fact.dereference_ins_addr for fact in iter(use_facts.matching_facts)
    )
    word_source = _word_source_from_pointer_byte_pair_8616(
        low_use.rhs,
        use.rhs,
    )
    if not _mixed_projection_store_ok_8616(
        low_lhs, setup_rec.pointer, use_facts, low_source_addrs, fact_addrs, word_source
    ):
        return None
    low_use.rhs = word_source
    return {use_index}


def _apply_wide_or_single_store_8616(
    ctx: _CarrierStoreCtx8616,
    setup_rec: _CarrierSetup8616,
    use_facts: _CarrierUse8616,
    pair: object,
    index_type: SimType,
    tags: object,
) -> object:
    """Apply the wide-pair or single-store indexed rewrite."""
    word_source: object
    use = use_facts.use
    byte_index = use_facts.byte_index
    proven_width = use_facts.proven_width
    helper_width = use_facts.helper_width
    if byte_index % proven_width != 0:
        return None
    consumed: set[cython.longlong] = set()
    if proven_width > helper_width:
        word_source = _word_source_from_pointer_byte_pair_8616(
            pair[0][0].rhs,
            pair[1][0].rhs,
        )
        if word_source is None:
            return None
        use.lhs = structured_c.CIndexedVariable(
            setup_rec.pointer,
            structured_c.CConstant(byte_index // proven_width, index_type, codegen=ctx.codegen),
            codegen=ctx.codegen,
            tags=tags,
        )
        use.rhs = word_source
        consumed.update(item[1] for item in iter(pair[1:]))
    else:
        use.lhs = structured_c.CIndexedVariable(
            setup_rec.pointer,
            structured_c.CConstant(byte_index // proven_width, index_type, codegen=ctx.codegen),
            codegen=ctx.codegen,
            tags=tags,
        )
    return consumed


def _consume_one_carrier_store_8616(
    ctx: _CarrierStoreCtx8616,
    statements: object,
    setup_index: cython.longlong,
    setup_rec: _CarrierSetup8616,
    use_facts: _CarrierUse8616,
) -> object:
    """Try to consume the carrier store at ``use_facts``; return consumed indexes."""
    consumed: object
    use_index = use_facts.use_index
    helper_width = use_facts.helper_width
    proven_width = use_facts.proven_width
    byte_index = use_facts.byte_index
    pair: list[tuple[structured_c.CAssignment, cython.longlong, cython.longlong]] = [
        (use_facts.use, use_index, byte_index)
    ]
    mixed_projection = proven_width == 2 and byte_index % proven_width == 1
    if proven_width > helper_width and not mixed_projection:
        if helper_width != 1:
            return None
        pair.extend(
            _extend_carrier_store_pair_8616(
                ctx, statements, use_index, helper_width, byte_index,
                setup_rec.carrier_key, use_facts.matching_facts,
            )
        )
        if operator.ne(len(pair), proven_width):
            return None
    consumption_stores = tuple(item[0] for item in iter(pair))
    if mixed_projection and isinstance(statements[use_index - 1], structured_c.CAssignment):
        consumption_stores += (statements[use_index - 1],)
    intervening = tuple(statements[setup_index + 1:use_index])
    consumption, ok = _carrier_consumption_ok_8616(
        ctx, setup_rec, consumption_stores, intervening
    )
    if not ok:
        return None
    index_type = SimTypeShort(False).with_arch(ctx.project.arch)
    tags: dict[str, object] = {
        "inertia_source_instruction_addrs": tuple(
            sorted(fact.dereference_ins_addr for fact in iter(use_facts.matching_facts))
        )
    }
    if mixed_projection:
        consumed = _apply_mixed_projection_store_8616(
            ctx, statements, setup_rec, use_facts, consumption
        )
        if consumed is None:
            return None
    else:
        consumed = _apply_wide_or_single_store_8616(
            ctx, setup_rec, use_facts, pair, index_type, tags
        )
        if consumed is None:
            return None
    if consumption.complete:
        consumed.add(setup_index)
    return consumed


def _consume_carrier_setup_8616(
    ctx: _CarrierStoreCtx8616,
    statements: object,
    setup_index: cython.longlong,
    setup_rec: _CarrierSetup8616,
) -> object:
    """Consume helper stores fed by the carrier from ``setup_index``."""
    consumed: object
    use_facts: object
    consumed_indexes: set[cython.longlong] = set()
    for use_index in range(setup_index + 1, len(statements)):
        use = statements[use_index]
        if not isinstance(use, structured_c.CAssignment):
            break
        carrier_uses = tuple(
            node
            for node in builtins.iter(_iter_c_nodes_deep_8616(use))
            if isinstance(node, structured_c.CVariable) and operator.eq(_carrier_key_8616(node), setup_rec.carrier_key)
        )
        if not carrier_uses:
            continue
        use_facts = _carrier_use_gate_8616(ctx, use, use_index, carrier_uses, setup_rec)
        if use_facts is None:
            break
        consumed = _consume_one_carrier_store_8616(
            ctx, statements, setup_index, setup_rec, use_facts
        )
        if consumed is None:
            break
        consumed_indexes.update(consumed)
        break
    return consumed_indexes


@cython.ccall
def _lower_typed_pointer_register_carrier_stores_8616(
    codegen: _AngrCodegenBoundary8616,
) -> cython.bint:
    """Consume exact register copies from typed pointer arguments into stores."""
    cfunc: object
    project: object
    setup_rec: object
    root: object
    setup: object
    setup_index: object
    cfunc = codegen.cfunc
    project = codegen.project
    if cfunc is None or project is None:
        return False
    try:
        facts = codegen._inertia_near_pointer_argument_facts_8616
    except AttributeError:
        return False

    roots_by_id, function_roots = _carrier_store_roots_8616(cfunc)
    ctx = _CarrierStoreCtx8616(
        codegen=codegen,
        project=project,
        facts=facts,
        function_roots=function_roots,
    )

    changed = False
    for root in roots_by_id.values():
        statements = list(root.statements)
        consumed_indexes: set[cython.longlong] = set()
        for setup_index, setup in enumerate(statements):
            setup_rec = _carrier_setup_gate_8616(setup, codegen)
            if setup_rec is None:
                continue
            found = _consume_carrier_setup_8616(ctx, statements, setup_index, setup_rec)
            if found:
                consumed_indexes.update(found)
                changed = True
        if consumed_indexes:
            root.statements = [
                statement
                for index, statement in builtins.iter(enumerate(statements))
                if index not in consumed_indexes
            ]
    return changed


def _near_pointer_indexed_access_8616(
    matched: SegmentedMemoryExpr,
    indexed: object,
    codegen: _AngrCodegenBoundary8616 | None,
    provenance_stack_offset: int | None,
    facts: object,
) -> object | None:
    """Emit ``pointer[index]`` for a scaled-index near-pointer access."""
    materialized_pointer: object
    pointer_type: object
    pointer_arg, index = indexed
    pointer_type = _near_pointer_arg_type_8616(pointer_arg, codegen)
    if pointer_type is None or operator.ne(_pointer_element_width_bits_8616(pointer_type), matched.width_bits):
        materialized_pointer = _materialize_binary_proven_near_pointer_argument_8616(
            matched,
            codegen,
            segment_identity_proven=True,
            proven_stack_offset=provenance_stack_offset,
        )
        if materialized_pointer is not None:
            pointer_arg = materialized_pointer
            pointer_type = _near_pointer_arg_type_8616(pointer_arg, codegen)
    if pointer_type is None or operator.ne(_pointer_element_width_bits_8616(pointer_type), matched.width_bits):
        return None
    pointer_arg.variable_type = pointer_type
    return cast(
        object,
        structured_c.CIndexedVariable(
            pointer_arg,
            index,
            codegen=codegen,
            tags={
                "inertia_source_instruction_addrs": tuple(
                    sorted(fact.dereference_ins_addr for fact in iter(facts))
                )
            },
        ),
    )


def _near_pointer_zero_plus_access_8616(
    matched: SegmentedMemoryExpr,
    codegen: object,
    provenance_stack_offset: int | None,
    facts: object,
) -> object | None:
    """Emit ``pointer[0]`` for a zero-offset near-pointer access."""
    arch: object
    pointer_arg: object
    pointer_type: object
    pointer_arg = _zero_plus_pointer_arg_8616(matched.offset_expr, codegen)
    if pointer_arg is None:
        # The zero-index fallback may promote an untyped pointer base only
        # when additive-zero normalization proves there is no residual offset.
        # An unparsed scale or index must remain explicit instead of silently
        # becoming pointer[0].
        if _zero_plus_cvar_8616(matched.offset_expr) is None:
            return None
        pointer_arg = _materialize_binary_proven_near_pointer_argument_8616(
            matched,
            codegen,
            segment_identity_proven=True,
            proven_stack_offset=provenance_stack_offset,
        )
    if pointer_arg is None:
        return None
    pointer_type = _near_pointer_arg_type_8616(pointer_arg, codegen)
    if pointer_type is None or operator.ne(_pointer_element_width_bits_8616(pointer_type), matched.width_bits):
        return None
    pointer_arg.variable_type = pointer_type
    index_type = SimTypeShort(False)
    arch = codegen.project.arch if codegen is not None and codegen.project is not None else None
    if arch is not None and hasattr(index_type, "with_arch"):
        index_type = index_type.with_arch(arch)
    return cast(
        object,
        structured_c.CIndexedVariable(
            pointer_arg,
            structured_c.CConstant(0, index_type, codegen=codegen),
            codegen=codegen,
            tags={
                "inertia_source_instruction_addrs": tuple(
                    sorted(fact.dereference_ins_addr for fact in iter(facts))
                )
            },
        ),
    )


@cython.ccall
def _near_pointer_fact_cvar_8616(
    matched: SegmentedMemoryExpr, codegen: object
) -> object | None:
    """Resolve the fact carrier CVariable behind ``matched.offset_expr``."""
    fact_cvar: object
    indexed_fact_cvar: object
    fact_cvar = _zero_plus_cvar_8616(matched.offset_expr)
    if fact_cvar is None and matched.width_bits % 8 == 0:
        indexed_fact_cvar = _cvar_plus_scaled_index_8616(
            matched.offset_expr,
            matched.width_bits // 8,
        )
        if indexed_fact_cvar is not None:
            fact_cvar, _fact_index = indexed_fact_cvar
    return fact_cvar


def _near_pointer_width_facts_8616(
    available_facts: object,
    fact_stack_offset: int | None,
    provenance_node: object | None,
    width_bits: cython.longlong,
) -> tuple[tuple[NearPointerArgumentFact8616, ...], int | None]:
    """Select facts by width, then by stack offset or instruction addresses."""
    proven_stack_offset: object
    width_facts = tuple(
        fact
        for fact in iter(available_facts)
        if operator.eq(fact.access_width_bytes * 8, width_bits)
    )
    if isinstance(fact_stack_offset, int):
        facts = tuple(fact for fact in iter(width_facts) if operator.eq(fact.stack_offset, fact_stack_offset))
        return facts, fact_stack_offset
    source_addrs = instruction_addrs_from_node_8616(provenance_node)
    facts = tuple(fact for fact in iter(width_facts) if fact.dereference_ins_addr in source_addrs)
    proven_offsets: set[cython.longlong] = {fact.stack_offset for fact in iter(facts)}
    proven_stack_offset = next(iter(proven_offsets)) if len(proven_offsets) == 1 else None
    if proven_stack_offset is None:
        return (), None
    return facts, proven_stack_offset


def _near_pointer_arg_access_8616(
    matched: SegmentedMemoryExpr,
    codegen: object,
    *,
    provenance_node: object | None = None,
) -> structured_c.CIndexedVariable | None:
    """Bind near accesses using exact pointer storage and carrier provenance."""
    access: object
    bound: object
    indexed: object
    provenance_stack_offset: object
    if matched.space != "DS":
        return None
    try:
        available_facts = codegen._inertia_near_pointer_argument_facts_8616 if codegen is not None else ()
    except AttributeError:
        available_facts = ()
    if matched.width_bits == 8 and codegen is not None and codegen.cfunc is not None:
        bound = bind_byte_pointer_index_8616(
            _strip_casts_8616(matched.offset_expr), available_facts,
            instruction_addrs_from_node_8616(provenance_node), tuple(codegen.cfunc.arg_list or ()),
            lambda argument: _stack_offset_for_cvar_8616(argument, codegen), codegen=codegen,
        )
        if bound is not None:
            matched = replace(matched, offset_expr=bound)
    fact_cvar = _near_pointer_fact_cvar_8616(matched, codegen)
    fact_stack_offset = _stack_offset_for_cvar_8616(fact_cvar, codegen)
    facts, proven_stack_offset = _near_pointer_width_facts_8616(
        available_facts, fact_stack_offset, provenance_node, matched.width_bits
    )
    if codegen is not None and not may_lower_codegen_access_to_entry_ds_object_8616(
        codegen,
        provenance_node if provenance_node is not None else matched,
        instruction_addrs=frozenset(fact.dereference_ins_addr for fact in iter(facts)),
        segment_register="ds",
        offset=None,
        width=matched.width_bits // 8 if matched.width_bits % 8 == 0 else None,
    ):
        return None
    provenance_stack_offset = proven_stack_offset if not isinstance(fact_stack_offset, int) else None
    if matched.width_bits % 8 == 0:
        indexed = _cvar_plus_scaled_index_8616(
            matched.offset_expr,
            matched.width_bits // 8,
        )
        if indexed is not None:
            if provenance_stack_offset is not None:
                return None
            access = _near_pointer_indexed_access_8616(
                matched, indexed, codegen, provenance_stack_offset, facts
            )
            if access is not None:
                return access
    return cast(
        structured_c.CIndexedVariable | None,
        _near_pointer_zero_plus_access_8616(matched, codegen, provenance_stack_offset, facts),
    )


@cython.ccall
def _extract_segment_scale_8616(
    node: object,
    project: object,
    codegen: _AngrCodegenBoundary8616 | None = None,
) -> tuple[str | None, object | None]:
    expected_scale: object
    seg_name: object
    maybe_scale: object
    maybe_seg: object
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None, None
    expected_scale = 16 if node.op == "Mul" else 4 if node.op == "Shl" else None
    if expected_scale is None:
        return None, None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if operator.ne(_constant_value_8616(maybe_scale), expected_scale):
            continue
        seg_name = _segment_base_name_8616(maybe_seg, project, codegen=codegen)
        if seg_name is not None:
            return seg_name, maybe_seg
    return None, None


@cython.ccall
def _linear_carrier_name_8616(node: object) -> object:
    dirty: object
    node = _strip_casts_8616(node)
    dirty = _dynamic_angr_attr_8616(node, "dirty", None)
    if dirty is not None:
        varid = _dynamic_angr_attr_8616(dirty, "varid", None)
        if isinstance(varid, int):
            return f"vvar_{varid}"
        name = _dynamic_angr_attr_8616(dirty, "name", None)
        if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
            return name
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = _dynamic_angr_attr_8616(node, "variable", None)
    name = _dynamic_angr_attr_8616(node, "name", None) or _dynamic_angr_attr_8616(variable, "name", None)
    if isinstance(name, str) and name.startswith(("vvar_", "tmp_", "ir_")):
        return name
    return None


@cython.ccall
def _carrier_key_8616(node: object) -> _CarrierKey8616 | None:
    dirty: object
    variable: object
    node = _strip_casts_8616(node)
    dirty = _dynamic_angr_attr_8616(node, "dirty", None)
    if dirty is not None:
        varid = _dynamic_angr_attr_8616(dirty, "varid", None)
        if isinstance(varid, int):
            return ("vvar", varid)
        name = _dynamic_angr_attr_8616(dirty, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        oident = _dynamic_angr_attr_8616(dirty, "oident", None)
        category = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(dirty, "category", None), "name", None)
        if isinstance(oident, int | str) and isinstance(category, str):
            return (f"dirty-{category.lower()}", oident)
    if isinstance(node, structured_c.CVariable):
        variable = _dynamic_angr_attr_8616(node, "variable", None)
        name = _dynamic_angr_attr_8616(node, "name", None) or _dynamic_angr_attr_8616(variable, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        if variable is not None:
            return ("var", id(variable))
    return None


@cython.ccall
def _pointer_store_byte_index_8616(
    offset: object,
    carrier_key: _CarrierKey8616,
) -> int | None:
    """Return a proven byte offset from a register carrier expression."""
    offset = _strip_casts_8616(offset)
    if operator.eq(_carrier_key_8616(offset), carrier_key):
        return 0
    if not isinstance(offset, structured_c.CBinaryOp) or offset.op != "Add":
        return None
    if operator.eq(_carrier_key_8616(offset.lhs), carrier_key):
        return _constant_value_8616(offset.rhs)
    if operator.eq(_carrier_key_8616(offset.rhs), carrier_key):
        return _constant_value_8616(offset.lhs)
    return None


@cython.ccall
def _word_source_from_pointer_byte_pair_8616(
    low_rhs: object,
    high_rhs: object,
) -> object | None:
    """Recover one word source from its proven little-endian byte projections."""
    mask: object
    source: object
    low_source = _strip_casts_8616(low_rhs)
    high_projection = _strip_casts_8616(high_rhs)
    if (
        not isinstance(high_projection, structured_c.CBinaryOp)
        or high_projection.op != "Shr"
        or _constant_value_8616(high_projection.rhs) != 8
    ):
        return None
    high_source = _strip_casts_8616(high_projection.lhs)
    if _same_c_expression_8616(low_source, high_source):
        return low_source
    if isinstance(low_source, structured_c.CBinaryOp) and low_source.op == "And":
        for source, mask in (
            (low_source.lhs, low_source.rhs),
            (low_source.rhs, low_source.lhs),
        ):
            if _constant_value_8616(mask) == 0xFF and _same_c_expression_8616(
                _strip_casts_8616(source),
                high_source,
            ):
                return high_source
    return None


@cython.ccall
def _terminal_carrier_expr_8616(node: object, codegen: _AngrCodegenBoundary8616 | None) -> object:
    rhs: object
    current = _strip_casts_8616(node)
    seen: set[str] = set()
    while True:
        rhs = _single_assignment_carrier_rhs_8616(current, codegen, seen)
        if rhs is None:
            return current
        current = _strip_casts_8616(rhs)


@cython.ccall
def _single_assignment_carrier_rhs_8616(
    node: object,
    codegen: object,
    seen: object,
) -> object | None:
    name: object
    rhs: object
    if codegen is None:
        return None
    name = _linear_carrier_name_8616(node)
    if name is None or name in seen:
        return None
    seen.add(name)
    node = _strip_casts_8616(node)
    rhs = (
        _single_assignment_rhs_8616(codegen, node)
        if isinstance(node, structured_c.CVariable)
        else None
    )
    if rhs is None:
        rhs = _single_assignment_rhs_for_virtual_name_8616(codegen, name)
    if rhs is not None:
        _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_carrier_resolved_count_8616")
    return rhs


@cython.ccall
def _find_segment_expr_8616(
    node: object,
    *,
    project: object,
    codegen: _AngrCodegenBoundary8616 | None,
    segment_name: object,
    seen: object = None,
) -> object | None:
    found: object
    rhs: object
    scaled_name: object
    child: object
    if seen is None:
        seen = set()
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp):
        scaled_name, scaled_expr = _extract_segment_scale_8616(node, project, codegen=codegen)
        if scaled_name is not None and operator.eq(scaled_name.upper(), segment_name.upper()):
            return scaled_expr
        for child in (_dynamic_angr_attr_8616(node, "lhs", None), _dynamic_angr_attr_8616(node, "rhs", None)):
            found = _find_segment_expr_8616(
                child,
                project=project,
                codegen=codegen,
                segment_name=segment_name,
                seen=seen,
            )
            if found is not None:
                return found
    rhs = _single_assignment_carrier_rhs_8616(node, codegen, seen)
    if rhs is not None:
        return _find_segment_expr_8616(
            rhs,
            project=project,
            codegen=codegen,
            segment_name=segment_name,
            seen=seen,
        )
    return None


@cython.ccall
def _flatten_signed_terms_8616(node: object, sign: cython.longlong = 1) -> object:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, sign)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, -sign)
    return ((sign, node),)


@cython.ccall
def _build_offset_expr_8616(
    terms: object,
    codegen: _AngrCodegenBoundary8616 | None,
) -> object:
    expr: object
    sign: object
    term: object
    if not terms:
        return structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)

    expr = None
    for sign, term in terms:
        term = _strip_casts_8616(term)
        if expr is None:
            if sign == 1:
                expr = term
            else:
                expr = structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            continue
        expr = structured_c.CBinaryOp("Add" if sign == 1 else "Sub", expr, term, codegen=codegen)
    return expr


@cython.ccall
def _access_prologue_8616(
    node: object, access: object
) -> object:
    """Strip casts and pull ``base_expr``/``width_bits``/``codegen`` for the access kind."""
    if access == "read" or access == "write":
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None
        base_expr = node.operand
        width_bits = _dynamic_angr_int_attr_8616(_dynamic_angr_attr_8616(node, "type", None), "size", 16)
        codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(node, "codegen", None))
        return base_expr, int(width_bits), codegen
    base_expr = node
    width_bits = 0
    codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(node, "codegen", None))
    return base_expr, width_bits, codegen


@cython.ccall
def _decomposed_segmented_expr_8616(
    decomposed: object,
    base_expr: object,
    project: object,
    codegen: _AngrCodegenBoundary8616 | None,
    width_bits: cython.longlong,
    access: object,
) -> SegmentedMemoryExpr | None:
    """Build the segmented expr from decomposed linear-global terms."""
    segment_expr: object
    segment_name: object
    segment_name, displacement, residual_terms = decomposed
    if segment_name is None:
        return None
    segment_name = segment_name.upper()
    segment_expr = _find_segment_expr_8616(
        base_expr,
        project=project,
        codegen=codegen,
        segment_name=segment_name,
    )
    if not (
        segment_name in {"DS", "ES", "SS"}
        and segment_expr is not None
        and not (segment_name == "SS" and _expr_mentions_stack_variable_8616(base_expr))
    ):
        return None
    offset_terms = list(residual_terms)
    if displacement:
        sign = 1 if displacement >= 0 else -1
        offset_terms.insert(
            0,
            (
                sign,
                structured_c.CConstant(
                    abs(displacement),
                    SimTypeShort(False),
                    codegen=codegen,
                ),
            ),
        )
    return SegmentedMemoryExpr(
        space=segment_name,
        segment_expr=segment_expr,
        offset_expr=_build_offset_expr_8616(tuple(offset_terms), codegen),
        width_bits=int(width_bits),
        access=access,
    )


@cython.ccall
def _linear_segmented_expr_8616(
    base_expr: object,
    project: object,
    codegen: _AngrCodegenBoundary8616 | None,
    width_bits: cython.longlong,
    access: object,
) -> SegmentedMemoryExpr | None:
    """Build the segmented expr by scanning flattened signed terms."""
    local_name: object
    segment_expr: object
    segment_name: object
    sign: object
    term: object
    segment_name = None
    segment_expr = None
    linear_offset_terms: list[tuple[cython.longlong, object]] = []
    for sign, term in _flatten_signed_terms_8616(base_expr):
        local_name, local_expr = _extract_segment_scale_8616(term, project, codegen=codegen)
        if local_name is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = local_name.upper()
            segment_expr = local_expr
            continue
        linear_offset_terms.append((sign, term))

    if segment_name not in {"DS", "ES", "SS"} or segment_expr is None:
        return None
    return SegmentedMemoryExpr(
        space=segment_name,
        segment_expr=segment_expr,
        offset_expr=_build_offset_expr_8616(tuple(linear_offset_terms), codegen),
        width_bits=int(width_bits),
        access=access,
    )


@cython.ccall
def __match_segmented_memory_expr_8616___impl(
    node: object,
    project: object,
    access: object,
    decomposition_cache: LinearGlobalDecompositionCache8616 | None,
) -> SegmentedMemoryExpr | None:
    """Match ``node`` as a segmented memory expression."""
    codegen: object
    decomposed: object
    prologue: object
    segmented: object
    prologue = _access_prologue_8616(node, access)
    if prologue is None:
        return None
    base_expr, width_bits, codegen = prologue

    if not _may_contain_segment_linear_terms_8616(
        base_expr,
        project,
        codegen=codegen,
    ):
        if codegen is not None:
            _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_lowering_fast_refused_8616")
        return None

    decomposed = _decompose_linear_global_terms_8616(
        base_expr,
        project,
        codegen=codegen,
        _carrier_cache=decomposition_cache,
    )
    if decomposed is not None:
        segmented = _decomposed_segmented_expr_8616(
            decomposed, base_expr, project, codegen, width_bits, access
        )
        if segmented is not None:
            return segmented

    return _linear_segmented_expr_8616(base_expr, project, codegen, width_bits, access)


@cython.ccall
def _match_segmented_memory_expr_8616(
    node: object,
    *,
    project: object,
    access: object,
    decomposition_cache: LinearGlobalDecompositionCache8616 | None = None,
) -> SegmentedMemoryExpr | None:
    return __match_segmented_memory_expr_8616___impl(node, project, access, decomposition_cache)


@cython.ccall
def _may_contain_segment_linear_terms_8616(
    node: object,
    project: object,
    *,
    codegen: _AngrCodegenBoundary8616 | None = None,
) -> cython.bint:
    """Return whether this expression root can encode segmented linear terms.

    The decomposer consumes top-level additive terms, segment-scale binary
    expressions, and generated carriers. Structured-C containers and arbitrary
    nested children are visited separately by the child replacer, so descending
    into them here repeats work and cannot make this root a segmented address.
    """
    current: object
    root = _strip_casts_8616(node)
    pending = [root]
    seen: set[cython.longlong] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        if isinstance(current, structured_c.CBinaryOp) and current.op in {"Add", "Sub"}:
            pending.extend((current.rhs, current.lhs))
            continue
        if _linear_carrier_name_8616(current) is not None:
            return True
        if (
            isinstance(current, (structured_c.CBinaryOp, structured_c.CVariable))
            or _dynamic_angr_attr_8616(current, "dirty", None) is not None
        ) and _segment_base_name_8616(current, project, codegen=codegen) in {
            "ds",
            "es",
            "ss",
            "DS",
            "ES",
            "SS",
        }:
            return True
    return False


@cython.ccall
def _seg_macro_for_width_bits_8616(width_bits: cython.longlong) -> object:
    if width_bits <= 8:
        return "SEG_U8"
    if width_bits <= 16:
        return "SEG_U16"
    if width_bits <= 32:
        return "SEG_U32"
    return None


@cython.ccall
def _exact_segmented_load_tags_8616(
    matched: SegmentedMemoryExpr,
    codegen: object,
    macro: object,
    provenance_node: object,
) -> object:
    """Retain an exact segmented scalar identity when lowering proves one."""
    cfunc: object
    offset: object
    space: object
    tags: dict[str, object] = {"inertia_x86_16_runtime_segment_helper": macro}
    source_addrs = instruction_addrs_from_node_8616(provenance_node)
    if source_addrs:
        tags["inertia_source_instruction_addrs"] = tuple(sorted(source_addrs))
    offset = _constant_value_8616(matched.offset_expr)
    space = {
        "DS": MemSpace.DS,
        "ES": MemSpace.ES,
        "SS": MemSpace.SS,
    }.get(matched.space)
    width = max(int(matched.width_bits) // 8, 1)
    cfunc = codegen.cfunc if codegen is not None else None
    region = cfunc.addr if cfunc is not None and isinstance(cfunc.addr, int) else None
    if offset is None or space is None:
        return tags
    return dict(
        segmented_load_tags_8616(
        SegmentedLoadIdentity8616(
            space=space,
            offset=offset & 0xFFFF,
            width=width,
            region=region,
        ),
        existing=tags,
        ),
    )


def _expr_mentions_stack_variable_8616(node: object) -> cython.bint:
    child: object
    current: object
    attr: object
    pending = [_strip_casts_8616(node)]
    seen: set[cython.longlong] = set()
    while pending:
        current = _strip_casts_8616(pending.pop())
        if current is None:
            continue
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        variable = _dynamic_angr_attr_8616(current, "variable", None)
        if isinstance(variable, SimStackVariable):
            return True
        for attr in ("lhs", "rhs", "operand", "expr", "index", "variable"):
            child = _dynamic_angr_attr_8616(current, attr, None)
            if child is not None:
                pending.append(child)
        for attr in ("args", "operands"):
            children = _dynamic_angr_attr_8616(current, attr, None)
            if isinstance(children, (list, tuple)):
                pending.extend(child for child in iter(children) if child is not None)
    return False


@cython.ccall
def _is_proven_ss_stack_access_8616(
    matched: SegmentedMemoryExpr,
    *,
    codegen: _AngrCodegenBoundary8616 | None,
    project: object,
) -> cython.bint:
    if matched.space != "SS":
        return False
    if _expr_mentions_stack_variable_8616(matched.offset_expr):
        return True
    displacement = _stack_offset_from_expr_8616(matched.offset_expr, project, codegen)
    canonical_displacement = _canonical_stack_offset_8616(displacement)
    displacement = canonical_displacement if isinstance(canonical_displacement, int) else None
    if not isinstance(displacement, int):
        return False
    width = max(int(matched.width_bits or 16) // 8, 1)
    return _has_stack_storage_evidence_for_displacement_8616(
        codegen, displacement, width
    ) or displacement in _known_bp_stack_offsets_8616(codegen)


@cython.ccall
def _snapshot_adjusted_access_8616(
    expr: object, snapshot_tracker: object, codegen: object
) -> object | None:
    """Materialize a snapshot-adjusted indexed access when proven."""
    if not (
        snapshot_tracker is not None and isinstance(expr, structured_c.CIndexedVariable)
    ):
        return None
    adjusted_access = snapshot_tracker.materialize_indexed_access(
        expr,
        source_instruction_addrs=instruction_addrs_from_node_8616(expr),
        codegen=codegen,
    )
    if adjusted_access is not expr:
        adjusted_object: object = adjusted_access
        return adjusted_object
    return None


@cython.ccall
def _snapshot_adjusted_helper_8616(
    expr: object, snapshot_tracker: object, codegen: object
) -> object | None:
    """Materialize a snapshot-adjusted SEG helper call offset when proven."""
    if not (
        snapshot_tracker is not None
        and isinstance(expr, structured_c.CFunctionCall)
        and isinstance(expr.callee_target, str)
        and expr.callee_target in {"SEG_U8", "SEG_U16", "SEG_U32"}
        and len(expr.args) >= 2
    ):
        return None
    adjusted_offset = snapshot_tracker.materialize(
        expr.args[1],
        source_instruction_addrs=instruction_addrs_from_node_8616(expr),
        provenance_node=expr,
        codegen=codegen,
    )
    if adjusted_offset is not expr.args[1]:
        return cast(
            object,
            structured_c.CFunctionCall(
                expr.callee_target,
                expr.callee_func,
                [expr.args[0], adjusted_offset, ] + list(expr.args[2:]),
                show_demangled_name=expr.show_demangled_name,
                show_disambiguated_name=expr.show_disambiguated_name,
                tags=dict(expr.tags),
                codegen=codegen,
            ),
        )
    return None


@cython.ccall
def _lowered_matched_access_8616(
    expr: object,
    matched: SegmentedMemoryExpr,
    snapshot_tracker: object,
    codegen: _AngrCodegenBoundary8616,
    project: object,
) -> object | None:
    """Apply snapshot/SS/width adjustments then emit the lowered access."""
    exact_width_bits: object
    macro: object
    pointer_access: object
    if snapshot_tracker is not None:
        adjusted_offset = snapshot_tracker.materialize(
            matched.offset_expr,
            source_instruction_addrs=instruction_addrs_from_node_8616(expr),
            provenance_node=expr,
            codegen=codegen,
        )
        if adjusted_offset is not matched.offset_expr:
            matched = replace(matched, offset_expr=adjusted_offset)
    if matched.space == "SS" and _is_proven_ss_stack_access_8616(matched, codegen=codegen, project=project):
        return None
    exact_width_bits = _logical_segmented_access_width_bits_8616(
        expr,
        matched,
        codegen,
    )
    if exact_width_bits is not None:
        matched = replace(matched, width_bits=exact_width_bits)
    pointer_access = _near_pointer_arg_access_8616(matched, codegen, provenance_node=expr)
    if pointer_access is not None:
        return cast(object, pointer_access)
    macro = _seg_macro_for_width_bits_8616(matched.width_bits)
    if macro is None:
        return None
    return cast(
        object,
        structured_c.CFunctionCall(
            macro,
            None,
            [matched.segment_expr, matched.offset_expr],
            codegen=codegen,
            tags=_exact_segmented_load_tags_8616(matched, codegen, macro, expr),
        ),
    )


@cython.ccall
def lower_runtime_segment_access_8616(
    expr: object,
    *,
    target: object,
    snapshot_tracker: StackPointerSnapshotTracker8616 | None = None,
    decomposition_cache: LinearGlobalDecompositionCache8616 | None = None,
) -> object | None:
    """Lower a proven segmented dereference to a runtime helper or pointer access."""
    adjusted_access: object
    adjusted_helper: object
    matched: object
    project: object
    stripped_expr = _strip_casts_8616(expr)
    snapshot_candidate = snapshot_tracker is not None and (
        isinstance(expr, structured_c.CIndexedVariable)
        or (
            isinstance(expr, structured_c.CFunctionCall)
            and isinstance(expr.callee_target, str)
            and expr.callee_target in {"SEG_U8", "SEG_U16", "SEG_U32"}
            and len(expr.args) >= 2
        )
    )
    dereference_candidate = (
        isinstance(stripped_expr, structured_c.CUnaryOp)
        and stripped_expr.op == "Dereference"
    )
    if not snapshot_candidate and not dereference_candidate:
        return None
    codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(expr, "codegen", None))
    adjusted_access = _snapshot_adjusted_access_8616(expr, snapshot_tracker, codegen)
    if adjusted_access is not None:
        return adjusted_access
    adjusted_helper = _snapshot_adjusted_helper_8616(expr, snapshot_tracker, codegen)
    if adjusted_helper is not None:
        return adjusted_helper
    project = _dynamic_angr_attr_8616(codegen, "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(
        expr,
        project=project,
        access="read",
        decomposition_cache=decomposition_cache,
    )
    if matched is None:
        return None
    return _lowered_matched_access_8616(expr, matched, snapshot_tracker, cast(_AngrCodegenBoundary8616, codegen), project)


@cython.ccall
def lower_runtime_segment_address_8616(
    expr: object,
    *,
    target: object,
    decomposition_cache: LinearGlobalDecompositionCache8616 | None = None,
) -> object | None:
    """Lower a proven segmented address expression to an explicit far pointer helper."""
    matched: object
    project: object
    stripped_expr = _strip_casts_8616(expr)
    if not isinstance(
        stripped_expr,
        (structured_c.CBinaryOp, structured_c.CVariable),
    ) and _dynamic_angr_attr_8616(stripped_expr, "dirty", None) is None:
        return None
    codegen = cast(_AngrCodegenBoundary8616 | None, _dynamic_angr_attr_8616(expr, "codegen", None))
    project = _dynamic_angr_attr_8616(codegen, "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(
        expr,
        project=project,
        access="address",
        decomposition_cache=decomposition_cache,
    )
    if matched is None:
        return None
    if matched.space not in {"DS", "ES"}:
        return None
    return cast(
        object,
        structured_c.CFunctionCall(
            "MK_FP",
            None,
            [matched.segment_expr, matched.offset_expr],
            codegen=codegen,
            tags={"inertia_x86_16_runtime_segment_helper": "MK_FP"},
        ),
    )


@cython.ccall
def _runtime_segment_helper_name_8616(node: object) -> object:
    candidate: object
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    for candidate in (
        _dynamic_angr_attr_8616(node, "callee_target", None),
        _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(node, "callee_func", None), "name", None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate.strip()
    return None


@cython.ccall
def _runtime_segment_helper_width_8616(name: object) -> int | None:
    normalized = name.upper() if isinstance(name, str) else ""
    if normalized == "SEG_U8":
        return 1
    if normalized == "SEG_U16":
        return 2
    if normalized == "SEG_U32":
        return 4
    return None


@cython.ccall
def _runtime_segment_helper_args_8616(node: object) -> object:
    args = _dynamic_angr_attr_8616(node, "args", None)
    if not isinstance(args, (list, tuple)) or len(args) != 2:
        return None
    return args[0], args[1]


@cython.ccall
def _runtime_segment_address_helper_name_8616(node: object) -> object:
    name = _runtime_segment_helper_name_8616(node)
    if isinstance(name, str) and name.upper() in {"MK_FP", "SEG_PTR"}:
        return name.upper()
    return None


@cython.ccall
def _same_runtime_segment_address_helper_8616(lhs: object, rhs: object) -> cython.bint:
    lhs_args: object
    lhs_name: object
    rhs_args: object
    rhs_name: object
    lhs_name = _runtime_segment_address_helper_name_8616(lhs)
    rhs_name = _runtime_segment_address_helper_name_8616(rhs)
    if lhs_name is None or rhs_name is None:
        return False
    lhs_args = _runtime_segment_helper_args_8616(lhs)
    rhs_args = _runtime_segment_helper_args_8616(rhs)
    if lhs_args is None or rhs_args is None:
        return False
    return bool(
        _same_c_expression_8616(lhs_args[0], rhs_args[0])
        and _same_c_expression_8616(lhs_args[1], rhs_args[1])
    )


def _direct_global_offsets_for_segment_proof_8616(
    project: object,
    codegen: _AngrCodegenBoundary8616,
) -> frozenset[cython.longlong]:
    cod_metadata: object
    function: object
    item: object
    ref: object
    offsets: set[cython.longlong] = set()
    synthetic_globals = _dynamic_angr_attr_8616(codegen, "_inertia_synthetic_globals", None)
    if not isinstance(synthetic_globals, dict):
        synthetic_globals = _dynamic_angr_attr_8616(project, "_inertia_synthetic_globals", None)
    if isinstance(synthetic_globals, dict):
        offsets.update(int(offset) & 0xFFFF for offset in iter(synthetic_globals) if isinstance(offset, int))

    try:
        from inertia.structuring.simple_loop_recovery import _function_instruction_summaries_8616

        from .segmented_global_loads import (
            DirectSegmentedGlobalLoadEvidence8616,
            DirectSegmentedGlobalStoreEvidence8616,
            _collect_direct_global_symbol_refs_8616,
            _collect_synthetic_direct_global_symbol_refs_8616,
            _merge_direct_global_symbol_refs_8616,
            recover_direct_segmented_global_load_evidence_8616,
            recover_direct_segmented_global_store_evidence_8616,
        )
    except Exception:
        return frozenset(offsets)

    function = _dynamic_angr_attr_8616(codegen, "_inertia_function", None) or _dynamic_angr_attr_8616(codegen, "_func", None)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    anonymous_spaces_by_offset: dict[cython.longlong, set[MemSpace]] = {}
    if function is not None:
        anonymous_evidence: tuple[
            DirectSegmentedGlobalLoadEvidence8616 | DirectSegmentedGlobalStoreEvidence8616, ...
        ] = (
            *recover_direct_segmented_global_load_evidence_8616(project, function),
            *recover_direct_segmented_global_store_evidence_8616(project, function),
        )
        for item in anonymous_evidence:
            anonymous_spaces_by_offset.setdefault(item.offset & 0xFFFF, set()).add(
                item.space
            )
    offsets.update(
        offset
        for offset, spaces in builtins.iter(anonymous_spaces_by_offset.items())
        if spaces == {MemSpace.DS}
    )
    cod_metadata = None
    func_addr = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(codegen, "cfunc", None), "addr", None)
    metadata_by_addr = _dynamic_angr_attr_8616(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if isinstance(func_addr, int) and isinstance(metadata_by_addr, dict):
        cod_metadata = metadata_by_addr.get(func_addr)
    refs = _merge_direct_global_symbol_refs_8616(
        _collect_direct_global_symbol_refs_8616(cod_metadata, summaries),
        _collect_synthetic_direct_global_symbol_refs_8616(synthetic_globals, summaries),
    )
    for ref in refs:
        offset = _dynamic_angr_attr_8616(ref, "offset", None)
        if isinstance(offset, int):
            offsets.add(offset & 0xFFFF)
    return frozenset(offsets)


@cython.ccall
def _register_segment_expr_8616(
    codegen: _AngrCodegenBoundary8616,
    project: object,
    segment_name: object,
) -> structured_c.CVariable | None:
    registers = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(project, "arch", None), "registers", None)
    reg_info = registers.get(segment_name.lower()) if isinstance(registers, dict) else None
    if not (isinstance(reg_info, tuple) and len(reg_info) >= 2):
        return None
    reg_offset, reg_size = reg_info[0], reg_info[1]
    if not isinstance(reg_offset, int) or not isinstance(reg_size, int):
        return None
    return structured_c.CVariable(
        SimRegisterVariable(reg_offset, reg_size, name=segment_name.lower()),
        codegen=codegen,
        variable_type=SimTypeShort(False),
    )


@cython.ccall
def _sp_relative_stack_offset_for_segment_proof_8616(
    offset_expr: object,
    project: object,
    codegen: _AngrCodegenBoundary8616,
) -> int | None:
    """Resolve SP-relative offsets only for SS segment proof, not stack variable recovery."""
    old_cache: object
    old_allow = _dynamic_angr_attr_8616(codegen, "_inertia_allow_runtime_helper_sp_segment_proof_8616", False)
    old_cache = _dynamic_angr_attr_8616(codegen, "_inertia_stack_offset_cache", None)
    before = _dynamic_angr_int_attr_8616(codegen, "_inertia_runtime_helper_sp_segment_proof_count_8616")
    typing.cast(typing.Any, codegen)._inertia_allow_runtime_helper_sp_segment_proof_8616 = True
    typing.cast(typing.Any, codegen)._inertia_stack_offset_cache = {}
    try:
        displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    finally:
        typing.cast(typing.Any, codegen)._inertia_allow_runtime_helper_sp_segment_proof_8616 = old_allow
        if old_cache is None:
            with contextlib.suppress(AttributeError):
                delattr(codegen, "_inertia_stack_offset_cache")
        else:
            typing.cast(typing.Any, codegen)._inertia_stack_offset_cache = old_cache
    after = _dynamic_angr_int_attr_8616(codegen, "_inertia_runtime_helper_sp_segment_proof_count_8616")
    if not isinstance(displacement, int) or after <= before:
        return None
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_sp_offset_ss_proof_count_8616")
    return displacement


@cython.ccall
def _runtime_helper_segment_proof_8616(
    segment_expr: object,
    offset_expr: object,
    width: cython.longlong,
    *,
    codegen: _AngrCodegenBoundary8616,
    project: object,
    global_offsets: object,
) -> object:
    key: object
    terminal_segment = _terminal_carrier_expr_8616(segment_expr, codegen)
    key = _carrier_key_8616(terminal_segment)
    if key is None:
        return None, None

    displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    canonical_displacement = _canonical_stack_offset_8616(displacement)
    if isinstance(canonical_displacement, int) and (
        _has_stack_storage_evidence_for_displacement_8616(codegen, canonical_displacement, width)
        or canonical_displacement in _known_bp_stack_offsets_8616(codegen)
    ):
        return key, "SS"

    sp_displacement = _sp_relative_stack_offset_for_segment_proof_8616(offset_expr, project, codegen)
    if isinstance(sp_displacement, int):
        return key, "SS"

    constant_offset = _constant_value_8616(offset_expr)
    if isinstance(constant_offset, int) and (constant_offset & 0xFFFF) in global_offsets:
        return key, "DS"
    return key, None


@cython.ccall
def _collect_segment_carrier_proofs_8616(
    root: object,
    typed_codegen: _AngrCodegenBoundary8616,
    project: object,
    global_offsets: object,
) -> tuple[dict[_CarrierKey8616, str], set[_CarrierKey8616], cython.longlong]:
    """Collect proven carrier→segment proofs; ambiguous keys are excluded."""
    args: object
    key: object
    previous: object
    proof: object
    width: object
    node: object
    carrier_proofs: dict[_CarrierKey8616, str] = {}
    ambiguous: set[_CarrierKey8616] = set()
    candidate_count = 0
    for node in (root, ) + tuple(_iter_c_nodes_deep_8616(root)):
        node = _strip_casts_8616(node)
        helper_name = _runtime_segment_helper_name_8616(node)
        width = _runtime_segment_helper_width_8616(helper_name)
        if width is None:
            continue
        args = _runtime_segment_helper_args_8616(node)
        if args is None:
            continue
        candidate_count += 1
        key, proof = _runtime_helper_segment_proof_8616(
            args[0],
            args[1],
            width,
            codegen=typed_codegen,
            project=project,
            global_offsets=global_offsets,
        )
        if key is None or proof is None:
            continue
        previous = carrier_proofs.get(key)
        if previous is not None and operator.ne(previous, proof):
            ambiguous.add(key)
            carrier_proofs.pop(key, None)
            continue
        if key not in ambiguous:
            carrier_proofs[key] = proof
    return carrier_proofs, ambiguous, candidate_count


@cython.dataclasses.dataclass
class _SegmentCarrierCtx8616:
    """State for runtime-helper segment-carrier materialization."""

    typed_codegen: _AngrCodegenBoundary8616
    project: object
    carrier_proofs: object
    ambiguous: object
    changed: cython.bint = False
    materialized_count: cython.longlong = 0
    refused_count: cython.longlong = 0


@cython.ccall
def _rewrite_segment_carrier_arg_8616(node: object, ctx: _SegmentCarrierCtx8616) -> object:
    """Materialize only a proved helper argument, retaining all value conversions.

    Casts are inspected to find helpers, never removed by this segment owner.
    Unrelated casts can change numeric width or the expression's void category.
    """
    args: object
    current_segment_name: object
    key: object
    proof: object
    segment_expr: object
    original = node
    helper = _strip_casts_8616(node)
    helper_name = _runtime_segment_helper_name_8616(helper)
    if _runtime_segment_helper_width_8616(helper_name) is None:
        return original
    args = _runtime_segment_helper_args_8616(helper)
    if args is None:
        return original
    terminal_segment = _terminal_carrier_expr_8616(args[0], ctx.typed_codegen)
    key = _carrier_key_8616(terminal_segment)
    proof = ctx.carrier_proofs.get(key) if key is not None and key not in ctx.ambiguous else None
    if proof is None:
        ctx.refused_count += 1
        return original
    current_segment = _strip_casts_8616(args[0])
    current_variable = current_segment.variable if isinstance(current_segment, structured_c.CVariable) else None
    current_segment_name = runtime_segment_name_for_variable_8616(current_variable)
    if current_segment_name is None:
        current_segment_name = physical_register_name_8616(current_segment)
    if isinstance(current_segment_name, str) and current_segment_name.lower() in {"cs", "ds", "es", "ss"}:
        if operator.eq(current_segment_name.upper(), proof):
            ctx.materialized_count += 1
        else:
            ctx.refused_count += 1
        return original
    segment_expr = _register_segment_expr_8616(ctx.typed_codegen, ctx.project, proof)
    if segment_expr is None:
        ctx.refused_count += 1
        return original
    ctx.changed = True
    ctx.materialized_count += 1
    args_list = _dynamic_angr_attr_8616(helper, "args", None)
    if isinstance(args_list, list):
        args_list[0] = segment_expr
    return original


def materialize_runtime_helper_segment_carriers_8616(
    codegen: object,
    *,
    project: object | None = None,
) -> cython.bint:
    """Materialize proven segment-register carriers in runtime helper calls."""
    root: object
    typed_codegen = cast(_AngrCodegenBoundary8616, codegen)
    if project is None:
        project = _dynamic_angr_attr_8616(codegen, "project", None)
    root = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(codegen, "cfunc", None), "statements", None)
    if project is None or root is None:
        return False

    global_offsets = _direct_global_offsets_for_segment_proof_8616(project, typed_codegen)
    carrier_proofs, ambiguous, candidate_count = _collect_segment_carrier_proofs_8616(
        root, typed_codegen, project, global_offsets
    )

    ctx = _SegmentCarrierCtx8616(
        typed_codegen=typed_codegen,
        project=project,
        carrier_proofs=carrier_proofs,
        ambiguous=ambiguous,
    )

    if _replace_c_children_8616(root, lambda node: _rewrite_segment_carrier_arg_8616(node, ctx)):
        ctx.changed = True
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_segment_carrier_candidate_count_8616", candidate_count)
    _bump_codegen_counter_8616(
        codegen,
        "_inertia_runtime_helper_segment_carrier_materialized_count_8616",
        ctx.materialized_count,
    )
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_segment_carrier_refused_count_8616", ctx.refused_count)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_helper_segment_carrier_ambiguous_count_8616", len(ambiguous))
    return ctx.changed



def _prune_runtime_segment_address_self_assignments_8616(codegen: _AngrCodegenBoundary8616) -> cython.bint:
    """Prune exact segment-address identities from every structured statement body."""
    root: object
    node: object
    root = _dynamic_angr_attr_8616(_dynamic_angr_attr_8616(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False

    changed = False
    candidates = 0
    pruned = 0
    refused = 0

    def is_prunable(stmt: object) -> cython.bint:
        nonlocal candidates, pruned, refused
        stmt = _strip_casts_8616(stmt)
        if not isinstance(stmt, structured_c.CAssignment):
            return False
        lhs = _strip_casts_8616(_dynamic_angr_attr_8616(stmt, "lhs", None))
        rhs = _strip_casts_8616(_dynamic_angr_attr_8616(stmt, "rhs", None))
        if _runtime_segment_address_helper_name_8616(lhs) is None:
            return False
        candidates += 1
        if _same_runtime_segment_address_helper_8616(lhs, rhs):
            pruned += 1
            return True
        refused += 1
        return False

    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, structured_c.CStatements):
            statements = list(_dynamic_angr_sequence_attr_8616(node, "statements"))
            rebuilt = [stmt for stmt in iter(statements) if not is_prunable(stmt)]
            if operator.ne(len(rebuilt), len(statements)):
                node.statements = rebuilt
                changed = True
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_address_self_assign_candidates_8616", candidates)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_address_self_assign_pruned_8616", pruned)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_segment_address_self_assign_refused_8616", refused)
    return changed


@cython.ccall
def lower_runtime_ss_segment_helper_to_stack_8616(
    node: object,
    *,
    codegen: _AngrCodegenBoundary8616,
    project: object,
    require_lvalue: cython.bint = False,
) -> object | None:
    """Convert a proven SS helper to a readable stack value or exact lvalue."""
    args: object
    width: object
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CFunctionCall):
        return None
    helper_name = _runtime_segment_helper_name_8616(node)
    width = _runtime_segment_helper_width_8616(helper_name)
    if width is None:
        return None
    args = _runtime_segment_helper_args_8616(node)
    if args is None:
        return None
    segment_expr, offset_expr = args
    segment_name = _segment_base_name_8616(segment_expr, project, codegen=codegen)
    if segment_name != "ss":
        return None
    displacement = _stack_offset_from_expr_8616(offset_expr, project, codegen)
    canonical_displacement = _canonical_stack_offset_8616(displacement)
    displacement = canonical_displacement if isinstance(canonical_displacement, int) else None
    if not isinstance(displacement, int):
        return None
    known_offsets = _known_bp_stack_offsets_8616(codegen)
    if (
        not _has_stack_storage_evidence_for_displacement_8616(codegen, displacement, width)
        and displacement not in known_offsets
    ):
        return None
    access = RealModeLinearStackAccess8616(displacement=displacement, width=width)
    return cast(
        object,
        stack_cvar_for_stable_ss_linear_access_8616(
            codegen,
            access,
            require_lvalue=require_lvalue,
        ),
    )


@cython.ccall
def _lower_ss_helper_lvalues_8616(
    root: object,
    typed_codegen: _AngrCodegenBoundary8616,
    project: object,
) -> tuple[cython.longlong, cython.longlong, cython.longlong, set[cython.longlong], cython.bint]:
    """Rewrite helper lvalue assignments; return (candidates, materialized, refused, refused_ids, changed)."""
    replacement: object
    assignment: object
    candidate_count = 0
    materialized_count = 0
    refused_count = 0
    refused_lvalue_helper_ids: set[cython.longlong] = set()
    changed = False
    for assignment in tuple(_iter_c_nodes_deep_8616(root)):
        if not isinstance(assignment, structured_c.CAssignment):
            continue
        lhs = _dynamic_angr_attr_8616(assignment, "lhs", None)
        if _runtime_segment_helper_width_8616(_runtime_segment_helper_name_8616(lhs)) is None:
            continue
        candidate_count += 1
        replacement = lower_runtime_ss_segment_helper_to_stack_8616(
            lhs,
            codegen=typed_codegen,
            project=project,
            require_lvalue=True,
        )
        if replacement is None:
            refused_count += 1
            refused_lvalue_helper_ids.add(id(_strip_casts_8616(lhs)))
            continue
        assignment.lhs = replacement
        changed = True
        materialized_count += 1
    return candidate_count, materialized_count, refused_count, refused_lvalue_helper_ids, changed


@cython.dataclasses.dataclass
class _SSHelperLowerCtx8616:
    """State for SS-helper-to-stack lowering transforms."""

    typed_codegen: _AngrCodegenBoundary8616
    project: object
    refused_lvalue_helper_ids: object
    candidate_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    refused_count: cython.longlong = 0
    changed: cython.bint = False


@cython.ccall
def _ss_helper_transform_8616(node: object, ctx: _SSHelperLowerCtx8616) -> object:
    """Lower one SS segment-helper node to a stack variable when proven."""
    cvar: object
    stripped = _strip_casts_8616(node)
    if id(stripped) in ctx.refused_lvalue_helper_ids:
        return node
    if not isinstance(stripped, structured_c.CFunctionCall):
        return node
    if _runtime_segment_helper_width_8616(_runtime_segment_helper_name_8616(node)) is None:
        return node
    ctx.candidate_count += 1
    cvar = lower_runtime_ss_segment_helper_to_stack_8616(
        node,
        codegen=ctx.typed_codegen,
        project=ctx.project,
    )
    if cvar is None:
        ctx.refused_count += 1
        return node
    ctx.changed = True
    ctx.materialized_count += 1
    return cvar


def lower_runtime_ss_segment_helpers_to_stack_8616(
    codegen: object,
    *,
    project: object | None = None,
) -> cython.bint:
    """Convert proven SS helpers after invalidating mutable offset evidence caches."""
    cfunc: object
    root: object
    typed_codegen = cast(_AngrCodegenBoundary8616, codegen)
    if project is None:
        project = typed_codegen.project
    cfunc = typed_codegen.cfunc
    if project is None or cfunc is None:
        return False
    root = cfunc.statements
    if root is None:
        return False

    typed_codegen._inertia_stack_offset_cache = {}
    typed_codegen._inertia_assignment_maps = None

    (
        lvalue_candidates,
        lvalue_materialized,
        lvalue_refused,
        refused_lvalue_helper_ids,
        lvalue_changed,
    ) = _lower_ss_helper_lvalues_8616(root, typed_codegen, project)

    ctx = _SSHelperLowerCtx8616(
        typed_codegen=typed_codegen,
        project=project,
        refused_lvalue_helper_ids=refused_lvalue_helper_ids,
        candidate_count=lvalue_candidates,
        materialized_count=lvalue_materialized,
        refused_count=lvalue_refused,
        changed=lvalue_changed,
    )

    new_root = _ss_helper_transform_8616(root, ctx)
    if new_root is not root:
        _replace_cfunc_statements_root_8616(cfunc, new_root)
        ctx.changed = True
    if _replace_c_children_8616(cfunc.statements, lambda node: _ss_helper_transform_8616(node, ctx)):
        ctx.changed = True
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_ss_helper_candidate_count_8616", ctx.candidate_count)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_ss_helper_materialized_count_8616", ctx.materialized_count)
    _bump_codegen_counter_8616(codegen, "_inertia_runtime_ss_helper_refused_count_8616", ctx.refused_count)
    return ctx.changed


@cython.ccall
def finalize_runtime_stack_lowering_8616(
    codegen: object,
    *,
    project: object | None = None,
) -> cython.bint:
    """Finalize SS helper projection and normalize proven writable scalar views."""
    helper_changed = lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project)
    lvalue_changed = normalize_scalar_assignment_lvalues_8616(codegen)
    return helper_changed or lvalue_changed


@cython.ccall
def replay_final_codegen_projections_8616(codegen: object) -> cython.bint:
    """Replay exact lowering-owned state projections after AST cleanup.

    Cleanup passes may replace structured-C nodes after the initial lowering
    boundary. Re-materialize only state whose typed lowering evidence still
    exists; do not infer new semantics at this orchestration boundary.
    """
    flags_changed = bool(lower_packed_flags_live_in_8616(codegen))
    scalar_values_changed = normalize_pointer_scalar_temporaries_8616(codegen)
    gp_state_changed = bool(lower_architectural_gp_register_state_8616(codegen))
    gp_stack_changed = bool(materialize_gp_stack_restores_8616(codegen))
    return flags_changed or scalar_values_changed or gp_state_changed or gp_stack_changed


@cython.ccall
def _invalidate_segmented_address_caches_8616(project: object) -> None:
    """Discard address classifications whose segment child was replaced."""
    rewrite_cache: object
    rewrite_cache = getattr(project, "_inertia_rewrite_cache", None)
    if not isinstance(rewrite_cache, MutableMapping):
        return
    rewrite_cache.pop("segment_reg_name", None)
    rewrite_cache.pop("segmented_addr_expr", None)


@cython.ccall
def _runtime_lowering_early_passes_8616(
    typed_codegen: _AngrCodegenBoundary8616, codegen: object, project: object
) -> cython.bint:
    """Early lowering passes that run before the AST transform."""
    changed = _rematerialize_binary_proven_near_pointer_types_8616(typed_codegen)
    changed = lower_packed_flags_live_in_8616(codegen) or changed
    changed = lower_direction_flag_state_8616(codegen) or changed
    changed = materialize_string_io_loop_carriers_8616(project, codegen) or changed
    changed = lower_architectural_gp_register_state_8616(codegen) or changed
    initial_segment_changed = lower_architectural_segment_register_state_8616(codegen)
    if initial_segment_changed:
        _invalidate_segmented_address_caches_8616(project)
        changed = True
    return changed


@cython.ccall
def _runtime_lowering_transform_8616(
    node: object,
    target: object,
    snapshot_tracker: StackPointerSnapshotTracker8616,
    decomposition_cache: LinearGlobalDecompositionCache8616,
    changed: object,
) -> object:
    """Lower one node's segmented access or address expression."""
    lowered_access: object
    lowered_addr: object
    lowered_access = lower_runtime_segment_access_8616(
        node,
        target=target,
        snapshot_tracker=snapshot_tracker,
        decomposition_cache=decomposition_cache,
    )
    if lowered_access is not None:
        changed[0] = True
        return lowered_access
    lowered_addr = lower_runtime_segment_address_8616(
        node,
        target=target,
        decomposition_cache=decomposition_cache,
    )
    if lowered_addr is not None:
        changed[0] = True
        return lowered_addr
    return node


@cython.ccall
def _runtime_lowering_late_passes_a_8616(
    typed_codegen: _AngrCodegenBoundary8616, codegen: object, project: object
) -> cython.bint:
    """Late lowering passes: pruning, carriers, prototype materialization."""
    changed = False
    if _prune_runtime_segment_address_self_assignments_8616(typed_codegen):
        changed = True
    typed_codegen._inertia_assignment_maps = None
    if materialize_runtime_helper_segment_carriers_8616(codegen, project=project):
        changed = True
    if _lower_typed_pointer_register_carrier_stores_8616(typed_codegen):
        changed = True
    if _lower_binary_proven_pointer_argument_helpers_8616(typed_codegen):
        changed = True
    if materialize_annotated_stack_prototype_8616(
        project,
        typed_codegen,
        fallback_to_positive_bp=False,
    ):
        changed = True
    if materialize_positive_bp_arguments_8616(project, typed_codegen):
        changed = True
    if unify_positive_bp_argument_identity_8616(typed_codegen):
        changed = True
    if lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project):
        changed = True
    return changed


@cython.ccall
def _runtime_lowering_late_passes_b_8616(
    typed_codegen: _AngrCodegenBoundary8616,
    codegen: object,
    project: object,
    active_function: object,
) -> cython.bint:
    """Late lowering passes: restores, segment/GP state, lvalue normalization."""
    changed = False
    if materialize_balanced_immediate_register_restores_8616(
        codegen,
        active_function,
        project=project,
    ):
        changed = True
    if lower_architectural_segment_register_state_8616(codegen):
        _invalidate_segmented_address_caches_8616(project)
        changed = True
        typed_codegen._inertia_assignment_maps = None
    if normalize_pointer_scalar_temporaries_8616(codegen):
        changed = True
        typed_codegen._inertia_assignment_maps = None
    if lower_architectural_gp_register_state_8616(codegen):
        changed = True
        typed_codegen._inertia_assignment_maps = None
    if normalize_scalar_assignment_lvalues_8616(codegen):
        changed = True
    # GP binding consumes stack variables, including whole-word local reloads.
    # Validate only after the SS access and lvalue projections exist.
    changed = materialize_gp_stack_restores_8616(codegen) or changed
    return changed


@cython.ccall
def _publish_runtime_lowering_stats_8616(
    typed_codegen: _AngrCodegenBoundary8616,
    facts: object,
    snapshot_tracker: StackPointerSnapshotTracker8616,
    decomposition_cache: LinearGlobalDecompositionCache8616,
    initial_segment_stats: SegmentRegisterStateLoweringStats8616,
) -> None:
    """Merge segment-state stats and publish lowering counters."""
    final_segment_stats = typed_codegen._inertia_segment_register_state_lowering_stats_8616
    typed_codegen._inertia_segment_register_state_lowering_stats_8616 = (
        SegmentRegisterStateLoweringStats8616(
            raw_fact_count=initial_segment_stats.raw_fact_count
            + final_segment_stats.raw_fact_count,
            normalized_fact_count=initial_segment_stats.normalized_fact_count
            + final_segment_stats.normalized_fact_count,
            classified_fact_count=initial_segment_stats.classified_fact_count
            + final_segment_stats.classified_fact_count,
            materialized_count=initial_segment_stats.materialized_count
            + final_segment_stats.materialized_count,
            failure_count=initial_segment_stats.failure_count
            + final_segment_stats.failure_count,
        )
    )
    classified_count = len(typed_codegen._inertia_near_pointer_argument_classified_offsets_8616)
    materialized_count = len(typed_codegen._inertia_near_pointer_argument_materialized_offsets_8616)
    typed_codegen._inertia_near_pointer_argument_stats_8616 = NearPointerArgumentStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(classified_count - materialized_count, 0),
        refusals=tuple(typed_codegen._inertia_near_pointer_argument_refusals_8616),
    )
    typed_codegen._inertia_stack_pointer_snapshot_stats_8616 = snapshot_tracker.stats
    typed_codegen._inertia_linear_global_decomposition_cache_stats_8616 = (
        decomposition_cache.stats()
    )
    snapshot_tracker.assert_closed()


@cython.ccall
def apply_runtime_segment_lowering_8616(
    codegen: object,
    *,
    target: object = "portable-flat",
) -> cython.bint:
    """Apply all runtime segmented-memory lowering passes for one generated C function."""
    cfunc: object
    project: object
    root: object
    typed_codegen = cast(_AngrCodegenBoundary8616, codegen)
    typed_codegen._inertia_final_codegen_projection_replayer_8616 = replay_final_codegen_projections_8616
    cfunc = typed_codegen.cfunc
    project = typed_codegen.project
    if cfunc is None or project is None:
        return False
    root = cfunc.statements
    if root is None:
        return False

    # Offset resolution depends on mutable alias/prototype evidence. A cache
    # populated by an earlier Structuring replay cannot cross this pass boundary.
    typed_codegen._inertia_stack_offset_cache = {}
    typed_codegen._inertia_assignment_maps = None
    active_function = _active_function_for_codegen_8616(typed_codegen)
    facts = collect_near_pointer_argument_facts_8616(active_function, project=project)
    snapshot_tracker = StackPointerSnapshotTracker8616(facts)
    decomposition_cache = LinearGlobalDecompositionCache8616()
    snapshot_tracker.bind_unique_untagged_helpers(root)
    typed_codegen._inertia_near_pointer_argument_facts_8616 = facts
    typed_codegen._inertia_near_pointer_argument_classified_offsets_8616 = set()
    typed_codegen._inertia_near_pointer_argument_materialized_offsets_8616 = set()
    typed_codegen._inertia_near_pointer_argument_refusals_8616 = []
    _reset_segmented_access_width_lane_8616(typed_codegen)

    changed = _runtime_lowering_early_passes_8616(typed_codegen, codegen, project)
    initial_segment_stats = typed_codegen._inertia_segment_register_state_lowering_stats_8616
    typed_codegen._inertia_assignment_maps = None

    transform_changed = [changed]
    transform = functools.partial(
        _runtime_lowering_transform_8616,
        target=target,
        snapshot_tracker=snapshot_tracker,
        decomposition_cache=decomposition_cache,
        changed=transform_changed,
    )

    new_root = transform(root)
    if new_root is not root:
        _replace_cfunc_statements_root_8616(cfunc, new_root)
        transform_changed[0] = True
    if _replace_c_children_8616(cfunc.statements, transform):
        transform_changed[0] = True
    changed = transform_changed[0]
    changed = _runtime_lowering_late_passes_a_8616(typed_codegen, codegen, project) or changed
    changed = _runtime_lowering_late_passes_b_8616(
        typed_codegen, codegen, project, active_function
    ) or changed
    _publish_runtime_lowering_stats_8616(
        typed_codegen, facts, snapshot_tracker, decomposition_cache, initial_segment_stats
    )
    return changed


__all__ = [
    "SegmentedMemoryExpr",
    "apply_runtime_segment_lowering_8616",
    "finalize_runtime_stack_lowering_8616",
    "lower_runtime_segment_access_8616",
    "lower_runtime_segment_address_8616",
    "lower_runtime_ss_segment_helper_to_stack_8616",
    "lower_runtime_ss_segment_helpers_to_stack_8616",
    "materialize_runtime_helper_segment_carriers_8616",
    "runtime_segment_push_source_cvar_8616",
]
