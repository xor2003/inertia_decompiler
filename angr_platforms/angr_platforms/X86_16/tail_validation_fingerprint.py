"""Layer: Tail Validation.

Responsibility: fingerprint recovered calls, expressions, locations, and control effects for comparison.
Forbidden: semantic recovery from source, COD, assembly, or rendered C text.
Dynamic boundary: attribute access is limited to third-party angr structured-C
nodes, codegen objects, and compatibility objects exposed by the decompiler.
"""


from __future__ import annotations

import builtins
import contextlib
import contextvars
import copy
import logging
import os
import re
import sys
import typing
from collections.abc import Iterator, Mapping
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CExpression,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
    CWhileLoop,
)
from angr.sim_type import SimType, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable

from .call_target_identity import normalize_x86_16_call_target_addr_8616
from .callee_name_normalization import normalize_callee_name_8616
from .callsite_summary import (
    CallsiteSummary8616,
)
from .callsite_summary import (
    summarize_x86_16_callsite as _summarize_x86_16_callsite_fallback,
)
from .decompiler_postprocess_utils import (
    _match_bp_stack_dereference_8616,
    _match_segmented_dereference_8616,
    _same_c_expression_8616,
    _stack_bp_displacement_8616,
    _structured_codegen_node_8616,
)
from .lowering.gp_register_state import runtime_gp_name_for_variable_8616
from .lowering.segment_register_state import runtime_segment_name_for_variable_8616
from .lowering.segmented_global_loads import IndexedSegmentedGlobalStoreEvidence8616
from .lowering.semantic_cast import CSemanticCast8616
from .lowering.stack_function_coordinates import (
    c_function_argument_machine_bp_offset_8616,
)
from .lowering.stack_variable_binding import StackVariableBinding
from .lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from .lowering.structured_intrinsics import lower_structured_insert_call_8616
from .validation_additive_terms import flatten_additive_terms_8616 as _flatten_additive_terms_8616
from .validation_aggregate_storage import aggregate_field_storage_8616
from .validation_stack_projection import proven_stack_projection_fingerprint_8616

__all__ = [
    "TAIL_VALIDATION_FINGERPRINT_VERSION",
    "_bool_projection_fingerprint",
    "_c_constant_int_value",
    "_expr_fingerprint",
    "_extract_same_zero_compare_expr_8616",
    "_extract_zero_flag_source_expr_8616",
    "_function_for_call_context_8616",
    "_indexed_global_write_location_fingerprints_8616",
    "_is_structured_c_intrinsic_call_8616",
    "_location_fingerprint",
    "_lookup_function_for_call_context_8616",
    "_normalize_zero_flag_comparison_8616",
    "_register_name",
    "_wrap_not_fingerprint",
    "build_x86_16_contextual_call_fingerprints",
]


TAIL_VALIDATION_FINGERPRINT_VERSION: int = 40
_SUB_TARGET_RE = re.compile(r"^(?:sub_|0x)(?P<addr>[0-9a-fA-F]+)$")
log: logging.Logger = logging.getLogger(__name__)
_EXPR_FINGERPRINT_CACHE_LIMIT_8616 = 500000
_TEMPORARY_FINGERPRINT_NODES_8616: contextvars.ContextVar[dict[int, object] | None] = (
    contextvars.ContextVar("temporary_fingerprint_nodes_8616", default=None)
)
_ExprFingerprintCacheKey8616 = tuple[object, int, str]


def _dynamic_tail_validation_getattr_8616(obj: object, name: str, default: object = None) -> Any:
    """Read an attribute across the dynamic angr structured-C/codegen boundary."""
    return builtins.getattr(obj, name, default)


class TailValidationStructuredIntrinsic8616(Enum):
    """Structured-codegen value intrinsics that are not observable helper calls."""

    INSERT = "INSERT"


def _structured_c_intrinsic_kind_8616(node: object) -> TailValidationStructuredIntrinsic8616 | None:
    if not isinstance(node, CFunctionCall):
        return None
    candidates = (
        _dynamic_tail_validation_getattr_8616(node, "callee_target", None),
        _dynamic_tail_validation_getattr_8616(node, "callee", None),
        _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(node, "callee_func", None), "name", None),
    )
    for candidate in candidates:
        name = _dynamic_tail_validation_getattr_8616(candidate, "name", candidate)
        if not isinstance(name, str) or not name:
            continue
        normalized = name.rsplit(".", 1)[-1].lstrip("_")
        if normalized == TailValidationStructuredIntrinsic8616.INSERT.value:
            return TailValidationStructuredIntrinsic8616.INSERT
    return None


def _is_structured_c_intrinsic_call_8616(node: object) -> bool:
    return _structured_c_intrinsic_kind_8616(node) is not None


def _expr_fingerprint_cache_8616(
    project: Any,
) -> dict[_ExprFingerprintCacheKey8616, str]:
    """Return the bounded expression fingerprint cache at the angr boundary."""
    cache = _dynamic_tail_validation_getattr_8616(project, "_inertia_tail_validation_expr_fingerprint_cache_8616", None)
    if not isinstance(cache, dict) or len(cache) > _EXPR_FINGERPRINT_CACHE_LIMIT_8616:
        cache = {}
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, project)._inertia_tail_validation_expr_fingerprint_cache_8616 = cache
            typing.cast(typing.Any, project)._inertia_tail_validation_expr_fingerprint_cache_nodes_8616 = {}
    return cache


def _expr_fingerprint_cache_nodes_8616(
    project: Any,
) -> dict[_ExprFingerprintCacheKey8616, object]:
    """Retain cached AST nodes so Python cannot reuse their identity keys."""
    nodes = _dynamic_tail_validation_getattr_8616(
        project,
        "_inertia_tail_validation_expr_fingerprint_cache_nodes_8616",
        None,
    )
    if not isinstance(nodes, dict) or len(nodes) > _EXPR_FINGERPRINT_CACHE_LIMIT_8616:
        nodes = {}
        with contextlib.suppress(Exception):
            typing.cast(
                typing.Any,
                project,
            )._inertia_tail_validation_expr_fingerprint_cache_nodes_8616 = nodes
    return nodes


def _first_codegen_8616(*nodes: Any) -> object | None:
    for node in nodes:
        codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
        if codegen is not None:
            return cast(object | None, codegen)
    return None


def _remember_temporary_fingerprint_node_8616(node: object) -> None:
    """Retain a temporary AST node within the current fingerprint operation."""

    temporary_nodes = _TEMPORARY_FINGERPRINT_NODES_8616.get()
    if temporary_nodes is not None:
        temporary_nodes[id(node)] = node


def _safe_rebuild_binary_8616(op: str, lhs: object, rhs: object, template: object) -> object:
    """Project simplified children without rerunning angr type inference."""
    if lhs is _dynamic_tail_validation_getattr_8616(template, "lhs", None) and rhs is _dynamic_tail_validation_getattr_8616(template, "rhs", None):
        return template
    if not isinstance(template, CBinaryOp):
        return template
    try:
        rebuilt = copy.copy(template)
        rebuilt.op = op
        rebuilt.lhs = lhs
        rebuilt.rhs = rhs
    except (AttributeError, TypeError, ValueError):
        return template
    _remember_temporary_fingerprint_node_8616(rebuilt)
    return rebuilt


def _safe_rebuild_unary_8616(op: str, operand: object, template: object) -> object:
    if operand is _dynamic_tail_validation_getattr_8616(template, "operand", None):
        return template
    codegen = _first_codegen_8616(template, operand)
    if codegen is None or not isinstance(operand, CExpression):
        return template
    rebuilt = CUnaryOp(op, operand, codegen=codegen)
    _remember_temporary_fingerprint_node_8616(rebuilt)
    return rebuilt


def _segment_linear_lowering_allowed(node: Any, segment_reg: str, project: Any = None) -> bool:
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    for owner in (codegen, project):
        lowering = _dynamic_tail_validation_getattr_8616(owner, "_inertia_segmented_memory_lowering", None)
        if not isinstance(lowering, dict):
            continue
        entry = lowering.get(segment_reg.upper())
        if isinstance(entry, dict) and bool(entry.get("allow_linear_lowering", False)):
            return True
    return False


def _register_name(project: object, reg_offset: int, size_bytes: int | None = None) -> str:
    """Return the exact overlapping register name when width is available."""
    arch = _dynamic_tail_validation_getattr_8616(project, "arch", None)
    translate = _dynamic_tail_validation_getattr_8616(arch, "translate_register_name", None)
    if callable(translate) and isinstance(size_bytes, int) and size_bytes > 0:
        try:
            exact_name = translate(reg_offset, size_bytes)
        except (KeyError, TypeError, ValueError):
            exact_name = None
        if isinstance(exact_name, str):
            return exact_name
    register_names = _dynamic_tail_validation_getattr_8616(arch, "register_names", {})
    name = register_names.get(reg_offset) if isinstance(register_names, Mapping) else None
    return name if isinstance(name, str) else f"reg@{reg_offset}"


def _dirty_attr_8616(obj: Any, attr: str) -> Any:
    try:
        return _dynamic_tail_validation_getattr_8616(obj, attr, None)
    except (AttributeError, TypeError, ValueError):
        return None


def _dirty_register_fingerprint_8616(node: Any, project: Any) -> str | None:
    dirty = _dynamic_tail_validation_getattr_8616(node, "dirty", None)
    if dirty is None:
        return None
    reg_offset = None
    for attr in ("reg_offset", "reg", "variable_offset"):
        value = _dirty_attr_8616(dirty, attr)
        if isinstance(value, int):
            reg_offset = value
            break
    if not isinstance(reg_offset, int):
        return None
    bits = _dirty_attr_8616(dirty, "bits")
    size = _dirty_attr_8616(dirty, "size")
    size_bytes = int(bits // 8) if isinstance(bits, int) and bits > 0 else int(size) if isinstance(size, int) else None
    registers = _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(project, "arch", None), "registers", None)
    if isinstance(registers, dict) and isinstance(size_bytes, int) and size_bytes > 0:
        exact_names = sorted(
            name
            for name, reg_info in registers.items()
            if (
                isinstance(name, str)
                and isinstance(reg_info, tuple)
                and len(reg_info) >= 2
                and reg_info[0] == reg_offset
                and reg_info[1] == size_bytes
            )
        )
        if exact_names:
            canonical_name = _register_name(project, reg_offset, size_bytes)
            return f"reg:{canonical_name if canonical_name in exact_names else exact_names[0]}"
    register_names = _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(project, "arch", None), "register_names", None)
    if not isinstance(register_names, dict) or reg_offset not in register_names:
        return None
    return f"reg:{_register_name(project, reg_offset)}"


def _c_constant_int_value(node: object) -> int | None:
    value = _dynamic_tail_validation_getattr_8616(node, "value", None) if isinstance(node, CConstant) else None
    if isinstance(value, int):
        return value
    return None


def _constant_type_8616(node: object) -> SimType:
    """Return a concrete C constant type for synthetic fingerprint-only nodes."""
    type_ = _dynamic_tail_validation_getattr_8616(node, "type", None)
    return type_ if isinstance(type_, SimType) else SimTypeShort(False)


def _tail_validation_stack_alias_refusal_stats_8616(codegen: Any) -> dict[str, int]:
    stats = _dynamic_tail_validation_getattr_8616(codegen, "_inertia_tail_validation_stack_alias_refusals", None)
    if not isinstance(stats, dict):
        stats = {}
        codegen._inertia_tail_validation_stack_alias_refusals = stats
    return stats


def _record_stack_alias_refusal_8616(codegen: object, reason: str) -> None:
    if codegen is None or not isinstance(reason, str) or not reason:
        return
    stats = _tail_validation_stack_alias_refusal_stats_8616(codegen)
    stats[reason] = int(stats.get(reason, 0) or 0) + 1


def _stack_slot_fingerprint_from_slot_8616(offset: int, size: int | None = None) -> str:
    size_text = f":size{size}" if isinstance(size, int) and size > 0 else ""
    return f"stack_slot:SS:BP{offset:+#x}{size_text}"


def _source_arg_fingerprint_from_slot_8616(name: str, offset: int, size: int | None = None) -> str:
    size_text = f":size{size}" if isinstance(size, int) and size > 0 else ""
    return f"stack_arg:{name}{size_text}:bp{offset:+#x}"


def _type_size_bytes_8616(type_: Any, *, default: int = 2) -> int:
    try:
        bits = _dynamic_tail_validation_getattr_8616(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _target_abi_type_size_bytes_8616(type_: Any, project: Any, *, default: int = 2) -> int:
    arch_name = _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(project, "arch", None), "name", None)
    if arch_name == "86_16":
        type_name = type(type_).__name__
        if type_name in {"SimTypeChar", "SimTypeNum"}:
            return 1
        if type_name in {"SimTypeShort", "SimTypeInt", "SimTypeBool"}:
            return 2
        if type_name == "SimTypeLong":
            return 4
        if type_name == "SimTypeLongLong":
            return 8
        if type_name == "SimTypePointer":
            return 2
    return _type_size_bytes_8616(type_, default=default)


def _source_arg_names_by_offset_8616(function: Any) -> dict[int, str]:
    prototype = _dynamic_tail_validation_getattr_8616(function, "prototype", None) if function is not None else None
    arg_names = tuple(arg_name for arg_name in (_dynamic_tail_validation_getattr_8616(prototype, "arg_names", ()) or ()) if isinstance(arg_name, str))
    arg_types = tuple(_dynamic_tail_validation_getattr_8616(prototype, "args", ()) or ())
    if not arg_names or len(arg_names) != len(arg_types):
        return {}
    offset = 4
    names_by_offset: dict[int, str] = {}
    for arg_name, arg_type in zip(arg_names, arg_types, strict=False):
        names_by_offset[offset] = arg_name
        offset += max(2, _type_size_bytes_8616(arg_type))
    return names_by_offset


def _source_arg_sizes_by_offset_8616(function: Any, project: Any) -> dict[int, int]:
    prototype = _dynamic_tail_validation_getattr_8616(function, "prototype", None) if function is not None else None
    arg_names = tuple(arg_name for arg_name in (_dynamic_tail_validation_getattr_8616(prototype, "arg_names", ()) or ()) if isinstance(arg_name, str))
    arg_types = tuple(_dynamic_tail_validation_getattr_8616(prototype, "args", ()) or ())
    if not arg_names or len(arg_names) != len(arg_types):
        return {}
    offset = 4
    sizes_by_offset: dict[int, int] = {}
    for _arg_name, arg_type in zip(arg_names, arg_types, strict=False):
        size = _target_abi_type_size_bytes_8616(arg_type, project)
        sizes_by_offset[offset] = size
        offset += max(2, size)
    return sizes_by_offset


def _cfunc_source_arg_names_by_offset_8616(cfunc: object, codegen: object | None = None) -> dict[int, str]:
    """Map argument labels in machine BP coordinates, never rendered offsets."""
    names_by_offset: dict[int, str] = {}
    for arg in tuple(_dynamic_tail_validation_getattr_8616(cfunc, "arg_list", ()) or ()):
        if not isinstance(arg, CVariable):
            continue
        variable = _dynamic_tail_validation_getattr_8616(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or _dynamic_tail_validation_getattr_8616(variable, "base", None) != "bp":
            continue
        offset = machine_bp_offset_for_stack_variable_8616(codegen if codegen is not None else arg.codegen, variable)
        if not isinstance(offset, int) or offset <= 0:
            continue
        name = _dynamic_tail_validation_getattr_8616(arg, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
        if not isinstance(name, str) or not name or _stack_name_is_generic_for_validation_8616(name):
            continue
        names_by_offset[offset] = name
    return names_by_offset


def _cfunc_source_arg_sizes_by_offset_8616(cfunc: object, codegen: object | None = None) -> dict[int, int]:
    """Map storage widths using the same projected identity as argument labels."""
    sizes_by_offset: dict[int, int] = {}
    for arg in tuple(_dynamic_tail_validation_getattr_8616(cfunc, "arg_list", ()) or ()):
        if not isinstance(arg, CVariable):
            continue
        variable = _dynamic_tail_validation_getattr_8616(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or _dynamic_tail_validation_getattr_8616(variable, "base", None) != "bp":
            continue
        offset = machine_bp_offset_for_stack_variable_8616(codegen if codegen is not None else arg.codegen, variable)
        size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
        if isinstance(offset, int) and offset > 0 and isinstance(size, int) and size > 0:
            sizes_by_offset[offset] = size
    return sizes_by_offset


def _source_arg_match_by_offset_8616(
    function: object,
    project: object,
    offset: int,
    *,
    size: int | None,
) -> tuple[str, int, int | None] | None:
    source_names_by_offset = _source_arg_names_by_offset_8616(function)
    source_sizes_by_offset = _source_arg_sizes_by_offset_8616(function, project)
    source_name = source_names_by_offset.get(offset)
    if isinstance(source_name, str) and source_name:
        return source_name, offset, source_sizes_by_offset.get(offset, size)
    if len(source_names_by_offset) != 1:
        return None
    [(only_offset, only_name)] = source_names_by_offset.items()
    source_size = source_sizes_by_offset.get(only_offset)
    if not isinstance(only_name, str) or not only_name:
        return None
    if isinstance(size, int) and isinstance(source_size, int) and size != source_size:
        return None
    # Some MSC switch-helper lowering snapshots expose the sole source argument
    # through a transient positive-BP helper slot. In one-argument functions the
    # source prototype gives a stronger storage identity than that helper slot.
    return only_name, only_offset, source_size if isinstance(source_size, int) else size


def _source_arg_location_fingerprint_8616(node: Any, project: Any) -> str | None:
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    active_codegen = _dynamic_tail_validation_getattr_8616(project, "_inertia_tail_validation_active_codegen", None)
    cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        codegen = active_codegen
        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
    func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        codegen = active_codegen
        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
        func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None)
    active_cfunc = _dynamic_tail_validation_getattr_8616(active_codegen, "cfunc", None)
    active_func_addr = _dynamic_tail_validation_getattr_8616(active_cfunc, "addr", None)
    if isinstance(active_func_addr, int) and active_func_addr == func_addr:
        codegen = active_codegen
        cfunc = active_cfunc
    if not isinstance(func_addr, int):
        return None
    variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
    if not isinstance(variable, SimStackVariable) or _dynamic_tail_validation_getattr_8616(variable, "base", None) != "bp":
        return None
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if not isinstance(offset, int) or offset <= 0:
        return None
    name = _dynamic_tail_validation_getattr_8616(node, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
    if not isinstance(name, str) or not name:
        return None
    function = _lookup_function_for_call_context_8616(project, func_addr)
    variable_size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
    raw_offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
    cfunc_abi_offset = (
        c_function_argument_machine_bp_offset_8616(cfunc, raw_offset, variable_size)
        if isinstance(raw_offset, int)
        else None
    )
    if isinstance(cfunc_abi_offset, int):
        offset = cfunc_abi_offset
    source_names_by_offset = _source_arg_names_by_offset_8616(function)
    source_name = source_names_by_offset.get(offset)
    if isinstance(source_name, str) and source_name:
        source_size = _source_arg_sizes_by_offset_8616(function, project).get(offset, variable_size)
        return _source_arg_fingerprint_from_slot_8616(
            source_name,
            offset,
            source_size if isinstance(source_size, int) and source_size > 0 else None,
        )
    if isinstance(cfunc_abi_offset, int):
        return _source_arg_fingerprint_from_slot_8616(
            f"arg_{offset:x}",
            offset,
            variable_size if isinstance(variable_size, int) and variable_size > 0 else None,
        )
    source_name = _cfunc_source_arg_names_by_offset_8616(cfunc, codegen).get(offset)
    if not isinstance(source_name, str) or not source_name:
        return None
    size = _cfunc_source_arg_sizes_by_offset_8616(cfunc, codegen).get(offset, variable_size)
    return _source_arg_fingerprint_from_slot_8616(
        source_name,
        offset,
        size if isinstance(size, int) and size > 0 else None,
    )


def _lookup_widened_carrier_proof_8616(value: Any, codegen: Any) -> Any:
    def _impl() -> Any:
        mapping = _dynamic_tail_validation_getattr_8616(codegen, "_inertia_tail_validation_widened_carriers", None)
        if not isinstance(mapping, dict):
            return None
        variable = _dynamic_tail_validation_getattr_8616(value, "variable", None)
        name = _dynamic_tail_validation_getattr_8616(value, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
        size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
        offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
        keys = [
            id(value),
            id(variable) if variable is not None else None,
            name,
            (name, size) if isinstance(name, str) and isinstance(size, int) else None,
            (offset, size) if isinstance(offset, int) and isinstance(size, int) else None,
        ]
        for key in keys:
            if key is not None and key in mapping:
                return mapping[key]
        return None

    return _impl()


def _candidate_widened_keys_8616(value: Any) -> tuple[object, ...]:
    variable = _dynamic_tail_validation_getattr_8616(value, "variable", None)
    name = _dynamic_tail_validation_getattr_8616(value, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
    size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
    offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
    return tuple(
        key
        for key in (
            id(value),
            id(variable) if variable is not None else None,
            name,
            (name, size) if isinstance(name, str) and isinstance(size, int) else None,
            (offset, size) if isinstance(offset, int) and isinstance(size, int) else None,
        )
        if key is not None
    )


def _widened_carrier_slot_fingerprint_8616(
    var_name: str | None,
    *,
    value: object = None,
    variable: object = None,
    codegen: object,
) -> str | None:
    proof = _lookup_widened_carrier_proof_8616(value, codegen) if value is not None else None
    if proof is None and isinstance(var_name, str):
        mapping = _dynamic_tail_validation_getattr_8616(codegen, "_inertia_tail_validation_widened_carriers", None)
        if isinstance(mapping, dict):
            proof = mapping.get(var_name)
    if proof is None:
        return _first_assignment_stack_slot_fingerprint_8616(value, variable, codegen)
    if not isinstance(proof, dict):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_recurrence_proof")
        return None
    offset = proof.get("offset")
    size = proof.get("size")
    carrier_size = proof.get("carrier_size")
    if not isinstance(offset, int):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_stable_slot")
        return None
    if not isinstance(size, int):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_materialized_local")
        return None
    if isinstance(carrier_size, int) and size <= carrier_size:
        _record_stack_alias_refusal_8616(codegen, "carrier_width_not_widened")
        return None
    return _stack_slot_fingerprint_from_slot_8616(offset, size)


def _first_assignment_stack_slot_fingerprint_8616(value: object, variable: object, codegen: object) -> str | None:
    """Return a widened stack slot when a generic carrier is first assigned from one."""

    if not isinstance(value, CVariable) or not isinstance(variable, SimStackVariable):
        return None
    name = _dynamic_tail_validation_getattr_8616(value, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
    if not _stack_name_is_generic_for_validation_8616(name):
        return None
    assignment_maps = _validation_assignment_maps_8616(codegen)
    if assignment_maps is None:
        return None
    _var_id_map, _name_map, _reg_map, first_name_map, _first_reg_map = assignment_maps
    rhs = first_name_map.get(name) if isinstance(name, str) else None
    if not isinstance(rhs, CVariable):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_recurrence_proof")
        return None
    rhs_variable = _dynamic_tail_validation_getattr_8616(rhs, "variable", None)
    rhs_offset = _dynamic_tail_validation_getattr_8616(rhs_variable, "offset", None)
    rhs_size = _dynamic_tail_validation_getattr_8616(rhs_variable, "size", None)
    carrier_size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
    if not isinstance(rhs_variable, SimStackVariable) or not isinstance(rhs_offset, int):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_stable_slot")
        return None
    if not isinstance(rhs_size, int):
        _record_stack_alias_refusal_8616(codegen, "carrier_no_materialized_local")
        return None
    if isinstance(carrier_size, int) and rhs_size <= carrier_size:
        _record_stack_alias_refusal_8616(codegen, "carrier_width_not_widened")
        return None
    return _stack_slot_fingerprint_from_slot_8616(rhs_offset, rhs_size)


def _stack_name_is_generic_for_validation_8616(name: object) -> bool:
    return (
        isinstance(name, str)
        and re.fullmatch(
            r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)",
            name,
        )
        is not None
    )


def _resolve_validation_copy_alias_expr_8616(
    node: Any,
    project: Any = None,
    *,
    seen_var_ids: set[int] | None = None,
) -> Any:
    """Resolve a proven value alias without rewriting segment-register identity."""

    def _impl() -> Any:
        nonlocal node, seen_var_ids
        node = _strip_validation_casts(node)
        if not isinstance(node, CVariable):
            return None
        variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
        if variable is None:
            return None
        codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
        if codegen is None:
            return None
        name = _dynamic_tail_validation_getattr_8616(node, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
        if isinstance(variable, SimRegisterVariable):
            reg = _dynamic_tail_validation_getattr_8616(variable, "reg", None)
            register_project = project or _dynamic_tail_validation_getattr_8616(codegen, "project", None)
            register_name = (
                _register_name(register_project, reg, _dynamic_tail_validation_getattr_8616(variable, "size", None))
                if isinstance(reg, int)
                else name
            )
            if isinstance(register_name, str) and register_name.lower() in {"cs", "ds", "es", "ss"}:
                return None
        if not _stack_name_is_generic_for_validation_8616(name) and not isinstance(variable, SimRegisterVariable):
            return None
        variable_id = id(variable)
        if seen_var_ids is None:
            seen_var_ids = set()
        if variable_id in seen_var_ids:
            return None
        seen_var_ids.add(variable_id)
        assignment_maps = _validation_assignment_maps_8616(codegen)
        if assignment_maps is None:
            return None
        var_id_map, name_map, reg_map, first_name_map, _first_reg_map = assignment_maps

        rhs = _validation_alias_rhs_lookup_8616(
            variable=variable,
            variable_id=variable_id,
            name=name,
            var_id_map=var_id_map,
            name_map=name_map,
            reg_map=reg_map,
        )
        resolved_rhs = _acceptable_validation_expr_rhs_8616(rhs)
        if (
            resolved_rhs is not None
            and resolved_rhs is not node
            and not _rhs_references_same_variable_8616(resolved_rhs, variable)
        ):
            return resolved_rhs
        # Address/traversal order is not a reaching-definition proof. An
        # ambiguous register must never borrow its first physical/name writer.
        if isinstance(variable, SimRegisterVariable):
            return None
        if isinstance(name, str):
            # Validation-only fallback: generic stack carriers often receive a
            # final trivial/non-stack update after their initial widened stack-slot
            # seed is established. Preserve the earliest explicit stack proof for
            # fingerprint canonicalization when the direct map is non-stack noise.
            first_rhs = _acceptable_validation_expr_rhs_8616(first_name_map.get(name))
            if (
                first_rhs is not None
                and first_rhs is not node
                and not _rhs_references_same_variable_8616(first_rhs, variable)
            ):
                return first_rhs
        return None

    return _impl()


def _validation_assignment_maps_8616(
    codegen: object,
) -> tuple[
    dict[int, object],
    dict[str, object],
    dict[tuple[object, ...], object],
    dict[str, object],
    dict[tuple[object, ...], object],
] | None:
    try:
        from .lowering.real_mode_linear import _ensure_assignment_maps_8616
    except Exception as ex:
        log.debug("assignment map import failed: %s", ex)
        return None
    try:
        var_id_map, name_map, reg_map, _multi_var, _multi_name, _multi_reg, first_name_map, first_reg_map = (
            _ensure_assignment_maps_8616(codegen)
        )
    except Exception:
        return None
    return var_id_map, name_map, reg_map, first_name_map, first_reg_map


def _validation_alias_rhs_lookup_8616(*, variable: Any, variable_id: int, name: Any, var_id_map: Any, name_map: Any, reg_map: Any) -> Any:
    rhs = var_id_map.get(variable_id)
    if rhs is None and isinstance(name, str):
        rhs = name_map.get(name)
    if rhs is None and isinstance(variable, SimRegisterVariable):
        reg = _dynamic_tail_validation_getattr_8616(variable, "reg", None)
        size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
        if isinstance(reg, int) and isinstance(size, int):
            rhs = reg_map.get((reg, size))
    return rhs


def _acceptable_stack_alias_rhs_8616(value: object) -> object | None:
    value = _strip_validation_casts(value)
    if isinstance(value, (CVariable, CIndexedVariable)):
        return cast(object | None, value)
    if isinstance(value, CUnaryOp) and value.op in {"Dereference", "Reference"}:
        return cast(object | None, value)
    return None


def _dirty_virtual_name_8616(node: Any) -> str | None:
    dirty = _dynamic_tail_validation_getattr_8616(node, "dirty", None)
    varid = _dynamic_tail_validation_getattr_8616(dirty, "varid", None)
    if isinstance(varid, int):
        return f"vvar_{varid}"
    tmp_idx = _dynamic_tail_validation_getattr_8616(dirty, "tmp_idx", None)
    if isinstance(tmp_idx, int):
        return f"tmp_{tmp_idx}"
    return None


def _acceptable_validation_expr_rhs_8616(value: object) -> object | None:
    value = _strip_validation_casts(value)
    if isinstance(value, (CConstant, CVariable, CIndexedVariable, CDirtyExpression)):
        return cast(object | None, value)
    if isinstance(value, CUnaryOp):
        if value.op in {"Dereference", "Reference"}:
            return cast(object | None, value)
        operand = _acceptable_validation_expr_rhs_8616(value.operand)
        return value if operand is not None else None
    if isinstance(value, CBinaryOp):
        lhs = _acceptable_validation_expr_rhs_8616(value.lhs)
        rhs = _acceptable_validation_expr_rhs_8616(value.rhs)
        return value if lhs is not None and rhs is not None else None
    if isinstance(value, CITE):
        cond = _acceptable_validation_expr_rhs_8616(value.cond)
        iftrue = _acceptable_validation_expr_rhs_8616(value.iftrue)
        iffalse = _acceptable_validation_expr_rhs_8616(value.iffalse)
        return value if cond is not None and iftrue is not None and iffalse is not None else None
    return None


def _resolve_validation_dirty_alias_expr_8616(node: Any) -> Any:
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    if codegen is None:
        return None
    name = _dirty_virtual_name_8616(node)
    if not isinstance(name, str):
        return None
    assignment_maps = _validation_assignment_maps_8616(codegen)
    if assignment_maps is None:
        return None
    _var_id_map, name_map, _reg_map, first_name_map, _first_reg_map = assignment_maps
    rhs = name_map.get(name)
    resolved = _acceptable_validation_expr_rhs_8616(rhs)
    if os.environ.get("INERTIA_DEBUG_TAIL_DIRTY_ALIAS"):
        log.warning(
            "[tail-dirty-alias] name=%r rhs=%r resolved=%r first_rhs=%r",
            name,
            rhs,
            resolved,
            first_name_map.get(name),
        )
    if resolved is not None and resolved is not node:
        return resolved
    first_rhs = first_name_map.get(name)
    resolved = _acceptable_validation_expr_rhs_8616(first_rhs)
    if resolved is not None and resolved is not node:
        return resolved
    return None


def _rhs_references_same_variable_8616(value: Any, variable: Any) -> bool:
    pending = [_strip_validation_casts(value)]
    seen_nodes: set[int] = set()
    while pending:
        current = _strip_validation_casts(pending.pop())
        if current is None:
            continue
        current_id = id(current)
        if current_id in seen_nodes:
            continue
        seen_nodes.add(current_id)
        if isinstance(current, CVariable) and _dynamic_tail_validation_getattr_8616(current, "variable", None) is variable:
            return True
        for attr in ("variable", "index", "operand", "lhs", "rhs", "expr"):
            if hasattr(current, attr):
                pending.append(_dynamic_tail_validation_getattr_8616(current, attr, None))
    return False


def _debug_tail_stack_alias_8616(
    codegen: Any,
    *,
    node: Any = None,
    candidate: str | None = None,
    alias_keys: tuple[str, ...] = (),
    binding: str | None = None,
    final: str | None = None,
) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            return
        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None) if codegen is not None else None
        func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None) if cfunc is not None else None
        delta = (
            _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(codegen, "project", None), "_inertia_original_linear_delta", None)
            if codegen is not None
            else None
        )
        original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
        target_text = os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and original != target_addr:
            return
        try:
            c_repr = node.c_repr(indent=0) if node is not None else None
        except Exception:
            c_repr = str(node) if node is not None else None
        sys.stderr.write(
            "[TAIL_STACK_ALIAS] "
            f"func={original:#x} raw={c_repr!r} candidate={candidate!r} "
            f"alias_keys={alias_keys!r} binding={binding!r} final={final!r}\n"
        )
        sys.stderr.flush()

    return _impl()


def _debug_tail_stack_alias_indexed_8616(
    codegen: Any,
    *,
    node: Any = None,
    base_var: Any = None,
    index_value: Any = None,
    bridge_key: Any = None,
    bridge_value: Any = None,
    alias_base_offset: Any = None,
    fallback_offset: Any = None,
    selected: Any = None,
    note: str,
) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            return
        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None) if codegen is not None else None
        func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None) if cfunc is not None else None
        delta = (
            _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(codegen, "project", None), "_inertia_original_linear_delta", None)
            if codegen is not None
            else None
        )
        original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
        target_text = os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and original != target_addr:
            return
        try:
            c_repr = node.c_repr(indent=0) if node is not None else None
        except Exception:
            c_repr = str(node) if node is not None else None
        base_offset = _dynamic_tail_validation_getattr_8616(base_var, "offset", None)
        base_size = _dynamic_tail_validation_getattr_8616(base_var, "size", None)
        base_name = _dynamic_tail_validation_getattr_8616(base_var, "name", None)
        sys.stderr.write(
            "[TAIL_STACK_ALIAS_INDEXED] "
            f"func={original:#x} note={note} raw={c_repr!r} "
            f"base_name={base_name!r} base_offset={base_offset!r} base_size={base_size!r} "
            f"index={index_value!r} bridge_key={bridge_key!r} bridge_value={bridge_value!r} "
            f"alias_base_offset={alias_base_offset!r} fallback_offset={fallback_offset!r} "
            f"selected={selected!r}\n"
        )
        sys.stderr.flush()

    return _impl()


def _stack_alias_map_8616(codegen: object) -> dict[int, tuple[object, int]]:
    def _impl() -> dict[int, tuple[object, int]]:
        cached = _dynamic_tail_validation_getattr_8616(codegen, "_inertia_stack_pointer_aliases_for_cvars", None)
        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
        root = _dynamic_tail_validation_getattr_8616(cfunc, "statements", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is root and isinstance(cached[1], dict):
            return cached[1]
        if root is None:
            return {}

        def _is_pointer_capable_stack_variable(var: object, cvar: object | None = None) -> bool:
            if not isinstance(var, SimStackVariable):
                return False
            if _dynamic_tail_validation_getattr_8616(var, "base", None) != "bp":
                return False
            size = _dynamic_tail_validation_getattr_8616(var, "size", None)
            if isinstance(size, int) and size >= 2:
                return True
            var_type = _dynamic_tail_validation_getattr_8616(cvar, "variable_type", None)
            return isinstance(var_type, SimTypePointer)

        def _is_bp_stack_var(expr: Any) -> bool:
            expr = _strip_validation_casts(expr)
            if isinstance(expr, CUnaryOp) and expr.op == "Reference":
                expr = _strip_validation_casts(expr.operand)
            if not isinstance(expr, CVariable):
                return False
            var = _dynamic_tail_validation_getattr_8616(expr, "variable", None)
            return isinstance(var, SimStackVariable) and _dynamic_tail_validation_getattr_8616(var, "base", None) == "bp"

        def _resolve_alias_expr(expr: Any, aliases: Any) -> Any:
            expr = _strip_validation_casts(expr)
            if isinstance(expr, CVariable):
                var = _dynamic_tail_validation_getattr_8616(expr, "variable", None)
                if not isinstance(var, SimStackVariable) or _dynamic_tail_validation_getattr_8616(var, "base", None) != "bp":
                    return None
                alias = aliases.get(id(var))
                if alias is not None:
                    return alias
                if _is_pointer_capable_stack_variable(var, expr):
                    return expr, 0
                return None
            if isinstance(expr, CUnaryOp) and expr.op == "Reference":
                operand = _strip_validation_casts(expr.operand)
                if _is_bp_stack_var(operand):
                    return operand, 0
                return None
            if isinstance(expr, CBinaryOp) and expr.op in {"Add", "Sub"}:
                lhs = _resolve_alias_expr(expr.lhs, aliases)
                rhs = _resolve_alias_expr(expr.rhs, aliases)
                lhs_value = _c_constant_int_value(_strip_validation_casts(expr.lhs))
                rhs_value = _c_constant_int_value(_strip_validation_casts(expr.rhs))
                if lhs is not None and isinstance(rhs_value, int):
                    base, offset = lhs
                    return base, offset + (rhs_value if expr.op == "Add" else -rhs_value)
                if rhs is not None and isinstance(lhs_value, int) and expr.op == "Add":
                    base, offset = rhs
                    return base, offset + lhs_value
            return None

        def _alias_stable_key(resolved: tuple[object, int]) -> tuple[int, int]:
            base, offset = resolved
            variable = _dynamic_tail_validation_getattr_8616(base, "variable", None)
            return (id(variable) if variable is not None else id(base), offset)

        def _iter_alias_assignment_candidates(start: object) -> Iterator[CAssignment]:
            seen: set[int] = set()
            stack = [start]
            visited = 0
            while stack:
                current = stack.pop()
                current_id = id(current)
                if current_id in seen:
                    continue
                seen.add(current_id)
                visited += 1
                if visited > max_nodes:
                    typing.cast(typing.Any, codegen)._inertia_tail_validation_stack_alias_candidate_budget_exceeded = True
                    break
                if isinstance(current, CAssignment):
                    yield current
                    continue
                if isinstance(current, CStatements):
                    stack.extend(reversed(tuple(_dynamic_tail_validation_getattr_8616(current, "statements", ()) or ())))
                    continue
                if isinstance(current, CExpressionStatement):
                    expr = _dynamic_tail_validation_getattr_8616(current, "expr", None)
                    if expr is not None:
                        stack.append(expr)
                    continue
                if isinstance(current, CIfElse):
                    else_node = _dynamic_tail_validation_getattr_8616(current, "else_node", None)
                    if else_node is not None:
                        stack.append(else_node)
                    condition_pairs = _dynamic_tail_validation_getattr_8616(current, "condition_and_nodes", None)
                    if isinstance(condition_pairs, (list, tuple)):
                        for pair in reversed(tuple(condition_pairs)):
                            if isinstance(pair, tuple) and len(pair) >= 2:
                                stack.append(pair[1])
                    continue
                if isinstance(current, (CForLoop, CWhileLoop, CDoWhileLoop)):
                    for attr in ("body", "iterator", "initializer"):
                        child = _dynamic_tail_validation_getattr_8616(current, attr, None)
                        if child is not None:
                            stack.append(child)
                    continue
                if isinstance(current, (list, tuple)):
                    stack.extend(reversed(tuple(current)))

        aliases: dict[int, tuple[object, int]] = {}
        alias_keys: dict[int, tuple[int, int]] = {}
        changed = True
        iteration_count = 0
        max_iterations = 32
        visited_nodes = 0
        max_nodes = 4096
        budget_exceeded = False
        while changed and iteration_count < max_iterations:
            iteration_count += 1
            changed = False
            for node in _iter_alias_assignment_candidates(root):
                visited_nodes += 1
                if visited_nodes > max_nodes:
                    budget_exceeded = True
                    changed = False
                    break
                if not isinstance(node, CAssignment):
                    continue
                lhs = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "lhs", None))
                if not isinstance(lhs, CVariable):
                    continue
                lhs_var = _dynamic_tail_validation_getattr_8616(lhs, "variable", None)
                if not isinstance(lhs_var, SimStackVariable) or _dynamic_tail_validation_getattr_8616(lhs_var, "base", None) != "bp":
                    continue
                resolved = _resolve_alias_expr(_dynamic_tail_validation_getattr_8616(node, "rhs", None), aliases)
                if resolved is None:
                    continue
                if not _is_pointer_capable_stack_variable(lhs_var, lhs):
                    rhs_expr = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "rhs", None))
                    if not (
                        (isinstance(rhs_expr, CUnaryOp) and rhs_expr.op == "Reference") or isinstance(rhs_expr, CBinaryOp)
                    ):
                        continue
                lhs_key = id(lhs_var)
                resolved_key = _alias_stable_key(resolved)
                if alias_keys.get(lhs_key) != resolved_key:
                    aliases[lhs_key] = resolved
                    alias_keys[lhs_key] = resolved_key
                    changed = True
            if budget_exceeded:
                break
        if changed or budget_exceeded:
            aliases = {}
            typing.cast(typing.Any, codegen)._inertia_tail_validation_stack_alias_incomplete = True
        typing.cast(typing.Any, codegen)._inertia_tail_validation_stack_alias_iterations = iteration_count
        typing.cast(typing.Any, codegen)._inertia_tail_validation_stack_alias_nodes = visited_nodes
        typing.cast(typing.Any, codegen)._inertia_stack_pointer_aliases_for_cvars = (root, aliases)
        typing.cast(typing.Any, codegen)._inertia_tail_validation_stack_pointer_aliases = aliases
        return aliases

    return _impl()


def _materialized_local_map_8616(codegen: object) -> dict[int, tuple[int | None, str | None]]:
    def _impl() -> dict[int, tuple[int | None, str | None]]:
        materialized: dict[int, tuple[int | None, str | None]] = {}

        def _record(offset: int, size: int | None, name: str | None) -> None:
            current = materialized.get(offset)
            if current is None:
                materialized[offset] = (size, name)
                return
            current_size, current_name = current
            if isinstance(size, int) and (not isinstance(current_size, int) or size > current_size):
                materialized[offset] = (size, name if name is not None else current_name)

        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
        variables_in_use = _dynamic_tail_validation_getattr_8616(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for variable, cvar in variables_in_use.items():
                if not isinstance(variable, SimStackVariable) or _dynamic_tail_validation_getattr_8616(variable, "base", None) != "bp":
                    continue
                offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
                if not isinstance(offset, int):
                    continue
                size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
                name = _dynamic_tail_validation_getattr_8616(variable, "name", None) or _dynamic_tail_validation_getattr_8616(cvar, "name", None)
                _record(offset, size if isinstance(size, int) else None, name if isinstance(name, str) else None)
        bindings = _dynamic_tail_validation_getattr_8616(codegen, "_inertia_stack_variable_bindings", None)
        if isinstance(bindings, tuple | list):
            for binding in bindings:
                if not isinstance(binding, StackVariableBinding):
                    continue
                _record(
                    binding.bp_offset,
                    binding.size if isinstance(binding.size, int) else None,
                    binding.var_name if isinstance(binding.var_name, str) else None,
                )
        return materialized

    return _impl()


def _stack_canonicalization_bridges_8616(codegen: Any) -> dict[tuple[str, int, int], int]:
    bridges = _dynamic_tail_validation_getattr_8616(codegen, "_inertia_stack_canonicalization_bridges", None)
    return bridges if isinstance(bridges, dict) else {}


def canonicalize_stack_alias_fingerprint_8616(
    value: object,
    *,
    stack_alias_map: Mapping[int, tuple[object, int]],
    materialized_local_map: Mapping[int, tuple[int | None, str | None]],
) -> str | None:
    """Canonicalize a materialized local stack alias into a stable fingerprint."""
    if not isinstance(value, int):
        return None
    entry = materialized_local_map.get(value)
    if entry is None:
        return None
    size, _name = entry
    return _stack_slot_fingerprint_from_slot_8616(value, size)


def _source_arg_stack_slot_fingerprint_8616(offset: int, codegen: Any, *, size: int | None = None) -> str | None:
    if not isinstance(offset, int) or offset <= 0 or codegen is None:
        return None
    cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
    project = _dynamic_tail_validation_getattr_8616(codegen, "project", None)
    active_codegen = _dynamic_tail_validation_getattr_8616(project, "_inertia_tail_validation_active_codegen", None)
    func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None)
    if (cfunc is None or not isinstance(func_addr, int)) and active_codegen is not None:
        codegen = active_codegen
        cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
        project = _dynamic_tail_validation_getattr_8616(codegen, "project", project)
    func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None)
    if not isinstance(func_addr, int) or project is None:
        _debug_source_arg_stack_slot_8616(
            codegen,
            offset=offset,
            size=size,
            reason="missing_function_context",
            final=None,
        )
        return None
    function = _lookup_function_for_call_context_8616(project, func_addr)
    cfunc_abi_offset = c_function_argument_machine_bp_offset_8616(
        cfunc,
        offset,
        size,
    )
    if isinstance(cfunc_abi_offset, int):
        offset = cfunc_abi_offset
    source_match = _source_arg_match_by_offset_8616(function, project, offset, size=size)
    if source_match is not None:
        source_name, source_offset, source_size = source_match
    elif isinstance(cfunc_abi_offset, int):
        source_name = f"arg_{offset:x}"
        source_offset = offset
        source_size = size
    else:
        source_name = _cfunc_source_arg_names_by_offset_8616(cfunc, codegen).get(offset) or ""
        source_offset = offset
        source_size = _cfunc_source_arg_sizes_by_offset_8616(cfunc, codegen).get(offset, size)
    if not isinstance(source_name, str) or not source_name:
        _debug_source_arg_stack_slot_8616(
            codegen,
            offset=offset,
            size=size,
            reason="no_source_arg_name",
            final=None,
        )
        return None
    final = _source_arg_fingerprint_from_slot_8616(
        source_name,
        source_offset,
        source_size if isinstance(source_size, int) and source_size > 0 else None,
    )
    _debug_source_arg_stack_slot_8616(
        codegen,
        offset=offset,
        size=size,
        reason="matched",
        final=final,
    )
    return final


def _debug_source_arg_stack_slot_8616(
    codegen: Any,
    *,
    offset: int,
    size: int | None,
    reason: str,
    final: str | None,
) -> None:
    if not os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
        return
    cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None) if codegen is not None else None
    func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None) if cfunc is not None else None
    delta = (
        _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(codegen, "project", None), "_inertia_original_linear_delta", None)
        if codegen is not None
        else None
    )
    original = func_addr + delta if isinstance(func_addr, int) and isinstance(delta, int) else func_addr
    target_text = os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and original != target_addr:
        return
    sys.stderr.write(
        "[TAIL_SOURCE_ARG_SLOT] "
        f"func={original!r} offset={offset:+#x} size={size!r} reason={reason!r} final={final!r}\n"
    )
    sys.stderr.flush()


def _canonical_or_unresolved_stack_fingerprint_8616(offset: int, codegen: Any, *, source: str, node: Any = None) -> str:
    """Preserve exact typed storage ranges before considering legacy carriers."""
    def _impl() -> str:
        if source == "stack_var":
            variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
            size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
            if isinstance(variable, SimStackVariable) and _dynamic_tail_validation_getattr_8616(variable, "base", None) == "bp":
                machine_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
                if machine_offset is None:
                    return f"unresolved_stack_carrier:SS:BP{offset:+#x}:{source}"
                return _stack_slot_fingerprint_from_slot_8616(
                    machine_offset,
                    size if isinstance(size, int) and size > 0 else None,
                )
        if source == "word_pair":
            source_arg = _source_arg_stack_slot_fingerprint_8616(offset, codegen, size=2)
            if source_arg is not None:
                return source_arg
            return _stack_slot_fingerprint_from_slot_8616(offset, 2)
        source_arg = _source_arg_stack_slot_fingerprint_8616(offset, codegen)
        if source_arg is not None:
            return source_arg
        materialized_local_map = _materialized_local_map_8616(codegen) if codegen is not None else {}
        normalized = canonicalize_stack_alias_fingerprint_8616(
            offset,
            stack_alias_map={},
            materialized_local_map=materialized_local_map,
        )
        if normalized is not None:
            _debug_tail_stack_alias_8616(
                codegen,
                node=node,
                candidate=f"stack:{offset:+#x}",
                alias_keys=(),
                binding=f"bp{offset:+#x}",
                final=normalized,
            )
            return normalized
        stack_alias_map = _stack_alias_map_8616(codegen) if codegen is not None else {}
        if codegen is None:
            return f"stack:{offset:+#x}"
        has_alias_context = bool(
            stack_alias_map or materialized_local_map or _dynamic_tail_validation_getattr_8616(codegen, "_inertia_stack_variable_bindings", None)
        )
        if has_alias_context:
            unresolved = f"unresolved_stack_carrier:SS:BP{offset:+#x}:{source}"
            _debug_tail_stack_alias_8616(
                codegen,
                node=node,
                candidate=f"stack:{offset:+#x}",
                alias_keys=tuple(sorted(str(key) for key in stack_alias_map)),
                binding=None,
                final=unresolved,
            )
            return unresolved
        return f"stack:{offset:+#x}"

    return _impl()


def _resolve_stack_alias_base_offset_8616(base_expr: Any, codegen: Any, *, seen: set[int] | None = None) -> int | None:
    def _impl() -> int | None:
        nonlocal base_expr, seen
        if seen is None:
            seen = set()
        while isinstance(base_expr, CTypeCast):
            base_expr = base_expr.expr
        if isinstance(base_expr, CUnaryOp) and base_expr.op == "Reference":
            base_expr = base_expr.operand
            while isinstance(base_expr, CTypeCast):
                base_expr = base_expr.expr
        if not isinstance(base_expr, CVariable):
            return None
        variable = _dynamic_tail_validation_getattr_8616(base_expr, "variable", None)
        if not isinstance(variable, SimStackVariable) or _dynamic_tail_validation_getattr_8616(variable, "base", None) != "bp":
            return None
        variable_id = id(variable)
        if variable_id in seen:
            return None
        seen.add(variable_id)
        alias_entry = _stack_alias_map_8616(codegen).get(variable_id)
        if alias_entry is not None:
            alias_base_expr, alias_offset = alias_entry
            base_offset = _resolve_stack_alias_base_offset_8616(alias_base_expr, codegen, seen=seen)
            if isinstance(base_offset, int) and isinstance(alias_offset, int):
                return base_offset + alias_offset
            _record_stack_alias_refusal_8616(codegen, "stack_alias_ambiguous_offset")
            return None
        offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
        return offset if isinstance(offset, int) else None

    return _impl()


def _resolve_stack_offset_from_indexed_8616(node: object, project: object | None = None) -> int | None:
    def _impl() -> int | None:
        nonlocal node
        node = _strip_validation_casts(node)
        if isinstance(node, CUnaryOp) and node.op == "Reference":
            node = _strip_validation_casts(node.operand)
        if not isinstance(node, CIndexedVariable):
            return None
        base = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "variable", None))
        index = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "index", None))
        index_value = _c_constant_int_value(index)
        if not isinstance(index_value, int):
            return None
        codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
        if isinstance(base, CVariable):
            base_var = _dynamic_tail_validation_getattr_8616(base, "variable", None)
            if isinstance(base_var, SimStackVariable) and codegen is not None:
                bridge_key = ("indexed_value", id(base_var), index_value)
                bridged = _stack_canonicalization_bridges_8616(codegen).get(bridge_key)
                _debug_tail_stack_alias_indexed_8616(
                    codegen,
                    node=node,
                    base_var=base_var,
                    index_value=index_value,
                    bridge_key=bridge_key,
                    bridge_value=bridged,
                    note="resolve_indexed_before_alias",
                )
                if isinstance(bridged, int):
                    return bridged
        if codegen is None:
            return None
        combined = CBinaryOp(
            "Add",
            base,
            CConstant(index_value, _constant_type_8616(index), codegen=codegen),
            codegen=codegen,
        )
        displacement = _stack_bp_displacement_8616(combined, project, codegen)
        if isinstance(displacement, int):
            return displacement
        canonical_offset = _resolve_stack_alias_base_offset_8616(base, codegen) if codegen is not None else None
        if isinstance(canonical_offset, int):
            _debug_tail_stack_alias_indexed_8616(
                codegen,
                node=node,
                base_var=_dynamic_tail_validation_getattr_8616(base, "variable", None) if isinstance(base, CVariable) else None,
                index_value=index_value,
                alias_base_offset=canonical_offset,
                selected=canonical_offset + index_value,
                note="resolve_indexed_alias_base",
            )
            return canonical_offset + index_value
        if isinstance(base, CVariable):
            variable = _dynamic_tail_validation_getattr_8616(base, "variable", None)
            offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
            if isinstance(variable, SimStackVariable) and isinstance(offset, int):
                _debug_tail_stack_alias_indexed_8616(
                    codegen,
                    node=node,
                    base_var=variable,
                    index_value=index_value,
                    fallback_offset=offset,
                    selected=offset + index_value,
                    note="resolve_indexed_fallback",
                )
                return offset + index_value
        return None

    return _impl()


def _strip_validation_casts(node: object) -> object:
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


def _strip_cosmetic_validation_casts_8616(node: object) -> object:
    """Strip ordinary codegen casts while retaining proven semantic casts."""
    while isinstance(node, CTypeCast) and not isinstance(node, CSemanticCast8616):
        node = node.expr
    return node


def _semantic_cast_type_fingerprint_8616(type_: object) -> str:
    """Fingerprint the observable width and signedness of one angr C type."""
    size = _dynamic_tail_validation_getattr_8616(type_, "size", None)
    signed = _dynamic_tail_validation_getattr_8616(type_, "signed", None)
    size_token = str(size) if isinstance(size, int) else "unknown"
    signed_token = str(signed).lower() if isinstance(signed, bool) else "unknown"
    return f"{type(type_).__name__}:bits={size_token}:signed={signed_token}"


def _strip_validation_casts_and_dirty_aliases_8616(node: object) -> object:
    node = _strip_validation_casts(node)
    if isinstance(node, CDirtyExpression):
        resolved = _resolve_validation_dirty_alias_expr_8616(node)
        if resolved is not None and resolved is not node:
            return _strip_validation_casts_and_dirty_aliases_8616(resolved)
    return node


def _wrap_not_fingerprint(fingerprint: str) -> str:
    if fingerprint.startswith("Not(") and fingerprint.endswith(")"):
        return fingerprint[4:-1]
    return f"Not({fingerprint})"


def _invert_cmp_op_8616(op: str) -> str | None:
    return {
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
    }.get(op)


def _stack_word_pair_fingerprint(node: Any, project: Any) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    low_offset = _stack_byte_offset_from_expr_8616(left, project)
    high_offset = _stack_byte_offset_from_scaled_expr_8616(right, project, scale=256)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        low_offset = _stack_byte_offset_from_expr_8616(right, project)
        high_offset = _stack_byte_offset_from_scaled_expr_8616(left, project, scale=256)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return _canonical_or_unresolved_stack_fingerprint_8616(
        low_offset,
        _dynamic_tail_validation_getattr_8616(node, "codegen", None),
        source="word_pair",
        node=node,
    )


def _global_word_pair_fingerprint_8616(node: object, project: object) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    low_offset = _global_byte_offset_from_expr_8616(left, project)
    high_offset = _global_byte_offset_from_scaled_expr_8616(right, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        low_offset = _global_byte_offset_from_expr_8616(right, project)
        high_offset = _global_byte_offset_from_scaled_expr_8616(left, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return f"global:{low_offset:#x}"


def _global_word_pair_from_proven_byte_8616(node: object, project: object) -> str | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    left, right = node.lhs, node.rhs
    low_offset = _proven_global_byte_offset_8616(left, project)
    high_offset = _ds_linear_byte_offset_from_scaled_expr_8616(right, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        low_offset = _proven_global_byte_offset_8616(right, project)
        high_offset = _ds_linear_byte_offset_from_scaled_expr_8616(left, project)
    if not isinstance(low_offset, int) or not isinstance(high_offset, int):
        return None
    if high_offset != low_offset + 1:
        return None
    return f"global:{low_offset:#x}"


def _proven_global_byte_offset_8616(node: object, project: object) -> int | None:
    """Return only directly proven global-byte storage, never recurse via a fingerprint."""
    offset = _materialized_global_byte_offset_8616(node)
    if isinstance(offset, int):
        return offset
    offset = _global_byte_offset_from_expr_8616(node, project)
    if isinstance(offset, int):
        return offset
    return None


def _materialized_global_byte_offset_8616(node: Any) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CVariable):
        return None
    variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = _dynamic_tail_validation_getattr_8616(variable, "addr", None)
    return addr if isinstance(addr, int) and addr >= 0 else None


def _global_byte_offset_from_expr_8616(node: Any, project: Any) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if isinstance(node, CVariable):
        variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
        if isinstance(variable, SimMemoryVariable):
            addr = _dynamic_tail_validation_getattr_8616(variable, "addr", None)
            if isinstance(addr, int) and addr >= 0:
                return addr
    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        location = _deref_location_fingerprint_8616(node, project)
        if isinstance(location, str) and location.startswith("global:"):
            try:
                return int(location[len("global:") :], 16)
            except ValueError:
                return None
        segmented_offset = _global_offset_from_segmented_deref_operand_8616(node, project)
        if isinstance(segmented_offset, int):
            return segmented_offset
    return None


def _ds_linear_byte_offset_from_expr_8616(node: object, project: object) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    matched = _segment_linear_offset_from_deref_operand_8616(node, project)
    if matched is None:
        return None
    segment_name, offset = matched
    return offset if segment_name == "ds" else None


def _ds_linear_byte_offset_from_scaled_expr_8616(node: object, project: object) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _c_constant_int_value(node.lhs) == 256:
            return _ds_linear_byte_offset_from_expr_8616(node.rhs, project)
        if _c_constant_int_value(node.rhs) == 256:
            return _ds_linear_byte_offset_from_expr_8616(node.lhs, project)
    if node.op == "Shl" and _c_constant_int_value(node.rhs) == 8:
        return _ds_linear_byte_offset_from_expr_8616(node.lhs, project)
    return None


def _global_offset_from_segmented_deref_operand_8616(node: object, project: object) -> int | None:
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    matched = _segment_linear_offset_from_deref_operand_8616(node, project)
    if matched is None:
        return None
    segment_name, offset = matched
    if segment_name == "ss":
        return None
    if not _segment_linear_lowering_allowed(node, segment_name, project):
        return None
    return offset


def _segment_linear_offset_from_deref_operand_8616(
    node: CUnaryOp, project: object
) -> tuple[str, int] | None:
    segment_name: str | None = None
    offset = 0
    for sign, term in _flatten_additive_terms_8616(node.operand):
        term_segment = _linear_segment_term_name_8616(term, project)
        if term_segment is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = term_segment
            continue
        value = _c_constant_int_value(term)
        if not isinstance(value, int):
            return None
        offset += sign * value
    if segment_name is None:
        return None
    return segment_name, offset


def _linear_segment_term_name_8616(node: object, project: object) -> str | None:
    node = _strip_validation_casts(node)
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Shl":
        if _c_constant_int_value(node.rhs) == 4:
            return _segment_register_expr_name_8616(node.lhs, project)
        if _c_constant_int_value(node.lhs) == 4:
            return _segment_register_expr_name_8616(node.rhs, project)
        return None
    if node.op != "Mul":
        return None
    if _c_constant_int_value(node.rhs) == 16:
        return _segment_register_expr_name_8616(node.lhs, project)
    if _c_constant_int_value(node.lhs) == 16:
        return _segment_register_expr_name_8616(node.rhs, project)
    return None


def _segment_register_expr_name_8616(node: Any, project: Any) -> str | None:
    node = _strip_validation_casts(node)
    dirty_fingerprint = _dirty_register_fingerprint_8616(node, project) if isinstance(node, CDirtyExpression) else None
    if isinstance(dirty_fingerprint, str) and dirty_fingerprint.startswith("reg:"):
        name = dirty_fingerprint[len("reg:") :].lower()
        return name if name in {"cs", "ds", "es", "ss"} else None
    if not isinstance(node, CVariable):
        return None
    variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return None
    reg = _dynamic_tail_validation_getattr_8616(variable, "reg", None)
    if not isinstance(reg, int):
        return None
    name = _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(project, "arch", None), "register_names", {}).get(reg)
    if not isinstance(name, str):
        return None
    name = name.lower()
    return name if name in {"cs", "ds", "es", "ss"} else None


def _global_byte_offset_from_scaled_expr_8616(node: object, project: object) -> int | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _c_constant_int_value(node.lhs) == 256:
            return _global_byte_offset_from_expr_8616(node.rhs, project)
        if _c_constant_int_value(node.rhs) == 256:
            return _global_byte_offset_from_expr_8616(node.lhs, project)
    if node.op == "Shl" and _c_constant_int_value(node.rhs) == 8:
        return _global_byte_offset_from_expr_8616(node.lhs, project)
    return None


def _stack_byte_offset_from_expr_8616(node: Any, project: Any) -> int | None:
    def _impl() -> int | None:
        nonlocal node
        node = _strip_validation_casts_and_dirty_aliases_8616(node)
        if isinstance(node, CVariable):
            variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
            offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
            if isinstance(offset, int):
                return offset
        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            bp_disp = _match_bp_stack_dereference_8616(node, project)
            if isinstance(bp_disp, int):
                return bp_disp
            operand = _strip_validation_casts(node.operand)
            if isinstance(operand, CIndexedVariable):
                base = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(operand, "variable", None))
                index = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(operand, "index", None))
                if isinstance(base, CUnaryOp) and base.op == "Reference":
                    base = _strip_validation_casts(base.operand)
                base_var = _dynamic_tail_validation_getattr_8616(base, "variable", None) if isinstance(base, CVariable) else None
                index_value = _c_constant_int_value(index)
                codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
                if isinstance(base_var, SimStackVariable) and isinstance(index_value, int) and codegen is not None:
                    bridged = _stack_canonicalization_bridges_8616(codegen).get(
                        ("indexed_deref", id(base_var), index_value)
                    )
                    if isinstance(bridged, int):
                        return bridged
            indexed_offset = _resolve_stack_offset_from_indexed_8616(node.operand, project)
            if isinstance(indexed_offset, int):
                return indexed_offset
            matched_offset = _match_bp_stack_dereference_8616(node, project)
            return matched_offset if isinstance(matched_offset, int) else None
        indexed_offset = _resolve_stack_offset_from_indexed_8616(node, project)
        if isinstance(indexed_offset, int):
            return indexed_offset
        return None

    return _impl()


def _stack_indexed_location_fingerprint_8616(node: object, project: object | None = None) -> str | None:
    def _impl() -> str | None:
        nonlocal node
        node = _strip_validation_casts_and_dirty_aliases_8616(node)
        if isinstance(node, CUnaryOp) and node.op == "Reference":
            node = node.operand
            while isinstance(node, CTypeCast):
                node = node.expr
        if not isinstance(node, CIndexedVariable):
            return None
        base = _dynamic_tail_validation_getattr_8616(node, "variable", None)
        index = _dynamic_tail_validation_getattr_8616(node, "index", None)
        while isinstance(base, CTypeCast):
            base = base.expr
        while isinstance(index, CTypeCast):
            index = index.expr
        if isinstance(base, CUnaryOp) and base.op == "Reference":
            base = base.operand
            while isinstance(base, CTypeCast):
                base = base.expr
        index_value = _c_constant_int_value(index)
        codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
        dynamic_near_pointer = _dynamic_near_pointer_indexed_location_fingerprint_8616(
            node,
            base=base,
            index=index,
            index_value=index_value,
            codegen=codegen,
            project=project,
        )
        if dynamic_near_pointer is not None:
            return dynamic_near_pointer
        if not isinstance(index_value, int):
            return None
        bridged = _indexed_location_bridge_8616(node=node, base=base, index_value=index_value, codegen=codegen)
        if bridged is not None:
            return bridged
        if codegen is None:
            return None
        combined = CBinaryOp(
            "Add",
            base,
            CConstant(index_value, _constant_type_8616(index), codegen=codegen),
            codegen=codegen,
        )
        displacement = _stack_bp_displacement_8616(combined, project, codegen)
        if isinstance(displacement, int):
            return _canonical_or_unresolved_stack_fingerprint_8616(
                displacement,
                codegen,
                source="indexed_combined",
                node=node,
            )
        alias_fingerprint = _indexed_location_alias_or_fallback_8616(
            node=node, base=base, index_value=index_value, codegen=codegen
        )
        return alias_fingerprint

    return _impl()


def _dynamic_near_pointer_indexed_location_fingerprint_8616(
    node: CIndexedVariable,
    *,
    base: object,
    index: object,
    index_value: int | None,
    codegen: object,
    project: object | None,
) -> str | None:
    """Fingerprint a dynamic indexed write through a proven near-pointer argument."""
    if isinstance(index_value, int) or codegen is None or not isinstance(base, CVariable):
        return None
    if not _is_validation_near_pointer_arg_cvar_8616(base, codegen):
        return None
    active_project = project or _dynamic_tail_validation_getattr_8616(codegen, "project", None)
    element_type = _dynamic_tail_validation_getattr_8616(node, "variable_type", None)
    base_type = _dynamic_tail_validation_getattr_8616(base, "variable_type", None)
    if element_type is None and isinstance(base_type, SimTypePointer):
        element_type = base_type.pts_to
    element_size = _target_abi_type_size_bytes_8616(element_type, active_project, default=0)
    if not 0 < element_size <= 8:
        return None
    scaled_parts, constant_offset = _scaled_additive_expr_parts_8616(
        index,
        element_size,
        active_project,
        set(),
    )
    if not scaled_parts:
        return None
    address_parts = [
        "Mul(reg:ds,const:16)",
        _expr_fingerprint(base, active_project),
        *scaled_parts,
    ]
    if constant_offset:
        address_parts.append(f"const:{constant_offset}")
    return f"deref:Add({','.join(address_parts)})"


def _indexed_location_bridge_8616(*, node: object, base: object, index_value: int, codegen: object) -> str | None:
    if not (isinstance(base, CVariable) and codegen is not None):
        return None
    pointer_arg_location = _near_pointer_arg_location_fingerprint_8616(base, index_value, codegen)
    if pointer_arg_location is not None:
        return pointer_arg_location
    base_var = _dynamic_tail_validation_getattr_8616(base, "variable", None)
    if not isinstance(base_var, SimStackVariable):
        return None
    bridge_key = ("indexed_value", id(base_var), index_value)
    bridged = _stack_canonicalization_bridges_8616(codegen).get(bridge_key)
    _debug_tail_stack_alias_indexed_8616(
        codegen,
        node=node,
        base_var=base_var,
        index_value=index_value,
        bridge_key=bridge_key,
        bridge_value=bridged,
        note="indexed_location_before_alias",
    )
    if not isinstance(bridged, int):
        return None
    return _canonical_or_unresolved_stack_fingerprint_8616(bridged, codegen, source="indexed_bridge", node=node)


def _near_pointer_arg_location_fingerprint_8616(base: object, index_value: int, codegen: object) -> str | None:
    if not isinstance(base, CVariable) or index_value != 0:
        return None
    if not _is_validation_near_pointer_arg_cvar_8616(base, codegen):
        return None
    project = _dynamic_tail_validation_getattr_8616(codegen, "project", None)
    return f"deref:Add(Mul(reg:ds,const:16),{_expr_fingerprint(base, project)})"


def _is_validation_near_pointer_arg_cvar_8616(cvar: object, codegen: object) -> bool:
    if isinstance(_dynamic_tail_validation_getattr_8616(cvar, "variable_type", None), SimTypePointer):
        return True
    cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
    arg_list = tuple(_dynamic_tail_validation_getattr_8616(cfunc, "arg_list", ()) or ())
    prototype_args = tuple(_dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(cfunc, "functy", None), "args", ()) or ())
    cvar_offset = _validation_stack_cvar_offset_8616(cvar)
    for index, arg in enumerate(arg_list):
        if not isinstance(arg, CVariable):
            continue
        same_object = arg is cvar
        same_offset = isinstance(cvar_offset, int) and _validation_stack_cvar_offset_8616(arg) == cvar_offset
        if not same_object and not same_offset:
            continue
        proto_type = prototype_args[index] if index < len(prototype_args) else None
        if isinstance(_dynamic_tail_validation_getattr_8616(arg, "variable_type", None), SimTypePointer) or isinstance(proto_type, SimTypePointer):
            return True
    return False


def _validation_stack_cvar_offset_8616(cvar: object) -> int | None:
    if not isinstance(cvar, CVariable):
        return None
    for variable in (_dynamic_tail_validation_getattr_8616(cvar, "variable", None), _dynamic_tail_validation_getattr_8616(cvar, "unified_variable", None)):
        offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and isinstance(offset, int):
            return offset
    return None


def _indexed_location_alias_or_fallback_8616(*, node: Any, base: Any, index_value: int, codegen: Any) -> str | None:
    def _impl() -> str | None:
        canonical_offset = _resolve_stack_alias_base_offset_8616(base, codegen) if codegen is not None else None
        if isinstance(canonical_offset, int):
            _debug_tail_stack_alias_indexed_8616(
                codegen,
                node=node,
                base_var=_dynamic_tail_validation_getattr_8616(base, "variable", None) if isinstance(base, CVariable) else None,
                index_value=index_value,
                alias_base_offset=canonical_offset,
                selected=canonical_offset + index_value,
                note="indexed_location_alias_base",
            )
            normalized = canonicalize_stack_alias_fingerprint_8616(
                canonical_offset + index_value,
                stack_alias_map=_stack_alias_map_8616(codegen),
                materialized_local_map=_materialized_local_map_8616(codegen),
            )
            if normalized is not None:
                return normalized
            _record_stack_alias_refusal_8616(codegen, "stack_alias_no_materialized_local")
        if not isinstance(base, CVariable):
            _record_stack_alias_refusal_8616(codegen, "stack_alias_missing_binding")
            return None
        variable = _dynamic_tail_validation_getattr_8616(base, "variable", None)
        offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
        if not isinstance(variable, SimStackVariable) or not isinstance(offset, int):
            _record_stack_alias_refusal_8616(codegen, "stack_alias_missing_binding")
            return None
        size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
        if isinstance(size, int) and size > 0:
            direct_slot = _stack_slot_fingerprint_from_slot_8616(offset + index_value, size)
            if direct_slot is not None:
                return direct_slot
        if codegen is not None:
            _record_stack_alias_refusal_8616(codegen, "stack_alias_ambiguous_offset")
            _debug_tail_stack_alias_indexed_8616(
                codegen,
                node=node,
                base_var=variable if isinstance(variable, SimStackVariable) else None,
                index_value=index_value,
                fallback_offset=offset,
                selected=offset + index_value,
                note="indexed_location_fallback",
            )
        return _canonical_or_unresolved_stack_fingerprint_8616(
            offset + index_value, codegen, source="indexed_fallback", node=node
        )

    return _impl()


def _stack_byte_offset_from_scaled_expr_8616(
    node: object, project: object, *, scale: int
) -> int | None:
    node = _strip_validation_casts_and_dirty_aliases_8616(node)
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "Mul":
        if _c_constant_int_value(node.lhs) == scale:
            return _stack_byte_offset_from_expr_8616(node.rhs, project)
        if _c_constant_int_value(node.rhs) == scale:
            return _stack_byte_offset_from_expr_8616(node.lhs, project)
    if node.op == "Shl":
        shift_bits = _c_constant_int_value(node.rhs)
        if shift_bits == 8:
            return _stack_byte_offset_from_expr_8616(node.lhs, project)
    return None


def _extract_deref_node(node: object) -> CUnaryOp | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    if isinstance(node, CUnaryOp) and node.op == "Dereference":
        return node
    return None


def _extract_deref_scaled_node(node: object, *, scale: int) -> CUnaryOp | None:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CBinaryOp) or node.op != "Mul":
        return None
    if _c_constant_int_value(node.lhs) == scale:
        return _extract_deref_node(node.rhs)
    if _c_constant_int_value(node.rhs) == scale:
        return _extract_deref_node(node.lhs)
    return None


def _bool_projection_fingerprint(node: Any, project: Any) -> str | None:
    def _impl() -> str | None:
        nonlocal node
        while isinstance(node, CTypeCast):
            node = node.expr

        if isinstance(node, CUnaryOp) and node.op == "Not":
            operand = _dynamic_tail_validation_getattr_8616(node, "operand", None)
            inner = _bool_projection_fingerprint(operand, project)
            if inner is not None:
                return _wrap_not_fingerprint(inner)
            if isinstance(operand, CUnaryOp) and operand.op == "Not":
                return _expr_fingerprint(operand.operand, project)
            return None

        if not isinstance(node, CITE):
            return None

        iftrue = _c_constant_int_value(_dynamic_tail_validation_getattr_8616(node, "iftrue", None))
        iffalse = _c_constant_int_value(_dynamic_tail_validation_getattr_8616(node, "iffalse", None))
        if (iftrue, iffalse) == (1, 0):
            inner = _bool_projection_fingerprint(node.cond, project)
            return inner if inner is not None else _expr_fingerprint(node.cond, project)
        if (iftrue, iffalse) == (0, 1):
            inner = _bool_projection_fingerprint(node.cond, project)
            if inner is None:
                inner = _expr_fingerprint(node.cond, project)
            return _wrap_not_fingerprint(inner)
        return None

    return _impl()


def _extract_same_zero_compare_expr_8616(node: object) -> object | None:
    if not isinstance(node, CBinaryOp) or node.op != "CmpEQ":
        return None
    if _c_constant_int_value(node.rhs) == 0:
        return cast(object | None, node.lhs)
    if _c_constant_int_value(node.lhs) == 0:
        return cast(object | None, node.rhs)
    return None


def _extract_zero_flag_source_expr_8616(node: Any) -> Any:
    def _impl() -> Any:
        if isinstance(node, CBinaryOp):
            if node.op == "Mul":
                for maybe_logic, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                    if _c_constant_int_value(maybe_scale) != 64:
                        continue
                    source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                    if source_expr is not None:
                        return source_expr
                    if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                        continue
                    lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                    rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                    if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                        return lhs_expr

            for child in (node.lhs, node.rhs):
                if _structured_codegen_node_8616(child):
                    extracted = _extract_zero_flag_source_expr_8616(child)
                    if extracted is not None:
                        return extracted

        elif isinstance(node, CUnaryOp):
            child = _dynamic_tail_validation_getattr_8616(node, "operand", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        elif isinstance(node, CTypeCast):
            child = _dynamic_tail_validation_getattr_8616(node, "expr", None)
            if _structured_codegen_node_8616(child):
                return _extract_zero_flag_source_expr_8616(child)

        return None

    return _impl()


def _normalize_zero_flag_comparison_8616(node: object) -> object:
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return node

    if _c_constant_int_value(node.rhs) == 0:
        source = node.lhs
    elif _c_constant_int_value(node.lhs) == 0:
        source = node.rhs
    else:
        return node

    source_expr = _extract_zero_flag_source_expr_8616(source)
    if source_expr is None:
        return node
    if node.op == "CmpEQ":
        return source_expr
    return _safe_rebuild_unary_8616("Not", source_expr, node)


def _simplify_expr_for_fingerprint_8616(node: Any) -> Any:
    def _impl() -> Any:
        nonlocal node
        node = _strip_cosmetic_validation_casts_8616(node)
        if isinstance(node, CUnaryOp):
            operand = _simplify_expr_for_fingerprint_8616(_dynamic_tail_validation_getattr_8616(node, "operand", None))
            if operand is not _dynamic_tail_validation_getattr_8616(node, "operand", None):
                return _safe_rebuild_unary_8616(node.op, operand, node)
            return node
        if not isinstance(node, CBinaryOp):
            return node
        lhs = _simplify_expr_for_fingerprint_8616(node.lhs)
        rhs = _simplify_expr_for_fingerprint_8616(node.rhs)
        lhs_zero = _c_constant_int_value(lhs) == 0
        rhs_zero = _c_constant_int_value(rhs) == 0
        if node.op == "Mul" and (lhs_zero or rhs_zero):
            return lhs if lhs_zero else rhs
        if node.op in {"Or", "Add", "Xor"}:
            if lhs_zero:
                return rhs
            if rhs_zero:
                return lhs
        if node.op in {"Sub"} and rhs_zero:
            return lhs
        if lhs is not node.lhs or rhs is not node.rhs:
            return _safe_rebuild_binary_8616(node.op, lhs, rhs, node)
        return node

    return _impl()


def _is_register_expr_8616(node: Any, project: Any, reg_name: str) -> bool:
    node = _strip_validation_casts(node)
    if not isinstance(node, CVariable):
        return False
    variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
    if runtime_segment_name_for_variable_8616(variable) == reg_name:
        return True
    if not isinstance(variable, SimRegisterVariable):
        return False
    reg = _dynamic_tail_validation_getattr_8616(variable, "reg", None)
    if not isinstance(reg, int):
        return False
    try:
        expected = project.arch.registers[reg_name][0]
    except (AttributeError, KeyError, TypeError):
        expected = None
    if isinstance(expected, int) and reg == expected:
        return True
    name = _dynamic_tail_validation_getattr_8616(node, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
    return isinstance(name, str) and name.lower() == reg_name


def _is_ss_linear_segment_term_8616(node: object, project: object) -> bool:
    node = _strip_validation_casts(node)
    if not isinstance(node, CBinaryOp):
        return False
    if node.op == "Shl":
        return _is_register_expr_8616(node.lhs, project, "ss") and _c_constant_int_value(node.rhs) == 4
    if node.op != "Mul":
        return False
    return (_is_register_expr_8616(node.lhs, project, "ss") and _c_constant_int_value(node.rhs) == 16) or (
        _is_register_expr_8616(node.rhs, project, "ss") and _c_constant_int_value(node.lhs) == 16
    )


def _linear_segment_term_fingerprint_8616(node: object, project: object) -> str | None:
    """Fingerprint a structural real-mode segment-base term before value aliases."""

    node = _strip_validation_casts(node)
    if not isinstance(node, CBinaryOp):
        return None
    segment_expr: object | None = None
    if node.op == "Shl" and _c_constant_int_value(node.rhs) == 4:
        segment_expr = node.lhs
    elif node.op == "Mul":
        if _c_constant_int_value(node.rhs) == 16:
            segment_expr = node.lhs
        elif _c_constant_int_value(node.lhs) == 16:
            segment_expr = node.rhs
    if segment_expr is None:
        return None
    for segment_name in ("cs", "ds", "es", "ss"):
        if _is_register_expr_8616(segment_expr, project, segment_name):
            return f"Mul(reg:{segment_name},const:16)"
    return None


def _contains_bp_stack_location_expr_8616(node: Any, *, seen: set[int] | None = None) -> bool:
    node = _strip_validation_casts(node)
    if node is None:
        return False
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return False
    seen.add(node_id)
    if isinstance(node, CVariable):
        variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
        return isinstance(variable, SimStackVariable) and _dynamic_tail_validation_getattr_8616(variable, "base", "bp") == "bp"
    if isinstance(node, CIndexedVariable):
        return _contains_bp_stack_location_expr_8616(_dynamic_tail_validation_getattr_8616(node, "variable", None), seen=seen)
    if isinstance(node, CUnaryOp):
        return _contains_bp_stack_location_expr_8616(_dynamic_tail_validation_getattr_8616(node, "operand", None), seen=seen)
    if isinstance(node, CBinaryOp):
        return _contains_bp_stack_location_expr_8616(node.lhs, seen=seen) or _contains_bp_stack_location_expr_8616(
            node.rhs, seen=seen
        )
    return False


def _additive_term_parts_8616(
    terms: tuple[tuple[int, object], ...], project: object
) -> tuple[str, ...]:
    """Build canonical additive address terms, including distributed scaled offsets."""
    parts: list[str] = []
    const_total = 0
    for sign, term in terms:
        const_value = _c_constant_int_value(term)
        if isinstance(const_value, int):
            const_total += sign * const_value
            continue
        segment_term = _linear_segment_term_fingerprint_8616(term, project)
        if segment_term is not None:
            parts.append(segment_term if sign > 0 else f"Neg({segment_term})")
            continue
        stripped_term = _strip_validation_casts(term)
        if isinstance(stripped_term, CBinaryOp) and stripped_term.op == "Shl":
            shift = _c_constant_int_value(stripped_term.rhs)
            scaled_lhs = _strip_validation_casts(stripped_term.lhs)
            if (
                isinstance(shift, int)
                and 0 <= shift <= 31
                and isinstance(scaled_lhs, CBinaryOp)
                and scaled_lhs.op in {"Add", "Sub"}
            ):
                scaled_parts, scaled_constant = _scaled_additive_expr_parts_8616(
                    scaled_lhs,
                    1 << shift,
                    project,
                    set(),
                    outer_sign=sign,
                )
                parts.extend(scaled_parts)
                const_total += scaled_constant
                continue
        part = _expr_fingerprint(term, project, set())
        if sign < 0:
            part = f"Neg({part})"
        parts.append(part)
    if const_total != 0 or not parts:
        parts.append(f"const:{const_total!r}")
    return tuple(parts)


def _scaled_additive_expr_parts_8616(
    expr: object,
    scale: int,
    project: object,
    child_seen: set[int],
    *,
    outer_sign: int = 1,
) -> tuple[tuple[str, ...], int]:
    """Scale an additive address expression while keeping constants separate."""
    stripped_expr = _strip_cosmetic_validation_casts_8616(expr)
    terms = (
        _flatten_additive_terms_8616(stripped_expr)
        if isinstance(stripped_expr, CBinaryOp) and stripped_expr.op in {"Add", "Sub"}
        else ((1, stripped_expr),)
    )
    parts: list[str] = []
    const_total = 0
    for inner_sign, inner_term in terms:
        sign = outer_sign * inner_sign
        inner_constant = _c_constant_int_value(inner_term)
        if isinstance(inner_constant, int):
            const_total += sign * inner_constant * scale
            continue
        term_fp = _expr_fingerprint(inner_term, project, set(child_seen))
        if scale == 1:
            part = term_fp
        elif scale > 0 and scale & (scale - 1) == 0:
            part = f"Shl({term_fp},const:{scale.bit_length() - 1})"
        else:
            part = f"Mul({term_fp},const:{scale})"
        if sign < 0:
            part = f"Neg({part})"
        parts.append(part)
    return tuple(parts), const_total


def _additive_terms_fingerprint_8616(
    terms: tuple[tuple[int, object], ...], project: object
) -> str:
    """Canonicalize additive segmented-address terms."""
    return f"Add({','.join(_additive_term_parts_8616(terms, project))})"


def _deref_operand_fingerprint_8616(operand: object, project: object) -> str:
    operand = _strip_validation_casts(operand)
    if not isinstance(operand, CBinaryOp) or operand.op not in {"Add", "Sub"}:
        return _expr_fingerprint(operand, project)
    terms = _flatten_additive_terms_8616(operand)
    has_bp_stack_location = any(_contains_bp_stack_location_expr_8616(term) for _sign, term in terms)
    if not has_bp_stack_location:
        return _additive_terms_fingerprint_8616(terms, project)
    filtered_terms = tuple(
        (sign, term) for sign, term in terms if not (sign > 0 and _is_ss_linear_segment_term_8616(term, project))
    )
    if len(filtered_terms) == len(terms):
        return _additive_terms_fingerprint_8616(terms, project)
    return _additive_terms_fingerprint_8616(filtered_terms, project)


def _expr_fingerprint(node: object, project: object, _seen: set[int] | None = None) -> str:
    """Fingerprint expression semantics while retaining proven storage coordinates."""
    def _impl() -> str:
        nonlocal node, _seen
        if _seen is None:
            _seen = set()
        if node is None:
            return "none"
        node_id = id(node)
        if node_id in _seen:
            return "expr_cycle"
        _seen.add(node_id)

        projection = proven_stack_projection_fingerprint_8616(node)
        if projection is not None:
            return projection

        def _child_seen() -> set[int]:
            return set(_seen or ())

        node = _simplify_expr_for_fingerprint_8616(node)
        cache_key = (
            _dynamic_tail_validation_getattr_8616(project, "_inertia_tv_active_function_addr", None),
            id(node),
            type(node).__name__,
        )
        snapshot_cache_active = bool(_dynamic_tail_validation_getattr_8616(project, "_inertia_tail_validation_snapshot_expr_cache_enabled_8616", False))
        temporary_nodes = _TEMPORARY_FINGERPRINT_NODES_8616.get()
        temporary_fingerprint_node = (
            temporary_nodes is not None and temporary_nodes.get(id(node)) is node
        )
        cacheable = (
            not temporary_fingerprint_node
            and (snapshot_cache_active or not _contains_bp_stack_location_expr_8616(node))
        )
        cache = _expr_fingerprint_cache_8616(project) if cacheable else {}
        cache_nodes = (
            _expr_fingerprint_cache_nodes_8616(project)
            if cacheable
            else {}
        )
        cached = (
            cache.get(cache_key)
            if cacheable and cache_nodes.get(cache_key) is node
            else None
        )
        if isinstance(cached, str):
            return cached

        def _cached(result: str) -> str:
            if cacheable and len(cache) <= _EXPR_FINGERPRINT_CACHE_LIMIT_8616:
                cache[cache_key] = result
                cache_nodes[cache_key] = node
            return result

        if isinstance(node, CSemanticCast8616):
            source_type = _semantic_cast_type_fingerprint_8616(node.src_type)
            destination_type = _semantic_cast_type_fingerprint_8616(node.dst_type)
            expression = _expr_fingerprint(node.expr, project, _child_seen())
            return _cached(
                f"SemanticCast({source_type}->{destination_type},{expression})"
            )

        stack_pair = _stack_word_pair_fingerprint(node, project)
        if stack_pair is not None:
            return _cached(stack_pair)
        global_pair = _global_word_pair_fingerprint_8616(node, project)
        if global_pair is not None:
            return _cached(global_pair)
        materialized_global_pair = _global_word_pair_from_proven_byte_8616(node, project)
        if materialized_global_pair is not None:
            return _cached(materialized_global_pair)
        bool_projection = _bool_projection_fingerprint(node, project)
        if bool_projection is not None:
            return _cached(bool_projection)
        node = _normalize_zero_flag_comparison_8616(node)
        if isinstance(node, CDirtyExpression):
            dirty_register = _dirty_register_fingerprint_8616(node, project)
            if dirty_register in {"reg:cs", "reg:ds", "reg:es", "reg:ss"}:
                return _cached(dirty_register)
            resolved_dirty = _resolve_validation_dirty_alias_expr_8616(node)
            if resolved_dirty is not None and resolved_dirty is not node:
                return _cached(_expr_fingerprint(resolved_dirty, project, _child_seen()))
            if dirty_register is not None:
                return _cached(dirty_register)
            dirty_name = _dirty_virtual_name_8616(node)
            if isinstance(dirty_name, str):
                return _cached(f"virtual:{dirty_name}")
            return _cached("virtual:unknown")
        if isinstance(node, CConstant):
            return _cached(f"const:{node.value!r}")
        if isinstance(node, CVariable):
            return _cached(_location_fingerprint(node, project, _child_seen() - {id(node)}))
        aggregate_storage = aggregate_field_storage_8616(node)
        if aggregate_storage is not None:
            return _cached(f"global:{aggregate_storage.offset:#x}")
        indexed_global_field_deref = _global_indexed_field_ds_deref_fingerprint_8616(
            node,
            project,
            _child_seen(),
        )
        if indexed_global_field_deref is not None:
            return _cached(indexed_global_field_deref)
        indexed_global_location = _global_indexed_location_fingerprint_8616(node)
        if indexed_global_location is not None:
            return _cached(indexed_global_location)
        indexed_global_deref = _global_indexed_ds_deref_fingerprint_8616(node, project, _child_seen())
        if indexed_global_deref is not None:
            return _cached(indexed_global_deref)
        indexed_stack_location = _stack_indexed_location_fingerprint_8616(node, project)
        if indexed_stack_location is not None:
            return _cached(indexed_stack_location)
        if isinstance(node, CUnaryOp):
            indexed_stack_location = _stack_indexed_location_fingerprint_8616(node, project)
            if indexed_stack_location is not None:
                return _cached(indexed_stack_location)
            if node.op == "Dereference":
                referenced = _dynamic_tail_validation_getattr_8616(node, "operand", None)
                if isinstance(referenced, CUnaryOp) and referenced.op == "Reference":
                    # C guarantees that dereferencing the address of an
                    # lvalue yields that same lvalue. Canonicalize before
                    # location handling so lowering preserves the fingerprint.
                    return _cached(_expr_fingerprint(referenced.operand, project, _child_seen()))
                deref_location = _location_fingerprint(node, project, _child_seen() - {id(node)})
                if isinstance(deref_location, str) and deref_location.startswith(
                    ("global:", "stack:", "stack_slot:", "unresolved_stack_carrier:")
                ):
                    return _cached(deref_location)
                operand_fp = _deref_operand_fingerprint_8616(node.operand, project)
                if isinstance(operand_fp, str) and operand_fp.startswith("stack_slot:"):
                    return _cached(operand_fp)
                return _cached(f"Dereference({operand_fp})")
            operand = _dynamic_tail_validation_getattr_8616(node, "operand", None)
            if node.op == "Not" and isinstance(operand, CBinaryOp):
                inverted = _invert_cmp_op_8616(operand.op)
                if inverted is not None:
                    lhs = _expr_fingerprint(operand.lhs, project, _child_seen())
                    rhs = _expr_fingerprint(operand.rhs, project, _child_seen())
                    return _cached(f"{inverted}({lhs},{rhs})")
            return _cached(f"{node.op}({_expr_fingerprint(node.operand, project, _child_seen())})")
        if isinstance(node, CBinaryOp):
            if node.op in {"Add", "Sub"}:
                parts: list[str] = []
                const_total = 0
                for sign, term in _flatten_additive_terms_8616(
                    node,
                    preserve_semantic_casts=True,
                ):
                    const_value = _c_constant_int_value(term)
                    if isinstance(const_value, int):
                        const_total += sign * const_value
                        continue
                    part = _expr_fingerprint(term, project, _child_seen())
                    if sign < 0:
                        part = f"Neg({part})"
                    parts.append(part)
                if const_total != 0 or not parts:
                    parts.append(f"const:{const_total!r}")
                return _cached(f"Add({','.join(parts)})")
            if node.op == "Shl" and _c_constant_int_value(node.rhs) == 4:
                return _cached(f"Mul({_expr_fingerprint(node.lhs, project, _child_seen())},const:16)")
            if node.op == "And":
                mask = _c_constant_int_value(node.rhs)
                parent = _expr_fingerprint(node.lhs, project, _child_seen())
                view_names = {
                    ("reg:eax", 0xFFFF): "ax",
                    ("reg:ebx", 0xFFFF): "bx",
                    ("reg:ecx", 0xFFFF): "cx",
                    ("reg:edx", 0xFFFF): "dx",
                    ("reg:esi", 0xFFFF): "si",
                    ("reg:edi", 0xFFFF): "di",
                    ("reg:eax", 0xFF): "al",
                    ("reg:ebx", 0xFF): "bl",
                    ("reg:ecx", 0xFF): "cl",
                    ("reg:edx", 0xFF): "dl",
                }
                view_name = view_names.get((parent, mask)) if isinstance(mask, int) else None
                if view_name is not None:
                    return _cached(f"reg:{view_name}")
                return _cached(f"And({parent},{_expr_fingerprint(node.rhs, project, _child_seen())})")
            lhs = _expr_fingerprint(node.lhs, project, _child_seen())
            rhs = _expr_fingerprint(node.rhs, project, _child_seen())
            return _cached(f"{node.op}({lhs},{rhs})")
        if isinstance(node, CFunctionCall):
            runtime_helper = _runtime_segment_helper_fingerprint_8616(node, project)
            if runtime_helper is not None:
                return _cached(runtime_helper)
            intrinsic = _structured_c_intrinsic_kind_8616(node)
            if intrinsic is not None:
                lowered_insert = lower_structured_insert_call_8616(node)
                if lowered_insert is not None:
                    return _cached(_expr_fingerprint(lowered_insert, project, _child_seen()))
                args = ",".join(
                    _expr_fingerprint(arg, project, _child_seen()) for arg in _dynamic_tail_validation_getattr_8616(node, "args", ()) or ()
                )
                return _cached(f"intrinsic:{intrinsic.value}({args})")
            callee = _call_target_name(node, project)
            args = ",".join(_expr_fingerprint(arg, project, _child_seen()) for arg in _dynamic_tail_validation_getattr_8616(node, "args", ()) or ())
            return _cached(f"call:{callee}({args})")
        return _cached(type(node).__name__)

    owns_temporary_scope = _seen is None
    temporary_scope_token = (
        _TEMPORARY_FINGERPRINT_NODES_8616.set({})
        if owns_temporary_scope
        else None
    )
    try:
        return _impl()
    finally:
        if temporary_scope_token is not None:
            _TEMPORARY_FINGERPRINT_NODES_8616.reset(temporary_scope_token)


def _call_target_name(node: CFunctionCall, project: object) -> str:
    def _addr_token(addr: int) -> str:
        canonical = normalize_x86_16_call_target_addr_8616(project, addr)
        return f"addr:{canonical:#x}" if isinstance(canonical, int) else f"addr:{addr:#x}"

    callee = _dynamic_tail_validation_getattr_8616(node, "callee_target", None)
    normalized_callee = normalize_callee_name_8616(callee)
    if isinstance(normalized_callee, str):
        match = _SUB_TARGET_RE.match(normalized_callee)
        if match is not None:
            try:
                return _addr_token(int(match.group("addr"), 16))
            except ValueError:
                pass
        resolved_addr = _resolve_call_symbol_addr_8616(project, normalized_callee)
        if isinstance(resolved_addr, int):
            return _addr_token(resolved_addr)
    callee_func = _dynamic_tail_validation_getattr_8616(node, "callee_func", None)
    callee_addr = _dynamic_tail_validation_getattr_8616(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        return _addr_token(callee_addr)
    if isinstance(normalized_callee, str):
        return normalized_callee
    name = normalize_callee_name_8616(_dynamic_tail_validation_getattr_8616(callee_func, "name", None))
    if isinstance(name, str):
        resolved_addr = _resolve_call_symbol_addr_8616(project, name)
        if isinstance(resolved_addr, int):
            return _addr_token(resolved_addr)
    if isinstance(name, str):
        return name
    return "<indirect>"


def _resolve_call_symbol_addr_8616(project: object, name: str) -> int | None:
    for candidate_project in _call_symbol_lookup_projects_8616(project):
        resolved_addr = _resolve_call_symbol_addr_in_project_8616(candidate_project, name)
        if isinstance(resolved_addr, int):
            return resolved_addr
    return None


def _call_symbol_lookup_projects_8616(project: Any) -> tuple[object, ...]:
    projects: list[object] = []
    for candidate in (project, _dynamic_tail_validation_getattr_8616(project, "_inertia_original_project", None)):
        if candidate is not None and all(candidate is not existing for existing in projects):
            projects.append(candidate)
    return tuple(projects)


def _resolve_call_symbol_addr_in_project_8616(project: Any, name: str) -> int | None:
    function_addr = _function_addr_by_name_8616(project, name)
    if isinstance(function_addr, int):
        return function_addr
    for addr, label in _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(project, "kb", None), "labels", {}).items():
        if isinstance(addr, int) and _call_symbol_names_equivalent_8616(label, name):
            return addr
    metadata = _dynamic_tail_validation_getattr_8616(project, "_inertia_lst_metadata", None)
    code_labels = _dynamic_tail_validation_getattr_8616(metadata, "code_labels", None)
    if isinstance(code_labels, dict):
        for addr, label in code_labels.items():
            if isinstance(addr, int) and _call_symbol_names_equivalent_8616(label, name):
                return addr
    return None


def _function_addr_by_name_8616(project: Any, name: str) -> int | None:
    functions = _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(project, "kb", None), "functions", None)
    lookup = _dynamic_tail_validation_getattr_8616(functions, "function", None)
    if not callable(lookup):
        return None
    for lookup_name in _call_symbol_lookup_names_8616(name):
        try:
            function = lookup(name=lookup_name, create=False)
        except TypeError:
            continue
        addr = _dynamic_tail_validation_getattr_8616(function, "addr", None)
        if isinstance(addr, int):
            return addr
    return None


def _call_symbol_lookup_names_8616(name: str) -> tuple[str, ...]:
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return ()
    names = [normalized]
    undecorated = normalized.lstrip("_")
    decorated = f"_{undecorated}" if undecorated else None
    if decorated is not None and decorated not in names:
        names.append(decorated)
    if undecorated and undecorated not in names:
        names.append(undecorated)
    return tuple(names)


def _call_symbol_names_equivalent_8616(left: str | None, right: str | None) -> bool:
    left_name = normalize_callee_name_8616(left)
    right_name = normalize_callee_name_8616(right)
    if not isinstance(left_name, str) or not isinstance(right_name, str):
        return False
    return left_name == right_name or left_name.lstrip("_") == right_name.lstrip("_")


def _call_symbol_name_8616(node: CFunctionCall) -> str | None:
    callee_func = _dynamic_tail_validation_getattr_8616(node, "callee_func", None)
    for raw in (
        _dynamic_tail_validation_getattr_8616(callee_func, "name", None),
        _dynamic_tail_validation_getattr_8616(node, "callee_target", None),
    ):
        normalized = normalize_callee_name_8616(raw)
        if isinstance(normalized, str) and normalized:
            return normalized
    return None


def _fingerprint_target_addr_from_summary_8616(summary: Any) -> int | None:
    if isinstance(summary, dict):
        target_addr = summary.get("target_addr")
    else:
        target_addr = _dynamic_tail_validation_getattr_8616(summary, "target_addr", None)
    return target_addr if isinstance(target_addr, int) else None


def _summarize_x86_16_callsite_for_fingerprint_8616(function: Any, callsite_addr: int) -> Any:
    tail_validation_module = sys.modules.get("angr_platforms.X86_16.tail_validation")
    summarize = _dynamic_tail_validation_getattr_8616(tail_validation_module, "summarize_x86_16_callsite", None)
    if callable(summarize):
        return summarize(function, callsite_addr)
    return _summarize_x86_16_callsite_fallback(function, callsite_addr)


def build_x86_16_contextual_call_fingerprints(
    root: object,
    project: object,
    *,
    summary_inventory: Mapping[int, CallsiteSummary8616] | None = None,
) -> dict[int, str]:
    """Build evidence-matched callsite fingerprints keyed by C call identity.

    Structured-C traversal order is not machine instruction order after
    structuring or node cloning.  Pairing those sequences positionally can
    therefore assign one callee's identity to another call.  Match explicit
    callsite addresses first, then canonical target identities, and use a
    positional remainder only when exactly one pair remains.
    """

    def _impl() -> dict[int, str]:
        if root is None:
            return {}
        call_nodes = list(_iter_observable_call_nodes_8616(root))
        if not call_nodes:
            return {}
        fingerprints: dict[int, str] = {}
        function = _function_for_call_context_8616(root, project)
        if function is not None:
            callsite_addrs = tuple(sorted(_dynamic_tail_validation_getattr_8616(function, "get_call_sites", list)() or ()))
            if not callsite_addrs:
                callsite_addrs = _collect_direct_capstone_callsite_addrs_8616(function)
            contextual_calls: list[tuple[int, int | None]] = []
            for callsite_addr in callsite_addrs:
                summary = (
                    summary_inventory.get(callsite_addr)
                    if summary_inventory is not None
                    else _summarize_x86_16_callsite_for_fingerprint_8616(function, callsite_addr)
                )
                target_addr = _fingerprint_target_addr_from_summary_8616(summary)
                contextual_calls.append((callsite_addr, _canonical_contextual_call_target_8616(project, target_addr)))

            unmatched_nodes = list(call_nodes)
            unmatched_calls = list(contextual_calls)

            for node in tuple(unmatched_nodes):
                node_addr = _call_node_addr_8616(node)
                if not isinstance(node_addr, int):
                    continue
                match = next((item for item in unmatched_calls if item[0] == node_addr), None)
                if match is None:
                    continue
                _record_contextual_call_fingerprint_8616(fingerprints, node, match)
                unmatched_nodes.remove(node)
                unmatched_calls.remove(match)

            for node in tuple(unmatched_nodes):
                node_target = _call_node_target_addr_for_context_8616(node, project)
                if not isinstance(node_target, int):
                    continue
                match = next((item for item in unmatched_calls if item[1] == node_target), None)
                if match is None:
                    continue
                _record_contextual_call_fingerprint_8616(fingerprints, node, match)
                unmatched_nodes.remove(node)
                unmatched_calls.remove(match)

            if len(unmatched_nodes) == 1 and len(unmatched_calls) == 1:
                _record_contextual_call_fingerprint_8616(fingerprints, unmatched_nodes[0], unmatched_calls[0])
        if len(fingerprints) < len(call_nodes):
            for node_id, fingerprint in _build_cod_call_name_fingerprints_8616(root, project, call_nodes).items():
                fingerprints.setdefault(node_id, fingerprint)
        if len(fingerprints) < len(call_nodes):
            for node in call_nodes:
                node_addr = _call_node_addr_8616(node)
                if isinstance(node_addr, int):
                    fingerprints.setdefault(id(node), f"callsite:{node_addr:#x}")
        return fingerprints

    return _impl()


def _canonical_contextual_call_target_8616(project: object, target_addr: int | None) -> int | None:
    """Canonicalize one summary target for contextual identity matching."""
    if not isinstance(target_addr, int):
        return None
    canonical = normalize_x86_16_call_target_addr_8616(project, target_addr)
    return canonical if isinstance(canonical, int) else target_addr


def _call_node_target_addr_for_context_8616(node: CFunctionCall, project: object) -> int | None:
    """Return a call node's canonical address only when target evidence exists."""
    token = _call_target_name(node, project)
    if not token.startswith("addr:"):
        return None
    try:
        return int(token[5:], 0)
    except ValueError:
        return None


def _record_contextual_call_fingerprint_8616(
    fingerprints: dict[int, str],
    node: CFunctionCall,
    contextual_call: tuple[int, int | None],
) -> None:
    """Record a proven contextual target, or its explicit callsite fallback."""
    callsite_addr, target_addr = contextual_call
    fingerprints[id(node)] = (
        f"addr:{target_addr:#x}" if isinstance(target_addr, int) else f"callsite:{callsite_addr:#x}"
    )


def _function_for_call_context_8616(root: Any, project: Any) -> Any:
    codegen = _dynamic_tail_validation_getattr_8616(root, "codegen", None)
    cfunc = _dynamic_tail_validation_getattr_8616(codegen, "cfunc", None)
    func_addr = _dynamic_tail_validation_getattr_8616(cfunc, "addr", None)
    if isinstance(func_addr, int):
        function = _lookup_function_for_call_context_8616(project, func_addr)
        if function is not None:
            return function
    if cfunc is not None and (
        callable(_dynamic_tail_validation_getattr_8616(cfunc, "get_call_sites", None)) or _dynamic_tail_validation_getattr_8616(cfunc, "block_addrs_set", None)
    ):
        return cfunc
    return None


def _collect_direct_capstone_callsite_addrs_8616(function: Any) -> tuple[int, ...]:
    def _impl() -> tuple[int, ...]:
        project = _dynamic_tail_validation_getattr_8616(function, "project", None)
        factory = _dynamic_tail_validation_getattr_8616(project, "factory", None)
        if project is None or factory is None:
            return ()
        callsites: list[int] = []
        for block_addr in sorted(_dynamic_tail_validation_getattr_8616(function, "block_addrs_set", ()) or ()):
            try:
                block = factory.block(block_addr, opt_level=0)
            except Exception:
                continue
            for insn in _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(block, "capstone", None), "insns", ()) or ():
                if str(_dynamic_tail_validation_getattr_8616(insn, "mnemonic", "") or "").strip().lower() != "call":
                    continue
                address = _dynamic_tail_validation_getattr_8616(insn, "address", None)
                if isinstance(address, int):
                    callsites.append(address)
        return tuple(callsites)

    return _impl()


def _call_node_addr_8616(node: Any) -> int | None:
    for attr in ("ins_addr", "addr"):
        value = _dynamic_tail_validation_getattr_8616(node, attr, None)
        if isinstance(value, int):
            return value
    return None


def _build_cod_call_name_fingerprints_8616(root: object, project: object, call_nodes: object) -> dict[int, str]:
    return {}


def _lookup_function_for_call_context_8616(project: Any, func_addr: int) -> Any:
    addr_candidates = []
    original_delta = _dynamic_tail_validation_getattr_8616(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        addr_candidates.append(func_addr + original_delta)
        rebased = func_addr - original_delta
        if rebased >= 0:
            addr_candidates.append(rebased)
    addr_candidates.append(func_addr)
    deduped_addrs: list[int] = []
    for addr in addr_candidates:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)

    project_variants: list[tuple[object, tuple[int, ...]]] = [(project, tuple(deduped_addrs))]
    original_project = _dynamic_tail_validation_getattr_8616(project, "_inertia_original_project", None)
    if original_project is not None:
        original_addrs = [func_addr]
        if isinstance(original_delta, int):
            original_addrs = [func_addr + original_delta]
        deduped_original_addrs: list[int] = []
        for addr in original_addrs:
            if addr >= 0 and addr not in deduped_original_addrs:
                deduped_original_addrs.append(addr)
        project_variants.append((original_project, tuple(deduped_original_addrs)))

    for candidate_project, candidate_addrs in project_variants:
        functions = _dynamic_tail_validation_getattr_8616(_dynamic_tail_validation_getattr_8616(candidate_project, "kb", None), "functions", None)
        lookup = _dynamic_tail_validation_getattr_8616(functions, "function", lambda **_: None)
        for candidate_addr in candidate_addrs:
            function = lookup(addr=candidate_addr, create=False)
            if function is not None:
                return function
    return None


def _iter_observable_call_nodes_8616(node: object, _seen: set[int] | None = None) -> Iterator[CFunctionCall]:
    def _impl() -> Iterator[CFunctionCall]:
        if node is None:
            return
        seen = _seen
        if seen is None:
            seen = set()
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        if isinstance(node, CStatements):
            for stmt in _dynamic_tail_validation_getattr_8616(node, "statements", ()) or ():
                yield from _iter_observable_call_nodes_8616(stmt, seen)
            return
        if isinstance(node, CFunctionCall):
            if not _is_runtime_segment_helper_call_8616(node) and not _is_structured_c_intrinsic_call_8616(node):
                yield node
            return
        if isinstance(node, CAssignment):
            rhs = _dynamic_tail_validation_getattr_8616(node, "rhs", None)
            if (
                isinstance(rhs, CFunctionCall)
                and not _is_runtime_segment_helper_call_8616(rhs)
                and not _is_structured_c_intrinsic_call_8616(rhs)
            ) or rhs is not None:
                yield from _iter_observable_call_nodes_8616(rhs, seen)
            return
        for attr in ("retval", "condition", "cond", "expr", "lhs", "rhs", "operand"):
            child = _dynamic_tail_validation_getattr_8616(node, attr, None)
            if (
                isinstance(child, CFunctionCall)
                and not _is_runtime_segment_helper_call_8616(child)
                and not _is_structured_c_intrinsic_call_8616(child)
            ) or child is not None:
                yield from _iter_observable_call_nodes_8616(child, seen)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in _dynamic_tail_validation_getattr_8616(node, "condition_and_nodes", ()) or ():
                if (
                    isinstance(cond, CFunctionCall)
                    and not _is_runtime_segment_helper_call_8616(cond)
                    and not _is_structured_c_intrinsic_call_8616(cond)
                ) or cond is not None:
                    yield from _iter_observable_call_nodes_8616(cond, seen)
                yield from _iter_observable_call_nodes_8616(body, seen)
        for arg in tuple(_dynamic_tail_validation_getattr_8616(node, "args", ()) or ()):
            yield from _iter_observable_call_nodes_8616(arg, seen)
        else_node = _dynamic_tail_validation_getattr_8616(node, "else_node", None)
        if else_node is not None:
            yield from _iter_observable_call_nodes_8616(else_node, seen)
        for attr in ("body", "initializer", "iterator"):
            child = _dynamic_tail_validation_getattr_8616(node, attr, None)
            if child is not None:
                yield from _iter_observable_call_nodes_8616(child, seen)

    return _impl()


def _location_fingerprint(
    node: object,
    project: object,
    _seen: set[int] | None = None,
    *,
    resolve_copy_alias: bool = True,
) -> str:
    def _impl() -> str:
        nonlocal node, _seen
        if _seen is None:
            _seen = set()
        node_id = id(node)
        if node_id in _seen:
            return "alias_cycle"
        _seen.add(node_id)
        if isinstance(node, CFunctionCall):
            runtime_location = _runtime_segment_helper_location_8616(node, project)
            if runtime_location is not None:
                return runtime_location
        if isinstance(node, CDirtyExpression) and not resolve_copy_alias:
            dirty_register = _dirty_register_fingerprint_8616(node, project)
            if dirty_register is not None:
                return dirty_register
            dirty_name = _dirty_virtual_name_8616(node)
            if dirty_name is not None:
                return f"virtual:{dirty_name}"
        if isinstance(node, CVariable):
            variable_fingerprint = _cvariable_location_fingerprint_8616(
                node, project, _seen=_seen, resolve_copy_alias=resolve_copy_alias
            )
            if isinstance(variable_fingerprint, str):
                return variable_fingerprint
        if isinstance(node, CTypeCast):
            return _location_fingerprint(node.expr, project, _seen, resolve_copy_alias=resolve_copy_alias)

        indexed_stack_location = _stack_indexed_location_fingerprint_8616(node)
        if indexed_stack_location is not None:
            return indexed_stack_location

        if isinstance(node, CIndexedVariable):
            indexed_global_location = _global_indexed_location_fingerprint_8616(node)
            if indexed_global_location is not None:
                return indexed_global_location

        if isinstance(node, CUnaryOp) and node.op == "Dereference":
            deref_fingerprint = _deref_location_fingerprint_8616(node, project)
            if isinstance(deref_fingerprint, str):
                return deref_fingerprint

        child_seen = set(_seen)
        child_seen.discard(node_id)
        return _expr_fingerprint(node, project, child_seen)

    return _impl()


def _cvariable_location_fingerprint_8616(node: Any, project: Any, *, _seen: set[int], resolve_copy_alias: bool) -> str | None:
    """Return a terminating storage identity for an angr structured-C variable."""

    def _impl() -> str | None:
        variable = _dynamic_tail_validation_getattr_8616(node, "variable", None)
        codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
        name = _dynamic_tail_validation_getattr_8616(node, "name", None) or _dynamic_tail_validation_getattr_8616(variable, "name", None)
        if codegen is not None and isinstance(name, str):
            if os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
                log.warning(
                    "[tail-carrier] cvar_id=%s name=%r obj=%r var=%r unified=%r keys=%r widened_hit=%r",
                    id(node),
                    name,
                    node,
                    variable,
                    _dynamic_tail_validation_getattr_8616(node, "unified_variable", None),
                    _candidate_widened_keys_8616(node),
                    _lookup_widened_carrier_proof_8616(node, codegen),
                )
            widened = _widened_carrier_slot_fingerprint_8616(name, value=node, variable=variable, codegen=codegen)
            if widened is not None:
                return widened
        if isinstance(variable, SimStackVariable):
            source_arg_fingerprint = _source_arg_location_fingerprint_8616(node, project)
            if source_arg_fingerprint is not None:
                return source_arg_fingerprint
            offset = _dynamic_tail_validation_getattr_8616(variable, "offset", None)
            if isinstance(offset, int):
                return _canonical_or_unresolved_stack_fingerprint_8616(offset, codegen, source="stack_var", node=node)
            return "stack:unknown"
        resolved_alias = (
            _resolve_validation_copy_alias_expr_8616(node, project, seen_var_ids=_seen)
            if resolve_copy_alias
            else None
        )
        if resolved_alias is not None and resolved_alias is not node:
            resolved_location = _location_fingerprint(resolved_alias, project, _seen - {id(node)})
            if isinstance(resolved_location, str):
                return resolved_location
        if isinstance(variable, SimRegisterVariable) and _dynamic_tail_validation_getattr_8616(variable, "reg", None) is not None:
            return f"reg:{_register_name(project, variable.reg, variable.size)}"
        if isinstance(variable, SimMemoryVariable):
            runtime_gp_name = runtime_gp_name_for_variable_8616(variable)
            if runtime_gp_name is not None:
                return f"reg:{runtime_gp_name}"
            runtime_segment_name = runtime_segment_name_for_variable_8616(variable)
            if runtime_segment_name is not None:
                return f"reg:{runtime_segment_name}"
            addr = _dynamic_tail_validation_getattr_8616(variable, "addr", None)
            if isinstance(addr, int) and addr < 0:
                return f"stack:{addr:+#x}"
            return f"global:{addr:#x}" if isinstance(addr, int) else "global:unknown"
        if isinstance(variable, SimTemporaryVariable):
            return f"virtual:tmp_{variable.tmp_id}"
        if isinstance(name, str) and name:
            return f"virtual:{name}"
        return f"virtual:{type(variable).__name__}:unknown"

    return _impl()


def _global_indexed_location_fingerprint_8616(node: Any) -> str | None:
    node = _strip_validation_casts(node)
    if not isinstance(node, CIndexedVariable):
        return None
    base = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "variable", None))
    index = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "index", None))
    if isinstance(base, CUnaryOp) and base.op == "Reference":
        base = _strip_validation_casts(base.operand)
    if not isinstance(base, CVariable):
        return None
    variable = _dynamic_tail_validation_getattr_8616(base, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = _dynamic_tail_validation_getattr_8616(variable, "addr", None)
    elem_size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
    index_value = _c_constant_int_value(index)
    if not isinstance(addr, int) or not isinstance(elem_size, int) or not isinstance(index_value, int):
        return None
    if addr < 0 or elem_size <= 0:
        return None
    return f"global:{(addr + index_value * elem_size) & 0xFFFF:#x}"


def _indexed_global_write_location_fingerprints_8616(node: object, project: object) -> tuple[str, ...]:
    """Return byte-precise locations for a proven indexed global lvalue."""

    subject = _indexed_global_write_subject_8616(node)
    if subject is None:
        return ()
    node, field_offset, access_size = subject
    base = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "variable", None))
    index = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "index", None))
    if isinstance(base, CUnaryOp) and base.op == "Reference":
        base = _strip_validation_casts(base.operand)
    if not isinstance(base, CVariable):
        return ()
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    if codegen is not None and _is_validation_near_pointer_arg_cvar_8616(base, codegen):
        # The SimMemoryVariable address on an angr pointer argument is its
        # frame/argument carrier, not a fixed global address. Let the generic
        # location fingerprint preserve the symbolic near-pointer dereference.
        return ()
    variable = _dynamic_tail_validation_getattr_8616(base, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return ()
    addr = _dynamic_tail_validation_getattr_8616(variable, "addr", None)
    elem_size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
    if not isinstance(addr, int) or not isinstance(elem_size, int) or addr < 0 or not 0 < elem_size <= 8:
        return ()
    write_size = elem_size if access_size is None else access_size
    if not 0 < write_size <= 8:
        return ()
    index_value = _c_constant_int_value(index)
    if isinstance(index_value, int):
        first_byte = (addr + index_value * elem_size + field_offset) & 0xFFFF
        return tuple(f"global:{(first_byte + byte_offset) & 0xFFFF:#x}" for byte_offset in range(write_size))
    scaled_parts, index_constant = _scaled_additive_expr_parts_8616(index, elem_size, project, set())
    if not scaled_parts:
        return ()
    locations: list[str] = []
    for byte_offset in range(write_size):
        byte_addr = (addr + index_constant + field_offset + byte_offset) & 0xFFFF
        terms = (f"Reference(global:{byte_addr:#x})", *scaled_parts)
        locations.append(f"deref:Add({','.join(terms)})")
    return tuple(locations)


def _indexed_global_write_subject_8616(
    node: object,
) -> tuple[CIndexedVariable, int, int | None] | None:
    """Unwrap an indexed global lvalue and its proven memory-helper access width."""

    node = _strip_validation_casts(node)
    field_offset = 0
    access_size: int | None = None
    if isinstance(node, CFunctionCall):
        helper_widths = {"MEM_U8": 1, "MEM_U16": 2, "MEM_U32": 4}
        access_size = helper_widths.get(node.callee_target)
        args = tuple(node.args or ())
        if access_size is None or len(args) != 1:
            return None
        node = _strip_validation_casts(args[0])
        if isinstance(node, CBinaryOp) and node.op == "Add":
            for candidate, displacement in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                constant = _c_constant_int_value(_strip_validation_casts(displacement))
                if isinstance(constant, int):
                    node = _strip_validation_casts(candidate)
                    field_offset = constant
                    break
            else:
                return None
        if isinstance(node, CUnaryOp) and node.op in {"Reference", "AddressOf"}:
            node = _strip_validation_casts(node.operand)
    if not isinstance(node, CIndexedVariable) or field_offset < 0:
        return None
    return node, field_offset, access_size


def _global_indexed_ds_deref_fingerprint_8616(
    node: Any,
    project: Any,
    child_seen: set[int],
    *,
    field_offset: int = 0,
) -> str | None:
    """Canonicalize a proven indexed DS global to its segmented byte address."""
    node = _strip_validation_casts(node)
    if not isinstance(node, CIndexedVariable):
        return None
    base = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(node, "variable", None))
    index = _strip_cosmetic_validation_casts_8616(node.index)
    if isinstance(base, CUnaryOp) and base.op == "Reference":
        base = _strip_validation_casts(base.operand)
    if not isinstance(base, CVariable):
        return None
    variable = _dynamic_tail_validation_getattr_8616(base, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = _dynamic_tail_validation_getattr_8616(variable, "addr", None)
    elem_size = _dynamic_tail_validation_getattr_8616(variable, "size", None)
    if not isinstance(addr, int) or not isinstance(elem_size, int) or field_offset < 0:
        return None
    if addr < 0 or elem_size <= 0:
        return None
    if isinstance(_c_constant_int_value(index), int):
        return None
    byte_addr = (addr + field_offset) & 0xFFFF
    scaled_parts, index_constant = _scaled_additive_expr_parts_8616(
        index,
        elem_size,
        project,
        child_seen,
    )
    address_parts = (*scaled_parts, f"const:{(byte_addr + index_constant) & 0xFFFF}")
    return f"Dereference(Add(Mul(reg:ds,const:16),{','.join(address_parts)}))"


def _global_indexed_field_ds_deref_fingerprint_8616(
    node: object,
    project: object,
    child_seen: set[int],
) -> str | None:
    """Canonicalize a non-pointer indexed global field to its segmented byte address."""
    node = _strip_validation_casts(node)
    if not isinstance(node, CVariableField) or node.var_is_ptr:
        return None
    field_offset = node.field.offset
    if not isinstance(field_offset, int):
        return None
    return _global_indexed_ds_deref_fingerprint_8616(
        node.variable,
        project,
        child_seen,
        field_offset=field_offset,
    )


def _deref_location_fingerprint_8616(node: Any, project: Any) -> str | None:
    evidenced_indexed_store = _indexed_store_evidence_location_fingerprint_8616(node)
    if evidenced_indexed_store is not None:
        return evidenced_indexed_store
    stack_disp = _match_bp_stack_dereference_8616(node, project)
    if isinstance(stack_disp, int):
        return _canonical_or_unresolved_stack_fingerprint_8616(
            stack_disp,
            _dynamic_tail_validation_getattr_8616(node, "codegen", None),
            source="bp_deref",
            node=node,
        )
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    if codegen is not None:
        try:
            from .lowering.real_mode_linear import match_stable_ss_linear_stack_access_8616
        except Exception:
            stable_ss_access = None
        else:
            stable_ss_access = match_stable_ss_linear_stack_access_8616(node, project, codegen)
        if stable_ss_access is not None and isinstance(_dynamic_tail_validation_getattr_8616(stable_ss_access, "displacement", None), int):
            return _canonical_or_unresolved_stack_fingerprint_8616(
                stable_ss_access.displacement,
                codegen,
                source="stable_ss_linear",
                node=node,
            )
    operand = _strip_validation_casts(node.operand)
    bridged = _indexed_deref_bridge_fingerprint_8616(node, operand)
    if isinstance(bridged, str):
        return bridged
    indexed_stack_location = _stack_indexed_location_fingerprint_8616(node.operand, project)
    if indexed_stack_location is not None:
        return indexed_stack_location
    seg_name, linear = _match_segmented_dereference_8616(node, project)
    if seg_name is not None:
        if isinstance(linear, int) and _segment_linear_lowering_allowed(node, seg_name, project):
            return f"global:{linear:#x}"
        return f"deref:{seg_name}:{linear:#x}" if isinstance(linear, int) else f"deref:{seg_name}:unknown"
    return f"deref:{_deref_operand_fingerprint_8616(node.operand, project)}"


def _indexed_store_evidence_location_fingerprint_8616(node: object) -> str | None:
    """Canonicalize a raw indexed store only from unique decoded store evidence."""

    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    evidence = _dynamic_tail_validation_getattr_8616(
        codegen,
        "_inertia_indexed_global_store_evidence_8616",
        (),
    )
    if not isinstance(evidence, tuple) or not evidence:
        return None
    operand = _strip_validation_casts(node.operand)
    if not isinstance(operand, CBinaryOp) or operand.op not in {"Add", "Sub"}:
        return None
    base_offsets: list[int] = []
    non_base_term_count = 0
    for sign, term in _flatten_additive_terms_8616(operand):
        stripped_term = _strip_validation_casts(term)
        if isinstance(stripped_term, CUnaryOp) and stripped_term.op == "Reference":
            stripped_term = _strip_validation_casts(stripped_term.operand)
        variable = (
            _dynamic_tail_validation_getattr_8616(stripped_term, "variable", None)
            if isinstance(stripped_term, CVariable)
            else None
        )
        addr = (
            _dynamic_tail_validation_getattr_8616(variable, "addr", None)
            if isinstance(variable, SimMemoryVariable)
            else None
        )
        if sign > 0 and isinstance(addr, int) and addr >= 0:
            base_offsets.append(addr & 0xFFFF)
        else:
            non_base_term_count += 1
    if len(base_offsets) != 1 or non_base_term_count == 0:
        return None
    byte_addr = base_offsets[0]
    candidates = {
        (fact.index_stack_offset, fact.index_shift)
        for fact in evidence
        if isinstance(fact, IndexedSegmentedGlobalStoreEvidence8616)
        and 0 < fact.width <= 8
        and byte_addr in {((fact.base_offset + byte_offset) & 0xFFFF) for byte_offset in range(fact.width)}
    }
    if len(candidates) != 1:
        return None
    index_stack_offset, index_shift = next(iter(candidates))
    if index_shift < 0 or index_shift > 4:
        return None
    index_fingerprint = _stack_slot_fingerprint_from_slot_8616(index_stack_offset, 2)
    scaled_index = (
        index_fingerprint
        if index_shift == 0
        else f"Shl({index_fingerprint},const:{index_shift})"
    )
    return f"deref:Add(Reference(global:{byte_addr:#x}),{scaled_index})"


def _indexed_deref_bridge_fingerprint_8616(node: Any, operand: Any) -> str | None:
    if not isinstance(operand, CIndexedVariable):
        return None
    base = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(operand, "variable", None))
    index = _strip_validation_casts(_dynamic_tail_validation_getattr_8616(operand, "index", None))
    if isinstance(base, CUnaryOp) and base.op == "Reference":
        base = _strip_validation_casts(base.operand)
    base_var = _dynamic_tail_validation_getattr_8616(base, "variable", None) if isinstance(base, CVariable) else None
    index_value = _c_constant_int_value(index)
    codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
    if not (isinstance(base_var, SimStackVariable) and isinstance(index_value, int) and codegen is not None):
        return None
    bridged = _stack_canonicalization_bridges_8616(codegen).get(("indexed_deref", id(base_var), index_value))
    if not isinstance(bridged, int):
        return None
    return _canonical_or_unresolved_stack_fingerprint_8616(
        bridged,
        codegen,
        source="indexed_deref_bridge",
        node=node,
    )


def _runtime_segment_helper_name_8616(node: CFunctionCall) -> str | None:
    tags = _dynamic_tail_validation_getattr_8616(node, "tags", None)
    marker_name = tags.get("inertia_x86_16_runtime_segment_helper") if isinstance(tags, dict) else None
    if isinstance(marker_name, str):
        return marker_name
    callee = normalize_callee_name_8616(_dynamic_tail_validation_getattr_8616(node, "callee_target", None))
    if isinstance(callee, str):
        return callee
    callee_func = _dynamic_tail_validation_getattr_8616(node, "callee_func", None)
    callee = normalize_callee_name_8616(_dynamic_tail_validation_getattr_8616(callee_func, "name", None))
    if isinstance(callee, str):
        return callee
    return None


def _runtime_segment_helper_args_8616(node: CFunctionCall) -> tuple[object, ...] | None:
    args = tuple(_dynamic_tail_validation_getattr_8616(node, "args", ()) or ())
    name = _runtime_segment_helper_name_8616(node)
    if name in {"MEM_U8", "MEM_U16", "MEM_U32"}:
        return args if len(args) == 1 else None
    if len(args) != 2:
        return None
    return args[0], args[1]


def _is_runtime_segment_helper_call_8616(node: CFunctionCall) -> bool:
    name = _runtime_segment_helper_name_8616(node)
    return name in {"SEG_U8", "SEG_U16", "SEG_U32", "MK_FP", "SEG_PTR", "MEM_U8", "MEM_U16", "MEM_U32"}


def _runtime_segment_linear_fingerprint_8616(
    seg_expr: object, off_expr: object, project: object
) -> str:
    """Canonicalize a segmented runtime-helper address as a linear fingerprint."""
    seg_fp = next(
        (
            f"reg:{segment_name}"
            for segment_name in ("cs", "ds", "es", "ss")
            if _is_register_expr_8616(seg_expr, project, segment_name)
        ),
        None,
    )
    if seg_fp is None:
        seg_fp = _expr_fingerprint(seg_expr, project)
    stripped_off = _strip_validation_casts(off_expr)
    if isinstance(stripped_off, CBinaryOp) and stripped_off.op in {"Add", "Sub"}:
        off_parts = _additive_term_parts_8616(
            _flatten_additive_terms_8616(stripped_off),
            project,
        )
        return f"Add(Mul({seg_fp},const:16),{','.join(off_parts)})"
    off_fp = _expr_fingerprint(off_expr, project)
    return f"Add(Mul({seg_fp},const:16),{off_fp})"


def _runtime_segment_helper_fingerprint_8616(node: CFunctionCall, project: object) -> str | None:
    name = _runtime_segment_helper_name_8616(node)
    args = _runtime_segment_helper_args_8616(node)
    if name is None or args is None:
        return None
    if name in {"MEM_U8", "MEM_U16", "MEM_U32"} and len(args) == 1:
        address = _strip_validation_casts(args[0])
        if isinstance(address, CUnaryOp) and address.op == "Reference":
            return _expr_fingerprint(address.operand, project)
        return f"Dereference({_expr_fingerprint(address, project)})"
    seg_expr, off_expr = args
    linear = _runtime_segment_linear_fingerprint_8616(seg_expr, off_expr, project)
    if name in {"MK_FP", "SEG_PTR"}:
        return linear
    if name in {"SEG_U8", "SEG_U16", "SEG_U32"}:
        return f"Dereference({linear})"
    return None


def _runtime_segment_helper_location_8616(node: CFunctionCall, project: object) -> str | None:
    name = _runtime_segment_helper_name_8616(node)
    args = _runtime_segment_helper_args_8616(node)
    if name in {"MEM_U8", "MEM_U16", "MEM_U32"} and args is not None and len(args) == 1:
        return f"deref:{_expr_fingerprint(args[0], project)}"
    if name not in {"SEG_U8", "SEG_U16", "SEG_U32"} or args is None:
        return None
    seg_expr, off_expr = args
    near_pointer = _near_pointer_arg_from_offset_expr_8616(off_expr)
    if near_pointer is not None:
        codegen = _dynamic_tail_validation_getattr_8616(node, "codegen", None)
        pointer_location = _near_pointer_arg_location_fingerprint_8616(near_pointer, 0, codegen)
        if pointer_location is not None:
            return pointer_location
    if isinstance(seg_expr, CVariable):
        variable = _dynamic_tail_validation_getattr_8616(seg_expr, "variable", None)
        runtime_segment_name = runtime_segment_name_for_variable_8616(variable)
        if runtime_segment_name is not None:
            off_value = _c_constant_int_value(off_expr)
            if isinstance(off_value, int):
                return f"deref:{runtime_segment_name}:{off_value:#x}"
        if isinstance(variable, SimRegisterVariable):
            seg_name = _register_name(project, variable.reg)
            off_value = _c_constant_int_value(off_expr)
            if isinstance(off_value, int):
                return f"deref:{seg_name}:{off_value:#x}"
    return f"deref:{_runtime_segment_linear_fingerprint_8616(seg_expr, off_expr, project)}"


def _near_pointer_arg_from_offset_expr_8616(expr: object) -> CVariable | None:
    expr = _strip_validation_casts(expr)
    if isinstance(expr, CVariable):
        return expr
    if not isinstance(expr, CBinaryOp) or expr.op != "Add":
        return None
    lhs = expr.lhs
    rhs = expr.rhs
    if _c_constant_int_value(lhs) == 0:
        return _near_pointer_arg_from_offset_expr_8616(rhs)
    if _c_constant_int_value(rhs) == 0:
        return _near_pointer_arg_from_offset_expr_8616(lhs)
    return None
