"""Reconcile binary-proven calls with known external-helper ABI metadata.

Layer: Types/Lowering.
Responsibility: refine an exact direct callee's typed prototype from the owned
helper ABI catalog and materialize required pointer casts without changing the
binary-proven argument count, widths, values, or call target.
Consumes alias, widening, and typed facts; it does not invent them.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: treating a helper name as call-identity proof, filling arguments,
using COD/source/rendered C, or replacing helper bodies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeArray, SimTypeFunction, SimTypePointer
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616
from ..helper_abi import known_helper_prototype_8616
from ..pipeline.errors import PipelineHardError
from .callee_global_object_type_surface import resolved_type_8616
from .near_pointer_type import near_pointer_type_8616
from .semantic_cast import CSemanticCast8616

__all__ = (
    "KnownHelperCallInterfaceStats8616",
    "materialize_known_helper_call_interfaces_8616",
)


class _ProjectBoundary8616(Protocol):
    """Third-party project fields consumed by this lowering owner."""

    arch: Arch


class _CodegenBoundary8616(Protocol):
    """Owned projection of the dynamic angr codegen fields used here."""

    cfunc: object
    project: _ProjectBoundary8616
    _inertia_callsite_summaries: object
    _inertia_known_helper_call_interface_stats_8616: KnownHelperCallInterfaceStats8616


class _CFunctionBoundary8616(Protocol):
    """Structured function roots exposed by angr codegen."""

    statements: object
    body: object


class _CalleeBoundary8616(Protocol):
    """Direct callee fields refined after exact identity proof."""

    addr: object
    name: object
    prototype: object
    is_prototype_guessed: bool


class _ExpressionBoundary8616(Protocol):
    """Structured expression type exposed by angr."""

    type: object


@dataclass(slots=True)
class KnownHelperCallInterfaceStats8616:
    """Closed evidence loop for known-helper interface materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    prototype_materialized_count: int = 0
    pointer_cast_materialized_count: int = 0


def _structured_root_8616(cfunc: object) -> object | None:
    """Return the current structured root through the third-party boundary."""
    if cfunc is None:
        return None
    typed_cfunc = cast(_CFunctionBoundary8616, cfunc)
    try:
        statements = typed_cfunc.statements
    except AttributeError:
        statements = None
    if statements is not None:
        return statements
    try:
        return typed_cfunc.body
    except AttributeError:
        return None


def _summary_map_8616(codegen: _CodegenBoundary8616) -> dict[int, CallsiteSummary8616]:
    """Return only complete owned callsite-summary entries."""
    raw = codegen._inertia_callsite_summaries
    if not isinstance(raw, dict):
        return {}
    return {
        node_id: summary
        for node_id, summary in raw.items()
        if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
    }


def _type_width_bytes_8616(type_: object) -> int | None:
    """Return one architecture-bound SimType width in bytes."""
    if not isinstance(type_, SimType):
        return None
    size_bits = type_.size
    if not isinstance(size_bits, int) or size_bits <= 0 or size_bits % 8:
        return None
    return size_bits // 8


def _summary_argument_widths_8616(summary: CallsiteSummary8616) -> tuple[int, ...] | None:
    """Return the exact logical argument widths represented by structured C."""
    widths = summary.logical_arg_widths or summary.arg_widths
    if (
        len(widths) != summary.arg_count
        or any(not isinstance(width, int) or width <= 0 for width in widths)
    ):
        return None
    return tuple(int(width) for width in widths)


def _prototype_matches_summary_8616(
    prototype: SimTypeFunction,
    summary: CallsiteSummary8616,
    materialized_arg_count: int,
) -> bool:
    """Prove that helper metadata preserves the binary call shape."""
    widths = _summary_argument_widths_8616(summary)
    fixed_args = tuple(prototype.args)
    if widths is None or materialized_arg_count != summary.arg_count:
        return False
    if prototype.variadic:
        if len(fixed_args) > len(widths):
            return False
    elif len(fixed_args) != len(widths):
        return False
    expected_widths = tuple(_type_width_bytes_8616(argument) for argument in fixed_args)
    return all(width is not None for width in expected_widths) and tuple(
        cast(int, width) for width in expected_widths
    ) == widths[: len(fixed_args)]


def _prototype_with_exact_pointer_widths_8616(
    prototype: SimTypeFunction,
    summary: CallsiteSummary8616,
    arch: Arch,
) -> SimTypeFunction | None:
    """Project pointer kinds from exact stack widths, not loader address width.

    DOS loaders widen ``Arch86_16.bits`` to represent the linear image. Generic
    angr pointers consequently appear four bytes wide even when the callsite
    proves a two-byte near pointer. The callsite owns width; helper ABI metadata
    contributes only the pointee type.
    """
    widths = _summary_argument_widths_8616(summary)
    if widths is None:
        return None
    arguments: list[SimType] = []
    for index, argument_raw in enumerate(prototype.args):
        if index >= len(widths):
            return None
        argument = resolved_type_8616(argument_raw)
        if not isinstance(argument, SimType):
            return None
        if isinstance(argument, SimTypePointer) and widths[index] == 2:
            argument = near_pointer_type_8616(argument.pts_to, arch)
        arguments.append(argument)
    return SimTypeFunction(
        arguments,
        prototype.returnty,
        arg_names=tuple(prototype.arg_names or ()),
        variadic=prototype.variadic,
    ).with_arch(arch)


def _prototype_return_width_compatible_8616(
    current: object,
    expected: SimTypeFunction,
) -> bool:
    """Require helper metadata to preserve the current machine return width."""
    if not isinstance(current, SimTypeFunction):
        return True
    current_width = _type_width_bytes_8616(current.returnty)
    expected_width = _type_width_bytes_8616(expected.returnty)
    return current_width is None or expected_width is None or current_width == expected_width


def _expression_type_8616(expression: object) -> SimType | None:
    """Read one structured expression type at the dynamic angr boundary."""
    try:
        type_ = cast(_ExpressionBoundary8616, expression).type
    except AttributeError:
        return None
    return type_ if isinstance(type_, SimType) else None


def _pointer_types_compatible_8616(current: SimTypePointer, expected: SimTypePointer) -> bool:
    """Return whether no explicit pointer conversion is required."""
    current_pointee = resolved_type_8616(current.pts_to)
    expected_pointee = resolved_type_8616(expected.pts_to)
    return bool(current_pointee == expected_pointee)


def _materialize_required_pointer_casts_8616(
    codegen: _CodegenBoundary8616,
    call: structured_c.CFunctionCall,
    prototype: SimTypeFunction,
    summary: CallsiteSummary8616,
) -> tuple[bool, bool, int]:
    """Cast only proven-width pointer expressions to fixed helper ABI types."""
    changed = False
    materialized = 0
    args = list(call.args)
    widths = _summary_argument_widths_8616(summary)
    if widths is None:
        return False, False, 0
    for index, expected_raw in enumerate(prototype.args):
        if index >= len(args):
            return False, False, 0
        expected = resolved_type_8616(expected_raw)
        if not isinstance(expected, SimTypePointer):
            continue
        if _type_width_bytes_8616(expected) != widths[index]:
            return False, False, 0
        coerced = _coerce_pointer_arg_8616(codegen, args[index], expected)
        if coerced is None:
            return False, False, 0
        args[index], arg_changed = coerced
        materialized += 1
        changed = changed or arg_changed
    if changed:
        call.args = args
    return True, changed, materialized


def _coerce_pointer_arg_8616(
    codegen: _CodegenBoundary8616,
    argument: object,
    expected: SimTypePointer,
) -> tuple[object, bool] | None:
    """Return (arg, changed) when the arg can satisfy the expected pointer type."""
    if isinstance(argument, CSemanticCast8616) and argument.dst_type == expected:
        return argument, False
    current = _expression_type_8616(argument)
    if isinstance(current, SimTypeArray):
        current = SimTypePointer(current.elem_type).with_arch(codegen.project.arch)
    if not isinstance(current, SimTypePointer):
        return None
    if _pointer_types_compatible_8616(current, expected):
        return argument, False
    return CSemanticCast8616(current, expected, argument, codegen=codegen), True


def _bound_call_callee_8616(
    node: structured_c.CFunctionCall,
) -> tuple[_CalleeBoundary8616, object, object] | None:
    """Bind a call node's callee name/address at the angr object boundary."""
    callee_obj = node.callee_func
    if callee_obj is None:
        return None
    callee = cast(_CalleeBoundary8616, callee_obj)
    try:
        return callee, callee.name, callee.addr
    except AttributeError:
        return None


def _exact_helper_prototype_8616(
    node: structured_c.CFunctionCall,
    callee: _CalleeBoundary8616,
    callee_addr: object,
    prototype: SimTypeFunction,
    summary: CallsiteSummary8616 | None,
    arch: Arch,
) -> SimTypeFunction | None:
    """Return the exact-width helper prototype when callsite evidence agrees."""
    if summary is None or not isinstance(callee_addr, int) or summary.target_addr != callee_addr:
        return None
    exact_prototype = _prototype_with_exact_pointer_widths_8616(prototype, summary, arch)
    if (
        exact_prototype is None
        or not _prototype_matches_summary_8616(exact_prototype, summary, len(node.args))
        or not _prototype_return_width_compatible_8616(callee.prototype, exact_prototype)
    ):
        return None
    return exact_prototype


def materialize_known_helper_call_interfaces_8616(
    project: object,
    codegen: object,
) -> bool:
    """Refine exactly identified helper calls without changing machine shape."""
    del project
    typed_codegen = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        return False
    root = _structured_root_8616(cfunc)
    stats = KnownHelperCallInterfaceStats8616()
    typed_codegen._inertia_known_helper_call_interface_stats_8616 = stats
    if root is None:
        return False
    summaries = _summary_map_8616(typed_codegen)
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        changed = (
            _materialize_helper_call_node_8616(typed_codegen, node, summaries, stats) or changed
        )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified helper call interfaces were not materialized")
    return changed


def _materialize_helper_call_node_8616(
    codegen: _CodegenBoundary8616,
    node: structured_c.CFunctionCall,
    summaries: dict[int, CallsiteSummary8616],
    stats: KnownHelperCallInterfaceStats8616,
) -> bool:
    """Materialize one known-helper call node and record evidence counts."""
    bound = _bound_call_callee_8616(node)
    if bound is None:
        return False
    callee, callee_name, callee_addr = bound
    prototype = known_helper_prototype_8616(
        callee_name if isinstance(callee_name, str) else None,
        codegen.project.arch,
    )
    if prototype is None:
        return False
    stats.raw_fact_count += 1
    summary = summaries.get(id(node))
    exact_prototype = _exact_helper_prototype_8616(
        node, callee, callee_addr, prototype, summary, codegen.project.arch
    )
    if summary is None or exact_prototype is None:
        stats.failure_count += 1
        return False
    pointer_compatible, cast_changed, cast_count = _materialize_required_pointer_casts_8616(
        codegen,
        node,
        exact_prototype,
        summary,
    )
    if not pointer_compatible:
        stats.failure_count += 1
        return False
    stats.normalized_fact_count += 1
    stats.classified_fact_count += 1
    changed = cast_changed
    if callee.prototype != exact_prototype:
        callee.prototype = exact_prototype
        callee.is_prototype_guessed = False
        stats.prototype_materialized_count += 1
        changed = True
    stats.pointer_cast_materialized_count += cast_count
    stats.materialized_count += 1
    return changed
