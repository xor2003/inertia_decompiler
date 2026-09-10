"""Layer: Frontend/angr compatibility.

Responsibility: adapt angr return rendering for proven 16-bit x86 return facts.
Forbidden: source/COD/text-backed return recovery or whole-body rewrite repair.
Dynamic boundary: this module patches and reads third-party angr ReturnMaker,
AIL, codegen, C AST, Function, and SimType compatibility objects. Owned
Inertia contracts must use typed fields and dot access.
Producer evidence decides whether a scalar return exists, not when its inputs
are read. ReturnMaker must capture the architectural return register at RET;
only SSA may propagate earlier definitions across intervening state changes.
An existing native dereference is a return value, not a missing-value placeholder.
"""

from __future__ import annotations

import contextlib
import logging
import os
import struct
import sys
import typing
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Protocol, cast

from angr import ailment
from angr.ailment.expression import BasePointerOffset, Expression, StackBaseOffset
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CVariable,
    MakeTypecastsImplicit,
)
from angr.calling_conventions import SimComboArg, SimRegArg
from angr.sim_type import (
    SimType,
    SimTypeBottom,
    SimTypeDouble,
    SimTypeFloat,
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable

from .ailment_variant_access import (
    AilBasePointerOffset8616,
    AilBinaryOp8616,
    AilLoad8616,
    AilOperands8616,
    AilRegister8616,
    AilStackBaseOffset8616,
)
from .ailment_variant_access import (
    ail_const_value_8616 as _ail_const_value_8616,
)
from .ailment_variant_access import (
    register_assignment_source_8616 as _register_assignment_source_8616,
)
from .ailment_variant_access import (
    tmp_assignment_source_8616 as _tmp_assignment_source_8616,
)
from .calling_convention_compat import collect_wide_stack_argument_width_evidence_8616
from .callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
from .lowering.return_type_evidence import proven_function_result_observation_8616
from .lowering.terminal_return_expressions import (
    uncollapse_safe_scalar_expression_8616,
)
from .lowering.unobserved_returns import (
    return_expr_is_unresolved_carrier_8616,
    return_value_needs_neutralization_8616,
)
from .msvc_x87_interrupts import msvc_x87_escape_opcode_8616
from .semantics.branch_target_return import (
    TerminalAxReturnEffectKind8616,
    terminal_ax_return_effect_8616,
)
from .structuring.register_dependencies import resolve_same_block_data_register_dependencies_8616
from .structuring.wide_return_values import combine_word_return_sources_8616
from .type_clinic_return_compat import apply_x86_16_clinic_return_type_compatibility

__all__ = [
    "apply_x86_16_decompiler_return_compatibility",
    "describe_x86_16_decompiler_return_compatibility",
    "x86_16_msvc_x87_scalar_stack_args",
]

log: logging.Logger = logging.getLogger(__name__)


class _ReturnCompatProjectContract8616(Protocol):
    """Inertia context carried by a third-party angr project."""

    _inertia_original_linear_delta: int
    _inertia_original_project: object


class _ReturnCompatFunctionContract8616(Protocol):
    """Legacy Inertia return-use override carried by an angr function."""

    _inertia_return_compat_caller_uses_return_8616: bool


def _return_compat_original_linear_delta_8616(project: object | None) -> int | None:
    """Read the owned exact-slice address delta with direct contract access."""
    if project is None:
        return None
    try:
        value = cast(_ReturnCompatProjectContract8616, project)._inertia_original_linear_delta
    except AttributeError:
        return None
    return value if isinstance(value, int) else None


def _return_compat_original_project_8616(project: object | None) -> object | None:
    """Read the owned source-project link with direct contract access."""
    if project is None:
        return None
    try:
        return cast(_ReturnCompatProjectContract8616, project)._inertia_original_project
    except AttributeError:
        return None


def _return_compat_caller_use_override_8616(function: object) -> bool | None:
    """Read the legacy owned caller-use override with direct contract access."""
    try:
        value = cast(_ReturnCompatFunctionContract8616, function)._inertia_return_compat_caller_uses_return_8616
    except AttributeError:
        return None
    return value if isinstance(value, bool) else None


def _dynamic_int_counter_8616(owner: object, name: str) -> int:
    """Read a runtime compatibility counter from a third-party angr object."""
    value = getattr(cast(Any, owner), name, None)
    if isinstance(value, int):
        return value
    info = getattr(cast(Any, owner), "info", None)
    if not isinstance(info, dict):
        return 0
    stored = info.get(name)
    return stored if isinstance(stored, int) else 0


def _increment_dynamic_int_counter_8616(owner: object, name: str) -> None:
    """Increment telemetry without requiring mutable attributes on slotted angr objects."""
    value = _dynamic_int_counter_8616(owner, name) + 1
    try:
        setattr(cast(Any, owner), name, value)
        return
    except (AttributeError, TypeError):
        pass
    info = getattr(cast(Any, owner), "info", None)
    if isinstance(info, dict):
        info[name] = value


def _object_tuple_8616(value: object) -> tuple[object, ...]:
    """Return a tuple for dynamic angr sequence payloads."""
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return ()


def _describe_c_expr_8616(expr: object, *, depth: int = 0) -> str:
    if expr is None:
        return "None"
    if depth >= 3:
        return type(expr).__name__
    parts = [type(expr).__name__]
    for attr in ("op", "variable", "reg", "reg_name", "value"):
        if hasattr(expr, attr):
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            parts.append(f"{attr}={value!r}")
    for attr in ("operand", "lhs", "rhs", "expr"):
        if hasattr(expr, attr):
            try:
                child = getattr(expr, attr)
            except Exception:
                continue
            parts.append(f"{attr}=({_describe_c_expr_8616(child, depth=depth + 1)})")
    return " ".join(parts)


def _is_stack_base_return_register_8616(reg_arg: SimRegArg) -> bool:
    return reg_arg.reg_name.lower() in {"sp", "bp", "ebp", "esp", "rbp", "rsp"}


def _is_void_return_type_8616(return_type: object) -> bool:
    """Return whether an angr SimType is explicitly the C ``void`` return type."""
    return type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void"


def _is_x86_16_near_pointer_return_8616(arch: object, return_type: object) -> bool:
    return isinstance(return_type, SimTypePointer) and getattr(arch, "name", None) == "86_16"


def _prototype_has_return_type_8616(prototype: object) -> bool:
    """Return whether a dynamic angr prototype carries a return type."""
    return prototype is not None and getattr(prototype, "returnty", None) is not None


def _resolve_codegen_prototype_8616(codegen: object) -> tuple[object | None, object | None]:
    """Resolve the best available function/prototype pair from dynamic codegen state."""
    if codegen is None:
        return None, None

    codegen_func = getattr(codegen, "_func", None)
    prototype = getattr(codegen_func, "prototype", None)
    if _prototype_has_return_type_8616(prototype):
        return codegen_func, prototype

    cfunc = getattr(codegen, "cfunc", None)
    for attr_name in ("functy", "prototype"):
        prototype = getattr(cfunc, attr_name, None)
        if _prototype_has_return_type_8616(prototype):
            if codegen_func is not None:
                with contextlib.suppress(Exception):
                    codegen_func.prototype = prototype
            return codegen_func, prototype

    project = getattr(codegen, "project", None)
    if project is None:
        project = getattr(codegen_func, "project", None)
    func_addr = getattr(cfunc, "addr", None)
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
        print(
            "[dbg-return] prototype-resolve "
            f"codegen_project={project is not None} "
            f"func_project={getattr(codegen_func, 'project', None) is not None} "
            f"cfunc={cfunc is not None} "
            f"cfunc_addr={func_addr!r} "
            f"functions={functions is not None} "
            f"func_proto={getattr(codegen_func, 'prototype', None)!r} "
            f"cfunc_functy={getattr(cfunc, 'functy', None)!r} "
            f"cfunc_proto={getattr(cfunc, 'prototype', None)!r}",
            file=sys.stderr,
            flush=True,
        )
    if not isinstance(func_addr, int) or functions is None:
        return codegen_func, None

    try:
        kb_func = functions.function(addr=func_addr, create=False)
    except Exception:
        kb_func = None
    prototype = getattr(kb_func, "prototype", None)
    if not _prototype_has_return_type_8616(prototype):
        return codegen_func or kb_func, None

    for target in (codegen_func, cfunc):
        if target is None:
            continue
        with contextlib.suppress(Exception):
            target.prototype = prototype
        with contextlib.suppress(Exception):
            target.functy = prototype
    if kb_func is not None:
        _increment_dynamic_int_counter_8616(kb_func, "_inertia_return_compat_codegen_prototype_resolved_count")
    return codegen_func or kb_func, prototype


def codegen_has_explicit_void_return_8616(project: object, codegen: object) -> bool:
    """Return whether dynamic codegen/function metadata proves an explicit void return."""

    cfunc = getattr(codegen, "cfunc", None)
    function = getattr(codegen, "_inertia_current_function_8616", None)
    func_addr = getattr(cfunc, "addr", None)
    if function is None and isinstance(func_addr, int):
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is not None:
            with contextlib.suppress(Exception):
                function = functions.function(addr=func_addr, create=False)

    resolved_function, resolved_prototype = _resolve_codegen_prototype_8616(codegen)
    if function is None:
        function = resolved_function

    for candidate in (
        getattr(cfunc, "functy", None),
        getattr(cfunc, "prototype", None),
        getattr(getattr(codegen, "_func", None), "prototype", None),
        resolved_prototype,
        getattr(function, "prototype", None) if function is not None else None,
    ):
        return_type = getattr(candidate, "returnty", None)
        if return_type is not None and _is_void_return_type_8616(return_type):
            return True
    return function is not None and getattr(function, "returning", None) is False


def describe_x86_16_decompiler_return_compatibility() -> tuple[str, ...]:
    """Describe the third-party angr return compatibility patches installed here."""
    return ("ReturnMaker._handle_Return: SimComboArg support",)


def _make_return_register_expr_8616(self: object, stmt: object, reg_arg: SimRegArg) -> object:
    """Capture return-time state; SSA, not producer substitution, binds its value."""
    self_dynamic = cast(Any, self)
    stmt_dynamic = cast(Any, stmt)
    reg = self_dynamic.arch.registers[reg_arg.reg_name]
    reg_name = self_dynamic.arch.translate_register_name(reg[0], reg_arg.size)
    if reg_name is None:
        reg_name = reg_arg.reg_name
    return ailment.Expr.Register(
        self_dynamic._next_atom(),
        reg[0],
        reg_arg.size * self_dynamic.arch.byte_width,
        reg_name=reg_name,
        ins_addr=stmt_dynamic.tags["ins_addr"],
    )


def _resolve_same_block_tmp_source_8616(
    expr: object,
    statements: Sequence[object],
    *,
    before_index: int,
    depth: int = 0,
) -> object:
    if depth > 8 or not isinstance(expr, ailment.Expr.Tmp):
        return expr
    tmp_idx = getattr(expr, "tmp_idx", None)
    if not isinstance(tmp_idx, int):
        return expr
    for idx in range(before_index - 1, -1, -1):
        src = _tmp_assignment_source_8616(statements[idx], tmp_idx=tmp_idx)
        if src is None:
            continue
        if isinstance(src, ailment.Expr.Tmp):
            return _resolve_same_block_tmp_source_8616(src, statements, before_index=idx, depth=depth + 1)
        return src
    return expr


def _resolve_same_block_tmps_in_expr_8616(
    expr: object,
    statements: Sequence[object],
    *,
    before_index: int,
    depth: int = 0,
) -> object:
    if depth > 8 or expr is None:
        return expr
    if isinstance(expr, ailment.Expr.Tmp):
        resolved = _resolve_same_block_tmp_source_8616(expr, statements, before_index=before_index, depth=depth)
        if resolved is expr:
            return expr
        return _resolve_same_block_tmps_in_expr_8616(resolved, statements, before_index=before_index, depth=depth + 1)

    copy = _copy_ail_expr_8616(expr)
    for attr in ("addr", "operand", "expr"):
        if not hasattr(copy, attr):
            continue
        try:
            child = getattr(copy, attr)
            setattr(
                copy,
                attr,
                _resolve_same_block_tmps_in_expr_8616(child, statements, before_index=before_index, depth=depth + 1),
            )
        except Exception:
            pass
    if hasattr(copy, "operands"):
        try:
            operand_view = cast(AilOperands8616, copy)
            operands = operand_view.operands
            operand_view.operands = [
                _resolve_same_block_tmps_in_expr_8616(child, statements, before_index=before_index, depth=depth + 1)
                for child in operands
            ]
        except Exception:
            pass
    return copy


def _resolve_same_block_register_reads_in_expr_8616(
    self: object,
    expr: object,
    statements: Sequence[object],
    *,
    before_index: int,
    reg_offset: int,
    reg_size: int,
    depth: int = 0,
) -> object:
    del reg_offset, reg_size

    def resolve_temporaries(candidate: object, block_statements: Sequence[object], index: int) -> object:
        source = _resolve_same_block_tmp_source_8616(candidate, block_statements, before_index=index)
        return _resolve_same_block_tmps_in_expr_8616(source, block_statements, before_index=index)

    return resolve_same_block_data_register_dependencies_8616(
        expr,
        statements,
        before_index=before_index,
        register_name=lambda candidate: _ail_register_name_8616(self, candidate),
        resolve_temporaries=resolve_temporaries,
        copy_expression=_copy_ail_expr_8616,
        depth=depth,
    )


def _copy_ail_expr_8616(expr: object) -> object:
    copy = getattr(expr, "copy", None)
    if callable(copy):
        return copy()
    return expr


def _ail_register_name_8616(self: object, expr: object) -> str | None:
    """Translate the offset and width of a checked native register."""
    self_dynamic = cast(Any, self)
    if not isinstance(expr, ailment.Expr.Register):
        return None
    register = cast(AilRegister8616, expr)
    reg_offset = register.reg_offset
    size_bits = register.bits
    if not isinstance(reg_offset, int) or not isinstance(size_bits, int):
        return None
    size_bytes = max(size_bits // self_dynamic.arch.byte_width, 1)
    return str(self_dynamic.arch.translate_register_name(reg_offset, size_bytes))


def _strip_ail_convert_8616(expr: object) -> object:
    while isinstance(expr, ailment.Expr.Convert):
        expr = getattr(expr, "operand", expr)
    return expr


def _bp_offset_expr_8616(self: object, expr: object) -> int | None:
    """Return the BP-relative offset represented by one canonical AIL address."""
    expr = _strip_ail_convert_8616(expr)
    if isinstance(expr, BasePointerOffset):
        base_pointer = cast(AilBasePointerOffset8616, expr)
        offset = base_pointer.offset
        return offset if base_pointer.base == "bp" and isinstance(offset, int) else None
    if isinstance(expr, StackBaseOffset):
        stack_base = cast(AilStackBaseOffset8616, expr)
        variable = stack_base.tags.get("variable")
        offset = stack_base.offset
        return (
            offset
            if isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and isinstance(offset, int)
            else None
        )
    if _ail_register_name_8616(self, expr) == "bp":
        return 0
    if not isinstance(expr, ailment.Expr.BinaryOp):
        return None
    binary = cast(AilBinaryOp8616, expr)
    op = binary.op
    operands = _object_tuple_8616(binary.operands)
    if len(operands) != 2 or op not in {"Add", "Sub"}:
        return None
    lhs, rhs = operands
    lhs_offset = _bp_offset_expr_8616(self, lhs)
    rhs_offset = _bp_offset_expr_8616(self, rhs)
    lhs_const = _ail_const_value_8616(_strip_ail_convert_8616(lhs))
    rhs_const = _ail_const_value_8616(_strip_ail_convert_8616(rhs))
    if lhs_offset is not None and rhs_const is not None:
        return lhs_offset + (rhs_const if op == "Add" else -rhs_const)
    if op == "Add" and rhs_offset is not None and lhs_const is not None:
        return rhs_offset + lhs_const
    return None


def _is_ss_segment_scale_8616(self: object, expr: object) -> bool:
    """Recognize an explicit SS segment scale in a native binary expression."""
    expr = _strip_ail_convert_8616(expr)
    if not isinstance(expr, ailment.Expr.BinaryOp):
        return False
    binary = cast(AilBinaryOp8616, expr)
    op = binary.op
    operands = _object_tuple_8616(binary.operands)
    if len(operands) != 2 or op not in {"Shl", "Mul"}:
        return False
    scale = 4 if op == "Shl" else 16
    for maybe_seg, maybe_scale in (operands, tuple(reversed(operands))):
        if _ail_const_value_8616(_strip_ail_convert_8616(maybe_scale)) != scale:
            continue
        if _ail_register_name_8616(self, _strip_ail_convert_8616(maybe_seg)) == "ss":
            return True
    return False


def _bp_offset_from_linear_stack_addr_8616(self: object, addr_expr: object) -> int | None:
    """Read a BP displacement only from canonical stack-address evidence."""
    addr_expr = _strip_ail_convert_8616(addr_expr)
    direct = _bp_offset_expr_8616(self, addr_expr)
    if direct is not None:
        return direct
    if not isinstance(addr_expr, ailment.Expr.BinaryOp):
        return None
    binary = cast(AilBinaryOp8616, addr_expr)
    if binary.op != "Add":
        return None
    operands = _object_tuple_8616(binary.operands)
    if len(operands) != 2:
        return None
    lhs, rhs = operands
    if _is_ss_segment_scale_8616(self, lhs):
        return _bp_offset_expr_8616(self, rhs)
    if _is_ss_segment_scale_8616(self, rhs):
        return _bp_offset_expr_8616(self, lhs)
    return None


def _materialize_return_stack_load_8616(self: object, expr: object) -> object:
    """Attach proven BP-relative storage to a native return load copy."""
    self_dynamic = cast(Any, self)
    if isinstance(expr, ailment.Expr.Load):
        load = cast(AilLoad8616, expr)
        offset = _bp_offset_from_linear_stack_addr_8616(self, load.addr)
        if not isinstance(offset, int):
            return expr
        bits = load.bits
        size = max(bits // self_dynamic.arch.byte_width, 1) if isinstance(bits, int) and bits > 0 else 2
        region = getattr(getattr(self, "function", None), "addr", None)
        variable = SimStackVariable(offset, size, base="bp", region=region)
        materialized_addr = StackBaseOffset(
            self_dynamic._next_atom(),
            size * self_dynamic.arch.byte_width,
            offset,
            variable=variable,
            ins_addr=load.tags.get("ins_addr", None),
        )
        result = cast(AilLoad8616, _copy_ail_expr_8616(expr))
        try:
            result.addr = materialized_addr
        except Exception:
            return expr
        return result

    result = cast(Any, _copy_ail_expr_8616(expr))
    for attr in ("addr", "operand", "expr"):
        if not hasattr(result, attr):
            continue
        with contextlib.suppress(Exception):
            setattr(result, attr, _materialize_return_stack_load_8616(self, getattr(result, attr)))
    if hasattr(result, "operands"):
        with contextlib.suppress(Exception):
            result.operands = [_materialize_return_stack_load_8616(self, operand) for operand in result.operands]
    return result


def _find_terminal_register_source_8616(
    self: object,
    stmt: object,
    *,
    block: object | None = None,
    reg_offset: int,
    reg_size: int,
    max_insn_distance: int = 32,
) -> object | None:
    """Find a nearby producer without crossing a branch or unmodeled call effect."""
    graph = getattr(self, "graph", None)
    if graph is None:
        return None
    return_ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
    if not isinstance(return_ins_addr, int):
        return None

    candidates: list[tuple[int, int, object]] = []
    tied = False
    graph_blocks = (block,) if block is not None else tuple(graph.nodes())
    for graph_block in graph_blocks:
        if graph_block is None:
            continue
        statements = tuple(getattr(graph_block, "statements", ()) or ())
        for idx, graph_stmt in enumerate(statements):
            ins_addr = getattr(graph_stmt, "tags", {}).get("ins_addr", None)
            if not isinstance(ins_addr, int):
                continue
            if ins_addr > return_ins_addr or return_ins_addr - ins_addr > max_insn_distance:
                continue
            src = _register_assignment_source_8616(graph_stmt, reg_offset=reg_offset, reg_size=reg_size)
            if src is None:
                continue
            if any(
                isinstance(next_stmt, (ailment.Stmt.ConditionalJump, ailment.Stmt.SideEffectStatement, ailment.Expr.Call))
                or (isinstance(next_stmt, ailment.Stmt.Assignment) and isinstance(cast(Any, next_stmt).src, ailment.Expr.Call))
                for next_stmt in statements[idx + 1 :]
            ):
                continue
            src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
            src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
            src = _resolve_same_block_register_reads_in_expr_8616(
                self,
                src,
                statements,
                before_index=idx,
                reg_offset=reg_offset,
                reg_size=reg_size,
            )
            candidates.append((ins_addr, id(graph_block), src))
            if sum(1 for candidate in candidates if candidate[0] == ins_addr) > 1:
                tied = True
    if not candidates or tied:
        return None
    best = max(candidates, key=lambda candidate: candidate[0])
    return _materialize_return_stack_load_8616(self, _copy_ail_expr_8616(best[2]))


def _find_reaching_register_source_8616(
    self: object,
    block: object,
    *,
    reg_offset: int,
    reg_size: int,
    max_depth: int = 8,
) -> object | None:
    graph = getattr(self, "graph", None)
    if graph is None or block is None:
        return None

    candidates = []
    seen_blocks: set[int] = set()

    def scan_predecessors(node: object, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            predecessors = tuple(graph.predecessors(node))
        except Exception:
            return
        for pred in predecessors:
            pred_id = id(pred)
            if pred_id in seen_blocks:
                continue
            seen_blocks.add(pred_id)
            statements = tuple(getattr(pred, "statements", ()) or ())
            for idx in range(len(statements) - 1, -1, -1):
                pred_stmt = statements[idx]
                src = _register_assignment_source_8616(pred_stmt, reg_offset=reg_offset, reg_size=reg_size)
                if src is not None:
                    src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
                    src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
                    src = _resolve_same_block_register_reads_in_expr_8616(
                        self,
                        src,
                        statements,
                        before_index=idx,
                        reg_offset=reg_offset,
                        reg_size=reg_size,
                    )
                    candidates.append(src)
                    break
            else:
                scan_predecessors(pred, depth + 1)

    scan_predecessors(block, 0)
    if len(candidates) != 1:
        return None
    return _materialize_return_stack_load_8616(self, _copy_ail_expr_8616(candidates[0]))


def _infer_x86_16_ax_return_expr_8616(self: object, stmt: object, block: object | None) -> object | None:
    """Infer a 16-bit scalar return only from concrete AX producer evidence.

    This is deliberately narrower than prototype-driven ReturnMaker recovery: if
    no terminal/reaching AX assignment is found, the caller must keep upstream's
    original return handling.
    """
    arch = getattr(self, "arch", None)
    registers = getattr(arch, "registers", {}) if arch is not None else {}
    ax_reg = registers.get("ax") if isinstance(registers, dict) else None
    if not isinstance(ax_reg, tuple) or len(ax_reg) < 2:
        return None

    reg_offset = ax_reg[0]
    reg_size = int(ax_reg[1])
    if reg_size <= 0:
        reg_size = 2

    ret_expr = _find_terminal_register_source_8616(
        self,
        stmt,
        block=block,
        reg_offset=reg_offset,
        reg_size=reg_size,
    )
    if ret_expr is None:
        ret_expr = _find_reaching_register_source_8616(self, block, reg_offset=reg_offset, reg_size=reg_size)
    if ret_expr is None:
        function = getattr(self, "function", None)
        if function is not None:
            _increment_dynamic_int_counter_8616(function, "_inertia_return_compat_ax_refused_count")
        return None

    function = getattr(self, "function", None)
    if function is not None:
        _increment_dynamic_int_counter_8616(function, "_inertia_return_compat_ax_materialized_count")
    return ret_expr


def _return_compat_prototype_is_guessed_8616(function: object) -> bool:
    # Dynamic angr Function compatibility boundary.
    return bool(getattr(function, "is_prototype_guessed", False))


def _return_compat_function_block_count_8616(self: object) -> int | None:
    # Dynamic angr ReturnMaker compatibility boundary.
    graph = getattr(self, "graph", None)
    if graph is None:
        return None
    try:
        return len(tuple(graph.nodes()))
    except Exception:
        return None


def _return_compat_target_addrs_8616(function: object) -> tuple[int, ...]:
    """Return addresses that may name ``function`` across exact-region slices."""
    # Dynamic angr Function compatibility boundary.
    target_addr = getattr(function, "addr", None)
    if not isinstance(target_addr, int):
        return ()
    targets = [target_addr]
    project = _return_compat_function_project_8616(function)
    original_delta = _return_compat_original_linear_delta_8616(project)
    if isinstance(original_delta, int):
        targets.append(target_addr + original_delta)
    return tuple(dict.fromkeys(targets))


def _return_compat_candidate_projects_8616(function: object) -> tuple[object, ...]:
    """Return projects that may contain callers for ``function``."""
    project = _return_compat_function_project_8616(function)
    projects: list[object] = []
    for candidate in (project, _return_compat_original_project_8616(project)):
        if candidate is not None and not any(candidate is existing for existing in projects):
            projects.append(candidate)
    return tuple(projects)


def _return_compat_function_project_8616(function: object) -> object | None:
    """Return the project attached to an angr Function-like object."""
    for attr_name in ("project", "_project"):
        # Dynamic angr Function compatibility boundary.
        project = getattr(function, attr_name, None)
        if project is not None:
            return cast(object, project)
    return None


def _return_compat_attach_project_context_8616(function: object, owner: object) -> None:
    """Attach ReturnMaker project context to a Function-like object when missing."""
    if function is None:
        return
    current_project = _return_compat_function_project_8616(function)
    for attr_name in ("project", "_project"):
        # Dynamic angr ReturnMaker compatibility boundary.
        candidate_project = getattr(owner, attr_name, None)
        if candidate_project is None:
            continue
        if current_project is None or _return_compat_original_project_8616(current_project) is None:
            with contextlib.suppress(Exception):
                # Dynamic angr Function compatibility boundary.
                typing.cast(typing.Any, function).project = candidate_project
            return


def _return_compat_function_caller_return_use_8616(function: object) -> bool | None:
    """Return proven caller observation, retaining legacy overrides as hints."""
    observation = _return_compat_proven_result_observation_8616(function)
    if observation is CallerReturnUseVerdict8616.USED:
        return True
    if observation is CallerReturnUseVerdict8616.UNUSED:
        return False
    override = _return_compat_caller_use_override_8616(function)
    if override is not None:
        return bool(override)
    candidate_projects = _return_compat_candidate_projects_8616(function)
    target_addrs = set(_return_compat_target_addrs_8616(function))
    if not candidate_projects or not target_addrs:
        return None
    try:
        from .analysis_helpers import collect_neighbor_call_targets
        from .callsite_summary import CallsiteReturnUseKind8616, summarize_x86_16_callsite
    except Exception:
        return None
    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    failure_count = 0
    used_callsite_count = 0
    unused_callsite_count = 0
    callsite_addrs: set[int] = set()
    for candidate_project in candidate_projects:
        # Dynamic project compatibility boundary.
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        if functions is None:
            continue
        try:
            function_values = tuple(functions.values())
        except Exception:
            continue
        for caller in function_values:
            try:
                seeds = tuple(collect_neighbor_call_targets(caller))
            except Exception:
                failure_count += 1
                continue
            raw_fact_count += len(seeds)
            for seed in seeds:
                # Dynamic callsite-summary compatibility boundary.
                if getattr(seed, "target_addr", None) not in target_addrs:
                    continue
                normalized_fact_count += 1
                # Dynamic callsite-summary compatibility boundary.
                callsite_addr = getattr(seed, "callsite_addr", None)
                if not isinstance(callsite_addr, int):
                    failure_count += 1
                    continue
                summary = summarize_x86_16_callsite(caller, callsite_addr)
                if summary is None or summary.return_used is None:
                    failure_count += 1
                    continue
                classified_fact_count += 1
                callsite_addrs.add(callsite_addr)
                if summary.return_used and summary.return_use_kind is not CallsiteReturnUseKind8616.FUNCTION_RETURN:
                    used_callsite_count += 1
                else:
                    unused_callsite_count += 1
    verdict = (
        CallerReturnUseVerdict8616.USED
        if used_callsite_count
        else CallerReturnUseVerdict8616.UNUSED
        if normalized_fact_count and classified_fact_count == normalized_fact_count and not failure_count
        else CallerReturnUseVerdict8616.UNKNOWN
    )
    project = _return_compat_function_project_8616(function)
    function_addr = getattr(function, "addr", None)  # Dynamic angr Function boundary.
    if project is not None and isinstance(function_addr, int):
        record_caller_return_use_evidence_8616(
            project,
            function_addr,
            CallerReturnUseEvidence8616(
                target_addr=function_addr,
                verdict=verdict,
                raw_fact_count=raw_fact_count,
                normalized_fact_count=normalized_fact_count,
                classified_fact_count=classified_fact_count,
                materialized_count=int(verdict is not CallerReturnUseVerdict8616.UNKNOWN),
                failure_count=failure_count,
                used_callsite_count=used_callsite_count,
                unused_callsite_count=unused_callsite_count,
                callsite_addrs=tuple(sorted(callsite_addrs)),
            ),
        )
    if verdict is CallerReturnUseVerdict8616.USED:
        return True
    if verdict is CallerReturnUseVerdict8616.UNUSED:
        return False
    return None


def _return_compat_proven_result_observation_8616(
    function: object,
) -> CallerReturnUseVerdict8616 | None:
    """Resolve one non-conflicting closed caller-result observation proof."""
    project = _return_compat_function_project_8616(function)
    if project is None:
        return None
    observations = {
        observation
        for target_addr in _return_compat_target_addrs_8616(function)
        if (observation := proven_function_result_observation_8616(project, target_addr)) is not None
    }
    return next(iter(observations)) if len(observations) == 1 else None


def _return_compat_debug_caller_state_8616(function: object) -> dict[str, object]:
    """Return opt-in diagnostics for caller return-use visibility."""

    candidate_projects = _return_compat_candidate_projects_8616(function)
    target_addrs = tuple(sorted(_return_compat_target_addrs_8616(function)))
    project_rows: list[dict[str, object]] = []
    try:
        from .analysis_helpers import collect_neighbor_call_targets
    except Exception as ex:
        return {
            "project_count": len(candidate_projects),
            "target_addrs": target_addrs,
            "import_error": f"{type(ex).__name__}: {ex}",
        }
    for index, candidate_project in enumerate(candidate_projects):
        # Dynamic project compatibility boundary.
        functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        row: dict[str, object] = {"index": index, "has_functions": functions is not None}
        if functions is None:
            project_rows.append(row)
            continue
        try:
            function_values = tuple(functions.values())
        except Exception as ex:
            row["function_values_error"] = f"{type(ex).__name__}: {ex}"
            project_rows.append(row)
            continue
        row["function_count"] = len(function_values)
        matching: list[dict[str, object]] = []
        for caller in function_values:
            try:
                seeds = tuple(collect_neighbor_call_targets(caller))
            except Exception:
                continue
            for seed in seeds:
                # Dynamic callsite-summary compatibility boundary.
                target_addr = getattr(seed, "target_addr", None)
                if target_addr not in target_addrs:
                    continue
                matching.append(
                    {
                        # Dynamic angr Function compatibility boundary.
                        "caller": getattr(caller, "addr", None),
                        # Dynamic callsite-summary compatibility boundary.
                        "callsite": getattr(seed, "callsite_addr", None),
                        "target": target_addr,
                    }
                )
        row["matching_calls"] = matching[:8]
        row["matching_call_count"] = len(matching)
        project_rows.append(row)
    return {
        "project_count": len(candidate_projects),
        "target_addrs": target_addrs,
        "projects": project_rows,
    }


def _return_compat_c_expr_is_unresolved_carrier_8616(expr: object, *, depth: int = 0) -> bool:
    """Return whether a C return expression is only an unresolved carrier."""
    if depth != 0:
        return False
    return bool(return_expr_is_unresolved_carrier_8616(expr))


def _return_compat_c_result_needs_neutralization_8616(
    expr: object | None,
    return_type: object,
) -> bool:
    """Classify unusable C return expressions through typed lowering evidence."""
    return bool(return_value_needs_neutralization_8616(expr, return_type))


def _return_compat_should_drop_unresolved_c_return_8616(_function: object, _retval: object) -> bool:
    """Refuse to drop an unresolved return solely because callers ignore it."""
    return False


def _return_compat_unknown_caller_terminal_expr_8616(
    self: object, stmt: object, block: object | None, ret_val: object
) -> object | None:
    if not isinstance(ret_val, SimRegArg):
        return None
    if ret_val.reg_name.lower() != "ax":
        return None
    self_dynamic = cast(Any, self)
    try:
        reg = self_dynamic.arch.registers[ret_val.reg_name]
    except Exception:
        return None
    return _find_terminal_register_source_8616(
        self,
        stmt,
        block=block,
        reg_offset=reg[0],
        reg_size=ret_val.size,
        max_insn_distance=16,
    )


def _return_compat_unknown_caller_unconditional_predecessor_expr_8616(
    self: object, block: object | None, ret_val: object
) -> object | None:
    """Find predecessor producer evidence without crossing its side effects."""
    if not isinstance(ret_val, SimRegArg) or ret_val.reg_name.lower() != "ax":
        return None
    self_dynamic = cast(Any, self)
    # Dynamic angr ReturnMaker compatibility boundary.
    graph = getattr(self, "graph", None)
    if graph is None or block is None:
        return None
    try:
        predecessors = tuple(graph.predecessors(block))
    except Exception:
        return None
    if len(predecessors) != 1:
        return None
    predecessor = predecessors[0]
    try:
        reg = self_dynamic.arch.registers[ret_val.reg_name]
    except Exception:
        return None
    # Dynamic angr AIL block compatibility boundary.
    statements = tuple(getattr(predecessor, "statements", ()) or ())
    for idx in range(len(statements) - 1, -1, -1):
        pred_stmt = statements[idx]
        src = _register_assignment_source_8616(pred_stmt, reg_offset=reg[0], reg_size=ret_val.size)
        if src is None:
            continue
        following = statements[idx + 1 :]
        if any(
            isinstance(stmt, (ailment.Stmt.ConditionalJump, ailment.Stmt.SideEffectStatement, ailment.Expr.Call))
            or (isinstance(stmt, ailment.Stmt.Assignment) and isinstance(cast(Any, stmt).src, ailment.Expr.Call))
            for stmt in following
        ):
            return None
        src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
        src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
        src = _resolve_same_block_register_reads_in_expr_8616(
            self,
            src,
            statements,
            before_index=idx,
            reg_offset=reg[0],
            reg_size=ret_val.size,
        )
        return _materialize_return_stack_load_8616(self, _copy_ail_expr_8616(src))
    return None


def _return_compat_unknown_caller_reaching_register_proven_8616(
    self: object,
    block: object | None,
    ret_val: object,
    *,
    max_depth: int = 8,
) -> bool:
    """Return True when every predecessor path proves a reaching AX definition."""
    if not isinstance(ret_val, SimRegArg) or ret_val.reg_name.lower() != "ax":
        return False
    self_dynamic = cast(Any, self)
    # Dynamic angr ReturnMaker compatibility boundary.
    graph = getattr(self, "graph", None)
    if graph is None or block is None:
        return False
    try:
        reg = self_dynamic.arch.registers[ret_val.reg_name]
    except Exception:
        return False

    def _source_is_explicit_scalar_return(source: object) -> bool:
        """Return whether a reaching AX source is explicit enough for unknown callers."""
        if isinstance(source, ailment.Expr.Const):
            return True
        if isinstance(source, (ailment.Expr.Load, ailment.Expr.Register, ailment.Expr.Tmp)):
            return False
        if isinstance(source, ailment.Expr.BinaryOp):
            # Dynamic AIL compatibility boundary: BinaryOp children are exposed as operands.
            binary = cast(AilBinaryOp8616, source)
            return all(_source_is_explicit_scalar_return(child) for child in _object_tuple_8616(binary.operands))
        # Dynamic AIL compatibility boundary: UnaryOp is version-dependent in ailment.
        unary_op_type = getattr(ailment.Expr, "UnaryOp", None)
        if unary_op_type is not None and isinstance(source, unary_op_type):
            # Dynamic AIL compatibility boundary: unary expression payload is named operand.
            return _source_is_explicit_scalar_return(cast(Any, source).operand)
        if source.__class__.__name__ == "Convert":
            # Dynamic AIL compatibility boundary: Convert payload is named operand.
            return _source_is_explicit_scalar_return(getattr(source, "operand", None))
        return False

    seen: set[int] = set()

    def _path_has_reaching_definition(node: object, depth: int) -> bool:
        if depth > max_depth:
            return False
        try:
            predecessors = tuple(graph.predecessors(node))
        except Exception:
            return False
        if not predecessors:
            return False
        for predecessor in predecessors:
            pred_id = id(predecessor)
            if pred_id in seen:
                return False
            seen.add(pred_id)
            # Dynamic angr AIL block compatibility boundary.
            statements = tuple(getattr(predecessor, "statements", ()) or ())
            for idx in range(len(statements) - 1, -1, -1):
                pred_stmt = statements[idx]
                src = _register_assignment_source_8616(pred_stmt, reg_offset=reg[0], reg_size=ret_val.size)
                if src is None:
                    continue
                if not _source_is_explicit_scalar_return(
                    _resolve_same_block_tmps_in_expr_8616(
                        _resolve_same_block_tmp_source_8616(src, statements, before_index=idx),
                        statements,
                        before_index=idx,
                    )
                ):
                    return False
                break
            else:
                if not _path_has_reaching_definition(predecessor, depth + 1):
                    return False
        return True

    return _path_has_reaching_definition(block, 0)


def _iter_function_ail_blocks_8616(function: object, graph: object | None = None) -> tuple[object, ...]:
    if graph is None:
        graph = getattr(function, "graph", None)
    if graph is None:
        return ()
    try:
        return tuple(cast(Any, graph).nodes())
    except Exception:
        return ()


def _return_insn_addrs_8616(function: object, graph: object | None = None) -> tuple[int, ...]:
    addrs: list[int] = []
    fallback_addrs: list[int] = []
    for block in _iter_function_ail_blocks_8616(function, graph=graph):
        for stmt in tuple(getattr(block, "statements", ()) or ()):
            ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
            if isinstance(ins_addr, int):
                fallback_addrs.append(ins_addr)
            if not isinstance(stmt, ailment.Stmt.Return):
                continue
            if isinstance(ins_addr, int):
                addrs.append(ins_addr)
    if addrs:
        return tuple(sorted(set(addrs)))
    if fallback_addrs:
        return (max(fallback_addrs),)
    return ()


def _terminal_register_sources_for_function_8616(
    *,
    arch: object,
    function: object,
    graph: object | None = None,
    reg_offset: int,
    reg_size: int,
    max_insn_distance: int = 32,
) -> tuple[object, ...]:
    return_addrs = _return_insn_addrs_8616(function, graph=graph)
    if not return_addrs:
        return ()
    sources: list[object] = []
    for return_ins_addr in return_addrs:
        best: tuple[int, object] | None = None
        tied = False
        for block in _iter_function_ail_blocks_8616(function, graph=graph):
            statements = tuple(getattr(block, "statements", ()) or ())
            for idx, graph_stmt in enumerate(statements):
                ins_addr = getattr(graph_stmt, "tags", {}).get("ins_addr", None)
                if not isinstance(ins_addr, int):
                    continue
                if ins_addr > return_ins_addr or return_ins_addr - ins_addr > max_insn_distance:
                    continue
                src = _register_assignment_source_8616(graph_stmt, reg_offset=reg_offset, reg_size=reg_size)
                if src is None:
                    continue
                src = _resolve_same_block_tmp_source_8616(src, statements, before_index=idx)
                src = _resolve_same_block_tmps_in_expr_8616(src, statements, before_index=idx)
                src = _resolve_same_block_register_reads_in_expr_8616(
                    type("_ReturnCompatCtx8616", (), {"arch": arch})(),
                    src,
                    statements,
                    before_index=idx,
                    reg_offset=reg_offset,
                    reg_size=reg_size,
                )
                if best is None or ins_addr > best[0]:
                    best = (ins_addr, src)
                    tied = False
                elif ins_addr == best[0]:
                    tied = True
        if best is not None and not tied:
            sources.append(best[1])
    return tuple(sources)


def _stack_annotation_name_for_bp_disp_8616(function: object, bp_disp: int) -> str | None:
    info = getattr(function, "info", None)
    annotations = info.get("x86_16_annotations") if isinstance(info, dict) else None
    stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
    if not isinstance(stack_vars, dict):
        return None
    for key in (bp_disp, bp_disp - 2):
        spec = stack_vars.get(key)
        if isinstance(spec, str) and spec:
            return spec
        if isinstance(spec, dict):
            name = spec.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def _stack_name_preference_8616(cvar: object) -> int:
    variable = getattr(cvar, "variable", None)
    name = getattr(variable, "name", None) or getattr(cvar, "name", None)
    if not isinstance(name, str) or not name:
        return 0
    if name.startswith(("vvar_", "tmp_", "ir_", "s_")):
        return 1
    if name.startswith(("local_", "arg_")):
        return 2
    return 3


def _existing_stack_cvar_for_bp_disp_8616(codegen: object, bp_disp: int) -> CVariable | None:
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return None
    candidate_offsets = (bp_disp, bp_disp - 2) if bp_disp < 0 else (bp_disp,)
    best = None
    best_score = None
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable) or not isinstance(cvar, CVariable):
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset not in candidate_offsets:
            continue
        score = (_stack_name_preference_8616(cvar), int(getattr(variable, "size", 0) or 0), -abs(offset - bp_disp))
        if best_score is None or score > best_score:
            best = cvar
            best_score = score
    return best


def _make_c_stack_return_value_8616(codegen: object, *, bp_disp: int, size: int) -> CVariable:
    return _make_c_stack_value_8616(codegen, bp_disp=bp_disp, size=size, variable_type=SimTypeShort(False))


def _update_cfunc_arg_type_for_bp_disp_8616(codegen: object, *, bp_disp: int, variable_type: object) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    arg_list = getattr(cfunc, "arg_list", None)
    functy = getattr(cfunc, "functy", None)
    arg_types = getattr(functy, "args", None)
    if not isinstance(arg_list, list) or not isinstance(arg_types, (list, tuple)):
        return
    if isinstance(arg_types, tuple):
        arg_types = list(arg_types)
        with contextlib.suppress(Exception):
            cast(Any, functy).args = arg_types
    for idx, cvar in enumerate(arg_list):
        variable = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            continue
        if variable.offset not in {bp_disp, bp_disp - 2}:
            continue
        with contextlib.suppress(Exception):
            cvar.variable_type = variable_type
        if idx < len(arg_types):
            arg_types[idx] = variable_type
        variable_manager = getattr(cfunc, "variable_manager", None)
        if variable_manager is not None:
            with contextlib.suppress(Exception):
                variable_manager.set_variable_type(variable, variable_type)
        return


def _make_c_stack_value_8616(
    codegen: object,
    *,
    bp_disp: int,
    size: int,
    variable_type: SimType,
) -> CVariable:
    """Return one stack value without weakening an existing typed variable."""
    existing = _existing_stack_cvar_for_bp_disp_8616(codegen, bp_disp)
    if existing is not None and (
        existing.variable_type is not None or getattr(existing, "type", None) is not None
    ):
        return existing
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(variable_type, "with_arch"):
        variable_type = variable_type.with_arch(arch)
    _update_cfunc_arg_type_for_bp_disp_8616(codegen, bp_disp=bp_disp, variable_type=variable_type)
    if existing is not None:
        with contextlib.suppress(Exception):
            existing.variable_type = variable_type
        return existing
    function = getattr(codegen, "_func", None)
    region = getattr(function, "addr", None)
    internal_offset = bp_disp - 2 if bp_disp < 0 else bp_disp
    name = _stack_annotation_name_for_bp_disp_8616(function, bp_disp) or (
        f"local_{max(((-internal_offset) + 1) // 2, 1)}"
        if internal_offset < 0
        else f"arg_{max(internal_offset // 2, 1)}"
    )
    variable = SimStackVariable(internal_offset, max(size, 1), base="bp", name=name, region=region)
    cvar = CVariable(variable, variable_type=variable_type, codegen=codegen)
    cfunc = getattr(codegen, "cfunc", None)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, variable_type)}
    return cvar


def _return_scan_project_and_addr_8616(project: object, function: object) -> tuple[object, int]:
    start = getattr(function, "addr", None)
    if not isinstance(start, int):
        return project, 0
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is not None and isinstance(original_delta, int):
        return original_project, start + original_delta
    return project, start


def _function_bytes_for_return_scan_8616(project: object, function: object) -> tuple[object, int, bytes]:
    scan_project, start = _return_scan_project_and_addr_8616(project, function)
    scan_project_dynamic = cast(Any, scan_project)
    if not isinstance(start, int):
        return project, 0, b""
    size = getattr(function, "size", None)
    if not isinstance(size, int) or size <= 0:
        end = start
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            scan_block_addr = int(block_addr)
            original_delta = getattr(project, "_inertia_original_linear_delta", None)
            if scan_project is not project and isinstance(original_delta, int):
                scan_block_addr += original_delta
            try:
                block = scan_project_dynamic.factory.block(scan_block_addr, opt_level=0)
            except Exception:
                continue
            block_size = getattr(block, "size", 0)
            if isinstance(block_size, int) and block_size > 0:
                end = max(end, scan_block_addr + block_size)
        size = end - start
    if not isinstance(size, int) or size <= 0 or size > 0x1000:
        return scan_project, start, b""
    try:
        return scan_project, start, bytes(scan_project_dynamic.loader.memory.load(start, size))
    except Exception:
        return scan_project, start, b""


def _modrm16_operand_8616(data: bytes, index: int) -> tuple[dict[str, int] | None, int]:
    if index >= len(data):
        return None, index
    modrm = data[index]
    index += 1
    mod = modrm >> 6
    reg = (modrm >> 3) & 0x7
    rm = modrm & 0x7
    operand: dict[str, int] = {"reg": reg, "mod": mod, "rm": rm}
    if mod == 3:
        operand["kind"] = 2
        return operand, index
    if mod == 0 and rm == 6:
        if index + 2 > len(data):
            return None, index
        operand["kind"] = 0
        operand["offset"] = int.from_bytes(data[index : index + 2], "little")
        return operand, index + 2
    if mod == 1:
        if index >= len(data):
            return None, index
        disp = struct.unpack("b", data[index : index + 1])[0]
        operand["disp"] = disp
        operand["kind"] = 1 if rm == 6 else 3
        return operand, index + 1
    if mod == 2:
        if index + 2 > len(data):
            return None, index
        disp = int.from_bytes(data[index : index + 2], "little")
        if disp >= 0x8000:
            disp -= 0x10000
        operand["disp"] = disp
        operand["kind"] = 1 if rm == 6 else 3
        return operand, index + 2
    operand["kind"] = 3
    return operand, index


def _x87_scalar_type_for_size_8616(project: object, size: int) -> SimType:
    scalar_type = SimTypeFloat() if size == 4 else SimTypeDouble()
    arch = getattr(project, "arch", None)
    if arch is not None and hasattr(scalar_type, "with_arch"):
        scalar_type = scalar_type.with_arch(arch)
    return scalar_type


def _x87_opcode_reads_memory_operand_8616(opcode: int, reg: int) -> bool:
    if opcode in (0xD8, 0xDC):
        # D8/DC group operations read a float/double memory operand:
        # arithmetic and compare variants all consume the operand as scalar data.
        return 0 <= reg <= 7
    if opcode == 0xD9:
        return reg == 0
    if opcode == 0xDD:
        return reg == 0
    return False


def x86_16_msvc_x87_scalar_stack_args(project: object, function: object) -> dict[int, object]:
    """Return BP-relative stack arguments that are proven scalar FP operands.

    Microsoft C's no-FPU runtime encodes x87 ESC instructions as INT 34h/35h/
    38h/39h followed by the original ModR/M operand.  A BP-relative memory
    operand read by those decoded x87 operations is scalar data, not a near
    pointer, so later prototype promotion must not reinterpret it as a pointer.
    """
    scan_project, _start, data = _function_bytes_for_return_scan_8616(project, function)
    if not data:
        return {}

    offsets: dict[int, int] = {}
    conflicts: set[int] = set()
    index = 0
    while index < len(data):
        byte = data[index]
        if byte != 0xCD or index + 1 >= len(data):
            index += 1
            continue
        int_no = data[index + 1]
        opcode = msvc_x87_escape_opcode_8616(int_no)
        if opcode is None:
            index += 2
            continue
        operand, next_index = _modrm16_operand_8616(data, index + 2)
        if operand is None:
            return {}
        reg = int(operand.get("reg", -1))
        if _x87_opcode_reads_memory_operand_8616(opcode, reg) and operand.get("kind") == 1:
            disp = int(operand.get("disp", 0))
            if disp > 0:
                size = 8 if opcode in (0xDC, 0xDD) else 4
                previous = offsets.get(disp)
                if previous is not None and previous != size:
                    conflicts.add(disp)
                    offsets.pop(disp, None)
                elif disp not in conflicts:
                    offsets[disp] = size
        index = max(next_index, index + 2)

    if not offsets:
        return {}
    return {
        offset: _x87_scalar_type_for_size_8616(scan_project, size)
        for offset, size in sorted(offsets.items())
        if offset not in conflicts
    }


def _peer_map_dgroup_base_8616(project: object) -> int | None:
    obj = getattr(getattr(project, "loader", None), "main_object", None)
    binary = getattr(obj, "binary", None)
    if not isinstance(binary, str):
        return None
    map_path = Path(binary).with_suffix(".MAP")
    if not map_path.is_file():
        map_path = Path(binary).with_suffix(".map")
    if not map_path.is_file():
        return None
    try:
        lines = map_path.read_text(errors="ignore").splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1].upper() == "DGROUP" and ":" in parts[0]:
            seg_text, off_text = parts[0].split(":", 1)
            try:
                seg = int(seg_text, 16)
                off = int(off_text, 16)
            except ValueError:
                continue
            linked_base = getattr(obj, "linked_base", None)
            if not isinstance(linked_base, int):
                linked_base = getattr(obj, "mapped_base", 0)
            if not isinstance(linked_base, int):
                return None
            return linked_base + (seg << 4) + off
    return None


def _read_x87_constant_8616(
    codegen: object,
    *,
    project: object | None = None,
    offset: int,
    size: int,
) -> float | None:
    if project is None:
        project = getattr(codegen, "project", None)
    if project is None:
        return None
    dgroup_base = _peer_map_dgroup_base_8616(project)
    if dgroup_base is None:
        return None
    try:
        data = bytes(cast(Any, project).loader.memory.load(dgroup_base + offset, size))
    except Exception:
        return None
    if len(data) != size:
        return None
    try:
        if size == 4:
            return float(struct.unpack("<f", data)[0])
        if size == 8:
            return float(struct.unpack("<d", data)[0])
    except struct.error:
        return None
    return None


def _c_expr_from_x87_operand_8616(
    codegen: object,
    operand: dict[str, int],
    *,
    project: object | None = None,
    size: int,
) -> object | None:
    kind = operand.get("kind")
    value_type = SimTypeFloat() if size == 4 else SimTypeDouble()
    if kind == 1:
        return cast(object, _make_c_stack_value_8616(
            codegen, bp_disp=int(operand.get("disp", 0)), size=size, variable_type=value_type
        ))
    if kind == 0:
        value = _read_x87_constant_8616(codegen, project=project, offset=int(operand.get("offset", 0)), size=size)
        if value is None:
            return None
        return cast(object, CConstant(value, value_type, codegen=codegen))
    return None


def _decode_msvc_x87_return_expr_8616(codegen: object) -> object | None:
    project = getattr(codegen, "project", None)
    function = getattr(codegen, "_func", None)
    if project is None or function is None:
        return None
    scan_project, _start, data = _function_bytes_for_return_scan_8616(project, function)
    if not data:
        return None

    stack: list[object] = []
    final_expr = None
    final_store_offset = None
    final_store_index = None
    fpu_ops = 0
    index = 0
    while index < len(data):
        byte = data[index]
        if byte == 0xCD and index + 1 < len(data):
            int_no = data[index + 1]
            opcode = msvc_x87_escape_opcode_8616(int_no)
            if opcode is None:
                index += 2
                continue
            operand, next_index = _modrm16_operand_8616(data, index + 2)
            if operand is None:
                return None
            reg = int(operand.get("reg", -1))
            size = 8 if opcode in (0xDC, 0xDD) else 4
            if (opcode, reg) in ((0xD9, 0), (0xDD, 0)):
                expr = _c_expr_from_x87_operand_8616(codegen, operand, project=scan_project, size=size)
                if expr is None:
                    return None
                stack.append(expr)
                fpu_ops += 1
            elif (opcode, reg) in ((0xD8, 0), (0xDC, 0), (0xD8, 1), (0xDC, 1)):
                if not stack:
                    return None
                expr = _c_expr_from_x87_operand_8616(codegen, operand, project=scan_project, size=size)
                if expr is None:
                    return None
                op = "Add" if reg == 0 else "Mul"
                stack[-1] = CBinaryOp(op, stack[-1], expr, codegen=codegen)
                fpu_ops += 1
            elif (opcode, reg) in ((0xD9, 3), (0xDD, 3)):
                if not stack:
                    return None
                if operand.get("kind") != 0:
                    return None
                final_expr = stack.pop()
                final_store_offset = int(operand.get("offset", -1))
                final_store_index = index
                fpu_ops += 1
            index = max(next_index, index + 2)
            continue
        index += 1

    if final_expr is None or final_store_offset is None or final_store_index is None or fpu_ops < 2:
        return None
    return_pattern = bytes((0xB8, final_store_offset & 0xFF, (final_store_offset >> 8) & 0xFF))
    if data.find(return_pattern, final_store_index + 1) < 0:
        return None
    with contextlib.suppress(Exception):
        function._inertia_msvc_x87_return_materialized_count = (
            int(getattr(function, "_inertia_msvc_x87_return_materialized_count", 0) or 0) + 1
        )
    return final_expr


def _infer_x86_16_c_return_value_from_ax_8616(codegen: object) -> object | None:
    def _debug_refuse(reason: str) -> None:
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            print(f"[dbg-return] CReturn compat-refused={reason}", file=sys.stderr, flush=True)

    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", {}) if arch is not None else {}
    ax_reg = registers.get("ax") if isinstance(registers, dict) else None
    if not isinstance(ax_reg, tuple) or len(ax_reg) < 2:
        _debug_refuse("missing-ax-register")
        return None
    function = getattr(codegen, "_func", None)
    if function is None:
        _debug_refuse("missing-function")
        return None
    reg_size = int(ax_reg[1]) if isinstance(ax_reg[1], int) and ax_reg[1] > 0 else 2
    sources = _terminal_register_sources_for_function_8616(
        arch=arch,
        function=function,
        graph=getattr(codegen, "ail_graph", None),
        reg_offset=int(ax_reg[0]),
        reg_size=reg_size,
    )
    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
        graph = getattr(codegen, "ail_graph", None)
        blocks = _iter_function_ail_blocks_8616(function, graph=graph)
        stmt_count = sum(len(tuple(getattr(block, "statements", ()) or ())) for block in blocks)
        ins_addrs = []
        for block in blocks:
            for stmt in tuple(getattr(block, "statements", ()) or ()):
                ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
                if isinstance(ins_addr, int):
                    ins_addrs.append(ins_addr)
        if len(sources) == 0:
            tail_stmts = []
            for block in blocks:
                for stmt in tuple(getattr(block, "statements", ()) or ()):
                    ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
                    if isinstance(ins_addr, int) and ins_addr >= (max(ins_addrs) - 0x30 if ins_addrs else 0):
                        tail_stmts.append((ins_addr, type(stmt).__name__, str(stmt)))
            for ins_addr, stmt_type, stmt_text in tail_stmts[-10:]:
                print(
                    f"[dbg-return] CReturn tail-stmt ins={ins_addr:#x} type={stmt_type} stmt={stmt_text}",
                    file=sys.stderr,
                    flush=True,
                )
        print(
            f"[dbg-return] CReturn compat-source-count={len(sources)} function=0x{getattr(function, 'addr', 0):x} "
            f"blocks={len(blocks)} statements={stmt_count} max_ins={hex(max(ins_addrs)) if ins_addrs else None}",
            file=sys.stderr,
            flush=True,
        )
    offsets: set[int] = set()
    sizes: set[int] = set()
    ctx = type("_ReturnCompatCtx8616", (), {"arch": arch})()
    for source in sources:
        if not isinstance(source, ailment.Expr.Load):
            continue
        load = cast(AilLoad8616, source)
        bp_disp = _bp_offset_from_linear_stack_addr_8616(ctx, load.addr)
        if not isinstance(bp_disp, int):
            continue
        bits = load.bits
        size = max(bits // getattr(arch, "byte_width", 8), 1) if isinstance(bits, int) and bits > 0 else reg_size
        offsets.add(bp_disp)
        sizes.add(size)
    if len(offsets) != 1:
        instruction_fact = _terminal_ax_stack_load_from_instructions_8616(function)
        if instruction_fact is not None:
            bp_disp, size = instruction_fact
            retval = _make_c_stack_return_value_8616(codegen, bp_disp=bp_disp, size=size)
            _increment_dynamic_int_counter_8616(function, "_inertia_return_compat_c_ast_materialized_count")
            return cast(object, retval)
        _debug_refuse(f"offset-count:{len(offsets)}")
        _increment_dynamic_int_counter_8616(function, "_inertia_return_compat_c_ast_refused_count")
        return None
    bp_disp = next(iter(offsets))
    size = next(iter(sizes)) if len(sizes) == 1 else reg_size
    retval = _make_c_stack_return_value_8616(codegen, bp_disp=bp_disp, size=size)
    _increment_dynamic_int_counter_8616(function, "_inertia_return_compat_c_ast_materialized_count")
    return cast(object, retval)


def _terminal_ax_stack_load_from_instructions_8616(function: object) -> tuple[int, int] | None:
    """Return one stack range when every terminal block proves the same AX load."""
    terminal_facts: list[tuple[int, int]] = []
    # Dynamic angr Function and capstone boundary. Typed instruction effects
    # below own the semantic classification.
    blocks: Iterable[object] = getattr(function, "blocks", ()) or ()
    for block in tuple(blocks):
        capstone = getattr(block, "capstone", None)
        wrappers: tuple[object, ...] = tuple(getattr(capstone, "insns", ()) or ())
        if not wrappers:
            continue
        instructions = tuple(getattr(wrapper, "insn", wrapper) for wrapper in wrappers)
        terminal_mnemonic = str(getattr(instructions[-1], "mnemonic", "") or "").lower()
        if terminal_mnemonic not in {"ret", "retf", "retn"}:
            continue
        terminal_fact: tuple[int, int] | None = None
        for instruction in reversed(instructions[:-1]):
            effect = terminal_ax_return_effect_8616(instruction)
            if effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER:
                break
            if effect.dst_reg not in {"ax", "al", "ah"}:
                continue
            if (
                effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK
                and effect.dst_reg == "ax"
                and isinstance(effect.mem_disp, int)
                and isinstance(effect.mem_size, int)
                and effect.mem_size == 2
            ):
                terminal_fact = (effect.mem_disp, effect.mem_size)
            break
        if terminal_fact is None:
            return None
        terminal_facts.append(terminal_fact)
    if not terminal_facts or len(set(terminal_facts)) != 1:
        return None
    return terminal_facts[0]


def _make_return_combo_expr_8616(
    self: object, stmt: object, block: object | None, ret_val: SimComboArg
) -> object | None:
    self_dynamic = cast(Any, self)
    stmt_dynamic = cast(Any, stmt)
    function = getattr(self, "function", None)
    project = _return_compat_function_project_8616(function)
    wide_evidence = (
        collect_wide_stack_argument_width_evidence_8616(project, function)
        if project is not None and function is not None
        else None
    )
    locations = tuple(ret_val.locations)
    if (
        wide_evidence is not None
        and len(wide_evidence.terminal_return_offsets) == 1
        and all(isinstance(location, SimRegArg) for location in locations)
        and tuple(location.reg_name for location in locations) == ("ax", "dx")
    ):
        terminal_owner = _make_bp_stack_load_expr_8616(
            self,
            stmt,
            bp_disp=wide_evidence.terminal_return_offsets[0],
            size=4,
        )
        if isinstance(terminal_owner, Expression):
            return cast(object, terminal_owner)
    parts: list[Expression] = []
    for loc in reversed(locations):
        if isinstance(loc, SimRegArg) and _is_stack_base_return_register_8616(loc):
            return None
        if not isinstance(loc, SimRegArg):
            return None
        reg_offset, reg_size = self_dynamic.arch.registers[loc.reg_name]
        part = _find_terminal_register_source_8616(self, stmt, block=block, reg_offset=reg_offset, reg_size=reg_size)
        candidate = part if part is not None else _make_return_register_expr_8616(self, stmt, loc)
        if not isinstance(candidate, Expression):
            return None
        parts.append(candidate)

    if not parts:
        return None

    expr = parts[0]
    for part in parts[1:]:
        high_stack_offset = (
            _bp_offset_from_linear_stack_addr_8616(self, expr.addr)
            if isinstance(expr, ailment.Expr.Load)
            else None
        )
        low_stack_offset = (
            _bp_offset_from_linear_stack_addr_8616(self, part.addr)
            if isinstance(part, ailment.Expr.Load)
            else None
        )
        wide_offsets = wide_evidence.classified_offsets if wide_evidence is not None else ()
        wide_stack_owner = None
        if (
            isinstance(high_stack_offset, int)
            and isinstance(low_stack_offset, int)
            and high_stack_offset == low_stack_offset + 2
            and low_stack_offset in wide_offsets
        ):
            candidate_owner = _make_bp_stack_load_expr_8616(self, stmt, bp_disp=low_stack_offset, size=4)
            if isinstance(candidate_owner, Expression):
                wide_stack_owner = candidate_owner
        expr = combine_word_return_sources_8616(
            expr,
            part,
            next_atom=self_dynamic._next_atom,
            ins_addr=stmt_dynamic.tags["ins_addr"],
            wide_stack_owner=wide_stack_owner,
        )
    return cast(object, expr)


def _raw_capstone_insn_8616(insn: object) -> object:
    return getattr(insn, "insn", insn)


def _capstone_reg_name_8616(insn: object, reg_id: int) -> str:
    raw = cast(Any, _raw_capstone_insn_8616(insn))
    try:
        return str(raw.reg_name(reg_id)).lower()
    except Exception:
        return ""


def _mem_bp_disp_operand_8616(insn: object, operand_index: int) -> int | None:
    raw = _raw_capstone_insn_8616(insn)
    operands = tuple(getattr(raw, "operands", ()) or ())
    if operand_index >= len(operands):
        return None
    operand = operands[operand_index]
    if int(getattr(operand, "type", -1)) != 3:
        return None
    if int(getattr(operand, "size", 0) or 0) != 2:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None or not getattr(mem, "base", None):
        return None
    if _capstone_reg_name_8616(raw, int(mem.base)) != "bp":
        return None
    disp = int(getattr(mem, "disp", 0) or 0)
    if 0x8000 <= disp <= 0xFFFF:
        disp -= 0x10000
    return disp


def _reg_operand_name_8616(insn: object, operand_index: int) -> str | None:
    raw = _raw_capstone_insn_8616(insn)
    operands = tuple(getattr(raw, "operands", ()) or ())
    if operand_index >= len(operands):
        return None
    operand = operands[operand_index]
    if int(getattr(operand, "type", -1)) != 1:
        return None
    return _capstone_reg_name_8616(raw, int(getattr(operand, "reg", 0) or 0))


def _insn_mnemonic_8616(insn: object) -> str:
    return str(getattr(_raw_capstone_insn_8616(insn), "mnemonic", "") or "").lower()


def _match_wide_stack_arith_sequence_8616(insns: Sequence[object]) -> tuple[str, int, int] | None:
    for index in range(max(0, len(insns) - 3)):
        first, second, third, fourth = insns[index : index + 4]
        if _insn_mnemonic_8616(first) != "mov" or _reg_operand_name_8616(first, 0) != "ax":
            continue
        if _insn_mnemonic_8616(second) != "mov" or _reg_operand_name_8616(second, 0) != "dx":
            continue
        first_low = _mem_bp_disp_operand_8616(first, 1)
        first_high = _mem_bp_disp_operand_8616(second, 1)
        if first_low is None or first_high != first_low + 2:
            continue
        low_op = _insn_mnemonic_8616(third)
        high_op = _insn_mnemonic_8616(fourth)
        if _reg_operand_name_8616(third, 0) != "ax" or _reg_operand_name_8616(fourth, 0) != "dx":
            continue
        second_low = _mem_bp_disp_operand_8616(third, 1)
        second_high = _mem_bp_disp_operand_8616(fourth, 1)
        if second_low is None or second_high != second_low + 2:
            continue
        if low_op == "add" and high_op == "adc":
            return "Add", second_low, first_low
        if low_op == "sub" and high_op == "sbb":
            return "Sub", first_low, second_low
    return None


def _terminal_wide_stack_arith_return_8616(self: object) -> tuple[str, int, int] | None:
    function = getattr(self, "function", None)
    project = getattr(function, "project", None) or getattr(self, "project", None)
    if function is None or project is None:
        return None
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = project.factory.block(int(block_addr), opt_level=0)
        except Exception:
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        matched = _match_wide_stack_arith_sequence_8616(insns)
        if matched is not None:
            return matched
    return None


def _make_bp_stack_load_expr_8616(self: object, stmt: object, *, bp_disp: int, size: int) -> object:
    self_dynamic = cast(Any, self)
    function = getattr(self, "function", None)
    variable = SimStackVariable(bp_disp, size, base="bp", region=getattr(function, "addr", None))
    ins_addr = getattr(stmt, "tags", {}).get("ins_addr", None)
    addr = StackBaseOffset(
        self_dynamic._next_atom(),
        size * self_dynamic.arch.byte_width,
        bp_disp,
        variable=variable,
        ins_addr=ins_addr,
    )
    return ailment.Expr.Load(
        self_dynamic._next_atom(),
        addr,
        size,
        "Iend_LE",
        variable=variable,
        ins_addr=ins_addr,
    )


def _make_wide_stack_arith_return_expr_8616(
    self: object,
    stmt: object,
    prototype: object,
) -> object | None:
    self_dynamic = cast(Any, self)
    returnty = getattr(prototype, "returnty", None)
    if not isinstance(returnty, SimTypeLong):
        return None
    matched = _terminal_wide_stack_arith_return_8616(self)
    if matched is None:
        return None
    op, lhs_offset, rhs_offset = matched
    lhs = _make_bp_stack_load_expr_8616(self, stmt, bp_disp=lhs_offset, size=4)
    rhs = _make_bp_stack_load_expr_8616(self, stmt, bp_disp=rhs_offset, size=4)
    signed = bool(returnty.signed)
    return cast(object, ailment.Expr.BinaryOp(
        self_dynamic._next_atom(),
        op,
        [cast(Any, lhs), cast(Any, rhs)],
        signed=signed,
        bits=32,
        ins_addr=getattr(stmt, "tags", {}).get("ins_addr", None),
    ))


def apply_x86_16_decompiler_return_compatibility() -> None:
    """Install 16-bit x86 return handling hooks backed by structured evidence."""
    if os.environ.get("INERTIA_DISABLE_RETURN_COMPAT") == "1":
        return

    apply_x86_16_clinic_return_type_compatibility()

    _orig_handle_return = ReturnMaker._handle_Return

    def _handle_Return_8616(  # pylint:disable=unused-argument
        self: object, stmt_idx: int, stmt: ailment.Stmt.Return, block: object | None
    ) -> object | None:
        self_dynamic = cast(Any, self)
        block_dynamic = cast(Any, block)
        stmt_dynamic = cast(Any, stmt)
        function = getattr(self_dynamic, "function", None)
        function_dynamic = cast(Any, function)
        _return_compat_attach_project_context_8616(function_dynamic, self_dynamic)
        function_addr = getattr(function_dynamic, "addr", 0)
        prototype = getattr(function_dynamic, "prototype", None)
        calling_convention = getattr(function_dynamic, "calling_convention", None)
        retty = getattr(prototype, "returnty", None)
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            if block is not None and stmt_idx > 0:
                window_start = max(0, stmt_idx - 20)
                for i in range(window_start, stmt_idx + 1):
                    if i >= len(block_dynamic.statements):
                        continue
                    window_stmt = block_dynamic.statements[i]
                    print(
                        f"[dbg-return] stmt[{i}]={type(window_stmt).__name__} ins=0x{getattr(window_stmt, 'tags', {}).get('ins_addr', 0):x} "
                        f"repr={window_stmt}",
                        file=sys.stderr,
                        flush=True,
                    )
                prev_stmt = (
                    block_dynamic.statements[stmt_idx - 1] if stmt_idx - 1 < len(block_dynamic.statements) else None
                )
                print(
                    f"[dbg-return] prev_stmt={type(prev_stmt).__name__ if prev_stmt is not None else None} "
                    f"ins_addr={getattr(prev_stmt, 'tags', {}).get('ins_addr', None)} "
                    f"addr=0x{getattr(prev_stmt, 'tags', {}).get('ins_addr', 0):x} "
                    f"idx={stmt_idx - 1 if prev_stmt is not None else None}",
                    file=sys.stderr,
                    flush=True,
                )
                print(f"[dbg-return] prev_stmt_repr={prev_stmt}", file=sys.stderr, flush=True)
            print(
                f"[dbg-return] ReturnMaker.handle_Return_8616 addr=0x{function_addr:x} "
                f"stmt_idx={stmt_idx} block={'none' if block is None else 'set'} "
                f"retty={type(retty).__name__ if retty is not None else 'none'} "
                # Dynamic angr AIL Return compatibility boundary.
                f"ret_exprs={len(getattr(stmt, 'ret_exprs', ()) or ())} "
                # Dynamic angr Function compatibility boundary.
                f"prototype_guessed={getattr(function, 'is_prototype_guessed', None)!r} "
                f"caller_return_use={_return_compat_function_caller_return_use_8616(function)!r} "
                f"caller_state={_return_compat_debug_caller_state_8616(function)!r}",
                file=sys.stderr,
                flush=True,
            )
            log.debug(
                "ReturnMaker.handle_Return_8616 addr=%#x stmt_idx=%d block=%s retty=%s ret_exprs=%d",
                function_addr,
                stmt_idx,
                "set" if block is not None else "none",
                type(retty).__name__ if retty is not None else "none",
                # Dynamic angr AIL Return compatibility boundary.
                len(getattr(stmt, "ret_exprs", ()) or ()),
            )
        if not stmt_dynamic.ret_exprs and block is not None:
            if _is_void_return_type_8616(retty):
                _increment_dynamic_int_counter_8616(function_dynamic, "_inertia_return_compat_void_refused_count")
                try:
                    return cast(object, _orig_handle_return(self_dynamic, stmt_idx, stmt_dynamic, block_dynamic))
                except AttributeError as ex:
                    if "returnty" in str(ex):
                        log.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            guessed_caller_use = (
                _return_compat_function_caller_return_use_8616(function)
                if _return_compat_prototype_is_guessed_8616(function)
                else True
            )
            if guessed_caller_use is False:
                returnty = getattr(prototype, "returnty", None)
                ret_val = (
                    calling_convention.return_val(returnty) if calling_convention is not None else SimRegArg("ax", 2)
                )
                ret_expr = _return_compat_unknown_caller_terminal_expr_8616(self, stmt, block, ret_val)
                if ret_expr is None:
                    ret_expr = _return_compat_unknown_caller_unconditional_predecessor_expr_8616(self, block, ret_val)
                if ret_expr is not None:
                    _increment_dynamic_int_counter_8616(
                        function_dynamic,
                        "_inertia_return_compat_unused_caller_proven_return_materialized_count",
                    )
                    new_stmt = cast(Any, stmt.copy())
                    ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
                    new_stmt.ret_exprs = [*new_stmt.ret_exprs, cast(Any, ret_expr)]
                    return cast(object, new_stmt)
                return cast(object, stmt.copy())
            if guessed_caller_use is not True:
                # Dynamic angr SimTypeFunction compatibility boundary.
                returnty = getattr(prototype, "returnty", None)
                ret_val = (
                    calling_convention.return_val(returnty) if calling_convention is not None else SimRegArg("ax", 2)
                )
                ret_expr = _return_compat_unknown_caller_terminal_expr_8616(self, stmt, block, ret_val)
                if ret_expr is None:
                    ret_expr = _return_compat_unknown_caller_unconditional_predecessor_expr_8616(self, block, ret_val)
                if ret_expr is not None:
                    new_stmt = cast(Any, stmt.copy())
                    ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
                    new_stmt.ret_exprs = [*new_stmt.ret_exprs, cast(Any, ret_expr)]
                    return cast(object, new_stmt)
                if _return_compat_unknown_caller_reaching_register_proven_8616(self, block, ret_val):
                    ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
                    if ret_expr is not None:
                        _increment_dynamic_int_counter_8616(
                            function_dynamic,
                            "_inertia_return_compat_unknown_caller_reaching_ax_count",
                        )
                        new_stmt = cast(Any, stmt.copy())
                        new_stmt.ret_exprs = [*new_stmt.ret_exprs, cast(Any, ret_expr)]
                        return cast(object, new_stmt)
                _increment_dynamic_int_counter_8616(
                    function_dynamic,
                    "_inertia_return_compat_unknown_caller_no_terminal_ax_count",
                )

            has_prototype_return = (
                prototype is not None
                and getattr(prototype, "returnty", None) is not None
                and type(getattr(prototype, "returnty", None)) is not SimTypeBottom
                and calling_convention is not None
            )
            if not has_prototype_return:
                ret_expr = _infer_x86_16_ax_return_expr_8616(self, stmt, block)
                if ret_expr is not None:
                    new_stmt = cast(Any, stmt.copy())
                    ret_expr = _make_return_register_expr_8616(self, stmt, SimRegArg("ax", 2))
                    new_stmt.ret_exprs = [*new_stmt.ret_exprs, cast(Any, ret_expr)]
                    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                        print(
                            f"[dbg-return] compat-inferred-ax-ret-stmt-count={len(new_stmt.ret_exprs)} "
                            f"value={new_stmt.ret_exprs[0] if new_stmt.ret_exprs else None}",
                            file=sys.stderr,
                            flush=True,
                        )
                    return cast(object, new_stmt)
                try:
                    return cast(object, _orig_handle_return(self_dynamic, stmt_idx, stmt_dynamic, block_dynamic))
                except AttributeError as ex:
                    if "returnty" in str(ex):
                        log.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            returnty = getattr(prototype, "returnty", None)
            if _is_x86_16_near_pointer_return_8616(getattr(self_dynamic, "arch", None), returnty):
                ret_val = SimRegArg("ax", 2)
            else:
                ret_val = cast(Any, calling_convention).return_val(returnty)
            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                print(
                    f"[dbg-return] ret_val={type(ret_val).__name__} value={getattr(ret_val, 'reg_name', None)} "
                    f"size={getattr(ret_val, 'size', None)} locations={getattr(ret_val, 'locations', None)}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    f"[dbg-return] ret_val_is_simreg={isinstance(ret_val, SimRegArg)} "
                    f"ret_val_is_combo={isinstance(ret_val, SimComboArg)}",
                    file=sys.stderr,
                    flush=True,
                )
            if isinstance(ret_val, SimRegArg) and _is_stack_base_return_register_8616(ret_val):
                if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                    print(
                        f"[dbg-return] skip-sp-based-return-compat addr=0x{getattr(self_dynamic.function, 'addr', 0):x} "
                        f"return-reg={ret_val.reg_name}",
                        file=sys.stderr,
                        flush=True,
                    )
                try:
                    return cast(object, _orig_handle_return(self_dynamic, stmt_idx, stmt_dynamic, block_dynamic))
                except AttributeError as ex:
                    if "returnty" in str(ex):
                        log.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            ret_expr = None
            if isinstance(ret_val, SimRegArg):
                try:
                    reg = self_dynamic.arch.registers[ret_val.reg_name]
                    ret_expr = _find_terminal_register_source_8616(
                        self,
                        stmt,
                        block=block,
                        reg_offset=reg[0],
                        reg_size=ret_val.size,
                    )
                    if ret_expr is None:
                        ret_expr = _find_reaching_register_source_8616(
                            self,
                            block,
                            reg_offset=reg[0],
                            reg_size=ret_val.size,
                        )
                    if ret_expr is None:
                        ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
                except Exception as ex:
                    if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                        print(
                            f"[dbg-return] compat-ret-register-error={type(ex).__name__}: {ex}",
                            file=sys.stderr,
                            flush=True,
                        )
                    raise
            elif isinstance(ret_val, SimComboArg):
                ret_expr = _make_wide_stack_arith_return_expr_8616(self, stmt, prototype)
                if ret_expr is None:
                    ret_expr = _make_return_combo_expr_8616(self, stmt, block, ret_val)

            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1" and ret_expr is not None:
                reg_name = getattr(ret_expr, "reg_name", None)
                print(
                    f"[dbg-return] compat-ret-expr-class={type(ret_expr).__name__} reg={reg_name}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    f"[dbg-return] compat-ret-expr-variable={getattr(ret_expr, 'variable', None)} "
                    f"bits={getattr(ret_expr, 'bits', None)} reg_offset={getattr(ret_expr, 'reg_offset', None)}",
                    file=sys.stderr,
                    flush=True,
                )

            if ret_expr is None:
                try:
                    return cast(object, _orig_handle_return(self_dynamic, stmt_idx, stmt_dynamic, block_dynamic))
                except AttributeError as ex:
                    # Some tiny/irregular functions can reach ReturnMaker with a
                    # missing prototype return type in upstream angr internals.
                    # Keep decompilation alive by preserving the original
                    # statement when the failure is prototype-shape related.
                    if "returnty" in str(ex):
                        log.warning("ReturnMaker fallback skipped due to missing returnty: %s", ex)
                        return None
                    raise

            new_stmt = cast(Any, stmt.copy())
            if isinstance(ret_val, SimRegArg):
                ret_expr = _make_return_register_expr_8616(self, stmt, ret_val)
            new_stmt.ret_exprs = [*new_stmt.ret_exprs, cast(Any, ret_expr)]
            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                print(
                    f"[dbg-return] compat-ret-stmt-count={len(new_stmt.ret_exprs)} "
                    f"value={new_stmt.ret_exprs[0] if new_stmt.ret_exprs else None}",
                    file=sys.stderr,
                    flush=True,
                )
            return cast(object, new_stmt)

        try:
            return cast(object, _orig_handle_return(self_dynamic, stmt_idx, stmt_dynamic, block_dynamic))
        except AttributeError as ex:
            if "returnty" in str(ex):
                log.warning("ReturnMaker skipped due to missing returnty: %s", ex)
                return None
            raise

    if getattr(ReturnMaker._handle_Return, "__name__", "") != "_handle_Return_8616":
        cast(Any, ReturnMaker)._handle_Return = _handle_Return_8616

    _orig_handle_c_return = MakeTypecastsImplicit.handle_CReturn

    def _handle_CReturn_8616(self: object, obj: object) -> object | None:
        """Preserve native return expressions; infer only genuinely missing values."""
        self_dynamic = cast(Any, self)
        obj_dynamic = cast(Any, obj)
        codegen = getattr(self_dynamic, "codegen", None)
        if codegen is None:
            codegen = getattr(obj_dynamic, "codegen", None)
        codegen_func, prototype = _resolve_codegen_prototype_8616(codegen)
        codegen_func_dynamic = cast(Any, codegen_func)
        observation_function = codegen_func
        if observation_function is None and codegen is not None:
            observation_function = getattr(codegen, "_inertia_current_function_8616", None)
        if observation_function is not None and codegen is not None:
            _return_compat_attach_project_context_8616(observation_function, codegen)
        return_type = getattr(prototype, "returnty", None)
        return_type_size = getattr(return_type, "size", None)
        unobserved_result = (
            observation_function is not None
            and _return_compat_proven_result_observation_8616(observation_function) is CallerReturnUseVerdict8616.UNUSED
        )
        current_retval = getattr(obj_dynamic, "retval", None)
        if (
            codegen is not None
            and current_retval is None and not unobserved_result
            and return_type is not None
            and not isinstance(return_type, SimTypeBottom)
            and isinstance(return_type_size, int)
            and return_type_size <= 16
        ):
            retval = _infer_x86_16_c_return_value_from_ax_8616(codegen)
            if retval is not None:
                obj_dynamic.retval = retval
                if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                    print(
                        f"[dbg-return] CReturn compat-inferred-ax-retval={_describe_c_expr_8616(retval)}",
                        file=sys.stderr,
                        flush=True,
                    )
        if (
            codegen is not None
            and not _is_void_return_type_8616(return_type)
            and isinstance(getattr(obj_dynamic, "retval", None), CConstant)
        ):
            x87_retval = _decode_msvc_x87_return_expr_8616(codegen)
            if x87_retval is not None:
                obj_dynamic.retval = x87_retval
                if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                    print(
                        f"[dbg-return] CReturn msvc-x87-retval={_describe_c_expr_8616(x87_retval)}",
                        file=sys.stderr,
                        flush=True,
                    )
            else:
                _increment_dynamic_int_counter_8616(
                    codegen_func_dynamic,
                    "_inertia_msvc_x87_return_refused_count",
                )
        if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
            if codegen is not None:
                graph_attrs = tuple(
                    sorted(
                        name
                        for name in dir(codegen)
                        if "graph" in name.lower() or name in {"_func", "function", "cfunc"}
                    )
                )
                print(f"[dbg-return] CReturn codegen-graph-attrs={graph_attrs}", file=sys.stderr, flush=True)
            print(
                f"[dbg-return] CReturn obj={type(obj_dynamic).__name__} return_type={return_type_size}",
                file=sys.stderr,
                flush=True,
            )
            print(
                f"[dbg-return] CReturn retval-before={type(getattr(obj_dynamic, 'retval', None)).__name__} "
                f"expr={_describe_c_expr_8616(getattr(obj_dynamic, 'retval', None))}",
                file=sys.stderr,
                flush=True,
            )
        try:
            result = cast(Any, _orig_handle_c_return)(self_dynamic, obj_dynamic)
            if result is not None:
                uncollapse_safe_scalar_expression_8616(cast(Any, result).retval)
            if os.environ.get("INERTIA_DEBUG_RETURN_COMPAT") == "1":
                print(
                    f"[dbg-return] CReturn result={type(result).__name__}",
                    file=sys.stderr,
                    flush=True,
                )
                print(
                    f"[dbg-return] CReturn retval-after={type(getattr(result, 'retval', None)).__name__} "
                    f"expr={_describe_c_expr_8616(getattr(result, 'retval', None))}",
                    file=sys.stderr,
                    flush=True,
                )
            return cast(object, result)
        except AttributeError as ex:
            if "returnty" in str(ex):
                # Some irregular functions can reach this pass without a resolved
                # prototype. Keep return expression unchanged instead of aborting
                # the entire decompilation.
                log.warning("MakeTypecastsImplicit skipped CReturn collapse due to missing returnty: %s", ex)
                return obj
            raise

    if getattr(MakeTypecastsImplicit.handle_CReturn, "__name__", "") != "_handle_CReturn_8616":
        MakeTypecastsImplicit.handle_CReturn = _handle_CReturn_8616
