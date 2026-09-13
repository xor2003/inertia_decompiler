"""Typed-condition C rewrite consumer.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume proven ConditionIR facts and replace C condition syntax without inferring semantics.

This module replaces flag-shaped C conditions with explicit comparisons from
ConditionIR. The condition semantics must already be proven by the early
pipeline: lift/IR records the flag-producing operation, condition transfer binds
it to codegen nodes, and this file only builds the equivalent C AST.

Ownership rule:
- This module is temporary compatibility for typed-condition recovery.
- The owning layer for condition recovery is lift/IR + condition transfer +
  structuring.
- If this module is required to infer condition facts (beyond C AST shape
  remap), that logic must migrate off this layer and this function should become
  a compatibility delegate.

Allowed work in this file:
- preserve exact Structuring-owned loop continuation polarity; a taken-branch
  ConditionIR fact is not a replacement for an oriented loop guard;
- map ConditionIR operands to C AST nodes;
- replace matching tagged conditions without changing branch meaning;
- record materialization traces for validation/debugging.

Current migration debt:
- register operand selection delegates to Structuring's Alias-proof consumer;
  never restore the removed numeric-address predecessor lookup here;
- typed stack operand construction delegates to Lowering's condition_stack_value;
- compatibility operand handling still accepts raw VEX-like wrappers;
- stack/global operand rendering still constructs fallback C expressions here;
- delta/tag fallback lookup exists because transfer is not complete.

Those behaviors should move to IR operand normalization, alias/stack lowering,
segmented memory lowering, or condition transfer. Do not add new flag, JCC,
polarity, operand, or branch inference here. If ConditionIR cannot describe the
condition, keep the original C and let validation/reporting expose the missing
early fact.
"""

from __future__ import annotations

import builtins
import contextlib
import logging
import os
import typing
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CReturn,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .condition_call_effects import classify_condition_call_effects_8616
from .condition_trace import record_materialized_condition_trace_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .ir.condition_ir import ConditionIR
from .ir.core import (
    IRBinaryValue,
    IRValue,
    MemSpace,
)
from .lowering.condition_stack_value import complete_storage_signedness_requests_8616
from .lowering.condition_stack_value import (
    materialize_condition_stack_value_8616 as _build_stack_operand_expr_8616,
)
from .pipeline.contracts import SemanticLaneState
from .structuring.condition_lowering import (
    attach_condition_segment_access_provenance_8616,
    condition_origin_tags_8616,
    condition_segment_access_tags_8616,
    materialize_binary_ir_value_8616,
    materialize_condition_stack_declaration_view_8616,
    materialize_indexed_segmented_condition_value_8616,
)
from .structuring.condition_register_expression import condition_register_expression_8616
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = [
    "_apply_typed_condition_stack_arg_signedness_8616",
    "_apply_typed_conditions_to_codegen_8616",
]

log: logging.Logger = logging.getLogger(__name__)
_UnifiedTypeSnapshot8616 = tuple[tuple[dict[object, object], object, object], ...]
_CVariableTypeSnapshot8616 = tuple[tuple[CVariable, object], ...]
_PrototypeTypeSnapshot8616 = tuple[object, object]
_SignedStackArgTypeSnapshot8616 = tuple[
    _CVariableTypeSnapshot8616,
    _PrototypeTypeSnapshot8616,
    _UnifiedTypeSnapshot8616,
]


def _dynamic_typed_condition_getattr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic angr/C-AST typed-condition boundary."""
    return builtins.getattr(obj, name, default)


def _project_arch_8616(project: object) -> Any:  # noqa: ANN401
    """Return the dynamic angr architecture object attached to a project."""
    return _dynamic_typed_condition_getattr_8616(project, "arch")


def _iter_switch_case_bodies_8616(cases: object) -> tuple[object, ...]:
    """Return only case bodies from angr's dict-style or pair-list switch cases."""
    if cases is None:
        return ()
    if isinstance(cases, dict):
        return tuple(cases.values())
    bodies: list[object] = []
    if isinstance(cases, (list, tuple)):
        for case in cases:
            if isinstance(case, (list, tuple)) and len(case) >= 2:
                bodies.append(case[1])
            else:
                bodies.append(case)
    return tuple(bodies)


def _build_reg_var(project: object, reg_name: str, codegen: object, size: int = 2) -> CVariable | None:
    """Build a CVariable for an x86-16 register by name."""
    normalized_name = reg_name.lower()
    reg = _project_arch_8616(project).registers.get(normalized_name)
    if reg is None:
        return None
    reg_offset, _ = reg
    function_region = _dynamic_typed_condition_getattr_8616(
        _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None),
        "addr",
        None,
    )
    variable_type = {
        1: SimTypeChar(False),
        2: SimTypeShort(False),
        4: SimTypeInt(False),
    }.get(size)
    if variable_type is None:
        return None
    variable_type = variable_type.with_arch(_project_arch_8616(project))
    return CVariable(
        SimRegisterVariable(
            int(reg_offset),
            size,
            ident=f"inertia-register-{normalized_name}",
            region=function_region if isinstance(function_region, int) else None,
            name=normalized_name,
        ),
        variable_type=variable_type,
        codegen=codegen,
    )


def _assignment_lhs_register_info_8616(project: object, lhs: object) -> tuple[int, int] | None:
    variable = _dynamic_typed_condition_getattr_8616(lhs, "variable", None) if isinstance(lhs, CVariable) else None
    if isinstance(variable, SimRegisterVariable):
        return int(variable.reg), int(_dynamic_typed_condition_getattr_8616(variable, "size", 0) or 0)
    name = _dynamic_typed_condition_getattr_8616(lhs, "name", None)
    if isinstance(name, str):
        reg = _dynamic_typed_condition_getattr_8616(_project_arch_8616(project), "registers", {}).get(name.lower())
        if reg is not None:
            return int(reg[0]), int(reg[1])
    return None


def _register_exprs_by_ins_addr_8616(codegen: object, project: object) -> dict[tuple[int, str, int], object]:
    cache = _dynamic_typed_condition_getattr_8616(codegen, "_inertia_typed_condition_register_exprs_by_ins_addr_8616", None)
    if isinstance(cache, dict):
        return cache
    reg_exprs: dict[tuple[int, str, int], object] = {}
    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    roots = (cfunc, _dynamic_typed_condition_getattr_8616(cfunc, "statements", None), _dynamic_typed_condition_getattr_8616(cfunc, "body", None))
    seen_nodes: set[int] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            node_id = id(node)
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            if not isinstance(node, CAssignment):
                continue
            tags = _dynamic_typed_condition_getattr_8616(node, "tags", None)
            ins_addr = None if tags is None else tags.get("ins_addr")
            if not isinstance(ins_addr, int):
                continue
            lhs_reg_info = _assignment_lhs_register_info_8616(project, node.lhs)
            if lhs_reg_info is None:
                continue
            lhs_reg_offset, var_size = lhs_reg_info
            for reg_name, (reg_offset, reg_size) in _project_arch_8616(project).registers.items():
                if int(reg_offset) != int(lhs_reg_offset):
                    continue
                if var_size and int(reg_size) != var_size:
                    continue
                rhs = _dynamic_typed_condition_getattr_8616(node, "rhs", None)
                expr = (
                    node.lhs
                    if any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(rhs))
                    else rhs
                )
                reg_exprs[(ins_addr, reg_name.lower(), int(reg_size))] = expr
    with contextlib.suppress(Exception):
        typing.cast(typing.Any, codegen)._inertia_typed_condition_register_exprs_by_ins_addr_8616 = reg_exprs
    return reg_exprs


def _type_for_operand_size_8616(size: int, *, signed: bool = False) -> object:
    """Return the scalar C type for a typed-condition operand width."""
    if size <= 1:
        return SimTypeChar(signed=signed)
    if size >= 4:
        return SimTypeLong(signed=signed)
    return SimTypeShort(signed=signed)


def _build_segmented_operand_expr_8616(project: object, operand: IRValue, codegen: object) -> CFunctionCall | None:
    space_to_segment = {
        MemSpace.DS: "ds",
        MemSpace.ES: "es",
        MemSpace.SS: "ss",
    }
    segment_name = space_to_segment.get(operand.space)
    if segment_name is None:
        return None
    width = int(operand.memory_access_size or operand.size or 2)
    helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(width)
    if helper is None:
        return None
    segment = _build_reg_var(project, segment_name, codegen, size=2)
    if segment is None:
        return None
    offset = CConstant(int(operand.offset) & 0xFFFF, SimTypeShort(signed=False), codegen=codegen)
    return CFunctionCall(
        helper,
        None,
        [segment, offset],
        codegen=codegen,
        tags=condition_segment_access_tags_8616(operand, helper),
    )


def _build_indexed_segmented_operand_expr_8616(
    project: object,
    operand: IRValue,
    codegen: object,
    cond: ConditionIR | None = None,
) -> CFunctionCall | None:
    """Build indexed segmented memory while preserving condition bind context."""
    if operand.index is None:
        return None
    segment = _build_reg_var(project, "ds", codegen, size=2)
    if segment is None:
        return None
    return materialize_indexed_segmented_condition_value_8616(
        operand,
        segment,
        codegen,
        lambda value: cast(
            Any,
            _build_c_expr_for_operand(
                project,
                value,
                codegen,
                cond,
                apply_condition_value_view=False,
            ),
        ),
        condition_segment_access_tags_8616,
    )


def _clone_stack_expr_with_condition_signedness_8616(expr: object, cond: ConditionIR | None, codegen: object) -> object:
    """Build a signed expression view when ConditionIR proves signed comparison."""
    if cond is None or not cond.is_signed or not isinstance(expr, CVariable):
        return expr
    projected = materialize_condition_stack_declaration_view_8616(
        codegen,
        expr,
        signed=True,
    )
    return projected if projected is not None else expr


def _build_c_expr_for_operand(
    project: object,
    operand: object,
    codegen: object,
    cond: ConditionIR | None = None,
    *,
    apply_condition_value_view: bool = True,
) -> object | None:
    """Lower typed condition IR, keeping address indices at their proven width."""

    def _impl() -> object | None:
        """Convert a ConditionIR operand (reg name string or int) to a C AST node."""
        if isinstance(operand, IRBinaryValue):
            return materialize_binary_ir_value_8616(operand, codegen, lambda value: _build_c_expr_for_operand(
                project, value, codegen, cond, apply_condition_value_view=apply_condition_value_view,
            ))
        if isinstance(operand, IRValue):
            if operand.space == MemSpace.CONST:
                return cast(object, CConstant(int(operand.const or 0), SimTypeInt(signed=False, label="int"), codegen=codegen))
            if operand.space == MemSpace.REG and isinstance(operand.name, str) and operand.name:
                bind_addr = cond.operand_bind_insn if cond is not None else None
                if not isinstance(bind_addr, int):
                    bind_addr = cond.producer_insn if cond is not None else None
                if not isinstance(bind_addr, int):
                    bind_addr = cond.src_insn if cond is not None else None
                if isinstance(bind_addr, int):
                    expr = condition_register_expression_8616(
                        project,
                        codegen,
                        _register_exprs_by_ins_addr_8616(codegen, project),
                        instruction_addr=bind_addr,
                        register=operand.name,
                        size=max(1, int(operand.size or 2)),
                    )
                    if expr is not None:
                        if apply_condition_value_view:
                            return _clone_stack_expr_with_condition_signedness_8616(expr, cond, codegen)
                        return expr
                    # Failed binding must retain the existing condition, not
                    # invent a register carrier without a reaching definition.
                    return None
                return _build_reg_var(project, operand.name, codegen, size=max(1, int(operand.size or 2)))
            if operand.space in {MemSpace.DS, MemSpace.ES}:
                indexed_expr = _build_indexed_segmented_operand_expr_8616(
                    project,
                    operand,
                    codegen,
                    cond,
                )
                if indexed_expr is not None:
                    return cast(object, indexed_expr)
                return _build_segmented_operand_expr_8616(project, operand, codegen)
            if operand.space == MemSpace.SS:
                condition_view = cond if apply_condition_value_view else None
                stack_expr = _build_stack_operand_expr_8616(
                    operand,
                    codegen,
                    signed=bool(condition_view is not None and condition_view.is_signed),
                    cond=condition_view,
                )
                return stack_expr if stack_expr is not None else _build_segmented_operand_expr_8616(project, operand, codegen)
            return None
        if isinstance(operand, str):
            return _build_reg_var(project, operand, codegen)
        if isinstance(operand, int):
            return cast(object, CConstant(int(operand), SimTypeInt(signed=False, label="int"), codegen=codegen))
        # Compatibility lane: some condition facts still carry raw VexValue-like
        # wrappers. Resolve register/const evidence if present.
        try:
            value_const = _dynamic_typed_condition_getattr_8616(operand, "value", None)
        except Exception:
            value_const = None
        if isinstance(value_const, int):
            return cast(object, CConstant(int(value_const), SimTypeInt(signed=False, label="int"), codegen=codegen))
        try:
            reg_name = _dynamic_typed_condition_getattr_8616(operand, "reg_name", None)
        except Exception:
            reg_name = None
        if isinstance(reg_name, str) and reg_name:
            return _build_reg_var(project, reg_name, codegen)
        try:
            reg_offset = _dynamic_typed_condition_getattr_8616(operand, "reg", None)
        except Exception:
            reg_offset = None
        if isinstance(reg_offset, int):
            reg_label = _project_arch_8616(project).register_names.get(int(reg_offset))
            if isinstance(reg_label, str) and reg_label:
                return _build_reg_var(project, reg_label, codegen)
        return None

    return _impl()


def _signed_type_for_operand_size_8616(size: int) -> SimType:
    if size <= 1:
        return SimTypeChar(signed=True)
    if size >= 4:
        return SimTypeLong(signed=True)
    return SimTypeShort(signed=True)


def _type_size_bytes_8616(type_: object, *, default: int = 2) -> int:
    if isinstance(type_, SimTypeChar):
        return 1
    if isinstance(type_, SimTypeShort):
        return 2
    if isinstance(type_, SimTypeLong):
        return 4
    try:
        bits = _dynamic_typed_condition_getattr_8616(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return default


def _bind_type_to_arch_8616(project: object, type_: SimType) -> SimType:
    arch = _dynamic_typed_condition_getattr_8616(project, "arch", None)
    if arch is not None and hasattr(type_, "with_arch"):
        with contextlib.suppress(Exception):
            return cast(SimType, _dynamic_typed_condition_getattr_8616(type_, "with_arch")(arch))
    return type_


def _return_expr_reads_signed_stack_arg_8616(cfunc: object, signed_offsets: dict[int, int]) -> bool:
    """Return whether any emitted return value reads a proven-signed stack arg."""
    if not signed_offsets:
        return False
    roots = (_dynamic_typed_condition_getattr_8616(cfunc, "statements", None), _dynamic_typed_condition_getattr_8616(cfunc, "body", None))
    seen_nodes: set[int] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            node_id = id(node)
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)
            if not isinstance(node, CReturn):
                continue
            retval = _dynamic_typed_condition_getattr_8616(node, "retval", None)
            for child in _iter_c_nodes_deep_8616(retval):
                if not isinstance(child, CVariable):
                    continue
                variable = _dynamic_typed_condition_getattr_8616(child, "variable", None)
                offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
                if (
                    isinstance(variable, SimStackVariable)
                    and _dynamic_typed_condition_getattr_8616(variable, "base", None) == "bp"
                    and isinstance(offset, int)
                    and offset in signed_offsets
                ):
                    return True
    return False


def _signed_return_type_from_stack_arg_evidence_8616(
    project: object, cfunc: object, return_type: SimType | None, signed_offsets: dict[int, int]
) -> SimType | None:
    """Promote a 16-bit return type when returns read proven-signed stack args."""
    if not _return_expr_reads_signed_stack_arg_8616(cfunc, signed_offsets):
        return return_type
    if isinstance(return_type, SimTypeShort) and not bool(_dynamic_typed_condition_getattr_8616(return_type, "signed", False)):
        return _bind_type_to_arch_8616(project, SimTypeShort(signed=True))
    return return_type


def _stack_arg_offset_from_condition_operand_8616(
    project: object,
    codegen: object,
    cond: ConditionIR,
    operand: object,
) -> tuple[int, int] | None:
    if not isinstance(operand, IRValue):
        return None
    if operand.space == MemSpace.SS and operand.name == "bp":
        offset = int(operand.offset)
        if offset >= 4:
            return offset, max(1, int(operand.size or 2))
        return None
    if operand.space != MemSpace.REG or not isinstance(operand.name, str) or not operand.name:
        return None
    bind_addr = cond.producer_insn if isinstance(cond.producer_insn, int) else cond.src_insn
    if not isinstance(bind_addr, int):
        return None
    expr = condition_register_expression_8616(
        project,
        codegen,
        _register_exprs_by_ins_addr_8616(codegen, project),
        instruction_addr=bind_addr,
        register=operand.name,
        size=max(1, int(operand.size or 2)),
    )
    variable = _dynamic_typed_condition_getattr_8616(expr, "variable", None)
    if not isinstance(variable, SimStackVariable) or _dynamic_typed_condition_getattr_8616(variable, "base", None) != "bp":
        return None
    offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
    if not isinstance(offset, int) or offset < 4:
        return None
    return offset, max(1, int(operand.size or _dynamic_typed_condition_getattr_8616(variable, "size", 2) or 2))


def _signed_stack_arg_offsets_from_conditions_8616(
    project: object,
    codegen: object,
    conditions: object,
) -> dict[int, int]:
    if not isinstance(conditions, (list, tuple)):
        return {}
    signed_offsets: dict[int, int] = {}
    unsigned_offsets: set[int] = set()
    for cond in conditions:
        if not isinstance(cond, ConditionIR):
            continue
        for operand in (cond.lhs, cond.rhs):
            stack_arg = _stack_arg_offset_from_condition_operand_8616(project, codegen, cond, operand)
            if stack_arg is None:
                continue
            offset, size = stack_arg
            if cond.is_signed:
                signed_offsets[offset] = max(size, signed_offsets.get(offset, 0))
            elif cond.is_unsigned:
                unsigned_offsets.add(offset)
    for offset in unsigned_offsets:
        signed_offsets.pop(offset, None)
    return signed_offsets


def _unsigned_stack_arg_offsets_from_conditions_8616(
    project: object,
    codegen: object,
    conditions: object,
) -> set[int]:
    if not isinstance(conditions, (list, tuple)):
        return set()
    unsigned_offsets: set[int] = set()
    for cond in conditions:
        if not isinstance(cond, ConditionIR) or not cond.is_unsigned:
            continue
        for operand in (cond.lhs, cond.rhs):
            stack_arg = _stack_arg_offset_from_condition_operand_8616(project, codegen, cond, operand)
            if stack_arg is None:
                continue
            unsigned_offsets.add(stack_arg[0])
    return unsigned_offsets


def _stack_arg_offset_from_c_expr_8616(expr: object) -> tuple[int, int] | None:
    if not isinstance(expr, CVariable):
        return None
    variable = _dynamic_typed_condition_getattr_8616(expr, "variable", None)
    if not isinstance(variable, SimStackVariable) or _dynamic_typed_condition_getattr_8616(variable, "base", None) != "bp":
        return None
    offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
    if not isinstance(offset, int) or offset < 4:
        return None
    size = max(1, int(_dynamic_typed_condition_getattr_8616(variable, "size", 0) or _type_size_bytes_8616(_dynamic_typed_condition_getattr_8616(expr, "variable_type", None))))
    return offset, size


def _propagate_signed_stack_arg_comparison_peers_8616(
    codegen: object,
    signed_offsets: dict[int, int],
    unsigned_offsets: set[int],
) -> dict[int, int]:
    if not signed_offsets:
        return signed_offsets
    propagated = dict(signed_offsets)
    changed = True
    while changed:
        changed = False
        cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
        for node in _iter_c_nodes_deep_8616(cfunc):
            if not isinstance(node, CBinaryOp) or node.op not in {"CmpLT", "CmpLE", "CmpGT", "CmpGE"}:
                continue
            lhs = _stack_arg_offset_from_c_expr_8616(_dynamic_typed_condition_getattr_8616(node, "lhs", None))
            rhs = _stack_arg_offset_from_c_expr_8616(_dynamic_typed_condition_getattr_8616(node, "rhs", None))
            if lhs is None or rhs is None:
                continue
            lhs_offset, lhs_size = lhs
            rhs_offset, rhs_size = rhs
            if lhs_offset in propagated and rhs_offset not in propagated and rhs_offset not in unsigned_offsets:
                propagated[rhs_offset] = rhs_size
                changed = True
            if rhs_offset in propagated and lhs_offset not in propagated and lhs_offset not in unsigned_offsets:
                propagated[lhs_offset] = lhs_size
                changed = True
    return propagated


def _stack_arg_offsets_read_by_expr_8616(expr: object) -> frozenset[int]:
    """Return positive BP stack-argument offsets read by a C expression tree."""
    offsets: set[int] = set()
    for node in _iter_c_nodes_deep_8616(expr):
        if not isinstance(node, CVariable):
            continue
        variable = _dynamic_typed_condition_getattr_8616(node, "variable", None)
        offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and _dynamic_typed_condition_getattr_8616(variable, "base", None) == "bp" and isinstance(  # noqa: SIM102
            offset, int
        ):
            if offset >= 4:
                offsets.add(offset)
    return frozenset(offsets)


def _comparison_fingerprints_by_node_8616(cfunc: object, project: object) -> dict[int, tuple[str, frozenset[int]]]:
    """Fingerprint comparison nodes and the stack arguments each comparison reads."""
    fingerprints: dict[int, tuple[str, frozenset[int]]] = {}
    for node in _iter_c_nodes_deep_8616(cfunc):
        if not isinstance(node, CBinaryOp) or not str(_dynamic_typed_condition_getattr_8616(node, "op", "")).startswith("Cmp"):
            continue
        with contextlib.suppress(Exception):
            fingerprints[id(node)] = (_expr_fingerprint(node, project), _stack_arg_offsets_read_by_expr_8616(node))
    return fingerprints


def _condition_fingerprint_changes_are_owned_by_stack_args_8616(
    before: dict[int, tuple[str, frozenset[int]]],
    after: dict[int, tuple[str, frozenset[int]]],
    signed_offsets: dict[int, int],
) -> bool:
    """Decide whether signedness changed only conditions reading proven stack args."""
    if not signed_offsets:
        return False
    if before.keys() != after.keys():
        return False
    signed = frozenset(int(offset) for offset in signed_offsets)
    for node_id, (before_fingerprint, before_offsets) in before.items():
        after_fingerprint, after_offsets = after[node_id]
        if before_fingerprint == after_fingerprint:
            continue
        if not ((before_offsets | after_offsets) & signed):
            return False
    return True


def _iter_signedness_stack_arg_cvars_8616(cfunc: object) -> tuple[CVariable, ...]:
    """Return every known positive-BP CVariable surface that may drive argument rebuilding."""
    nodes: list[CVariable] = []
    seen: set[int] = set()

    def _remember(node: object) -> None:
        if not isinstance(node, CVariable):
            return
        variable = _dynamic_typed_condition_getattr_8616(node, "variable", None)
        offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
        if not isinstance(variable, SimStackVariable) or _dynamic_typed_condition_getattr_8616(variable, "base", None) != "bp":
            return
        if not isinstance(offset, int) or offset < 4:
            return
        marker = id(node)
        if marker in seen:
            return
        seen.add(marker)
        nodes.append(node)

    for arg in tuple(_dynamic_typed_condition_getattr_8616(cfunc, "arg_list", ()) or ()):
        _remember(arg)
    for root in (cfunc, _dynamic_typed_condition_getattr_8616(cfunc, "statements", None), _dynamic_typed_condition_getattr_8616(cfunc, "body", None)):
        for node in _iter_c_nodes_deep_8616(root):
            _remember(node)
    variables_in_use = _dynamic_typed_condition_getattr_8616(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for node in tuple(variables_in_use.values()):
            _remember(node)
    unified = _dynamic_typed_condition_getattr_8616(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for entries in tuple(unified.values()):
            for entry in tuple(entries or ()):
                node = entry[0] if isinstance(entry, tuple) and entry else entry
                _remember(node)
    return tuple(nodes)


def _snapshot_unified_signed_stack_arg_types_8616(cfunc: object) -> tuple[tuple[dict[object, object], object, object], ...]:
    """Capture unified-local entries whose stored type may be signedness-adjusted."""
    unified = _dynamic_typed_condition_getattr_8616(cfunc, "unified_local_vars", None)
    if not isinstance(unified, dict):
        return ()
    rows: list[tuple[dict[object, object], object, object]] = []
    for key, value in tuple(unified.items()):
        rows.append((unified, key, value))
    return tuple(rows)


def _restore_unified_signed_stack_arg_types_8616(
    snapshot: tuple[tuple[dict[object, object], object, object], ...],
) -> None:
    """Restore unified-local type entries after rejected signedness propagation."""
    for mapping, key, value in snapshot:
        with contextlib.suppress(Exception):
            mapping[key] = value


def _snapshot_signed_stack_arg_type_state_8616(
    project: object,
    codegen: object,
) -> _SignedStackArgTypeSnapshot8616:
    """Capture mutable type state touched by signed stack-argument propagation."""
    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    nodes: list[tuple[CVariable, object]] = []
    unified_snapshot: _UnifiedTypeSnapshot8616 = ()

    if cfunc is not None:
        nodes.extend((node, _dynamic_typed_condition_getattr_8616(node, "variable_type", None)) for node in _iter_signedness_stack_arg_cvars_8616(cfunc))
        unified_snapshot = _snapshot_unified_signed_stack_arg_types_8616(cfunc)
    prototype = _dynamic_typed_condition_getattr_8616(cfunc, "functy", None) if cfunc is not None else None
    if prototype is None and cfunc is not None:
        prototype = _dynamic_typed_condition_getattr_8616(cfunc, "prototype", None)
    function_prototype = None
    func_addr = _dynamic_typed_condition_getattr_8616(cfunc, "addr", None) if cfunc is not None else None
    functions = _dynamic_typed_condition_getattr_8616(_dynamic_typed_condition_getattr_8616(project, "kb", None), "functions", None)
    if isinstance(func_addr, int) and functions is not None:
        with contextlib.suppress(Exception):
            function = functions.function(addr=func_addr, create=False)
            function_prototype = _dynamic_typed_condition_getattr_8616(function, "prototype", None) if function is not None else None
    return tuple(nodes), (prototype, function_prototype), unified_snapshot


def _restore_signed_stack_arg_type_state_8616(
    project: object,
    codegen: object,
    snapshot: _SignedStackArgTypeSnapshot8616,
) -> None:
    """Restore mutable type state after an unsafe signedness propagation."""
    nodes, prototypes, unified_snapshot = snapshot
    for node, variable_type in nodes:
        with contextlib.suppress(Exception):
            node.variable_type = cast(SimType | None, variable_type)
    _restore_unified_signed_stack_arg_types_8616(unified_snapshot)
    prototype, function_prototype = prototypes
    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    if cfunc is not None:
        with contextlib.suppress(Exception):
            cfunc.functy = prototype
        with contextlib.suppress(Exception):
            cfunc.prototype = prototype
    func_addr = _dynamic_typed_condition_getattr_8616(cfunc, "addr", None) if cfunc is not None else None
    functions = _dynamic_typed_condition_getattr_8616(_dynamic_typed_condition_getattr_8616(project, "kb", None), "functions", None)
    if isinstance(func_addr, int) and functions is not None:
        with contextlib.suppress(Exception):
            function = functions.function(addr=func_addr, create=False)
            if function is not None:
                function.prototype = function_prototype


def _apply_signed_stack_arg_types_to_prototype_8616(project: object, codegen: object, signed_offsets: dict[int, int]) -> bool:
    """Apply sign-only type changes authorized by complete storage-owner proof."""
    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    if cfunc is None or not signed_offsets:
        return False
    stack_nodes = _iter_signedness_stack_arg_cvars_8616(cfunc)
    signed_offsets = complete_storage_signedness_requests_8616(
        signed_offsets,
        (node.variable for node in stack_nodes if isinstance(node.variable, SimStackVariable)),
    )
    if not signed_offsets:
        return False
    changed = False
    changed_fields: set[str] = set()
    changed_offsets: set[int] = set()
    changed_nodes: list[tuple[int, str | None, str]] = []
    arg_list = list(_dynamic_typed_condition_getattr_8616(cfunc, "arg_list", ()) or ())
    for node in stack_nodes:
        variable = _dynamic_typed_condition_getattr_8616(node, "variable", None)
        offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
        if not isinstance(offset, int) or offset not in signed_offsets:
            continue
        signed_type = _bind_type_to_arch_8616(project, _signed_type_for_operand_size_8616(signed_offsets[offset]))
        if _dynamic_typed_condition_getattr_8616(node, "variable_type", None) != signed_type:
            node.variable_type = cast(SimType | None, signed_type)
            changed = True
            changed_fields.add("body_cvar")
            changed_offsets.add(offset)
            try:
                rendered = node.c_repr()
            except Exception:
                rendered = repr(node)
            changed_nodes.append((offset, _dynamic_typed_condition_getattr_8616(variable, "name", None), rendered))
    unified = _dynamic_typed_condition_getattr_8616(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for key, entries in tuple(unified.items()):
            new_entries: set[object] = set()
            entries_changed = False
            for entry in tuple(entries or ()):
                if not (isinstance(entry, tuple) and len(entry) >= 2 and isinstance(entry[0], CVariable)):
                    new_entries.add(entry)
                    continue
                cvar = entry[0]
                variable = _dynamic_typed_condition_getattr_8616(cvar, "variable", None)
                offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
                if not (
                    isinstance(variable, SimStackVariable)
                    and _dynamic_typed_condition_getattr_8616(variable, "base", None) == "bp"
                    and isinstance(offset, int)
                    and offset in signed_offsets
                ):
                    new_entries.add(entry)
                    continue
                signed_type = _bind_type_to_arch_8616(project, _signed_type_for_operand_size_8616(signed_offsets[offset]))
                new_entry = (cvar, signed_type)
                new_entries.add(new_entry)
                if entry != new_entry:
                    entries_changed = True
            if entries_changed:
                unified[key] = new_entries
                changed = True
                changed_fields.add("unified_local_var")
    arg_by_offset: dict[int, CVariable] = {}
    for arg in arg_list:
        variable = _dynamic_typed_condition_getattr_8616(arg, "variable", None)
        offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
        if isinstance(variable, SimStackVariable) and _dynamic_typed_condition_getattr_8616(variable, "base", None) == "bp" and isinstance(offset, int):
            arg_by_offset[offset] = arg
    for offset, size in signed_offsets.items():
        arg = arg_by_offset.get(offset)
        if arg is None:
            continue
        signed_type = _bind_type_to_arch_8616(project, _signed_type_for_operand_size_8616(size))
        if _dynamic_typed_condition_getattr_8616(arg, "variable_type", None) != signed_type:
            arg.variable_type = cast(SimType | None, signed_type)
            changed = True
            changed_fields.add("arg_cvar")
            changed_offsets.add(offset)

    prototype = _dynamic_typed_condition_getattr_8616(cfunc, "functy", None) or _dynamic_typed_condition_getattr_8616(cfunc, "prototype", None)
    if prototype is None and not arg_list:
        return changed
    old_args = list(_dynamic_typed_condition_getattr_8616(prototype, "args", ()) or ())
    old_names = list(_dynamic_typed_condition_getattr_8616(prototype, "arg_names", None) or ())
    if arg_list:
        args: list[SimType] = []
        arg_names: list[str] = []
        for index, arg in enumerate(arg_list):
            variable = _dynamic_typed_condition_getattr_8616(arg, "variable", None)
            offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
            arg_type = _dynamic_typed_condition_getattr_8616(arg, "variable_type", None)
            if not isinstance(arg_type, (SimTypeChar, SimTypeShort, SimTypeLong)):
                arg_type = old_args[index] if index < len(old_args) else SimTypeShort(signed=False)
            args.append(cast(SimType, arg_type))
            arg_names.append(
                _dynamic_typed_condition_getattr_8616(variable, "name", None)
                or _dynamic_typed_condition_getattr_8616(arg, "name", None)
                or (old_names[index] if index < len(old_names) and isinstance(old_names[index], str) else f"arg_{index}")
            )
            if isinstance(offset, int) and offset in signed_offsets:
                signed_type = _bind_type_to_arch_8616(project, _signed_type_for_operand_size_8616(signed_offsets[offset]))
                if args[-1] != signed_type:
                    args[-1] = signed_type
                    changed = True
                    changed_fields.add("prototype_arg")
                    changed_offsets.add(offset)
        return_type = cast(SimType | None, _dynamic_typed_condition_getattr_8616(prototype, "returnty", SimTypeShort(signed=False)))
    else:
        args = [cast(SimType, arg_type) for arg_type in old_args]
        arg_names = list(old_names)
        cursor = 4
        for index, arg_type in enumerate(args):
            width = max(2, _type_size_bytes_8616(arg_type))
            if cursor in signed_offsets:
                signed_type = _bind_type_to_arch_8616(project, _signed_type_for_operand_size_8616(signed_offsets[cursor]))
                if args[index] != signed_type:
                    args[index] = signed_type
                    changed = True
                    changed_fields.add("prototype_arg")
                    changed_offsets.add(cursor)
            cursor += width
        return_type = cast(SimType | None, _dynamic_typed_condition_getattr_8616(prototype, "returnty", SimTypeShort(signed=False)))
    signed_return_type = _signed_return_type_from_stack_arg_evidence_8616(project, cfunc, return_type, signed_offsets)
    if signed_return_type != return_type:
        return_type = signed_return_type
        changed = True
        changed_fields.add("prototype_return")
    if not changed:
        return False
    new_prototype = SimTypeFunction(
        args,
        return_type,
        arg_names=tuple(arg_names),
        variadic=_dynamic_typed_condition_getattr_8616(prototype, "variadic", False) if prototype is not None else False,
    )
    new_prototype = _bind_type_to_arch_8616(project, new_prototype)
    cfunc.functy = new_prototype
    with contextlib.suppress(Exception):
        cfunc.prototype = new_prototype
    func_addr = _dynamic_typed_condition_getattr_8616(cfunc, "addr", None)
    functions = _dynamic_typed_condition_getattr_8616(_dynamic_typed_condition_getattr_8616(project, "kb", None), "functions", None)
    if isinstance(func_addr, int) and functions is not None:
        with contextlib.suppress(Exception):
            function = functions.function(addr=func_addr, create=False)
            if function is not None:
                function.prototype = new_prototype
                function.is_prototype_guessed = False
    typing.cast(typing.Any, codegen)._inertia_typed_condition_signed_stack_arg_count_8616 = len(signed_offsets)
    typing.cast(typing.Any, codegen)._inertia_typed_condition_signed_stack_arg_changed_fields_8616 = tuple(sorted(changed_fields))
    typing.cast(typing.Any, codegen)._inertia_typed_condition_signed_stack_arg_changed_offsets_8616 = tuple(sorted(changed_offsets))
    typing.cast(typing.Any, codegen)._inertia_typed_condition_signed_stack_arg_changed_nodes_8616 = tuple(changed_nodes)
    if os.environ.get("INERTIA_DEBUG_TYPED_CONDITION_SIGNEDNESS"):
        log.warning(
            "[typed-condition-signedness] stage=%r offsets=%r changed_offsets=%r fields=%r arg_names=%r nodes=%r",
            _dynamic_typed_condition_getattr_8616(project, "_inertia_decompiler_stage", None),
            dict(sorted(signed_offsets.items())),
            tuple(sorted(changed_offsets)),
            tuple(sorted(changed_fields)),
            tuple(arg_names),
            tuple(changed_nodes),
        )
    return True


def _signed_stack_arg_type_debug_state_8616(codegen: object) -> tuple[tuple[str, int, str | None, bool | None], ...]:
    """Return signedness state for positive BP CVariables on emitted surfaces."""
    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return ()
    rows: list[tuple[str, int, str | None, bool | None]] = []
    seen: set[int] = set()

    def _record(surface: str, node: object) -> None:
        if not isinstance(node, CVariable):
            return
        marker = id(node)
        if marker in seen:
            return
        seen.add(marker)
        variable = _dynamic_typed_condition_getattr_8616(node, "variable", None)
        offset = _dynamic_typed_condition_getattr_8616(variable, "offset", None)
        if not isinstance(variable, SimStackVariable) or _dynamic_typed_condition_getattr_8616(variable, "base", None) != "bp":
            return
        if not isinstance(offset, int) or offset < 4:
            return
        variable_type = _dynamic_typed_condition_getattr_8616(node, "variable_type", None)
        rows.append((surface, offset, _dynamic_typed_condition_getattr_8616(variable, "name", None), _dynamic_typed_condition_getattr_8616(variable_type, "signed", None)))

    for arg in tuple(_dynamic_typed_condition_getattr_8616(cfunc, "arg_list", ()) or ()):
        _record("arg_list", arg)
    for root_name in ("statements", "body"):
        for node in _iter_c_nodes_deep_8616(_dynamic_typed_condition_getattr_8616(cfunc, root_name, None)):
            _record(root_name, node)
    return tuple(rows)


def _apply_typed_condition_stack_arg_signedness_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    """Propagate signed ConditionIR comparison evidence into stack-argument types."""
    conditions = _dynamic_typed_condition_getattr_8616(codegen, "_inertia_typed_conditions", None)
    signed_offsets = _signed_stack_arg_offsets_from_conditions_8616(
        project,
        codegen,
        conditions,
    )
    unsigned_offsets = _unsigned_stack_arg_offsets_from_conditions_8616(
        project,
        codegen,
        conditions,
    )
    signed_offsets = _propagate_signed_stack_arg_comparison_peers_8616(
        codegen,
        signed_offsets,
        unsigned_offsets,
    )
    if not signed_offsets:
        return False
    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    if os.environ.get("INERTIA_DEBUG_TYPED_CONDITION_SIGNEDNESS"):
        log.warning(
            "[typed-condition-signedness-before] stage=%r state=%r",
            _dynamic_typed_condition_getattr_8616(project, "_inertia_decompiler_stage", None),
            _signed_stack_arg_type_debug_state_8616(codegen),
        )
    before_conditions = _comparison_fingerprints_by_node_8616(cfunc, project)
    snapshot = _snapshot_signed_stack_arg_type_state_8616(project, codegen)
    changed = _apply_signed_stack_arg_types_to_prototype_8616(project, codegen, signed_offsets)
    if not changed:
        return False
    if os.environ.get("INERTIA_DEBUG_TYPED_CONDITION_SIGNEDNESS"):
        log.warning(
            "[typed-condition-signedness-after] stage=%r state=%r",
            _dynamic_typed_condition_getattr_8616(project, "_inertia_decompiler_stage", None),
            _signed_stack_arg_type_debug_state_8616(codegen),
        )
    after_conditions = _comparison_fingerprints_by_node_8616(cfunc, project)
    if not _condition_fingerprint_changes_are_owned_by_stack_args_8616(
        before_conditions,
        after_conditions,
        signed_offsets,
    ):
        _restore_signed_stack_arg_type_state_8616(project, codegen, snapshot)
        codegen._inertia_typed_condition_signed_stack_arg_refused_reason_8616 = "condition_fingerprint_drift"
        return False
    return True


def _build_c_condition_expr(
    project: object, cond: ConditionIR, codegen: object,
    *, operand_builder: Callable[[object], object | None] | None = None,
) -> CBinaryOp | None:
    """Build comparison syntax from operands supplied by the owning proof consumer."""
    build_operand = operand_builder or (lambda value: _build_c_expr_for_operand(project, value, codegen, cond))
    lhs_expr = build_operand(cond.lhs)
    if lhs_expr is None:
        return None
    if cond.op in ("zero", "nonzero"):
        rhs_expr = CConstant(0, SimTypeShort(signed=False), codegen=codegen)
    else:
        rhs_expr = build_operand(cond.rhs)
        if rhs_expr is None:
            return None

    _OP_MAP = {
        "eq": "CmpEQ",
        "ne": "CmpNE",
        "slt": "CmpLT",
        "sle": "CmpLE",
        "sgt": "CmpGT",
        "sge": "CmpGE",
        "ult": "CmpLT",
        "ule": "CmpLE",
        "ugt": "CmpGT",
        "uge": "CmpGE",
        "zero": "CmpEQ",
        "nonzero": "CmpNE",
    }
    structured_op = _OP_MAP.get(cond.op)
    if structured_op is None:
        return None

    expression = CBinaryOp(structured_op, lhs_expr, rhs_expr, codegen=codegen, tags=condition_origin_tags_8616(cond))
    attach_condition_segment_access_provenance_8616(expression, cond)
    return expression


def _condition_key_from_tags(node: object) -> tuple[int, int] | None:
    """Extract a match key (ins_addr, block_addr) from node tags."""
    seen: set[int] = set()

    def _walk(current: object) -> tuple[int, int] | None:
        if current is None:
            return None
        marker = id(current)
        if marker in seen:
            return None
        seen.add(marker)

        tags = _dynamic_typed_condition_getattr_8616(current, "tags", None)
        if isinstance(tags, dict):
            ins_addr = tags.get("ins_addr")
            block_addr = tags.get("vex_block_addr")
            if isinstance(ins_addr, int) and isinstance(block_addr, int):
                return (ins_addr, block_addr)

        if isinstance(current, CUnaryOp):
            return _walk(_dynamic_typed_condition_getattr_8616(current, "operand", None))
        if isinstance(current, CBinaryOp):
            return _walk(_dynamic_typed_condition_getattr_8616(current, "lhs", None)) or _walk(_dynamic_typed_condition_getattr_8616(current, "rhs", None))

        cond = _dynamic_typed_condition_getattr_8616(current, "cond", None)
        if cond is not None:
            return _walk(cond)
        return None

    return _walk(node)


def _index_conditions_by_tag(conditions: list[ConditionIR]) -> dict[tuple[Any, ...], ConditionIR]:
    """Index ConditionIR objects by their (ins_addr, block_addr) key."""
    index: dict[tuple[Any, ...], ConditionIR] = {}
    for cond in conditions:
        if not isinstance(cond.src_insn, int) or not isinstance(cond.block_addr, int):
            continue
        key = (cond.src_insn, cond.block_addr)
        index[key] = cond
    return index


def _resolve_condition_by_tag_with_delta(
    project: object, index: dict[tuple[Any, ...], ConditionIR], key: tuple[Any, ...] | None
) -> ConditionIR | None:
    def _impl() -> ConditionIR | None:
        if key is None:
            return None
        cond = index.get(key)
        if cond is not None:
            return cond
        if not (isinstance(key, tuple) and len(key) == 2):
            return None
        ins_addr, block_addr = key
        if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
            return None
        delta = _dynamic_typed_condition_getattr_8616(project, "_inertia_original_linear_delta", None)
        if not isinstance(delta, int) or delta == 0:
            return None
        for signed in (delta, -delta):
            alt_key = (ins_addr + signed, block_addr + signed)
            cond = index.get(alt_key)
            if cond is not None:
                return cond
        return None

    return _impl()


def _is_flag_based_condition_node(node: object) -> bool:
    def _has_flag_carrier_name(current: object) -> bool:
        fragments: list[str] = []
        with contextlib.suppress(Exception):
            fragments.append(str(current).lower())
        for obj in (current, _dynamic_typed_condition_getattr_8616(current, "variable", None)):
            if obj is None:
                continue
            for attr in ("name", "ident", "unified_variable", "unified_variable_name"):
                value = _dynamic_typed_condition_getattr_8616(obj, attr, None)
                if value is None:
                    continue
                with contextlib.suppress(Exception):
                    fragments.append(str(value).lower())
            with contextlib.suppress(Exception):
                fragments.append(str(obj).lower())
        return any("flags" in text or "tmp" in text or "vvar_" in text for text in fragments)

    def _impl() -> bool:
        """Detect if a condition node is flag-based (tmp_* or flags mask pattern)."""
        if isinstance(node, CITE):
            cond = _dynamic_typed_condition_getattr_8616(node, "cond", None) or _dynamic_typed_condition_getattr_8616(node, "condition", None)
            if cond is not None:
                return _is_flag_based_condition_node(cond)
            return False

        # CVariable looking like flags register
        if isinstance(node, CVariable):
            if _has_flag_carrier_name(node):
                return True
            var = _dynamic_typed_condition_getattr_8616(node, "variable", None)
            if isinstance(var, SimRegisterVariable):
                reg = _dynamic_typed_condition_getattr_8616(var, "reg", None)
                if reg == 18 or _has_flag_carrier_name(var):
                    return True

        # CBinaryOp with And or Shr on what looks like flags
        if isinstance(node, CBinaryOp):
            if node.op in ("And", "Shr") and _is_flag_based_condition_node(node.lhs):
                return True
            if _is_flag_based_condition_node(node.lhs) or _is_flag_based_condition_node(node.rhs):
                return True

        if isinstance(node, CUnaryOp):
            return _is_flag_based_condition_node(_dynamic_typed_condition_getattr_8616(node, "operand", None))

        return False

    return _impl()


def _debug_condition_candidate_8616(label: str, cond: object, key: tuple[Any, ...] | None, flag_based: bool) -> None:
    if not os.environ.get("INERTIA_DEBUG_TYPED_CONDITIONS"):
        return
    try:
        rendered = _dynamic_typed_condition_getattr_8616(cond, "c_repr")()
    except Exception:
        rendered = repr(cond)
    tags = _dynamic_typed_condition_getattr_8616(cond, "tags", None)
    log.warning(
        "[typed-condition] candidate label=%s type=%s key=%r flag_based=%s tags=%r cond=%s",
        label,
        type(cond).__name__,
        key,
        flag_based,
        tags,
        rendered,
    )


def _contains_flag_mask_operator_8616(node: object) -> bool:
    if node is None or not _structured_codegen_node_8616(node):
        return False
    if isinstance(node, CBinaryOp):
        if node.op in {"And", "Shr"} and (_is_flag_based_condition_node(node.lhs) or _is_flag_based_condition_node(node.rhs)):
            return True
        return _contains_flag_mask_operator_8616(node.lhs) or _contains_flag_mask_operator_8616(node.rhs)
    if isinstance(node, CUnaryOp):
        return _contains_flag_mask_operator_8616(_dynamic_typed_condition_getattr_8616(node, "operand", None))
    if isinstance(node, CITE):
        return _contains_flag_mask_operator_8616(_dynamic_typed_condition_getattr_8616(node, "cond", None))
    return False


def _contains_cite_node_8616(node: object) -> bool:
    if node is None or not _structured_codegen_node_8616(node):
        return False
    if isinstance(node, CITE):
        return True
    if isinstance(node, CBinaryOp):
        return _contains_cite_node_8616(node.lhs) or _contains_cite_node_8616(node.rhs)
    if isinstance(node, CUnaryOp):
        return _contains_cite_node_8616(_dynamic_typed_condition_getattr_8616(node, "operand", None))
    return False


def _typed_condition_carrier_polarity_8616(node: object) -> bool | None:
    """Return whether a tagged boolean carrier has direct typed-condition polarity."""

    def _constant_truth(expr: object) -> bool | None:
        if not isinstance(expr, CConstant) or not isinstance(expr.value, int):
            return None
        return bool(expr.value)

    if isinstance(node, CITE):
        true_value = _constant_truth(node.iftrue)
        false_value = _constant_truth(node.iffalse)
        if true_value is None or false_value is None or true_value == false_value:
            return None
        return true_value and not false_value
    if isinstance(node, CUnaryOp) and node.op == "Not":
        operand_polarity = _typed_condition_carrier_polarity_8616(node.operand)
        return None if operand_polarity is None else not operand_polarity
    if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE"}:
        lhs_polarity = _typed_condition_carrier_polarity_8616(node.lhs)
        rhs_truth = _constant_truth(node.rhs)
        if lhs_polarity is not None and rhs_truth is not None:
            preserve = (node.op == "CmpEQ") == rhs_truth
            return lhs_polarity if preserve else not lhs_polarity
        rhs_polarity = _typed_condition_carrier_polarity_8616(node.rhs)
        lhs_truth = _constant_truth(node.lhs)
        if rhs_polarity is not None and lhs_truth is not None:
            preserve = (node.op == "CmpEQ") == lhs_truth
            return rhs_polarity if preserve else not rhs_polarity
    return None


def _apply_typed_conditions_to_codegen_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool:
    """Replace flag-based conditions in C AST with explicit comparisons from ConditionIR.

    Compatibility consumer invoked by Structuring, not a Rewrite semantic
    recovery pass. A single fact cannot replace a compound condition; its
    complete CFG ownership belongs to Structuring's chain materializer.
    """
    conditions = _dynamic_typed_condition_getattr_8616(codegen, "_inertia_typed_conditions", None)
    if not conditions:
        return False

    condition_index = _index_conditions_by_tag(conditions)
    if not condition_index:
        return False

    changed = False
    matched_condition_keys: set[tuple[Any, ...]] = set()
    visited_nodes: set[int] = set()

    def _is_literal_condition(expr: object) -> bool:
        node = expr
        while isinstance(node, CUnaryOp) and _dynamic_typed_condition_getattr_8616(node, "op", None) == "Not":
            node = _dynamic_typed_condition_getattr_8616(node, "operand", None)
        return isinstance(node, CConstant) and isinstance(_dynamic_typed_condition_getattr_8616(node, "value", None), int)

    def _replacement_for_condition_node(cond: object) -> object | None:
        from .structuring.condition_ownership import requires_composite_condition_ownership_8616
        from .structuring.loop_condition_identity import is_owned_loop_continuation_8616

        if is_owned_loop_continuation_8616(cond):
            return None
        if requires_composite_condition_ownership_8616(cond):
            return None
        if classify_condition_call_effects_8616(cond).has_semantic_call:
            return None
        key = _condition_key_from_tags(cond)
        flag_based = _is_flag_based_condition_node(cond)
        cite_carrier = key is not None and _contains_cite_node_8616(cond)
        typed_comparison = (
            isinstance(cond, CBinaryOp)
            and str(cond.op).startswith("Cmp")
            and key is not None
        )
        _debug_condition_candidate_8616("replacement", cond, key, flag_based or cite_carrier)
        if not (flag_based or cite_carrier or typed_comparison):
            return None
        if key is None:
            return None
        typed_cond = _resolve_condition_by_tag_with_delta(project, condition_index, key)
        if typed_cond is None:
            if os.environ.get("INERTIA_DEBUG_TYPED_CONDITIONS"):
                try:
                    rendered = _dynamic_typed_condition_getattr_8616(cond, "c_repr")()
                except Exception:
                    rendered = repr(cond)
                log.warning("[typed-condition] unresolved key=%r cond=%s", key, rendered)
            return None
        new_cond = _build_c_condition_expr(project, typed_cond, codegen)
        if new_cond is None:
            return None
        if _same_c_expression_8616(new_cond.lhs, new_cond.rhs):
            return None
        if _expr_fingerprint(new_cond, project) == _expr_fingerprint(cond, project):
            return None
        if _same_c_expression_8616(new_cond, cond):
            return None
        carrier_polarity = _typed_condition_carrier_polarity_8616(cond)
        if carrier_polarity is False:
            new_cond = CUnaryOp("Not", new_cond, tags=dict(new_cond.tags), codegen=codegen)
        record_materialized_condition_trace_8616(project, codegen, key, new_cond)
        if key is not None:
            matched_condition_keys.add(key)
        return cast(object, new_cond)

    def _walk_statements(statements_obj: object) -> None:
        nonlocal changed
        raw = _dynamic_typed_condition_getattr_8616(statements_obj, "statements", ()) or ()
        raw_statements = _dynamic_typed_condition_getattr_8616(raw, "statements", raw) or ()
        stmts = (raw_statements,) if _structured_codegen_node_8616(raw_statements) else tuple(raw_statements)
        for stmt in stmts:
            _walk(stmt)

    def _walk(node: object) -> None:
        nonlocal changed
        if node is None or not _structured_codegen_node_8616(node):
            return
        node_id = id(node)
        if node_id in visited_nodes:
            return
        visited_nodes.add(node_id)

        # Replace condition in if statements
        if isinstance(node, CIfElse):
            cond = _dynamic_typed_condition_getattr_8616(node, "condition", None)
            if cond is not None:
                new_cond = _replacement_for_condition_node(cond)
                if new_cond is not None:
                    typing.cast(typing.Any, node).condition = new_cond
                    changed = True
            cond_pairs = _dynamic_typed_condition_getattr_8616(node, "condition_and_nodes", None)
            if cond_pairs:
                rebuilt_pairs = []
                pair_changed = False
                for cond_pair in cond_pairs:
                    if isinstance(cond_pair, (tuple, list)) and len(cond_pair) >= 2:
                        pair_cond = cond_pair[0]
                        pair_body = cond_pair[1]
                        new_pair_cond = _replacement_for_condition_node(pair_cond)
                        if new_pair_cond is not None:
                            rebuilt_pairs.append((new_pair_cond, pair_body))
                            pair_changed = True
                            changed = True
                        else:
                            rebuilt_pairs.append(tuple(cond_pair))
                    else:
                        rebuilt_pairs.append(cond_pair)
                if pair_changed:
                    typing.cast(typing.Any, node).condition_and_nodes = rebuilt_pairs
                    primary = _dynamic_typed_condition_getattr_8616(node, "condition", None)
                    if _is_literal_condition(primary):
                        first_pair = rebuilt_pairs[0] if rebuilt_pairs else None
                        if isinstance(first_pair, (tuple, list)) and len(first_pair) >= 1 and first_pair[0] is not None:
                            typing.cast(typing.Any, node).condition = first_pair[0]
                            changed = True

        # Replace condition in loops
        if hasattr(node, "condition") and not isinstance(node, CIfElse):
            cond = _dynamic_typed_condition_getattr_8616(node, "condition", None)
            condition_key = _condition_key_from_tags(cond)
            typed_comparison = (
                isinstance(cond, CBinaryOp)
                and str(cond.op).startswith("Cmp")
                and condition_key is not None
            )
            if _is_flag_based_condition_node(cond) or typed_comparison:
                new_cond = _replacement_for_condition_node(cond)
                if new_cond is not None:
                    typing.cast(typing.Any, node).condition = new_cond
                    changed = True

        # Recurse into children
        if hasattr(node, "statements"):
            _walk_statements(node)
        for attr in ("body", "else_node", "iftrue", "iffalse"):
            child = _dynamic_typed_condition_getattr_8616(node, attr, None)
            if child is not None:
                _walk(child)
        if hasattr(node, "condition_and_nodes"):
            for cond_pair in _dynamic_typed_condition_getattr_8616(node, "condition_and_nodes", ()) or ():
                if isinstance(cond_pair, (tuple, list)) and len(cond_pair) >= 2:
                    _walk(cond_pair[0])
                    _walk(cond_pair[1])
        if hasattr(node, "cases"):
            for case_body in _iter_switch_case_bodies_8616(_dynamic_typed_condition_getattr_8616(node, "cases", None)):
                _walk(case_body)

    cfunc = _dynamic_typed_condition_getattr_8616(codegen, "cfunc", None)
    if cfunc is not None:
        _walk_statements(cfunc)

    # ── Update CONDITION lane contract counters ──
    # count condition replacements actually performed
    if changed:
        lane = _dynamic_typed_condition_getattr_8616(codegen, "_inertia_condition_lane", None)
        if isinstance(lane, SemanticLaneState):
            matched_count = len(matched_condition_keys)
            lane.classified = max(lane.classified, matched_count)
            lane.materialized = matched_count
        codegen._inertia_semantic_condition_materialized_count = len(matched_condition_keys)

    return changed
