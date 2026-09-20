"""Legacy JCC cleanup bridge; do not add new semantic recovery here.

Layer: Rewrite/Postprocess cleanup.
Responsibility: consume already-collected JCC/condition evidence for temporary
cleanup while preserving the rule that branch semantics belong in earlier
structuring/IR/transfer layers.

Dynamic attribute access in this module is a third-party angr C AST, Capstone
instruction, and codegen telemetry boundary; owned Inertia evidence
must stay typed before this rewrite bridge consumes it.

This module is intentionally a late, temporary consumer of branch-condition
evidence. The permanent owner for 16-bit x86 condition semantics is the early
pipeline: lift/IR records the flag-producing operation, ConditionIR carries the
branch meaning, condition transfer/lowering preserves it, and structuring emits
explicit conditions.

Ownership rule:
- This file is migration debt for condition materialization and must not define
  new branch semantics.
- Evidence produced earlier in structuring/IR/transfer owns JCC semantics.
- This module is temporary; once all decoded/JCC materialization is owned in
  structuring + lowering, this module should shrink to a compatibility shim or be
  removed.

Allowed work in this file:
- preserve exact Structuring-owned loop continuation polarity; never replace
  it with the raw taken-branch comparison during compatibility replay;
- consume already-collected evidence and replace leaked raw flag carriers;
- prune duplicate raw if-breaks after an explicit condition is present;
- keep validation/reporting honest while older pipeline stages still leak state.

Do not add fresh semantic decoding here for cmp/test/sub/dec/jcc, polarity,
operand-width recovery, Capstone instruction windows, or reconstructed compare
operands. If behavior is proven here, migrate it earlier and delete the late
case. Any short-lived bridge must be narrow, evidence-backed,
validation-gated, deterministic, and documented as migration debt.

Project rule reminder: semantics early, rewrite late; no text-based recovery;
validation is the source of truth.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .condition_call_effects import classify_condition_call_effects_8616
from .decompiler_postprocess_flags import _c_expr_uses_register_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .frontend_function_instructions import (
    FunctionInstructionInventory8616,
    collect_function_instruction_inventory_8616,
)
from .frontend_instruction_reachability import decoded_block_instructions_8616
from .ir.condition_ir import JCC_TO_COND_8616, ConditionIR
from .ir.core import IRValue
from .lowering.real_mode_linear import (
    project_stack_value_range_8616,
    proven_wide_stack_pair_low_offset_8616,
    stack_cvar_for_machine_bp_value_range_8616,
)
from .lowering.segmented_memory_lowering import lower_runtime_segment_access_8616
from .lowering.wide_stack_pair_evidence import (
    materialize_proven_wide_stack_pair_variable_8616,
)
from .pipeline.contracts import SemanticLaneState
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = ["_rewrite_decoded_jcc_conditions_8616"]

_COND_TO_CMP_OP_8616: dict[str, str] = {
    "eq": "CmpEQ",
    "ne": "CmpNE",
    "ult": "CmpLT",
    "ule": "CmpLE",
    "ugt": "CmpGT",
    "uge": "CmpGE",
    "slt": "CmpLT",
    "sle": "CmpLE",
    "sgt": "CmpGT",
    "sge": "CmpGE",
}

_JCC_COMPARE_OPS_8616: dict[str, str] = {
    mnemonic: _COND_TO_CMP_OP_8616[cond_op]
    for mnemonic, cond_op in JCC_TO_COND_8616.items()
    if cond_op in _COND_TO_CMP_OP_8616
}

_JCC_COMPARE_MASK_TESTS_8616: dict[str, tuple[int, bool]] = {
    "jo": (0x800, True),
    "jno": (0x800, False),
    "js": (0x80, True),
    "jns": (0x80, False),
    "jp": (0x4, True),
    "jpe": (0x4, True),
    "jnp": (0x4, False),
    "jpo": (0x4, False),
}

_JCC_BLOCK_ENTRY_CARRY_TESTS_8616: dict[str, tuple[int, bool]] = {
    "jb": (0x1, True),
    "jc": (0x1, True),
    "jnae": (0x1, True),
    "jae": (0x1, False),
    "jnb": (0x1, False),
    "jnc": (0x1, False),
}

_INVERT_CMP_OP_8616: dict[str, str] = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
}

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _DecodedCmpGuard8616:
    lhs: object
    rhs: object
    op: str
    expr: object | None = None
    consumed_branch_keys: tuple[tuple[int, int], ...] = ()
    status_output_proven: bool = False


class _JccPolarityEvidence8616(Enum):
    UNKNOWN = "unknown"
    JCC_TARGET_BODY = "jcc_target_body"
    JCC_TARGET_FOLLOWING_SIBLING = "jcc_target_following_sibling"
    BREAK_CONDITION = "break_condition"
    LOOP_CONTINUATION = "loop_continuation"


class _JccDuplicateGuardDecision8616(Enum):
    KEEP_UNKNOWN = "keep_unknown"
    PRUNE_CURRENT_RAW_DUPLICATE = "prune_current_raw_duplicate"
    PRUNE_PREVIOUS_RAW_DUPLICATE = "prune_previous_raw_duplicate"


def _condition_tags_8616(node: object) -> tuple[int, int] | None:
    seen: set[int] = set()

    def _walk(current: object) -> tuple[int, int] | None:
        if current is None:
            return None
        marker = id(current)
        if marker in seen:
            return None
        seen.add(marker)
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict):
            ins_addr = tags.get("ins_addr")
            block_addr = tags.get("vex_block_addr")
            if isinstance(ins_addr, int) and isinstance(block_addr, int):
                return (ins_addr, block_addr)
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond"):
            child = getattr(current, attr, None)
            found = _walk(child)
            if found is not None:
                return found
        return None

    return _walk(node)


def _condition_materialized_by_jcc_8616(node: object) -> bool:
    seen: set[int] = set()

    def _walk(current: object) -> bool:
        if current is None:
            return False
        marker = id(current)
        if marker in seen:
            return False
        seen.add(marker)
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict) and (
            tags.get("inertia_jcc_materialized_8616") is True
            or tags.get("inertia_structuring_condition_chain_materialized_8616") is True
        ):
            return True
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond"):
            child = getattr(current, attr, None)
            if _walk(child):
                return True
        return False

    return _walk(node)


def _jcc_materialized_polarity_evidence_8616(node: object) -> str | None:
    seen: set[int] = set()

    def _walk(current: object) -> str | None:
        if current is None:
            return None
        marker = id(current)
        if marker in seen:
            return None
        seen.add(marker)
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict):
            evidence = tags.get("inertia_jcc_polarity_evidence_8616")
            if isinstance(evidence, str) and evidence:
                return evidence
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond"):
            child = getattr(current, attr, None)
            found = _walk(child)
            if found is not None:
                return found
        return None

    return _walk(node)


def _reg_offset_8616(project: Any, name: str) -> int | None:
    registers = getattr(getattr(project, "arch", None), "registers", None)
    if not isinstance(registers, dict):
        return None
    reg = registers.get(name.lower())
    return None if reg is None else int(reg[0])


def _assignment_lhs_register_info_8616(project: Any, lhs: object) -> tuple[int, int] | None:
    variable = getattr(lhs, "variable", None) if isinstance(lhs, CVariable) else None
    if isinstance(variable, SimRegisterVariable):
        return int(variable.reg), int(variable.size or 0)
    if type(lhs).__name__ != "CDirtyExpression":
        return None
    dirty = getattr(lhs, "dirty", None)
    reg_offset = None
    with contextlib.suppress(TypeError, AttributeError):
        reg_offset = getattr(dirty, "reg_offset", None)
    if not isinstance(reg_offset, int):
        return None
    bits = getattr(dirty, "bits", None)
    size = getattr(dirty, "size", None)
    size_bytes = int(bits // 8) if isinstance(bits, int) and bits > 0 else int(size or 0)
    if size_bytes <= 0:
        size_bytes = 2
    return int(reg_offset), int(size_bytes)


def _const_8616(value: int, codegen: object) -> CConstant:
    """Build an unsigned word constant bound to the active project arch when available."""
    const_type = SimTypeShort(False)
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is not None:
        with contextlib.suppress(Exception):
            const_type = const_type.with_arch(arch)
    return CConstant(int(value), const_type, codegen=codegen)


def _signed_const_8616(value: int, codegen: object) -> CConstant:
    """Build a signed word constant bound to the active project arch when available."""
    const_type = SimTypeShort(True)
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is not None:
        with contextlib.suppress(Exception):
            const_type = const_type.with_arch(arch)
    return CConstant(int(value), const_type, codegen=codegen)


def _type_with_project_arch_8616(project: Any, sim_type: Any) -> Any | None:
    if sim_type is None:
        return None
    try:
        _ = sim_type.size
        return sim_type
    except ValueError:
        pass
    except Exception:
        return sim_type
    arch = getattr(project, "arch", None)
    if arch is None or not hasattr(sim_type, "with_arch"):
        return sim_type
    with contextlib.suppress(Exception):
        return sim_type.with_arch(arch)
    return sim_type


def _ensure_c_expr_type_has_arch_8616(project: Any, expr: Any) -> Any | None:
    if expr is None:
        return None
    seen: set[int] = set()

    def _fix(node: Any) -> Any | None:
        if node is None:
            return None
        marker = id(node)
        if marker in seen:
            return node
        seen.add(marker)
        if isinstance(node, CVariable):
            variable_type = node.variable_type
            fixed_type = _type_with_project_arch_8616(project, variable_type)
            if fixed_type is not None and fixed_type is not variable_type:
                with contextlib.suppress(Exception):
                    node.variable_type = fixed_type
        elif isinstance(node, CConstant):
            const_type = node._type
            fixed_type = _type_with_project_arch_8616(project, const_type)
            if fixed_type is not None and fixed_type is not const_type:
                with contextlib.suppress(Exception):
                    node._type = fixed_type
        elif isinstance(node, CBinaryOp):
            with contextlib.suppress(Exception):
                node.lhs = _fix(node.lhs)
            with contextlib.suppress(Exception):
                node.rhs = _fix(node.rhs)
            common_type = node.common_type
            fixed_type = _type_with_project_arch_8616(project, common_type)
            if fixed_type is not None and fixed_type is not common_type:
                with contextlib.suppress(Exception):
                    node.common_type = fixed_type
        elif isinstance(node, CUnaryOp):
            with contextlib.suppress(Exception):
                fixed_operand = _fix(node.operand)
                if fixed_operand is not None:
                    node.operand = fixed_operand
        elif isinstance(node, CTypeCast):
            with contextlib.suppress(Exception):
                fixed_expr = _fix(node.expr)
                if fixed_expr is not None:
                    node.expr = fixed_expr
            src_type = node.src_type
            fixed_src_type = _type_with_project_arch_8616(project, src_type)
            if fixed_src_type is not None and fixed_src_type is not src_type:
                with contextlib.suppress(Exception):
                    node.src_type = fixed_src_type
            dst_type = node.dst_type
            fixed_dst_type = _type_with_project_arch_8616(project, dst_type)
            if fixed_dst_type is not None and fixed_dst_type is not dst_type:
                with contextlib.suppress(Exception):
                    node.dst_type = fixed_dst_type
        elif isinstance(node, CITE):
            with contextlib.suppress(Exception):
                node.cond = _fix(node.cond)
            with contextlib.suppress(Exception):
                fixed_condition = _fix(getattr(node, "condition", None))
                if fixed_condition is not None:
                    cast(Any, node).condition = fixed_condition
            with contextlib.suppress(Exception):
                node.iftrue = _fix(node.iftrue)
            with contextlib.suppress(Exception):
                node.iffalse = _fix(node.iffalse)
        return node

    return _fix(expr)


def _build_arch_safe_binary_op_8616(
    project: Any, codegen: Any, op: str, lhs: Any, rhs: Any, **kwargs: Any
) -> CBinaryOp:
    fixed_lhs = _ensure_c_expr_type_has_arch_8616(project, lhs)
    fixed_rhs = _ensure_c_expr_type_has_arch_8616(project, rhs)
    return CBinaryOp(op, fixed_lhs, fixed_rhs, codegen=codegen, **kwargs)


def _try_build_arch_safe_binary_op_8616(
    project: Any, codegen: Any, op: str, lhs: Any, rhs: Any, **kwargs: Any
) -> CBinaryOp | None:
    try:
        return _build_arch_safe_binary_op_8616(project, codegen, op, lhs, rhs, **kwargs)
    except ValueError as ex:
        if "without an arch" not in str(ex):
            raise
        return None
    except Exception:
        raise


def _register_exprs_by_ins_addr_8616(codegen: Any, project: Any) -> dict[tuple[int, str, int], object]:
    def _impl() -> dict[tuple[int, str, int], object]:
        cache = getattr(codegen, "_inertia_jcc_register_exprs_by_ins_addr_8616", None)
        if isinstance(cache, dict):
            return cache
        reg_exprs: dict[tuple[int, str, int], object] = {}
        for node in _iter_c_nodes_deep_8616(getattr(codegen, "cfunc", None)):
            if not isinstance(node, CAssignment):
                continue
            tags = node.tags
            ins_addr = None if tags is None else tags.get("ins_addr")
            if not isinstance(ins_addr, int):
                continue
            lhs_reg_info = _assignment_lhs_register_info_8616(project, node.lhs)
            if lhs_reg_info is None:
                continue
            lhs_reg_offset, var_size = lhs_reg_info
            for reg_name, (reg_offset, reg_size) in project.arch.registers.items():
                if int(reg_offset) != int(lhs_reg_offset):
                    continue
                if var_size and int(reg_size) != var_size:
                    continue
                rhs = node.rhs
                expr = (
                    node.lhs if any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(rhs)) else rhs
                )
                reg_exprs[(ins_addr, reg_name.lower(), int(reg_size))] = expr
        with contextlib.suppress(Exception):
            codegen._inertia_jcc_register_exprs_by_ins_addr_8616 = reg_exprs
        return reg_exprs

    return _impl()


def _lookup_register_expr_8616(
    reg_exprs: dict[tuple[int, str, int], object], ins_addr: int, reg_name: str, size: int
) -> object | None:
    expr = reg_exprs.get((int(ins_addr), reg_name.lower(), int(size)))
    if expr is not None:
        return expr
    for (candidate_addr, candidate_name, _candidate_size), candidate_expr in reg_exprs.items():
        if int(candidate_addr) == int(ins_addr) and candidate_name == reg_name.lower():
            return candidate_expr
    return None


def _lookup_register_expr_before_8616(
    reg_exprs: dict[tuple[int, str, int], object], ins_addr: int, reg_name: str, size: int
) -> object | None:
    best_addr = None
    best_expr = None
    for (candidate_addr, candidate_name, candidate_size), candidate_expr in reg_exprs.items():
        if candidate_name != reg_name.lower():
            continue
        if int(size) and int(candidate_size) != int(size):
            continue
        if int(candidate_addr) >= int(ins_addr):
            continue
        if best_addr is None or int(candidate_addr) > best_addr:
            best_addr = int(candidate_addr)
            best_expr = candidate_expr
    return best_expr


def _lookup_prior_register_stack_load_8616(
    project: Any, codegen: Any, ins_addr: int, reg_name: str, size: int
) -> object | None:
    for insn in sorted(
        _function_insns_for_codegen_8616(project, codegen),
        key=lambda item: int(getattr(item, "address", -1)),
        reverse=True,
    ):
        addr = int(getattr(insn, "address", -1))
        if addr >= int(ins_addr):
            continue
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic in {"jmp", "ljmp", "ret", "retf", "iret", "call", "lcall"} or mnemonic.startswith("j"):
            break
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != reg_name.lower():
            continue
        if int(getattr(operands[0], "size", 0) or size) != int(size):
            continue
        mem = operands[1].mem
        if not mem.base or str(insn.reg_name(mem.base)).lower() != "bp":
            continue
        return cast(
            object | None,
            _bp_operand_stack_expr_8616(codegen, int(mem.disp), int(getattr(operands[1], "size", 0) or size)),
        )
    return None


def _wide_stack_pair_expr_8616(codegen: Any, hi_expr: object, lo_expr: object) -> object | None:
    lo_offset = proven_wide_stack_pair_low_offset_8616(hi_expr, lo_expr)
    if lo_offset is None:
        return None
    return cast(
        object | None,
        materialize_proven_wide_stack_pair_variable_8616(
            codegen, hi_expr, lo_expr, _stack_slot_expr_8616(codegen, lo_offset, 4)
        ),
    )


def _expr_is_register_8616(project: Any, expr: object, reg_name: str) -> bool:
    node = expr
    while isinstance(node, CTypeCast):
        node = getattr(node, "expr", None)
    if not isinstance(node, CVariable):
        return False
    variable = node.variable
    if not isinstance(variable, SimRegisterVariable):
        return False
    expected = _reg_offset_8616(project, reg_name)
    return expected is not None and int(variable.reg) == int(expected)


def _wide_call_return_pair_expr_8616(
    project: Any, codegen: Any, hi_expr: object, lo_expr: object, ins_addr: int
) -> object | None:
    if not (_expr_is_register_8616(project, hi_expr, "dx") and _expr_is_register_8616(project, lo_expr, "ax")):
        return None
    debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
    if debug_jcc:
        _log.warning(
            "[jcc-rewrite] wide-call-return candidate ins_addr=%#x hi=%r lo=%r", int(ins_addr), hi_expr, lo_expr
        )
    with contextlib.suppress(Exception):
        codegen._inertia_jcc_wide_call_return_pair_candidates_8616 = (
            int(getattr(codegen, "_inertia_jcc_wide_call_return_pair_candidates_8616", 0) or 0) + 1
        )
    call_expr = _call_return_expr_before_insn_8616(project, codegen, int(ins_addr))
    if call_expr is None:
        if debug_jcc:
            _log.warning("[jcc-rewrite] wide-call-return refused-no-call ins_addr=%#x", int(ins_addr))
        with contextlib.suppress(Exception):
            codegen._inertia_jcc_wide_call_return_pair_refused_8616 = (
                int(getattr(codegen, "_inertia_jcc_wide_call_return_pair_refused_8616", 0) or 0) + 1
            )
        return None
    with contextlib.suppress(Exception):
        codegen._inertia_jcc_wide_call_return_pair_materialized_8616 = (
            int(getattr(codegen, "_inertia_jcc_wide_call_return_pair_materialized_8616", 0) or 0) + 1
        )
    if debug_jcc:
        _log.warning("[jcc-rewrite] wide-call-return materialized ins_addr=%#x expr=%r", int(ins_addr), call_expr)
    return cast(object | None, call_expr)


def _wide_call_return_pair_operands_8616(
    project: Any,
    codegen: Any,
    hi_operand: Any,
    lo_operand: Any,
    hi_reg_name_fn: Any,
    lo_reg_name_fn: Any,
    ins_addr: int,
) -> object | None:
    if int(getattr(hi_operand, "type", -1)) != 1 or int(getattr(lo_operand, "type", -1)) != 1:
        return None
    if str(hi_reg_name_fn(hi_operand.reg)).lower() != "dx":
        return None
    if str(lo_reg_name_fn(lo_operand.reg)).lower() != "ax":
        return None
    dx_offset = _reg_offset_8616(project, "dx")
    ax_offset = _reg_offset_8616(project, "ax")
    if dx_offset is None or ax_offset is None:
        return None
    return _wide_call_return_pair_expr_8616(
        project,
        codegen,
        CVariable(SimRegisterVariable(dx_offset, int(getattr(hi_operand, "size", 0) or 2), name="dx"), codegen=codegen),
        CVariable(SimRegisterVariable(ax_offset, int(getattr(lo_operand, "size", 0) or 2), name="ax"), codegen=codegen),
        ins_addr,
    )


def _stack_slot_placeholder_name_8616(disp: int, size: int) -> str:
    sign = "m" if int(disp) < 0 else "p"
    return f"stack_bp_{sign}{abs(int(disp)):x}_b{int(size)}"


def _is_unstable_stack_arg_name_8616(name: object) -> bool:
    return isinstance(name, str) and (
        name.startswith(("arg_", "local_", "stack_bp_", "s_"))
    )


def _stack_slot_expr_8616(
    codegen: Any, disp: int, size: int = 2, *, project: Any | None = None
) -> Any:
    """Read one proven machine-BP stack object without changing its identity."""
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None

    requested_disp = int(disp)
    requested_size = int(size) or 2
    proven = stack_cvar_for_machine_bp_value_range_8616(
        codegen,
        requested_disp,
        requested_size,
    )
    if isinstance(proven, CVariable):
        return proven
    projected = project_stack_value_range_8616(
        codegen,
        requested_disp,
        requested_size,
    )
    if projected.materialized:
        return projected.expression

    region = getattr(cfunc, "addr", None)
    return CVariable(
        SimStackVariable(
            requested_disp,
            requested_size,
            base="bp",
            name=_stack_slot_placeholder_name_8616(requested_disp, requested_size),
            region=region,
        ),
        codegen=codegen,
    )


def _bp_operand_stack_expr_8616(codegen: Any, disp: int, size: int = 2) -> Any:
    """Read a BP operand through the Types/Lowering coordinate owner."""
    return _stack_slot_expr_8616(codegen, disp, size)


def _low_byte_expr_from_assignment_8616(expr: Any) -> Any:
    def _impl() -> Any:
        if isinstance(expr, CBinaryOp) and expr.op == "Or":
            if isinstance(expr.lhs, CBinaryOp) and expr.lhs.op == "And" and isinstance(expr.lhs.rhs, CConstant):  # noqa: SIM102
                if int(expr.lhs.rhs.value) == 0xFF00:
                    return expr.rhs
            if isinstance(expr.rhs, CBinaryOp) and expr.rhs.op == "And" and isinstance(expr.rhs.rhs, CConstant):  # noqa: SIM102
                if int(expr.rhs.rhs.value) == 0xFF00:
                    return expr.lhs
        return expr

    return _impl()


def _stack_slot_key_8616(insn: Any) -> tuple[int, int] | None:
    if len(insn.operands) < 2:
        return None
    mem = (
        insn.operands[1].mem
        if insn.operands[1].type == 3
        else insn.operands[0].mem
        if insn.operands[0].type == 3
        else None
    )
    if mem is None:
        return None
    base = insn.reg_name(mem.base) if mem.base else None
    if base != "bp":
        return None
    return int(mem.disp), int(getattr(insn.operands[0], "size", 0) or getattr(insn.operands[1], "size", 0) or 2)


def _memory_load_expr_8616(
    project: Any, codegen: Any, ds_var: Any, base_expr: Any, disp: int, size: int
) -> Any | None:
    if ds_var is None:
        return None
    offset_expr = (
        _const_8616(disp, codegen)
        if base_expr is None
        else CBinaryOp("Add", base_expr, _const_8616(disp, codegen), codegen=codegen)
    )
    addr_expr = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ds_var, _const_8616(4, codegen), codegen=codegen),
        offset_expr,
        codegen=codegen,
    )
    pointee = (SimTypeChar() if int(size) == 1 else SimTypeShort(False)).with_arch(project.arch)
    deref = CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False).with_arch(project.arch),
            SimTypePointer(pointee).with_arch(project.arch),
            addr_expr,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    lowered = lower_runtime_segment_access_8616(deref, target="portable-flat")
    return lowered if lowered is not None else deref


_JCC_LOW_OP_8616: dict[str, str] = {
    "jb": "CmpLT",
    "jnae": "CmpLT",
    "jc": "CmpLT",
    "jbe": "CmpLE",
    "jna": "CmpLE",
    "ja": "CmpGT",
    "jnbe": "CmpGT",
    "jae": "CmpGE",
    "jnb": "CmpGE",
    "jnc": "CmpGE",
    "je": "CmpEQ",
    "jz": "CmpEQ",
    "jne": "CmpNE",
    "jnz": "CmpNE",
}


def _branch_target_imm_8616(insn: Any) -> int | None:
    operands = tuple(getattr(insn, "operands", ()) or ())
    if not operands:
        return None
    op0 = operands[0]
    if int(getattr(op0, "type", -1)) != 2:
        return None
    return int(getattr(op0, "imm", 0))


def _function_insns_for_codegen_8616(project: Any, codegen: Any) -> tuple[Any, ...]:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return ()
    cache = getattr(codegen, "_inertia_jcc_function_insns_8616", None)
    cache_entry = getattr(codegen, "_inertia_jcc_function_entry_8616", None)
    if (
        isinstance(cache, tuple)
        and cache_entry in {None, func_addr}
        and all(int(getattr(insn, "address", -1)) >= func_addr for insn in cache)
    ):
        return cache
    inventory = collect_function_instruction_inventory_8616(
        project,
        function_entry=func_addr,
    )
    result = inventory.instructions if inventory.complete else ()
    with contextlib.suppress(Exception):
        codegen._inertia_jcc_function_inventory_8616 = inventory
        codegen._inertia_jcc_function_insns_8616 = result
        codegen._inertia_jcc_function_entry_8616 = func_addr
    return result


def _merge_unique_insns_by_addr_8616(*groups: tuple[Any, ...]) -> tuple[Any, ...]:
    by_addr: dict[int, Any] = {}
    for group in groups:
        for insn in tuple(group or ()):
            addr = int(getattr(insn, "address", 0) or 0)
            if addr:
                by_addr.setdefault(addr, insn)
    return tuple(sorted(by_addr.values(), key=lambda item: int(getattr(item, "address", 0) or 0)))


def _linear_insns_before_addr_8616(
    project: Any, codegen: Any, ins_addr: int, *, max_bytes: int = 0x800
) -> tuple[Any, ...]:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    stop_addr = int(ins_addr)
    start_candidates: list[int] = []
    if isinstance(func_addr, int) and 0 <= func_addr < stop_addr:
        start_candidates.append(int(func_addr))
    loader = getattr(project, "loader", None)
    main_object = getattr(loader, "main_object", None)
    main_min_addr = getattr(main_object, "min_addr", None)
    loader_min_addr = getattr(loader, "min_addr", None)
    if isinstance(main_min_addr, int):
        start_candidates.append(int(main_min_addr))
    elif isinstance(loader_min_addr, int):
        start_candidates.append(int(loader_min_addr))
    cache = getattr(codegen, "_inertia_jcc_function_insns_8616", None)
    if isinstance(cache, tuple):
        cached_addrs = sorted(
            {
                int(getattr(insn, "address", -1))
                for insn in cache
                if 0 <= int(getattr(insn, "address", -1)) < stop_addr
            }
        )
        if cached_addrs:
            start_candidates.append(cached_addrs[0])
    start_candidates = sorted({addr for addr in start_candidates if 0 <= addr < stop_addr})
    if not start_candidates:
        return ()
    start_addr = int(func_addr) if isinstance(func_addr, int) and func_addr in start_candidates else start_candidates[0]
    if stop_addr <= start_addr:
        return ()
    end_addr = min(stop_addr, start_addr + int(max_bytes))
    addr = start_addr
    insns: list[object] = []
    while addr < end_addr:
        try:
            decoded = decoded_block_instructions_8616(project, addr, num_inst=1, opt_level=0)
        except TypeError:
            try:
                decoded = decoded_block_instructions_8616(project, addr, opt_level=0)
            except Exception:
                break
        except Exception:
            break
        if not decoded:
            break
        insn = decoded[0]
        insn_addr = int(getattr(insn, "address", addr) or addr)
        if insn_addr >= stop_addr:
            break
        insns.append(insn)
        size = int(getattr(insn, "size", 0) or 0)
        if str(getattr(insn, "mnemonic", "")).lower() in {"ret", "retf", "iret"}:
            break
        if size <= 0:
            break
        next_addr = insn_addr + size
        if next_addr <= addr:
            break
        addr = next_addr
    return tuple(insns)


def _direct_call_target_8616(insn: Any) -> int | None:
    mnemonic = str(getattr(insn, "mnemonic", "")).lower()
    if mnemonic not in {"call", "lcall"}:
        return None
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 1:
        return None
    op0 = operands[0]
    if int(getattr(op0, "type", -1)) != 2:
        return None
    return int(getattr(op0, "imm", 0))


def _callee_name_for_target_8616(project: Any, target_addr: int) -> tuple[str, object | None]:
    callee_func = None
    with contextlib.suppress(Exception):
        callee_func = project.kb.functions.function(addr=int(target_addr), create=False)
    name = getattr(callee_func, "name", None)
    if not isinstance(name, str) or not name:
        name = f"sub_{int(target_addr):x}"
    if name.startswith("_") and len(name) > 1:
        name = name[1:]
    return name, callee_func


def _callee_prototype_arg_count_8616(callee_func: Any, callee_name: str | None = None) -> int | None:
    prototype = getattr(callee_func, "prototype", None)
    args = getattr(prototype, "args", None)
    if isinstance(args, (list, tuple)):
        return len(args)
    if isinstance(callee_name, str) and callee_name in {"clock"}:
        return 0
    return None


def _const_from_push_imm_8616(value: int, codegen: Any) -> CConstant:
    return CConstant(int(value) & 0xFFFF, SimTypeShort(False), codegen=codegen)


def _call_args_from_push_setup_8616(
    project: Any, codegen: Any, insns: tuple[Any, ...], call_index: int, arg_count: int | None = None
) -> tuple[object, ...] | None:
    if arg_count == 0:
        return ()
    start = call_index
    lower_bound = max(0, call_index - 16)
    for idx in range(call_index - 1, lower_bound - 1, -1):
        mnemonic = str(getattr(insns[idx], "mnemonic", "")).lower()
        if mnemonic in {"push", "mov"}:
            start = idx
            continue
        break
    reg_values: dict[str, object] = {}
    pushed: list[object] = []
    for insn in insns[start:call_index]:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic == "mov" and len(operands) == 2 and int(getattr(operands[0], "type", -1)) == 1:
            reg_name = insn.reg_name(operands[0].reg).lower()
            if int(getattr(operands[1], "type", -1)) == 2:
                reg_values[reg_name] = _const_from_push_imm_8616(int(getattr(operands[1], "imm", 0)), codegen)
            else:
                reg_values.pop(reg_name, None)
            continue
        if mnemonic == "push" and len(operands) == 1:
            op0 = operands[0]
            op_type = int(getattr(op0, "type", -1))
            if op_type == 2:
                pushed.append(_const_from_push_imm_8616(int(getattr(op0, "imm", 0)), codegen))
                continue
            if op_type == 1:
                reg_name = insn.reg_name(op0.reg).lower()
                expr = reg_values.get(reg_name)
                if expr is None:
                    if isinstance(arg_count, int):
                        pushed.append(None)
                        continue
                    return None
                pushed.append(expr)
                continue
            return None
        return None
    if isinstance(arg_count, int):
        if arg_count < 0 or len(pushed) < arg_count:
            return None
        pushed = [] if arg_count == 0 else pushed[-arg_count:]
        if any(item is None for item in pushed):
            return None
    return tuple(reversed(pushed))


def _call_return_expr_before_insn_8616(project: Any, codegen: Any, ins_addr: int) -> CFunctionCall | None:
    debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
    insns = _function_insns_for_codegen_8616(project, codegen)
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    inventory = getattr(codegen, "_inertia_jcc_function_inventory_8616", None)
    inventory_covers_query = bool(
        isinstance(inventory, FunctionInstructionInventory8616)
        and inventory.complete
        and inventory.function_entry == getattr(getattr(codegen, "cfunc", None), "addr", None)
        and int(ins_addr) in index_by_addr
    )
    linear_insns = (
        ()
        if inventory_covers_query
        else _linear_insns_before_addr_8616(project, codegen, int(ins_addr))
    )
    if linear_insns:
        insns = _merge_unique_insns_by_addr_8616(insns, linear_insns)
        with contextlib.suppress(Exception):
            codegen._inertia_jcc_function_insns_8616 = insns
    if not insns:
        return None
    if linear_insns:
        index_by_addr = {
            int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)
        }
    start_idx = index_by_addr.get(int(ins_addr))
    if start_idx is None and linear_insns:
        start_idx = len(tuple(insn for insn in insns if int(getattr(insn, "address", -1)) < int(ins_addr)))
    if start_idx is None:
        return None
    lower_bound = max(0, start_idx - 8)
    arg_count = None
    for idx in range(start_idx - 1, lower_bound - 1, -1):
        insn = insns[idx]
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        target = _direct_call_target_8616(insn)
        if target is not None:
            name, callee_func = _callee_name_for_target_8616(project, target)
            if name == "aNchkstk":
                return None
            effective_arg_count = arg_count
            if effective_arg_count is None:
                effective_arg_count = _callee_prototype_arg_count_8616(callee_func, name)
            args = _call_args_from_push_setup_8616(project, codegen, insns, idx, effective_arg_count)
            if args is None:
                return None
            return CFunctionCall(name, callee_func, list(args), codegen=codegen)
        if (
            mnemonic == "add"
            and len(tuple(getattr(insn, "operands", ()) or ())) == 2
            and int(getattr(insn.operands[0], "type", -1)) == 1
            and str(insn.reg_name(insn.operands[0].reg)).lower() == "sp"
            and int(getattr(insn.operands[1], "type", -1)) == 2
        ):
            cleanup = int(getattr(insn.operands[1], "imm", 0) or 0)
            if cleanup >= 0 and cleanup % 2 == 0:
                arg_count = cleanup // 2
            continue
        if mnemonic in {"add", "sub", "nop"}:
            continue
        break
    if debug_jcc:
        seen = getattr(codegen, "_inertia_jcc_call_return_debug_logged_8616", None)
        if not isinstance(seen, set):
            seen = set()
            with contextlib.suppress(Exception):
                codegen._inertia_jcc_call_return_debug_logged_8616 = seen
        key = int(ins_addr)
        if key not in seen:
            seen.add(key)
            window = []
            for insn in insns:
                addr = int(getattr(insn, "address", -1))
                if int(ins_addr) - 0x40 <= addr <= int(ins_addr):
                    window.append(f"{addr:#x}:{str(getattr(insn, 'mnemonic', '')).lower()}")
            cfunc = getattr(codegen, "cfunc", None)
            loader = getattr(project, "loader", None)
            _log.warning(
                "[jcc-rewrite] call-return no-call ins_addr=%#x cfunc_addr=%r loader_min=%r main_min=%r "
                "cache_count=%d linear_count=%d window=%s",
                int(ins_addr),
                getattr(cfunc, "addr", None),
                getattr(loader, "min_addr", None),
                getattr(getattr(loader, "main_object", None), "min_addr", None),
                len(tuple(insns or ())),
                len(tuple(linear_insns or ())),
                ",".join(window[-16:]),
            )
    return None


def _decode_cmp_jcc_32bit_chain_8616(
    project: Any, codegen: Any, cmp_insn: Any, jcc_insn: Any, reg_exprs: Any, ds_var: Any
) -> _DecodedCmpGuard8616 | None:
    def _impl() -> _DecodedCmpGuard8616 | None:
        jcc1 = str(getattr(jcc_insn, "mnemonic", "")).lower()
        mid_addr = _branch_target_imm_8616(jcc_insn)
        if mid_addr is None:
            return None
        try:
            mid_insns = decoded_block_instructions_8616(project, mid_addr, opt_level=0)
        except Exception:
            return None

        reg_state: dict[str, object] = {}
        stack_slots: dict[tuple[int, int], object] = {}
        for state_insn in sorted(
            _function_insns_for_codegen_8616(project, codegen),
            key=lambda item: int(getattr(item, "address", -1)),
        ):
            state_addr = int(getattr(state_insn, "address", -1))
            if state_addr >= int(cmp_insn.address):
                break
            _apply_cmp_state_update_8616(project, codegen, state_insn, reg_state, stack_slots, reg_exprs, ds_var)

        if jcc1 in {"je", "jz"}:
            cmp2_insn = next((ins for ins in mid_insns if str(getattr(ins, "mnemonic", "")).lower() == "cmp"), None)
            jcc2_insn = next(
                (ins for ins in mid_insns if str(getattr(ins, "mnemonic", "")).lower() in {"je", "jz", "jne", "jnz"}),
                None,
            )
            if cmp2_insn is not None and jcc2_insn is not None:
                lhs_lo = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp_insn.operands[0],
                    reg_state,
                    ds_var,
                    cmp_insn.reg_name,
                    reg_exprs,
                    int(cmp_insn.address),
                )
                rhs_lo = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp_insn.operands[1],
                    reg_state,
                    ds_var,
                    cmp_insn.reg_name,
                    reg_exprs,
                    int(cmp_insn.address),
                )
                lhs_hi = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp2_insn.operands[0],
                    reg_state,
                    ds_var,
                    cmp2_insn.reg_name,
                    reg_exprs,
                    int(cmp2_insn.address),
                )
                rhs_hi = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp2_insn.operands[1],
                    reg_state,
                    ds_var,
                    cmp2_insn.reg_name,
                    reg_exprs,
                    int(cmp2_insn.address),
                )
                lhs_wide = _wide_stack_pair_expr_8616(codegen, lhs_hi, lhs_lo)
                rhs_wide = _wide_stack_pair_expr_8616(codegen, rhs_hi, rhs_lo)
                if lhs_wide is None:
                    lhs_wide = _wide_call_return_pair_expr_8616(project, codegen, lhs_hi, lhs_lo, int(cmp_insn.address))
                if lhs_wide is None:
                    lhs_wide = _wide_call_return_pair_operands_8616(
                        project,
                        codegen,
                        cmp_insn.operands[0],
                        cmp2_insn.operands[0],
                        cmp_insn.reg_name,
                        cmp2_insn.reg_name,
                        int(cmp_insn.address),
                    )
                if rhs_wide is None:
                    rhs_wide = _wide_call_return_pair_expr_8616(project, codegen, rhs_hi, rhs_lo, int(cmp_insn.address))
                if rhs_wide is None:
                    rhs_wide = _wide_call_return_pair_operands_8616(
                        project,
                        codegen,
                        cmp_insn.operands[1],
                        cmp2_insn.operands[1],
                        cmp_insn.reg_name,
                        cmp2_insn.reg_name,
                        int(cmp_insn.address),
                    )
                if lhs_wide is not None and rhs_wide is not None:
                    jcc2_name = str(getattr(jcc2_insn, "mnemonic", "")).lower()
                    return _DecodedCmpGuard8616(
                        lhs=lhs_wide,
                        rhs=rhs_wide,
                        op="CmpNE" if jcc2_name in {"jne", "jnz"} else "CmpEQ",
                    )

        # Compilers often emit `jcc short; jmp far` in the middle block. Accept
        # both one-insn and two-insn forms and pick the first conditional jump.
        jcc2_insn = next(
            (
                ins
                for ins in mid_insns
                if str(getattr(ins, "mnemonic", "")).lower().startswith("j")
                and str(getattr(ins, "mnemonic", "")).lower() not in {"jmp", "ljmp"}
            ),
            None,
        )
        if jcc2_insn is None:
            return None
        jcc2 = str(getattr(jcc2_insn, "mnemonic", "")).lower()
        cmp2_addr = _branch_target_imm_8616(jcc2_insn)
        if cmp2_addr is None:
            return None
        try:
            low_insns = decoded_block_instructions_8616(project, cmp2_addr, opt_level=0)
        except Exception:
            return None
        if len(low_insns) < 2:
            return None
        cmp2_insn = low_insns[0]
        jcc3_insn = low_insns[1]
        if str(getattr(cmp2_insn, "mnemonic", "")).lower() != "cmp":
            return None
        jcc3 = str(getattr(jcc3_insn, "mnemonic", "")).lower()
        low_op = _JCC_LOW_OP_8616.get(jcc3)
        if low_op is None:
            return None
        consumed_low_branch_keys = (
            (int(getattr(jcc2_insn, "address", 0)), int(mid_addr)),
            (int(getattr(jcc3_insn, "address", 0)), int(cmp2_addr)),
        )

        lhs_hi = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            cmp_insn.operands[0],
            reg_state,
            ds_var,
            cmp_insn.reg_name,
            reg_exprs,
            int(cmp_insn.address),
        )
        rhs_hi = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            cmp_insn.operands[1],
            reg_state,
            ds_var,
            cmp_insn.reg_name,
            reg_exprs,
            int(cmp_insn.address),
        )
        lhs_lo = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            cmp2_insn.operands[0],
            reg_state,
            ds_var,
            cmp2_insn.reg_name,
            reg_exprs,
            int(cmp2_insn.address),
        )
        rhs_lo = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            cmp2_insn.operands[1],
            reg_state,
            ds_var,
            cmp2_insn.reg_name,
            reg_exprs,
            int(cmp2_insn.address),
        )
        if lhs_hi is None or rhs_hi is None or lhs_lo is None or rhs_lo is None:
            return None

        lhs_hi = _ensure_c_expr_type_has_arch_8616(project, lhs_hi)
        rhs_hi = _ensure_c_expr_type_has_arch_8616(project, rhs_hi)
        lhs_lo = _ensure_c_expr_type_has_arch_8616(project, lhs_lo)
        rhs_lo = _ensure_c_expr_type_has_arch_8616(project, rhs_lo)

        hi_lt = CBinaryOp("CmpLT", lhs_hi, rhs_hi, codegen=codegen)
        hi_gt = CBinaryOp("CmpGT", lhs_hi, rhs_hi, codegen=codegen)
        hi_eq = CBinaryOp("CmpEQ", lhs_hi, rhs_hi, codegen=codegen)
        lo_rel = CBinaryOp(low_op, lhs_lo, rhs_lo, codegen=codegen)
        eq_expr = CBinaryOp("LogicalAnd", hi_eq, CBinaryOp("CmpEQ", lhs_lo, rhs_lo, codegen=codegen), codegen=codegen)
        lhs_wide = _wide_stack_pair_expr_8616(codegen, lhs_hi, lhs_lo)
        rhs_wide = _wide_stack_pair_expr_8616(codegen, rhs_hi, rhs_lo)
        if lhs_wide is None:
            lhs_wide = _wide_call_return_pair_expr_8616(project, codegen, lhs_hi, lhs_lo, int(cmp_insn.address))
        if lhs_wide is None:
            lhs_wide = _wide_call_return_pair_operands_8616(
                project,
                codegen,
                cmp_insn.operands[0],
                cmp2_insn.operands[0],
                cmp_insn.reg_name,
                cmp2_insn.reg_name,
                int(cmp_insn.address),
            )
        if rhs_wide is None:
            rhs_wide = _wide_call_return_pair_expr_8616(project, codegen, rhs_hi, rhs_lo, int(cmp_insn.address))
        if rhs_wide is None:
            rhs_wide = _wide_call_return_pair_operands_8616(
                project,
                codegen,
                cmp_insn.operands[1],
                cmp2_insn.operands[1],
                cmp_insn.reg_name,
                cmp2_insn.reg_name,
                int(cmp_insn.address),
            )
        if lhs_wide is None and rhs_wide is None:
            # Widening owns storage pairing. A matching JCC shape alone cannot
            # turn unrelated fields or locals into one logical 32-bit value.
            return None

        if jcc1 in {"jl", "jnge", "jb", "jnae", "jc"} and jcc2 in {"jge", "jnl", "jae", "jnb", "jnc"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpLT",
                    consumed_branch_keys=consumed_low_branch_keys,
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpLT",
                expr=CBinaryOp(
                    "LogicalOr", hi_lt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"jle", "jng", "jbe", "jna"} and jcc2 in {"jge", "jnl", "jae", "jnb", "jnc"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpLT" if low_op == "CmpLT" else "CmpLE",
                    consumed_branch_keys=consumed_low_branch_keys,
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpLE",
                expr=CBinaryOp(
                    "LogicalOr", hi_lt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"jg", "jnle", "ja", "jnbe"} and jcc2 in {"jle", "jng", "jbe", "jna"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpGT",
                    consumed_branch_keys=consumed_low_branch_keys,
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpGT",
                expr=CBinaryOp(
                    "LogicalOr", hi_gt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"jge", "jnl", "jae", "jnb", "jnc"} and jcc2 in {"jle", "jng", "jbe", "jna"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpGT" if low_op == "CmpGT" else "CmpGE",
                    consumed_branch_keys=consumed_low_branch_keys,
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpGE",
                expr=CBinaryOp(
                    "LogicalOr", hi_gt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"je", "jz"} and jcc2 in {"je", "jz", "jne", "jnz"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpEQ",
                    consumed_branch_keys=consumed_low_branch_keys,
                )
            return _DecodedCmpGuard8616(lhs=None, rhs=None, op="CmpEQ", expr=eq_expr)
        if jcc1 in {"jne", "jnz"} and jcc2 in {"je", "jz", "jne", "jnz"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpNE",
                    consumed_branch_keys=consumed_low_branch_keys,
                )
            ne_expr = CBinaryOp(
                "LogicalOr",
                CBinaryOp("CmpNE", lhs_hi, rhs_hi, codegen=codegen),
                CBinaryOp("LogicalAnd", hi_eq, CBinaryOp("CmpNE", lhs_lo, rhs_lo, codegen=codegen), codegen=codegen),
                codegen=codegen,
            )
            return _DecodedCmpGuard8616(lhs=None, rhs=None, op="CmpNE", expr=ne_expr)
        return None

    return _impl()


def _resolve_cmp_operand_expr_8616(
    project: Any,
    codegen: Any,
    operand: Any,
    reg_state: dict[str, object],
    ds_var: Any,
    reg_name_fn: Any,
    reg_exprs: dict[tuple[int, str, int], object],
    ins_addr: int,
) -> object | None:
    """Consume proven comparison values; refuse registers without a definition."""
    def _impl() -> object | None:
        op_type = int(getattr(operand, "type", -1))
        if op_type == 1:
            reg_name = reg_name_fn(operand.reg).lower()
            expr = reg_state.get(reg_name)
            if expr is not None:
                return expr
            expr = _lookup_register_expr_8616(reg_exprs, int(ins_addr), reg_name, int(getattr(operand, "size", 0) or 2))
            if expr is not None:
                return expr
            expr = _lookup_prior_register_stack_load_8616(
                project,
                codegen,
                int(ins_addr),
                reg_name,
                int(getattr(operand, "size", 0) or 2),
            )
            if expr is not None:
                return expr
            # A physical register name does not establish its reaching value.
            # Refusal preserves the existing condition instead of inventing a read.
            return None
        if op_type == 2:
            return cast(object | None, _const_8616(int(operand.imm), codegen))
        if op_type == 3 and getattr(operand, "mem", None) is not None:
            mem = operand.mem
            if mem.base:
                base_reg_name = reg_name_fn(mem.base).lower()
                if base_reg_name == "bp":
                    return cast(
                        object | None,
                        _bp_operand_stack_expr_8616(codegen, int(mem.disp), int(getattr(operand, "size", 0) or 2)),
                    )
                base_expr = reg_state.get(base_reg_name)
                if base_expr is None:
                    return None
                return _memory_load_expr_8616(
                    project,
                    codegen,
                    ds_var,
                    base_expr,
                    int(mem.disp),
                    int(getattr(operand, "size", 0) or 2),
                )
            if not getattr(mem, "index", 0):
                return _memory_load_expr_8616(
                    project,
                    codegen,
                    ds_var,
                    None,
                    int(mem.disp),
                    int(getattr(operand, "size", 0) or 2),
                )
        return None

    return _impl()


def _decode_block_and_jcc_index_8616(
    project: Any, block_addr: int, jcc_addr: int, debug_jcc: bool
) -> tuple[tuple[Any, ...] | None, int | None]:
    try:
        insns = decoded_block_instructions_8616(project, block_addr, opt_level=0)
    except Exception:
        if debug_jcc:
            _log.warning("[jcc-rewrite] block decode failed block=%#x jcc=%#x", block_addr, jcc_addr)
        return None, None
    jcc_index = next((idx for idx, insn in enumerate(insns) if int(insn.address) == int(jcc_addr)), None)
    if jcc_index is None:
        if debug_jcc:
            _log.warning(
                "[jcc-rewrite] jcc index missing block=%#x jcc=%#x insn_count=%d", block_addr, jcc_addr, len(insns)
            )
        return None, None
    return insns, jcc_index


def _nearest_flag_producer_before_jcc_8616(insns: tuple[Any, ...], jcc_index: int) -> Any | None:
    for idx in range(int(jcc_index) - 1, -1, -1):
        insn = insns[idx]
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic in {"cmp", "test", "inc", "dec", "add", "sub", "and", "or", "xor"}:
            return insn
        if mnemonic.startswith("j") or mnemonic in {"ret", "retf", "iret", "call", "lcall"}:
            break
    return None


def _decode_mask_test_guard_8616(
    project: Any, codegen: Any, jcc_mnemonic: str, block_addr: int, jcc_addr: int, debug_jcc: bool
) -> _DecodedCmpGuard8616 | None:
    if jcc_mnemonic not in _JCC_COMPARE_MASK_TESTS_8616:
        return None
    flags_offset = _reg_offset_8616(project, "flags")
    if flags_offset is None:
        if debug_jcc:
            _log.warning(
                "[jcc-rewrite] flags register offset missing for compare-flags mnemonic=%s block=%#x jcc=%#x",
                jcc_mnemonic,
                block_addr,
                jcc_addr,
            )
        return None
    bitmask, is_set = _JCC_COMPARE_MASK_TESTS_8616[jcc_mnemonic]
    return _DecodedCmpGuard8616(
        lhs=CBinaryOp(
            "And",
            CVariable(SimRegisterVariable(flags_offset, 2, name="flags"), codegen=codegen),
            _const_8616(bitmask, codegen),
            codegen=codegen,
        ),
        rhs=_const_8616(0, codegen),
        op=("CmpNE" if is_set else "CmpEQ"),
    )


def _decode_block_entry_carry_guard_8616(
    project: Any,
    codegen: Any,
    jcc_mnemonic: str,
) -> _DecodedCmpGuard8616 | None:
    """Decode a carry JCC whose flag producer belongs to a predecessor block."""
    test = _JCC_BLOCK_ENTRY_CARRY_TESTS_8616.get(jcc_mnemonic)
    flags_offset = _reg_offset_8616(project, "flags")
    status_stats = getattr(
        codegen,
        "_inertia_software_interrupt_status_output_stats_8616",
        None,
    )
    if (
        test is None
        or flags_offset is None
        or int(getattr(status_stats, "materialized_count", 0) or 0) <= 0
    ):
        return None
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    status_carriers = tuple(
        node.lhs
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and isinstance(node.lhs, CVariable)
        and isinstance(getattr(node, "tags", None), dict)
        and node.tags.get("inertia_software_interrupt_status_output_8616") is True
        and isinstance(node.lhs.variable, SimRegisterVariable)
        and node.lhs.variable.reg == flags_offset
    )
    if len(status_carriers) != 1:
        return None
    bitmask, is_set = test
    return _DecodedCmpGuard8616(
        lhs=CBinaryOp(
            "And",
            status_carriers[0],
            _const_8616(bitmask, codegen),
            codegen=codegen,
        ),
        rhs=_const_8616(0, codegen),
        op="CmpNE" if is_set else "CmpEQ",
        status_output_proven=True,
    )


_INC_DEC_JCC_BASELINE_8616: dict[tuple[str, str], tuple[str, int, bool]] = {
    ("inc", "je"): ("CmpEQ", -1, True),
    ("inc", "jz"): ("CmpEQ", -1, True),
    ("inc", "jne"): ("CmpNE", -1, True),
    ("inc", "jnz"): ("CmpNE", -1, True),
    ("inc", "jge"): ("CmpGE", -1, True),
    ("inc", "jnl"): ("CmpGE", -1, True),
    ("inc", "jg"): ("CmpGT", -1, True),
    ("inc", "jnle"): ("CmpGT", -1, True),
    ("inc", "jl"): ("CmpLT", -1, True),
    ("inc", "jnge"): ("CmpLT", -1, True),
    ("inc", "jle"): ("CmpLE", -1, True),
    ("inc", "jng"): ("CmpLE", -1, True),
    ("dec", "je"): ("CmpEQ", 1, False),
    ("dec", "jz"): ("CmpEQ", 1, False),
    ("dec", "jne"): ("CmpNE", 1, False),
    ("dec", "jnz"): ("CmpNE", 1, False),
    ("dec", "jge"): ("CmpGE", 1, False),
    ("dec", "jnl"): ("CmpGE", 1, False),
    ("dec", "jg"): ("CmpGT", 1, False),
    ("dec", "jnle"): ("CmpGT", 1, False),
    ("dec", "jl"): ("CmpLT", 1, False),
    ("dec", "jnge"): ("CmpLT", 1, False),
    ("dec", "jle"): ("CmpLE", 1, False),
    ("dec", "jng"): ("CmpLE", 1, False),
}


def _decode_linear_insns_range_8616(project: Any, start_addr: int, stop_addr: int) -> tuple[Any, ...]:
    insns: list[object] = []
    addr = int(start_addr)
    while addr < int(stop_addr):
        try:
            decoded = decoded_block_instructions_8616(project, addr, num_inst=1, opt_level=0)
        except Exception:
            break
        if not decoded:
            break
        insn = decoded[0]
        insn_addr = int(getattr(insn, "address", addr) or addr)
        if insn_addr >= int(stop_addr):
            break
        insns.append(insn)
        size = int(getattr(insn, "size", 0) or 0)
        if size <= 0:
            break
        addr = insn_addr + size
    return tuple(insns)


def _switch_dispatch_seed_expr_8616(
    project: Any, codegen: Any, ins_addr: int, reg_name: str, reg_size: int
) -> tuple[object | None, int | None]:
    insns = tuple(_function_insns_for_codegen_8616(project, codegen) or ())
    for idx, insn in enumerate(insns[:-1]):
        if int(getattr(insn, "address", -1)) >= int(ins_addr):
            break
        next_insn = insns[idx + 1]
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        next_mnemonic = str(getattr(next_insn, "mnemonic", "")).lower()
        if mnemonic != "mov" or next_mnemonic not in {"jmp", "ljmp"}:
            continue
        operands = tuple(getattr(insn, "operands", ()) or ())
        if (
            len(operands) != 2
            or int(getattr(operands[0], "type", -1)) != 1
            or int(getattr(operands[1], "type", -1)) != 3
        ):
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != reg_name.lower():
            continue
        if int(getattr(operands[0], "size", 0) or reg_size) != int(reg_size):
            continue
        target = _branch_target_imm_8616(next_insn)
        if target is None or int(target) > int(ins_addr):
            continue
        mem = operands[1].mem
        if not mem.base or str(insn.reg_name(mem.base)).lower() != "bp":
            continue
        seed = _bp_operand_stack_expr_8616(codegen, int(mem.disp), int(getattr(operands[1], "size", 0) or reg_size))
        return seed, int(target)
    return None, None


def _stateful_register_expr_before_insn_8616(
    project: Any,
    codegen: Any,
    ins_addr: int,
    reg_name: str,
    reg_size: int,
    reg_exprs: dict[tuple[int, str, int], object],
    ds_var: Any,
) -> object | None:
    reg_state: dict[str, object] = {}
    stack_slots: dict[tuple[int, int], object] = {}
    seed_expr, replay_start = _switch_dispatch_seed_expr_8616(project, codegen, ins_addr, reg_name, reg_size)
    if seed_expr is not None and replay_start is not None:
        reg_state[reg_name.lower()] = seed_expr
        replay_insns = _decode_linear_insns_range_8616(project, replay_start, int(ins_addr))
    else:
        replay_insns = tuple(_function_insns_for_codegen_8616(project, codegen) or ())
    for insn in replay_insns:
        current_addr = int(getattr(insn, "address", -1))
        if current_addr >= int(ins_addr):
            break
        _apply_cmp_state_update_8616(project, codegen, insn, reg_state, stack_slots, reg_exprs, ds_var)
    return reg_state.get(reg_name.lower())


def _decode_inc_dec_jcc_guard_8616(
    project: Any,
    codegen: Any,
    arith_insn: Any,
    jcc_mnemonic: str,
    reg_exprs: dict[tuple[int, str, int], object],
    ds_var: Any = None,
) -> _DecodedCmpGuard8616 | None:
    def _impl() -> _DecodedCmpGuard8616 | None:
        mnemonic = str(getattr(arith_insn, "mnemonic", "")).lower()
        if mnemonic not in {"inc", "dec"}:
            return None
        decision = _INC_DEC_JCC_BASELINE_8616.get((mnemonic, jcc_mnemonic))
        if decision is None:
            return None
        operands = tuple(getattr(arith_insn, "operands", ()) or ())
        if len(operands) != 1 or int(getattr(operands[0], "type", -1)) != 1:
            return None
        reg_name = arith_insn.reg_name(operands[0].reg).lower()
        reg_size = int(getattr(operands[0], "size", 0) or 2)
        lhs = None
        if reg_name in {"ax", "al", "ah"}:
            lhs = _call_return_expr_before_insn_8616(project, codegen, int(arith_insn.address))
        if lhs is None:
            lhs = _stateful_register_expr_before_insn_8616(
                project,
                codegen,
                int(arith_insn.address),
                reg_name,
                reg_size,
                reg_exprs,
                ds_var,
            )
        if lhs is None:
            lhs = _lookup_register_expr_before_8616(reg_exprs, int(arith_insn.address), reg_name, reg_size)
        if lhs is None:
            reg_offset = _reg_offset_8616(project, reg_name)
            if reg_offset is None:
                return None
            lhs = CVariable(SimRegisterVariable(reg_offset, reg_size, name=reg_name), codegen=codegen)
        op, rhs_value, rhs_signed = decision
        rhs = _signed_const_8616(rhs_value, codegen) if rhs_signed else _const_8616(rhs_value, codegen)
        return _DecodedCmpGuard8616(lhs=lhs, rhs=rhs, op=op)

    return _impl()


def _decode_test_jcc_guard_8616(
    project: Any,
    codegen: Any,
    test_insn: Any,
    jcc_mnemonic: str,
    reg_exprs: dict[tuple[int, str, int], object],
    ds_var: Any,
) -> _DecodedCmpGuard8616 | None:
    def _impl() -> _DecodedCmpGuard8616 | None:
        mnemonic = str(getattr(test_insn, "mnemonic", "")).lower()
        if mnemonic not in {"test", "or", "and"}:
            return None
        if jcc_mnemonic not in {"je", "jz", "jne", "jnz"}:
            return None
        operands = tuple(getattr(test_insn, "operands", ()) or ())
        if len(operands) != 2:
            return None
        reg_state: dict[str, object] = {}
        lhs = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            operands[0],
            reg_state,
            ds_var,
            test_insn.reg_name,
            reg_exprs,
            int(test_insn.address),
        )
        rhs = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            operands[1],
            reg_state,
            ds_var,
            test_insn.reg_name,
            reg_exprs,
            int(test_insn.address),
        )
        if lhs is None or rhs is None:
            return None
        if _same_c_expression_8616(lhs, rhs):
            tested = lhs
        else:
            tested_op = "Or" if mnemonic == "or" else "And"
            tested = CBinaryOp(tested_op, lhs, rhs, codegen=codegen)
        return _DecodedCmpGuard8616(
            lhs=tested,
            rhs=_const_8616(0, codegen),
            op="CmpEQ" if jcc_mnemonic in {"je", "jz"} else "CmpNE",
        )

    return _impl()


def _apply_cmp_state_update_8616(
    project: object,
    codegen: object,
    insn: object,
    reg_state: dict[str, object],
    stack_slots: dict[tuple[int, int], object],
    reg_exprs: dict[tuple[int, str, int], object],
    ds_var: object,
) -> None:
    def _impl() -> None:
        insn_dynamic = cast(Any, insn)
        codegen_dynamic = cast(Any, codegen)
        mnemonic = str(getattr(insn_dynamic, "mnemonic", "")).lower()
        operands = tuple(getattr(insn_dynamic, "operands", ()) or ())
        if mnemonic == "mov" and len(operands) == 2 and operands[0].type == 1 and operands[1].type == 3:
            dst_reg = insn_dynamic.reg_name(operands[0].reg).lower()
            mem = operands[1].mem
            key = (int(mem.disp), int(operands[0].size)) if insn_dynamic.reg_name(mem.base) == "bp" else None
            expr = None
            if key is not None:
                expr = _bp_operand_stack_expr_8616(codegen, key[0], key[1]) or stack_slots.get(key)
            elif mem.base:
                base_reg_name = insn_dynamic.reg_name(mem.base).lower()
                base_expr = reg_state.get(base_reg_name)
                if base_expr is not None:
                    expr = _memory_load_expr_8616(
                        project,
                        codegen,
                        ds_var,
                        base_expr,
                        int(mem.disp),
                        int(operands[0].size),
                    )
            if expr is None:
                expr = _lookup_register_expr_8616(reg_exprs, int(insn_dynamic.address), dst_reg, int(operands[0].size))
            if dst_reg == "al" and expr is not None:
                expr = _low_byte_expr_from_assignment_8616(expr)
            elif expr is None and mem.base:
                base_expr = reg_state.get(insn_dynamic.reg_name(mem.base).lower())
                if base_expr is None:
                    return
                expr = _memory_load_expr_8616(
                    project,
                    codegen,
                    ds_var,
                    base_expr,
                    int(mem.disp),
                    int(operands[0].size),
                )
            if expr is not None:
                reg_state[dst_reg] = expr
                if key is not None:
                    stack_slots.setdefault(key, expr)
            return

        if mnemonic == "mov" and len(operands) == 2 and operands[0].type == 3 and operands[1].type == 1:
            mem = operands[0].mem
            if insn_dynamic.reg_name(mem.base) != "bp":
                return
            src_reg = insn_dynamic.reg_name(operands[1].reg).lower()
            size = int(operands[1].size)
            slot_expr = _bp_operand_stack_expr_8616(codegen, int(mem.disp), size)
            if slot_expr is not None:
                stack_slots[(int(mem.disp), size)] = slot_expr
            elif reg_state.get(src_reg) is not None:
                stack_slots[(int(mem.disp), size)] = reg_state[src_reg]
            return

        if mnemonic in {"cbw", "cwde"}:
            al_expr = reg_state.get("al")
            if al_expr is None:
                reg_state.pop("ax", None)
                reg_state.pop("eax", None)
                return
            reg_state["ax"] = al_expr
            reg_state["eax"] = al_expr
            codegen_dynamic._inertia_jcc_byte_extend_materialized_8616 = (
                int(getattr(codegen, "_inertia_jcc_byte_extend_materialized_8616", 0) or 0) + 1
            )
            return

        if (
            mnemonic in {"shl", "sal"}
            and len(operands) == 2
            and operands[0].type == 1
            and operands[1].type == 2
        ):
            reg_name = insn_dynamic.reg_name(operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is not None:
                shifted = _try_build_arch_safe_binary_op_8616(
                    project, codegen, "Shl", reg_expr, _const_8616(int(operands[1].imm), codegen)
                )
                if shifted is None:
                    reg_state.pop(reg_name, None)
                    return
                reg_state[reg_name] = shifted
            else:
                reg_state.pop(reg_name, None)
            return

        if mnemonic in {"inc", "dec"} and len(operands) == 1 and operands[0].type == 1:
            reg_name = insn_dynamic.reg_name(operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is None:
                reg_state.pop(reg_name, None)
                return
            op = "Add" if mnemonic == "inc" else "Sub"
            updated = _try_build_arch_safe_binary_op_8616(project, codegen, op, reg_expr, _const_8616(1, codegen))
            if updated is None:
                reg_state.pop(reg_name, None)
                return
            reg_state[reg_name] = updated
            return

        if mnemonic in {"add", "sub"} and len(operands) == 2 and operands[0].type == 1:
            reg_name = insn_dynamic.reg_name(operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is None:
                reg_state.pop(reg_name, None)
                return
            rhs = _resolve_cmp_operand_expr_8616(
                project,
                codegen,
                operands[1],
                reg_state,
                ds_var,
                insn_dynamic.reg_name,
                reg_exprs,
                int(insn_dynamic.address),
            )
            if rhs is None:
                reg_state.pop(reg_name, None)
                return
            op = "Add" if mnemonic == "add" else "Sub"
            updated = _try_build_arch_safe_binary_op_8616(project, codegen, op, reg_expr, rhs)
            if updated is None:
                reg_state.pop(reg_name, None)
                return
            reg_state[reg_name] = updated
            return

    return _impl()


def _bind_typed_condition_register_operand_8616(
    project: Any,
    codegen: Any,
    operand: object,
    expr: object,
    reg_exprs: dict[tuple[int, str, int], object],
    ds_var: Any,
    producer_insn: int,
) -> object:
    if not isinstance(operand, IRValue) or operand.space.name != "REG" or not isinstance(operand.name, str):
        return expr
    if not _expr_is_register_8616(project, expr, operand.name):
        return expr
    bound = _stateful_register_expr_before_insn_8616(
        project,
        codegen,
        producer_insn,
        operand.name,
        max(1, int(operand.size or 2)),
        reg_exprs,
        ds_var,
    )
    return bound if bound is not None else expr


def _bind_typed_condition_expr_operands_8616(
    project: object, codegen: object, cond: ConditionIR, expr: object
) -> object:
    if not isinstance(expr, CBinaryOp):
        return expr
    producer_insn = cond.producer_insn
    if not isinstance(producer_insn, int):
        return expr
    reg_exprs = _register_exprs_by_ins_addr_8616(codegen, project)
    ds_offset = _reg_offset_8616(project, "ds")
    ds_var = CVariable(SimRegisterVariable(ds_offset, 2, name="ds"), codegen=codegen) if ds_offset is not None else None

    lhs_operand = cond.lhs
    rhs_operand = cond.rhs
    expr.lhs = _bind_typed_condition_register_operand_8616(
        project, codegen, lhs_operand, expr.lhs, reg_exprs, ds_var, producer_insn
    )
    expr.rhs = _bind_typed_condition_register_operand_8616(
        project, codegen, rhs_operand, expr.rhs, reg_exprs, ds_var, producer_insn
    )
    return expr


def _typed_condition_is_reg_const_jcc_bridge_8616(cond: ConditionIR) -> bool:
    lhs = cond.lhs
    rhs = cond.rhs
    return (
        isinstance(lhs, IRValue)
        and lhs.space.name == "REG"
        and isinstance(rhs, IRValue)
        and rhs.space.name == "CONST"
    )


def _typed_condition_bridge_expr_is_plain_variable_compare_8616(expr: object) -> bool:
    return (
        isinstance(expr, CBinaryOp)
        and isinstance(getattr(expr, "lhs", None), CVariable)
        and isinstance(getattr(expr, "rhs", None), CConstant)
    )


def _translated_typed_condition_guard_8616(
    project: object,
    codegen: object,
    block_addr: int,
    jcc_addr: int,
) -> _DecodedCmpGuard8616 | None:
    # Early ConditionIR facts are available here, but applying them in this
    # rewrite pass can still perturb whole-tail control-flow fingerprints for
    # RunMenu switch-ladder exits. Keep this disabled until structuring owns
    # the polarity/CFG proof; postprocess must not rescue it by guessing.
    return None


def _translate_cmp_jcc_guard_8616(
    project: Any, codegen: Any, block_addr: int, jcc_addr: int
) -> _DecodedCmpGuard8616 | None:
    def _impl() -> _DecodedCmpGuard8616 | None:
        debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
        typed_decoded = _translated_typed_condition_guard_8616(project, codegen, block_addr, jcc_addr)
        if typed_decoded is not None:
            if debug_jcc:
                _log.warning("[jcc-rewrite] consumed typed condition block=%#x jcc=%#x", block_addr, jcc_addr)
            return typed_decoded
        insns, jcc_index = _decode_block_and_jcc_index_8616(project, block_addr, jcc_addr, debug_jcc)
        if insns is None or jcc_index is None:
            return None
        jcc_insn = insns[jcc_index]
        jcc_mnemonic = jcc_insn.mnemonic.lower()
        mask_decoded = _decode_mask_test_guard_8616(project, codegen, jcc_mnemonic, block_addr, jcc_addr, debug_jcc)
        if mask_decoded is not None:
            return mask_decoded
        if jcc_index == 0:
            entry_carry_decoded = _decode_block_entry_carry_guard_8616(
                project,
                codegen,
                jcc_mnemonic,
            )
            if entry_carry_decoded is not None:
                return entry_carry_decoded

        cmp_insn = _nearest_flag_producer_before_jcc_8616(insns, jcc_index)
        if cmp_insn is None:
            if debug_jcc:
                _log.warning("[jcc-rewrite] no flag producer block=%#x jcc=%#x", block_addr, jcc_addr)
            return None

        if jcc_mnemonic not in _JCC_COMPARE_OPS_8616:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] unsupported jcc mnemonic=%s block=%#x jcc=%#x", jcc_mnemonic, block_addr, jcc_addr
                )
            return None
        reg_exprs = _register_exprs_by_ins_addr_8616(codegen, project)
        ds_offset = _reg_offset_8616(project, "ds")
        ds_var = (
            CVariable(SimRegisterVariable(ds_offset, 2, name="ds"), codegen=codegen) if ds_offset is not None else None
        )
        arith_decoded = _decode_inc_dec_jcc_guard_8616(project, codegen, cmp_insn, jcc_mnemonic, reg_exprs, ds_var)
        if arith_decoded is not None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] decoded arithmetic-jcc block=%#x jcc=%#x mnemonic=%s predecessor=%s",
                    block_addr,
                    jcc_addr,
                    jcc_mnemonic,
                    cmp_insn.mnemonic,
                )
            return arith_decoded
        if ds_var is None:
            if debug_jcc:
                _log.warning("[jcc-rewrite] ds reg missing block=%#x jcc=%#x", block_addr, jcc_addr)
            return None
        test_decoded = _decode_test_jcc_guard_8616(project, codegen, cmp_insn, jcc_mnemonic, reg_exprs, ds_var)
        if test_decoded is not None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] decoded test-jcc block=%#x jcc=%#x mnemonic=%s predecessor=%s",
                    block_addr,
                    jcc_addr,
                    jcc_mnemonic,
                    cmp_insn.mnemonic,
                )
            return test_decoded
        if cmp_insn.mnemonic != "cmp" or len(cmp_insn.operands) != 2:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] predecessor not cmp mnemonic=%s block=%#x jcc=%#x",
                    cmp_insn.mnemonic,
                    block_addr,
                    jcc_addr,
                )
            return None

        chain_decoded = _decode_cmp_jcc_32bit_chain_8616(project, codegen, cmp_insn, jcc_insn, reg_exprs, ds_var)
        if chain_decoded is not None:
            return chain_decoded
        reg_state: dict[str, object] = {}
        stack_slots: dict[tuple[int, int], object] = {}

        for insn in insns[:jcc_index]:
            _apply_cmp_state_update_8616(project, codegen, insn, reg_state, stack_slots, reg_exprs, ds_var)

        lhs_op = cmp_insn.operands[0]
        rhs_op = cmp_insn.operands[1]
        lhs = _resolve_cmp_operand_expr_8616(
            project, codegen, lhs_op, reg_state, ds_var, cmp_insn.reg_name, reg_exprs, int(cmp_insn.address)
        )
        rhs = _resolve_cmp_operand_expr_8616(
            project, codegen, rhs_op, reg_state, ds_var, cmp_insn.reg_name, reg_exprs, int(cmp_insn.address)
        )
        call_return_expr = _call_return_expr_before_insn_8616(project, codegen, int(cmp_insn.address))
        if call_return_expr is not None:
            lhs_reg = int(getattr(lhs_op, "type", -1)) == 1 and str(cmp_insn.reg_name(lhs_op.reg)).lower() in {
                "ax",
                "al",
                "ah",
            }
            rhs_reg = int(getattr(rhs_op, "type", -1)) == 1 and str(cmp_insn.reg_name(rhs_op.reg)).lower() in {
                "ax",
                "al",
                "ah",
            }
            if lhs_reg:
                lhs = call_return_expr
            elif rhs_reg:
                rhs = call_return_expr

        if lhs is None or rhs is None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] operand recovery failed block=%#x jcc=%#x lhs=%r rhs=%r lhs_op_type=%s rhs_op_type=%s reg_state=%r stack_slots=%r",
                    block_addr,
                    jcc_addr,
                    lhs,
                    rhs,
                    getattr(lhs_op, "type", None),
                    getattr(rhs_op, "type", None),
                    reg_state,
                    stack_slots,
                )
            return None

        op = _JCC_COMPARE_OPS_8616.get(jcc_mnemonic)
        if op is None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] op map missing mnemonic=%s block=%#x jcc=%#x", jcc_mnemonic, block_addr, jcc_addr
                )
            return None
        if debug_jcc:
            reg_state_fp = {}
            stack_slots_fp = {}
            for key, value in reg_state.items():
                try:
                    reg_state_fp[key] = _expr_fingerprint(value, project)
                except Exception:
                    reg_state_fp[key] = repr(value)
            for slot_key, slot_value in stack_slots.items():
                try:
                    stack_slots_fp[slot_key] = _expr_fingerprint(slot_value, project)
                except Exception:
                    stack_slots_fp[slot_key] = repr(slot_value)
            _log.warning(
                "[jcc-rewrite] decoded block=%#x jcc=%#x mnemonic=%s op=%s lhs=%r rhs=%r reg_state=%r stack_slots=%r reg_state_fp=%r stack_slots_fp=%r",
                block_addr,
                jcc_addr,
                jcc_mnemonic,
                op,
                lhs,
                rhs,
                reg_state,
                stack_slots,
                reg_state_fp,
                stack_slots_fp,
            )
        return _DecodedCmpGuard8616(lhs=lhs, rhs=rhs, op=op)

    return _impl()


def _rewrite_decoded_jcc_conditions_8616(project: object, codegen: object) -> bool:
    def _impl() -> bool:
        codegen_dynamic = cast(Any, codegen)
        cfunc = getattr(codegen_dynamic, "cfunc", None)
        if cfunc is None:
            return False
        flags_offset = _reg_offset_8616(project, "flags")
        if flags_offset is None:
            return False
        project_dynamic = cast(Any, project)

        changed = False
        materialized_count = 0
        key_signature_plan: dict[tuple[int, int], tuple[Any, ...]] = {}
        key_decoded_plan: dict[tuple[int, int], _DecodedCmpGuard8616] = {}
        key_conflicts: set[tuple[int, int]] = set()
        unknown_polarity_refused_keys: set[tuple[int, int]] = set()
        raw_state_refused_keys: set[tuple[int, int]] = set()
        consumed_wide_compare_low_branch_keys: set[tuple[int, int]] = {
            key
            for key in tuple(getattr(codegen, "_inertia_jcc_consumed_32bit_low_guard_keys_8616", ()) or ())
            if isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], int) and isinstance(key[1], int)
        }

        def _record_consumed_decoded_guard_keys_8616(decoded: _DecodedCmpGuard8616) -> None:
            if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")) and decoded.consumed_branch_keys:
                _log.warning("[jcc-rewrite] record consumed branch keys=%r", decoded.consumed_branch_keys)
            for key in decoded.consumed_branch_keys:
                if not (
                    isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], int) and isinstance(key[1], int)
                ):
                    continue
                consumed_wide_compare_low_branch_keys.add(key)
            if consumed_wide_compare_low_branch_keys:
                codegen_dynamic._inertia_jcc_consumed_32bit_low_guard_keys_8616 = tuple(
                    sorted(consumed_wide_compare_low_branch_keys)
                )

        def _is_literal_condition_8616(expr: object) -> bool:
            node = expr
            while isinstance(node, CTypeCast):
                node = node.expr
            if isinstance(node, CConstant):
                return isinstance(node.value, int)
            return False

        def _is_tagged_condition_carrier_8616(expr: object) -> bool:
            seen: set[int] = set()

            def _walk(node: object) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CITE):
                    return True
                if isinstance(node, CBinaryOp):
                    return _walk(node.lhs) or _walk(node.rhs)
                if isinstance(node, CUnaryOp):
                    return _walk(node.operand)
                if isinstance(node, CTypeCast):
                    return _walk(node.expr)
                cond = getattr(node, "cond", None)
                if cond is not None and _walk(cond):
                    return True
                expr = getattr(node, "expr", None)
                return bool(expr is not None and _walk(expr))

            return _walk(expr)

        def _expr_uses_nonsegment_register_carrier_8616(expr: Any) -> bool:
            seen: set[int] = set()
            segment_offsets = {
                offset
                for name, (offset, _size) in getattr(project_dynamic.arch, "registers", {}).items()
                if name.lower() in {"cs", "ds", "es", "ss"}
            }

            def _walk(node: object) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CVariable):
                    variable = node.variable
                    if isinstance(variable, SimRegisterVariable):
                        return int(variable.reg) not in segment_offsets
                if isinstance(node, CBinaryOp):
                    return _walk(node.lhs) or _walk(node.rhs)
                if isinstance(node, CUnaryOp):
                    return _walk(node.operand)
                if isinstance(node, CTypeCast):
                    return _walk(node.expr)
                for attr in ("expr", "condition", "cond", "lhs", "rhs"):
                    child = getattr(node, attr, None)
                    if child is not None and _walk(child):
                        return True
                args = getattr(node, "args", None)
                if isinstance(args, (list, tuple)):
                    return any(_walk(arg) for arg in args)
                return False

            return _walk(expr)

        def _has_materialized_nonflag_cmp_8616(expr: object) -> bool:
            seen: set[int] = set()

            def _walk(node: object) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CBinaryOp):
                    op = node.op
                    if isinstance(op, str) and op.startswith("Cmp"):  # noqa: SIM102
                        if not _c_expr_uses_register_8616(node, flags_offset):
                            return not _expr_uses_nonsegment_register_carrier_8616(node)
                    return _walk(node.lhs) or _walk(node.rhs)
                if isinstance(node, CUnaryOp):
                    return _walk(node.operand)
                cond = getattr(node, "cond", None)
                if cond is not None:
                    return _walk(cond)
                return False

            return _walk(expr)

        def _arg_stack_offsets_8616() -> set[int]:
            cfunc = getattr(codegen, "cfunc", None)
            arg_offsets: set[int] = set()
            arg_list = tuple(getattr(cfunc, "arg_list", ()) or ())
            for arg in arg_list:
                variable = getattr(arg, "variable", None)
                if isinstance(variable, SimStackVariable):
                    arg_offsets.add(int(variable.offset or 0))
            variables_in_use = getattr(cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                for variable, cvar in tuple(variables_in_use.items()):
                    if not isinstance(variable, SimStackVariable):
                        continue
                    offset = int(variable.offset or 0)
                    if offset <= 0:
                        continue
                    cvar_name = getattr(cvar, "name", None)
                    var_name = variable.name
                    for name in (cvar_name, var_name):
                        if not isinstance(name, str):
                            continue
                        name = name.strip()
                        if not name or name.startswith(("tmp_", "vvar_", "ir_")):
                            break
                        arg_offsets.add(offset)
                        break
            unified_locals = getattr(cfunc, "unified_local_vars", None)
            if isinstance(unified_locals, dict):
                for cvars in unified_locals.values():
                    for item in tuple(cvars or ()):
                        if not isinstance(item, tuple) or not item:
                            continue
                        candidate = item[0]
                        variable = getattr(candidate, "variable", None)
                        if not isinstance(variable, SimStackVariable):
                            continue
                        offset = int(variable.offset or 0)
                        if offset <= 0:
                            continue
                        name = variable.name
                        if not isinstance(name, str):
                            continue
                        name = name.strip()
                        if name.startswith(("tmp_", "vvar_", "ir_")):
                            continue
                        arg_offsets.add(offset)
            return arg_offsets

        _arg_stack_offsets = _arg_stack_offsets_8616()

        def _expr_uses_nonarg_bp_positive_stack_slot_8616(expr: object) -> bool:
            seen: set[int] = set()

            def _walk(node: object) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CVariable):
                    variable = node.variable
                    if isinstance(variable, SimStackVariable):
                        offset = int(variable.offset or 0)
                        if offset >= 0 and offset not in _arg_stack_offsets:
                            return True
                if isinstance(node, CBinaryOp):
                    return _walk(node.lhs) or _walk(node.rhs)
                if isinstance(node, CUnaryOp):
                    return _walk(node.operand)
                if isinstance(node, CTypeCast):
                    return _walk(node.expr)
                for attr in ("expr", "condition", "cond"):
                    child = getattr(node, attr, None)
                    if child is not None and _walk(child):
                        return True
                return False

            return _walk(expr)

        def _expr_uses_unstable_positive_stack_arg_placeholder_8616(expr: object) -> bool:
            seen: set[int] = set()

            def _walk(node: object) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CVariable):
                    variable = node.variable
                    if isinstance(variable, SimStackVariable):
                        offset = int(variable.offset or 0)
                        if offset >= 0:
                            names = (
                                node.name,
                                variable.name,
                                getattr(node.unified_variable, "name", None),
                            )
                            if any(_is_unstable_stack_arg_name_8616(name) for name in names):
                                return True
                if isinstance(node, CBinaryOp):
                    return _walk(node.lhs) or _walk(node.rhs)
                if isinstance(node, CUnaryOp):
                    return _walk(node.operand)
                if isinstance(node, CTypeCast):
                    return _walk(node.expr)
                for attr in ("expr", "condition", "cond"):
                    child = getattr(node, attr, None)
                    if child is not None and _walk(child):
                        return True
                return False

            return _walk(expr)

        def _safe_fingerprint_8616(expr: object) -> tuple[str, str]:
            try:
                value = _expr_fingerprint(expr, project)
            except Exception:  # pragma: no cover - platform-specific fingerprints
                value = repr(expr)
            return (str(type(expr).__name__), repr(value))

        def _validation_fingerprint_8616(expr: object) -> str:
            try:
                return str(_expr_fingerprint(expr, project))
            except Exception:  # pragma: no cover - platform-specific fingerprints
                return repr(expr)

        def _record_jcc_validation_evidence_8616(before_expr: Any, after_expr: Any) -> None:
            before_fp = _validation_fingerprint_8616(before_expr)
            after_fp = _validation_fingerprint_8616(after_expr)
            if not before_fp or not after_fp or before_fp == after_fp:
                return
            evidence: list[dict[str, str]] = list(
                getattr(codegen, "_inertia_jcc_condition_validation_evidence_8616", ()) or ()
            )
            evidence.append(
                {
                    "removed": before_fp,
                    "added": after_fp,
                }
            )
            codegen_dynamic._inertia_jcc_condition_validation_evidence_8616 = tuple(evidence)

        def _record_jcc_decoded_condition_fingerprint_8616(expr: Any) -> None:
            fingerprint = _validation_fingerprint_8616(expr)
            if not fingerprint:
                return
            existing = tuple(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ())
            if fingerprint not in existing:
                codegen_dynamic._inertia_jcc_decoded_condition_fingerprint_evidence_count_8616 = (
                    int(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprint_evidence_count_8616", 0) or 0) + 1
                )
            codegen_dynamic._inertia_jcc_decoded_condition_fingerprints_8616 = tuple(
                dict.fromkeys((*existing, fingerprint))
            )

        def _record_decoded_guard_fingerprint_8616(decoded: _DecodedCmpGuard8616) -> None:
            expr = decoded.expr
            if expr is None:
                expr = _try_build_arch_safe_binary_op_8616(
                    project,
                    codegen,
                    decoded.op,
                    decoded.lhs,
                    decoded.rhs,
                )
                if expr is None:
                    codegen_dynamic._inertia_jcc_rewrite_refused_archless_type_fingerprint_8616 = (
                        int(getattr(codegen, "_inertia_jcc_rewrite_refused_archless_type_fingerprint_8616", 0) or 0) + 1
                    )
                    return
            _record_jcc_decoded_condition_fingerprint_8616(expr)

        def _const_bool_value_8616(expr: object) -> int | None:
            node = expr
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            if isinstance(node, CConstant) and int(getattr(node, "value", -1)) in {0, 1}:
                return int(node.value)
            return None

        def _condition_inverts_decoded_guard_8616(expr: object) -> bool:
            if isinstance(expr, CUnaryOp) and getattr(expr, "op", None) == "Not":
                return not _condition_inverts_decoded_guard_8616(expr.operand)
            if isinstance(expr, CITE):
                iftrue = _const_bool_value_8616(expr.iftrue)
                iffalse = _const_bool_value_8616(expr.iffalse)
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning(
                        "[jcc-rewrite] cite polarity iftrue=%r iffalse=%r inverts=%s",
                        iftrue,
                        iffalse,
                        (iftrue, iffalse) == (0, 1),
                    )
                if (iftrue, iffalse) == (0, 1):
                    return True
                if (iftrue, iffalse) == (1, 0):
                    return False
            return False

        def _condition_is_direct_inverting_cite_8616(expr: object) -> bool:
            if not isinstance(expr, CITE):
                return False
            iftrue = _const_bool_value_8616(expr.iftrue)
            iffalse = _const_bool_value_8616(expr.iffalse)
            return (iftrue, iffalse) == (0, 1)

        def _decoded_guard_contains_real_call_8616(decoded: _DecodedCmpGuard8616) -> bool:
            roots = (decoded.expr,) if decoded.expr is not None else (decoded.lhs, decoded.rhs)
            for root in roots:
                for child in _iter_c_nodes_deep_8616(root):
                    if not isinstance(child, CFunctionCall):
                        continue
                    callee = child.callee_target
                    if isinstance(callee, str) and callee in {
                        "SEG_PTR",
                        "MK_FP",
                        "SEG_U8",
                        "SEG_U16",
                        "SEG_U32",
                        "MEM_U8",
                        "MEM_U16",
                        "MEM_U32",
                    }:
                        continue
                    return True
            return False

        def _decoded_guard_uses_raw_state_register_8616(decoded: _DecodedCmpGuard8616) -> bool:
            raw_register_names = {"flags", "eflags", "sp"}
            raw_register_offsets = {
                offset
                for offset in (
                    _reg_offset_8616(project, "flags"),
                    _reg_offset_8616(project, "eflags"),
                    _reg_offset_8616(project, "sp"),
                )
                if isinstance(offset, int)
            }
            roots = (decoded.expr,) if decoded.expr is not None else (decoded.lhs, decoded.rhs)
            for root in roots:
                for child in _iter_c_nodes_deep_8616(root):
                    if not isinstance(child, CVariable):
                        continue
                    variable = child.variable
                    names = {
                        str(name).lower()
                        for name in (
                            child.name,
                            getattr(variable, "name", None),
                            getattr(child.unified_variable, "name", None),
                        )
                        if isinstance(name, str) and name
                    }
                    if names & raw_register_names:
                        return True
                    if isinstance(variable, SimRegisterVariable):
                        reg = variable.reg
                        if isinstance(reg, int) and reg in raw_register_offsets:
                            return True
            return False

        def _invert_decoded_guard_8616(
            decoded: _DecodedCmpGuard8616, tags: object
        ) -> _DecodedCmpGuard8616:
            if decoded.expr is not None:
                return _DecodedCmpGuard8616(
                    lhs=None,
                    rhs=None,
                    op=decoded.op,
                    expr=CUnaryOp("Not", cast(Any, decoded.expr), codegen=codegen, tags=tags),
                    consumed_branch_keys=decoded.consumed_branch_keys,
                )
            inverted_op = _INVERT_CMP_OP_8616.get(decoded.op)
            if inverted_op is not None and not _decoded_guard_contains_real_call_8616(decoded):
                return _DecodedCmpGuard8616(
                    lhs=decoded.lhs,
                    rhs=decoded.rhs,
                    op=inverted_op,
                    expr=None,
                    consumed_branch_keys=decoded.consumed_branch_keys,
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op=decoded.op,
                expr=CUnaryOp(
                    "Not",
                    CBinaryOp(decoded.op, decoded.lhs, decoded.rhs, codegen=codegen, tags=tags),
                    codegen=codegen,
                    tags=tags,
                ),
                consumed_branch_keys=decoded.consumed_branch_keys,
            )

        def _jcc_target_for_key_8616(key: tuple[int, int] | None) -> int | None:
            if not isinstance(key, tuple) or len(key) != 2:
                return None
            ins_addr, block_addr = key
            if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
                return None
            decoded = _decode_block_and_jcc_index_8616(project, block_addr, ins_addr, False)
            insns, jcc_index = decoded
            if insns is None or jcc_index is None:
                return None
            if jcc_index < 0 or jcc_index >= len(insns):
                return None
            return _branch_target_imm_8616(insns[jcc_index])

        def _root_contains_ins_addr_8616(
            root: object, target_addr: int, *, max_forward_bytes: int = 0
        ) -> bool:
            if root is None:
                return False
            pending = [root]
            seen: set[int] = set()
            while pending:
                current = pending.pop()
                if current is None:
                    continue
                if isinstance(current, (list, tuple)):
                    pending.extend(reversed(tuple(current)))
                    continue
                marker = id(current)
                if marker in seen:
                    continue
                seen.add(marker)
                tags = getattr(current, "tags", None)
                if isinstance(tags, dict):
                    ins_addr = tags.get("ins_addr")
                    if ins_addr == target_addr:
                        return True
                    if (
                        isinstance(ins_addr, int)
                        and max_forward_bytes > 0
                        and int(target_addr) <= ins_addr <= int(target_addr) + int(max_forward_bytes)
                    ):
                        return True
                stmts = getattr(current, "statements", None)
                if stmts is not None:
                    pending.extend(reversed(tuple(stmts or ())))
                    continue
                for attr in ("condition_and_nodes", "body", "else_node", "iftrue", "iffalse"):
                    child = getattr(current, attr, None)
                    if child is None:
                        continue
                    if attr == "condition_and_nodes" and isinstance(child, (list, tuple)):
                        for _cond, body in reversed(tuple(child)):
                            pending.append(body)
                    else:
                        pending.append(child)
            return False

        def _jcc_polarity_evidence_8616(
            key: tuple[int, int] | None, body: object
        ) -> _JccPolarityEvidence8616:
            target = _jcc_target_for_key_8616(key)
            if isinstance(target, int) and _root_contains_ins_addr_8616(body, target, max_forward_bytes=0):
                return _JccPolarityEvidence8616.JCC_TARGET_BODY
            return _JccPolarityEvidence8616.UNKNOWN

        def _body_is_break_only_8616(body: object) -> bool:
            if body is None:
                return False
            if isinstance(body, (CBreak, CReturn)):
                return True
            statements = getattr(body, "statements", None)
            if statements is None:
                return False
            if type(statements).__name__ == "CStatements":
                statements = getattr(statements, "statements", None)
            items = tuple(statements or ())
            return len(items) == 1 and isinstance(items[0], (CBreak, CReturn))

        def _condition_exprs_from_stmt_8616(stmt: object) -> Iterator[object]:
            cond_pairs = getattr(stmt, "condition_and_nodes", None)
            if isinstance(cond_pairs, (list, tuple)):
                for cond, _body in tuple(cond_pairs):
                    if cond is not None:
                        yield cond
            cond = getattr(stmt, "condition", None)
            if cond is not None:
                yield cond

        def _child_statement_roots_8616(stmt: object) -> Iterator[object]:
            for attr in ("body", "else_node", "iftrue", "iffalse", "initializer", "iterator"):
                child = getattr(stmt, attr, None)
                if child is not None:
                    yield child
            cond_pairs = getattr(stmt, "condition_and_nodes", None)
            if isinstance(cond_pairs, (list, tuple)):
                for _cond, body in tuple(cond_pairs):
                    if body is not None:
                        yield body
            cases = getattr(stmt, "cases", None)
            if isinstance(cases, dict):
                yield from cases.values()
            default = getattr(stmt, "default", None)
            if default is not None:
                yield default

        def _statements_from_root_8616(root: object) -> tuple[object, ...]:
            if root is None:
                return ()
            stmts = getattr(root, "statements", None)
            if stmts is not None:
                if type(stmts).__name__ == "CStatements":
                    stmts = getattr(stmts, "statements", None)
                raw_stmts = (stmts,) if _structured_codegen_node_8616(stmts) else tuple(stmts or ())
                flattened: list[object] = []
                for stmt in raw_stmts:
                    if type(stmt).__name__ == "CStatements":
                        nested = getattr(stmt, "statements", None)
                        if nested is not None:
                            flattened.extend(tuple(nested or ()))
                            continue
                    flattened.append(stmt)
                return tuple(flattened)
            if isinstance(root, (list, tuple)):
                flattened_list: list[object] = []
                for stmt in root:
                    if type(stmt).__name__ == "CStatements":
                        nested = getattr(stmt, "statements", None)
                        if nested is not None:
                            flattened_list.extend(tuple(nested or ()))
                            continue
                    flattened_list.append(stmt)
                return tuple(flattened_list)
            return ()

        def _assignment_rhs_has_real_call_8616(stmt: object) -> bool:
            if not isinstance(stmt, CAssignment):
                return False
            rhs = stmt.rhs
            if rhs is None:
                return False
            for child in _iter_c_nodes_deep_8616(rhs):
                if not isinstance(child, CFunctionCall):
                    continue
                callee = child.callee_target
                if isinstance(callee, str) and callee in {
                    "SEG_PTR",
                    "MK_FP",
                    "SEG_U8",
                    "SEG_U16",
                    "SEG_U32",
                    "MEM_U8",
                    "MEM_U16",
                    "MEM_U32",
                }:
                    continue
                return True
            return False

        def _call_return_guard_sources_by_key_8616() -> dict[tuple[int, int], object]:
            sources: dict[tuple[int, int], object] = {}
            conflicts: set[tuple[int, int]] = set()
            seen_roots: set[int] = set()
            debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
            debug_stats = {"blocks": 0, "stmts": 0, "assignments": 0, "callish": 0, "conditions_after_assign": 0}
            debug_stmt_types: dict[str, int] = {}

            def _record(cond: object, source: object) -> None:
                key = _condition_tags_8616(cond)
                if not isinstance(key, tuple) or key in conflicts:
                    return
                previous = sources.get(key)
                if previous is None:
                    sources[key] = source
                    return
                if _safe_fingerprint_8616(previous) != _safe_fingerprint_8616(source):
                    conflicts.add(key)
                    sources.pop(key, None)

            def _walk_block(root: object) -> None:
                root_id = id(root)
                if root_id in seen_roots:
                    return
                seen_roots.add(root_id)
                debug_stats["blocks"] += 1
                last_call_lhs = None
                for stmt in _statements_from_root_8616(root):
                    debug_stats["stmts"] += 1
                    stmt_type = type(stmt).__name__
                    debug_stmt_types[stmt_type] = debug_stmt_types.get(stmt_type, 0) + 1
                    if isinstance(stmt, CAssignment):
                        debug_stats["assignments"] += 1
                    if _assignment_rhs_has_real_call_8616(stmt):
                        debug_stats["callish"] += 1
                        lhs = getattr(stmt, "lhs", None)
                        last_call_lhs = lhs
                        continue
                    if last_call_lhs is not None:
                        for cond in _condition_exprs_from_stmt_8616(stmt):
                            debug_stats["conditions_after_assign"] += 1
                            _record(cond, last_call_lhs)
                    for child in _child_statement_roots_8616(stmt):
                        _walk_block(child)
                    last_call_lhs = None

            _walk_block(cfunc)
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] call-return guard sources=%d conflicts=%d stats=%r",
                    len(sources),
                    len(conflicts),
                    {**debug_stats, "types": debug_stmt_types},
                )
            return sources

        call_return_guard_sources = _call_return_guard_sources_by_key_8616()

        def _expr_is_return_register_8616(expr: object) -> bool:
            node = expr
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            if not isinstance(node, CVariable):
                return False
            variable = node.variable
            if not isinstance(variable, SimRegisterVariable):
                return False
            ax_offset = _reg_offset_8616(project, "ax")
            if ax_offset is None:
                return False
            return int(variable.reg) == int(ax_offset)

        def _rebind_adjacent_call_return_register_conditions_8616() -> bool:
            local_changed = False
            local_count = 0
            seen_roots: set[int] = set()

            def _replace_return_register_reads_8616(cond: Any, source: Any) -> Any:
                nonlocal local_changed, local_count
                if cond is None or source is None:
                    return cond
                if _expr_is_return_register_8616(cond):
                    local_changed = True
                    local_count += 1
                    return source
                if not _structured_codegen_node_8616(cond):
                    return cond

                def _replace_child(child: Any) -> Any:
                    nonlocal local_changed, local_count
                    if _expr_is_return_register_8616(child):
                        local_changed = True
                        local_count += 1
                        return source
                    return child

                if _replace_c_children_8616(cond, _replace_child):
                    local_changed = True
                return cond

            def _replace_stmt_conditions_8616(stmt: Any, source: Any) -> bool:
                before_count = local_count
                cond_pairs = getattr(stmt, "condition_and_nodes", None)
                if isinstance(cond_pairs, (list, tuple)):
                    pair_changed = False
                    new_pairs = []
                    for cond, body in tuple(cond_pairs):
                        new_cond = _replace_return_register_reads_8616(cond, source)
                        pair_changed = pair_changed or new_cond is not cond
                        new_pairs.append((new_cond, body))
                    if pair_changed:
                        stmt.condition_and_nodes = type(cond_pairs)(new_pairs)
                if hasattr(stmt, "condition"):
                    cond = getattr(stmt, "condition", None)
                    new_cond = _replace_return_register_reads_8616(cond, source)
                    if new_cond is not cond:
                        stmt.condition = new_cond
                return local_count != before_count

            def _walk_block(root: object) -> None:
                root_id = id(root)
                if root_id in seen_roots:
                    return
                seen_roots.add(root_id)
                last_call_lhs = None
                for stmt in _statements_from_root_8616(root):
                    if isinstance(stmt, CAssignment) and _assignment_rhs_has_real_call_8616(stmt):
                        last_call_lhs = stmt.lhs
                        continue
                    if last_call_lhs is not None:
                        _replace_stmt_conditions_8616(stmt, last_call_lhs)
                        last_call_lhs = None
                    for child in _child_statement_roots_8616(stmt):
                        _walk_block(child)

            _walk_block(cfunc)
            if local_count:
                with contextlib.suppress(Exception):
                    codegen_dynamic._inertia_jcc_call_return_register_rebindings = (
                        int(getattr(codegen, "_inertia_jcc_call_return_register_rebindings", 0) or 0) + local_count
                    )
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning("[jcc-rewrite] rebound adjacent call-return register reads count=%d", local_count)
            return local_changed

        def _expr_is_stale_literal_8616(expr: object) -> bool:
            node = expr
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            return isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int)

        def _rebind_decoded_call_return_guard_8616(
            key: tuple[int, int] | None, decoded: _DecodedCmpGuard8616
        ) -> _DecodedCmpGuard8616:
            source = call_return_guard_sources.get(key) if key is not None else None
            if source is None or decoded.expr is not None:
                return decoded
            lhs = decoded.lhs
            rhs = decoded.rhs
            rebound = False
            if _expr_is_return_register_8616(lhs) or _expr_is_stale_literal_8616(lhs):
                lhs = source
                rebound = True
            elif _expr_is_return_register_8616(rhs):
                rhs = source
                rebound = True
            if not rebound:
                return decoded
            with contextlib.suppress(Exception):
                codegen_dynamic._inertia_jcc_call_return_rebindings = (
                    int(getattr(codegen, "_inertia_jcc_call_return_rebindings", 0) or 0) + 1
                )
            if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                _log.warning("[jcc-rewrite] rebound call-return guard key=%r source=%r", key, source)
            return _DecodedCmpGuard8616(
                lhs=lhs,
                rhs=rhs,
                op=decoded.op,
                expr=None,
                consumed_branch_keys=decoded.consumed_branch_keys,
            )

        def _decoded_signature_8616(decoded: _DecodedCmpGuard8616) -> tuple[object, ...]:
            if decoded.expr is not None:
                return ("expr", decoded.op, *_safe_fingerprint_8616(decoded.expr))
            return ("cmp", decoded.op, *_safe_fingerprint_8616(decoded.lhs), *_safe_fingerprint_8616(decoded.rhs))

        def _collect_decoded_signature_8616(cond: object) -> None:
            key = _condition_tags_8616(cond)
            if not isinstance(key, tuple):
                return
            ins_addr = key[0]
            block_addr = key[1]
            if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
                return
            decoded = _decode_condition_from_tags_8616(cond, block_addr, ins_addr)
            if decoded is None:
                return
            signature = _decoded_signature_8616(decoded)
            previous = key_signature_plan.get(key)
            if previous is None:
                key_signature_plan[key] = signature
                key_decoded_plan[key] = decoded
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning("[jcc-rewrite] key plan set key=%r signature=%r", key, signature)
                return
            if previous != signature and key not in key_conflicts:
                key_conflicts.add(key)
                key_signature_plan.pop(key, None)
                key_decoded_plan.pop(key, None)
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning(
                        "[jcc-rewrite] key conflict key=%r signature_mismatch=%r prev=%r new=%r",
                        key,
                        key_signature_plan,
                        previous,
                        signature,
                    )

        def _iter_guard_conditions_8616() -> Iterator[Any]:
            seen_conditions: set[int] = set()
            for stmt in _statements_from_root_8616(cfunc):
                for node in _iter_c_nodes_deep_8616(stmt):
                    cond_pairs = getattr(node, "condition_and_nodes", None)
                    if isinstance(cond_pairs, (list, tuple)):
                        for cond, _body in tuple(cond_pairs):
                            if cond is None:
                                continue
                            marker = id(cond)
                            if marker in seen_conditions:
                                continue
                            seen_conditions.add(marker)
                            yield cond
                    cond = getattr(node, "condition", None)
                    if cond is None:
                        continue
                    marker = id(cond)
                    if marker in seen_conditions:
                        continue
                    seen_conditions.add(marker)
                    yield cond

        def _decode_condition_from_tags_8616(
            cond: object, block_addr: int, ins_addr: int
        ) -> _DecodedCmpGuard8616 | None:
            # Primary lane: flags-backed conditions.
            # Recovery lane: conditions that already collapsed to a literal constant
            # but still carry insn/block tags for a decodable cmp+jcc origin.
            tagged_key = _condition_tags_8616(cond)
            debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
            has_raw_register_carrier = _expr_uses_nonsegment_register_carrier_8616(cond)
            has_carrier_evidence = (
                _c_expr_uses_register_8616(cond, flags_offset)
                or _is_literal_condition_8616(cond)
                or _is_tagged_condition_carrier_8616(cond)
                or _has_materialized_nonflag_cmp_8616(cond)
                or has_raw_register_carrier
            )
            if not (has_carrier_evidence):
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] decode skip no-evidence key=%r tagged_key=%r cond_type=%s",
                        (ins_addr, block_addr),
                        tagged_key,
                        type(cond).__name__,
                    )
                return None

            decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
            if decoded is None:
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip no-decoded key=%r", (ins_addr, block_addr))
                return None

            if decoded.expr is not None:
                return decoded

            same_expr = _same_c_expression_8616(decoded.lhs, decoded.rhs)
            lhs_fp = _safe_fingerprint_8616(decoded.lhs)
            rhs_fp = _safe_fingerprint_8616(decoded.rhs)
            if same_expr or lhs_fp == rhs_fp:
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] decode skip same-operands key=%r lhs_fp=%r rhs_fp=%r",
                        (ins_addr, block_addr),
                        lhs_fp,
                        rhs_fp,
                    )
                return None

            # Safety guard: avoid rewriting via decoded jcc when compare operands
            # depend on BP+positive stack slots (arg/return area). This pattern is
            # frequently ambiguous in 16-bit lifted state and can introduce false
            # loop predicates.
            if _expr_uses_nonarg_bp_positive_stack_slot_8616(
                decoded.lhs
            ) or _expr_uses_nonarg_bp_positive_stack_slot_8616(decoded.rhs):
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] decode skip positive-stack-slot key=%r lhs_fp=%r rhs_fp=%r",
                        (ins_addr, block_addr),
                        lhs_fp,
                        rhs_fp,
                    )
                return None

            if has_raw_register_carrier and not _decoded_guard_uses_raw_state_register_8616(decoded):
                    codegen_dynamic._inertia_jcc_raw_register_condition_carrier_decoded_8616 = (
                        int(getattr(codegen, "_inertia_jcc_raw_register_condition_carrier_decoded_8616", 0) or 0) + 1
                    )

            # Guardrail: once a condition is an explicit non-flag comparison,
            # treat it as materialized. Exception: a compare sourced from an
            # unstable positive BP placeholder is weaker evidence than a decoded
            # JCC guard whose operands are stable BP-local stack slots.
            if _has_materialized_nonflag_cmp_8616(cond) and not _c_expr_uses_register_8616(
                cond,
                flags_offset,
            ):
                if not _expr_uses_unstable_positive_stack_arg_placeholder_8616(cond):
                    if not _decoded_guard_uses_raw_state_register_8616(decoded):
                        _record_decoded_guard_fingerprint_8616(decoded)
                        codegen_dynamic._inertia_jcc_rewrite_kept_explicit_cmp_with_decoded_evidence_8616 = (
                            int(
                                getattr(
                                    codegen,
                                    "_inertia_jcc_rewrite_kept_explicit_cmp_with_decoded_evidence_8616",
                                    0,
                                )
                                or 0
                            )
                            + 1
                        )
                    if debug_jcc:
                        _log.warning("[jcc-rewrite] decode skip explicit-cmp key=%r", (ins_addr, block_addr))
                    return None
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] replacing unstable explicit stack-arg cmp key=%r",
                        (ins_addr, block_addr),
                    )

            return decoded

        def _build_rewrite_8616(
            cond: object,
            decoded: _DecodedCmpGuard8616,
            key: tuple[int, int] | None,
            *,
            polarity_evidence: _JccPolarityEvidence8616 = _JccPolarityEvidence8616.UNKNOWN,
        ) -> object | None:
            """Publish a decoded guard with its original branch provenance."""
            decoded = _rebind_decoded_call_return_guard_8616(key, decoded)
            raw_tags = getattr(cond, "tags", None)
            tags: dict[str, object] = dict(raw_tags) if isinstance(raw_tags, dict) else {}
            if isinstance(key, tuple) and len(key) == 2:
                ins_addr, block_addr = key
                if isinstance(ins_addr, int) and isinstance(block_addr, int):
                    tags.setdefault("ins_addr", ins_addr)
                    tags.setdefault("vex_block_addr", block_addr)
            tags["inertia_jcc_materialized_8616"] = True
            tags["inertia_jcc_polarity_evidence_8616"] = polarity_evidence.value
            invert_guard = _condition_inverts_decoded_guard_8616(cond)
            if polarity_evidence is _JccPolarityEvidence8616.JCC_TARGET_BODY:
                invert_guard = False
            elif polarity_evidence is _JccPolarityEvidence8616.JCC_TARGET_FOLLOWING_SIBLING:
                invert_guard = True
            if invert_guard:
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning(
                        "[jcc-rewrite] applying decoded guard polarity inversion key=%r op=%s evidence=%s",
                        key,
                        decoded.op,
                        polarity_evidence.value,
                    )
                decoded = _invert_decoded_guard_8616(decoded, tags)
            if decoded.expr is not None:
                # A replacement denotes the branch, not its operand producer.
                expression_tags = getattr(decoded.expr, "tags", None)
                cast(Any, decoded.expr).tags = {
                    **(expression_tags if isinstance(expression_tags, dict) else {}), **tags,
                }
                _record_consumed_decoded_guard_keys_8616(decoded)
                return decoded.expr
            replacement = _try_build_arch_safe_binary_op_8616(
                project,
                codegen,
                decoded.op,
                decoded.lhs,
                decoded.rhs,
                tags=tags,
            )
            if replacement is None:
                codegen_dynamic._inertia_jcc_rewrite_refused_archless_type_replacement_8616 = (
                    int(getattr(codegen, "_inertia_jcc_rewrite_refused_archless_type_replacement_8616", 0) or 0) + 1
                )
            else:
                _record_consumed_decoded_guard_keys_8616(decoded)
            return replacement

        def _decoded_condition_replacement(
            cond: object,
            *,
            body: object | None = None,
            polarity_evidence: _JccPolarityEvidence8616 | None = None,
        ) -> object | None:
            from .structuring.condition_ownership import requires_composite_condition_ownership_8616

            if requires_composite_condition_ownership_8616(cond):
                return None
            if classify_condition_call_effects_8616(cond).has_semantic_call:
                return None
            key = _condition_tags_8616(cond)
            ins_addr = None if key is None else key[0]
            block_addr = None if key is None else key[1]
            debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] candidate key=%r uses_flags=%s cond_type=%s cond_op=%s",
                    key,
                    _c_expr_uses_register_8616(cond, flags_offset)  # noqa: RUF034
                    if isinstance(ins_addr, int) and isinstance(block_addr, int)
                    else _c_expr_uses_register_8616(cond, flags_offset),
                    type(cond).__name__ if cond is not None else None,
                    getattr(cond, "op", None),
                )
            if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
                return None
            if (
                isinstance(cond, CBinaryOp)
                and str(getattr(cond, "op", "")).startswith("Cmp")
                and not _c_expr_uses_register_8616(cond, flags_offset)
                and any(
                    isinstance(child, CBinaryOp) and getattr(child, "op", None) == "And"
                    for child in _iter_c_nodes_deep_8616(cond)
                )
            ):
                return None
            narrowed_key = key if key is not None else None
            if narrowed_key is None:
                return None
            if narrowed_key in key_conflicts:
                if debug_jcc:
                    _log.warning("[jcc-rewrite] key conflict detected key=%r skip", key)
                return None
            if polarity_evidence is None:
                polarity_evidence = _jcc_polarity_evidence_8616(narrowed_key, body)
            decoded = key_decoded_plan.get(narrowed_key)
            if decoded is None:
                decoded = _decode_condition_from_tags_8616(cond, block_addr, ins_addr)
            if decoded is None:
                return None
            planned_signature = key_signature_plan.get(narrowed_key)
            if planned_signature is None:
                return None
            signature = _decoded_signature_8616(decoded)
            if signature != planned_signature:
                key_conflicts.add(narrowed_key)
                key_signature_plan.pop(narrowed_key, None)
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] signature mismatch key=%r signature=%r planned=%r",
                        key,
                        signature,
                        planned_signature,
                    )
                return None
            if (
                _decoded_guard_uses_raw_state_register_8616(decoded)
                and not decoded.status_output_proven
            ):
                should_count_refusal = True
                if isinstance(key, tuple):
                    should_count_refusal = narrowed_key not in raw_state_refused_keys
                    raw_state_refused_keys.add(narrowed_key)
                if should_count_refusal:
                    codegen_dynamic._inertia_jcc_rewrite_refused_raw_state_guard_8616 = (
                        int(getattr(codegen, "_inertia_jcc_rewrite_refused_raw_state_guard_8616", 0) or 0) + 1
                    )
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip raw-state guard key=%r", key)
                return None
            if bool(decoded.expr is not None):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decoded candidate accepted (expr) key=%r", key)
            elif debug_jcc:
                _log.warning("[jcc-rewrite] decoded candidate accepted key=%r", key)
            materialized_polarity_evidence = _jcc_materialized_polarity_evidence_8616(cond)
            if (
                materialized_polarity_evidence == _JccPolarityEvidence8616.JCC_TARGET_FOLLOWING_SIBLING.value
                and polarity_evidence is not _JccPolarityEvidence8616.JCC_TARGET_FOLLOWING_SIBLING
            ):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] keeping following-sibling materialized condition key=%r", key)
                return None
            if (
                polarity_evidence is _JccPolarityEvidence8616.UNKNOWN
                and _condition_materialized_by_jcc_8616(cond)
                and _has_materialized_nonflag_cmp_8616(cond)
                and not _c_expr_uses_register_8616(cond, flags_offset)
            ):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] keeping already-materialized condition key=%r", key)
                return None
            if (
                polarity_evidence is _JccPolarityEvidence8616.BREAK_CONDITION
                and _condition_materialized_by_jcc_8616(cond)
                and _has_materialized_nonflag_cmp_8616(cond)
                and not _c_expr_uses_register_8616(cond, flags_offset)
            ):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] keeping already-materialized break condition key=%r", key)
                return None
            if (
                polarity_evidence is _JccPolarityEvidence8616.UNKNOWN
                and _condition_inverts_decoded_guard_8616(cond)
                and decoded.expr is None
                and not _decoded_guard_contains_real_call_8616(decoded)
            ):
                if isinstance(cond, CITE) and body is not None:
                    if debug_jcc:
                        _log.warning("[jcc-rewrite] direct inverted CITE supplies polarity key=%r", key)
                    replacement = _build_rewrite_8616(cond, decoded, narrowed_key, polarity_evidence=polarity_evidence)
                    if replacement is None:
                        return None
                    _record_jcc_decoded_condition_fingerprint_8616(replacement)
                    return replacement
                should_count_refusal = True
                if isinstance(key, tuple):
                    should_count_refusal = narrowed_key not in unknown_polarity_refused_keys
                    unknown_polarity_refused_keys.add(narrowed_key)
                if should_count_refusal:
                    codegen_dynamic._inertia_jcc_rewrite_refused_unknown_polarity_8616 = (
                        int(getattr(codegen, "_inertia_jcc_rewrite_refused_unknown_polarity_8616", 0) or 0) + 1
                    )
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip unknown-polarity-inversion key=%r", key)
                return None
            _record_decoded_guard_fingerprint_8616(decoded)
            replacement = _build_rewrite_8616(cond, decoded, key, polarity_evidence=polarity_evidence)
            if replacement is None:
                return None
            _record_jcc_decoded_condition_fingerprint_8616(replacement)
            if _condition_materialized_by_jcc_8616(cond) and _validation_fingerprint_8616(
                cond
            ) == _validation_fingerprint_8616(replacement):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip already-materialized key=%r", key)
                return None
            return replacement

        for cond in _iter_guard_conditions_8616():
            key = _condition_tags_8616(cond)
            if key is None:
                continue
            if key in key_conflicts:
                continue
            _collect_decoded_signature_8616(cond)

        if bool(os.environ.get("INERTIA_ENABLE_JCC_CALL_RETURN_REBIND")):  # noqa: SIM102
            if _rebind_adjacent_call_return_register_conditions_8616():
                changed = True

        def _rewrite_condition(
            node: object,
            *,
            body: object | None = None,
            polarity_evidence: _JccPolarityEvidence8616 | None = None,
        ) -> object | None:
            nonlocal changed, materialized_count
            replacement = _decoded_condition_replacement(node, body=body, polarity_evidence=polarity_evidence)
            if replacement is None:
                return None
            changed = True
            materialized_count += 1
            _record_jcc_validation_evidence_8616(node, replacement)
            return replacement

        def _replace_tagged_condition(
            node: object,
            *,
            body: object | None = None,
            polarity_evidence: _JccPolarityEvidence8616 | None = None,
        ) -> object:
            nonlocal changed
            from .structuring.loop_condition_identity import is_owned_loop_continuation_8616

            if is_owned_loop_continuation_8616(node):
                return node
            replacement = _rewrite_condition(node, body=body, polarity_evidence=polarity_evidence)
            if replacement is not None:
                return replacement
            if not _structured_codegen_node_8616(node):
                return node
            key = _condition_tags_8616(node)
            if isinstance(key, tuple) and key in unknown_polarity_refused_keys:
                return node

            def _replace_nested_condition(child: object) -> object:
                nested_replacement = _rewrite_condition(child)
                return child if nested_replacement is None else nested_replacement

            # _replace_c_children_8616 already owns a cycle-aware iterative
            # subtree walk. Recursing from its transform callback makes every
            # ancestor traverse the same descendants again, which is
            # exponential for deeply nested lifted flag expressions.
            changed_in_place = _replace_c_children_8616(node, _replace_nested_condition)
            if changed_in_place:
                changed = True
            return node

        def _following_sibling_jcc_polarity_evidence_8616(
            cond: object,
            body: object,
            following_siblings: tuple[object, ...],
        ) -> _JccPolarityEvidence8616 | None:
            key = _condition_tags_8616(cond)
            target = _jcc_target_for_key_8616(key)
            if not isinstance(target, int):
                return None
            if _root_contains_ins_addr_8616(body, target, max_forward_bytes=0):
                return None
            if _root_contains_ins_addr_8616(following_siblings, target, max_forward_bytes=0x40):
                return _JccPolarityEvidence8616.JCC_TARGET_FOLLOWING_SIBLING
            return None

        def _rewrite_following_sibling_guard_polarity_8616(
            root: object, seen: set[int] | None = None
        ) -> bool:
            local_changed = False
            if root is None:
                return False
            if seen is None:
                seen = set()
            root_id = id(root)
            if root_id in seen:
                return False
            seen.add(root_id)
            if isinstance(root, CStatements):
                statements = list(root.statements or ())
                for index, stmt in enumerate(statements):
                    if isinstance(stmt, CIfElse):
                        cond_pairs = stmt.condition_and_nodes
                        else_node = stmt.else_node
                        if isinstance(cond_pairs, (list, tuple)) and else_node is None:
                            pair_changed = False
                            new_pairs = []
                            first_old_cond = cond_pairs[0][0] if cond_pairs else None
                            following_siblings = tuple(statements[index + 1 :])
                            for cond, body in tuple(cond_pairs):
                                polarity_evidence = _following_sibling_jcc_polarity_evidence_8616(
                                    cond,
                                    body,
                                    following_siblings,
                                )
                                if polarity_evidence is None:
                                    new_pairs.append((cond, body))
                                    continue
                                new_cond = _replace_tagged_condition(
                                    cond,
                                    body=body,
                                    polarity_evidence=polarity_evidence,
                                )
                                pair_changed = pair_changed or (new_cond is not cond)
                                new_pairs.append((new_cond, body))
                            if pair_changed:
                                cast(Any, stmt).condition_and_nodes = type(cond_pairs)(new_pairs)
                                primary = getattr(stmt, "condition", None)
                                primary_key = _condition_tags_8616(primary)
                                first_old_key = _condition_tags_8616(first_old_cond)
                                if (
                                    primary is first_old_cond
                                    or (primary_key is not None and primary_key == first_old_key)
                                ) and new_pairs:
                                    first_cond = new_pairs[0][0]
                                    if first_cond is not None:
                                        cast(Any, stmt).condition = first_cond
                                local_changed = True
                    for child in _child_statement_roots_8616(stmt):
                        local_changed = _rewrite_following_sibling_guard_polarity_8616(child, seen) or local_changed
                return local_changed
            for child in _child_statement_roots_8616(root):
                local_changed = _rewrite_following_sibling_guard_polarity_8616(child, seen) or local_changed
            return local_changed

        if _rewrite_following_sibling_guard_polarity_8616(cfunc.statements):
            changed = True

        for node in _iter_c_nodes_deep_8616(cfunc.statements):
            cond_pairs = getattr(node, "condition_and_nodes", None)
            if isinstance(cond_pairs, (list, tuple)):
                pair_changed = False
                new_pairs = []
                first_old_cond = cond_pairs[0][0] if cond_pairs else None
                for cond, body in cond_pairs:
                    polarity_evidence = _jcc_polarity_evidence_8616(_condition_tags_8616(cond), body)
                    if (
                        polarity_evidence is not _JccPolarityEvidence8616.JCC_TARGET_BODY
                        and _body_is_break_only_8616(body)
                    ):
                        polarity_evidence = _JccPolarityEvidence8616.BREAK_CONDITION
                    new_cond = _replace_tagged_condition(cond, body=body, polarity_evidence=polarity_evidence)
                    pair_changed = pair_changed or (new_cond is not cond)
                    new_pairs.append((new_cond, body))
                    if new_cond is not cond:
                        changed = True
                if pair_changed:
                    cast(Any, node).condition_and_nodes = type(cond_pairs)(new_pairs)
                    # Keep primary condition in sync when the node-level condition
                    # has already collapsed (e.g. literal false), but a tagged
                    # branch-pair condition was successfully recovered.
                    primary = getattr(node, "condition", None)
                    primary_key = _condition_tags_8616(primary)
                    first_old_key = _condition_tags_8616(first_old_cond)
                    if (
                        _is_literal_condition_8616(primary)
                        or primary is first_old_cond
                        or (primary_key is not None and primary_key == first_old_key)
                    ) and new_pairs:
                        first_cond = new_pairs[0][0]
                        if first_cond is not None:
                            cast(Any, node).condition = first_cond
                            changed = True
            if hasattr(node, "condition"):
                cond = getattr(node, "condition", None)
                if cond is not None:
                    condition_polarity_evidence = (
                        _JccPolarityEvidence8616.BREAK_CONDITION
                        if isinstance(node, CIfBreak)
                        else _JccPolarityEvidence8616.LOOP_CONTINUATION
                        if isinstance(node, CDoWhileLoop)
                        else _JccPolarityEvidence8616.UNKNOWN
                    )
                    new_cond = _replace_tagged_condition(cond, polarity_evidence=condition_polarity_evidence)
                    if new_cond is not cond:
                        cast(Any, node).condition = new_cond
                        changed = True

        def _empty_return_body_8616(body: object) -> bool:
            if isinstance(body, CReturn):
                return body.retval is None
            if isinstance(body, CStatements):
                statements = tuple(body.statements or ())
                return len(statements) == 1 and _empty_return_body_8616(statements[0])
            return False

        def _empty_statement_root_8616(root: object) -> bool:
            if root is None:
                return True
            if isinstance(root, CStatements):
                return not tuple(root.statements or ())
            return False

        def _prune_consumed_low_guard_node_8616(node: Any) -> tuple[Any | None, bool]:
            if isinstance(node, CStatements):
                local_changed = False
                rebuilt: list[object] = []
                for stmt in tuple(node.statements or ()):
                    replacement, stmt_changed = _prune_consumed_low_guard_node_8616(stmt)
                    local_changed = local_changed or stmt_changed
                    if replacement is not None:
                        rebuilt.append(replacement)
                if local_changed:
                    node.statements = rebuilt
                return node, local_changed
            if not isinstance(node, CIfElse):
                local_changed = False
                for attr in ("body", "else_node", "iftrue", "iffalse"):
                    child = getattr(node, attr, None)
                    if child is None:
                        continue
                    new_child, child_changed = _prune_consumed_low_guard_node_8616(child)
                    if child_changed:
                        setattr(node, attr, new_child)
                        local_changed = True
                return node, local_changed

            local_changed = False
            cond_pairs = node.condition_and_nodes
            if isinstance(cond_pairs, (list, tuple)):
                new_pairs = []
                for cond, body in tuple(cond_pairs):
                    new_body, body_changed = _prune_consumed_low_guard_node_8616(body)
                    local_changed = local_changed or body_changed
                    if _condition_tags_8616(cond) in consumed_wide_compare_low_branch_keys and _empty_return_body_8616(
                        new_body
                    ):
                        codegen_dynamic._inertia_jcc_consumed_32bit_low_guard_pruned_8616 = (
                            int(getattr(codegen, "_inertia_jcc_consumed_32bit_low_guard_pruned_8616", 0) or 0) + 1
                        )
                        local_changed = True
                        continue
                    new_pairs.append((cond, new_body))
                if local_changed:
                    node.condition_and_nodes = list(new_pairs)
            else_node = getattr(node, "else_node", None)
            new_else, else_changed = _prune_consumed_low_guard_node_8616(else_node)
            if else_changed:
                node.else_node = new_else
                local_changed = True

            cond_pairs = getattr(node, "condition_and_nodes", None)
            if (
                isinstance(cond_pairs, (list, tuple))
                and not cond_pairs
                and _empty_statement_root_8616(getattr(node, "else_node", None))
            ):
                return None, True
            if isinstance(cond_pairs, (list, tuple)) and len(cond_pairs) == 1:
                cond, body = cond_pairs[0]
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning(
                        "[jcc-rewrite] consumed-low prune candidate key=%r consumed=%r body_empty=%s else_empty=%s",
                        _condition_tags_8616(cond),
                        tuple(sorted(consumed_wide_compare_low_branch_keys)),
                        _empty_return_body_8616(body),
                        _empty_statement_root_8616(getattr(node, "else_node", None)),
                    )
                if (
                    _condition_tags_8616(cond) in consumed_wide_compare_low_branch_keys
                    and _empty_return_body_8616(body)
                    and _empty_statement_root_8616(getattr(node, "else_node", None))
                ):
                    codegen_dynamic._inertia_jcc_consumed_32bit_low_guard_pruned_8616 = (
                        int(getattr(codegen, "_inertia_jcc_consumed_32bit_low_guard_pruned_8616", 0) or 0) + 1
                    )
                    return None, True
            return node, local_changed

        if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
            if_node_count = sum(
                1 for node in _iter_c_nodes_deep_8616(cfunc.statements) if isinstance(node, CIfElse)
            )
            _log.warning(
                "[jcc-rewrite] consumed-low prune start consumed=%r if_nodes=%d root_type=%s",
                tuple(sorted(consumed_wide_compare_low_branch_keys)),
                if_node_count,
                type(cfunc.statements).__name__,
            )
        if consumed_wide_compare_low_branch_keys:
            _pruned_root, pruned_changed = _prune_consumed_low_guard_node_8616(cfunc.statements)
            if pruned_changed:
                changed = True

        def _cmp_root_op_8616(cond: object) -> str | None:
            node = cond
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            if isinstance(node, CUnaryOp):
                return None
            if isinstance(node, CBinaryOp):
                op = node.op
                if isinstance(op, str) and op.startswith("Cmp"):
                    return op
            return None

        def _is_stable_materialized_guard_8616(cond: object) -> bool:
            if cond is None:
                return False
            if classify_condition_call_effects_8616(cond).has_semantic_call:
                return False
            if _expr_uses_nonsegment_register_carrier_8616(cond):
                return False
            return _condition_materialized_by_jcc_8616(cond) or _has_materialized_nonflag_cmp_8616(cond)

        def _is_raw_register_guard_8616(cond: object) -> bool:
            if cond is None:
                return False
            if classify_condition_call_effects_8616(cond).has_semantic_call:
                return False
            return _expr_uses_nonsegment_register_carrier_8616(cond)

        def _classify_duplicate_jcc_ifbreak_guard_8616(
            previous_stmt: object,
            current_stmt: object,
        ) -> _JccDuplicateGuardDecision8616:
            if not isinstance(previous_stmt, CIfBreak) or not isinstance(current_stmt, CIfBreak):
                return _JccDuplicateGuardDecision8616.KEEP_UNKNOWN
            previous_cond = getattr(previous_stmt, "condition", None)
            current_cond = getattr(current_stmt, "condition", None)
            previous_key = _condition_tags_8616(previous_cond)
            current_key = _condition_tags_8616(current_cond)
            if previous_key is None or previous_key != current_key:
                return _JccDuplicateGuardDecision8616.KEEP_UNKNOWN
            previous_op = _cmp_root_op_8616(previous_cond)
            current_op = _cmp_root_op_8616(current_cond)
            if previous_op is None or previous_op != current_op:
                return _JccDuplicateGuardDecision8616.KEEP_UNKNOWN

            previous_materialized = _is_stable_materialized_guard_8616(previous_cond)
            current_materialized = _is_stable_materialized_guard_8616(current_cond)
            previous_raw = _is_raw_register_guard_8616(previous_cond)
            current_raw = _is_raw_register_guard_8616(current_cond)
            if previous_materialized and current_raw and not previous_raw:
                return _JccDuplicateGuardDecision8616.PRUNE_CURRENT_RAW_DUPLICATE
            if current_materialized and previous_raw and not current_raw:
                return _JccDuplicateGuardDecision8616.PRUNE_PREVIOUS_RAW_DUPLICATE
            return _JccDuplicateGuardDecision8616.KEEP_UNKNOWN

        def _prune_duplicate_raw_jcc_ifbreaks_8616(root: Any, seen: set[int] | None = None) -> bool:
            if root is None:
                return False
            if seen is None:
                seen = set()
            marker = id(root)
            if marker in seen:
                return False
            seen.add(marker)
            local_changed = False
            if isinstance(root, CStatements):
                rebuilt: list[object] = []
                for stmt in tuple(root.statements or ()):
                    if _prune_duplicate_raw_jcc_ifbreaks_8616(stmt, seen):
                        local_changed = True
                    if rebuilt:
                        codegen_dynamic._inertia_jcc_duplicate_guard_candidates_8616 = (
                            int(getattr(codegen, "_inertia_jcc_duplicate_guard_candidates_8616", 0) or 0) + 1
                        )
                        decision = _classify_duplicate_jcc_ifbreak_guard_8616(rebuilt[-1], stmt)
                        if decision is _JccDuplicateGuardDecision8616.PRUNE_CURRENT_RAW_DUPLICATE:
                            codegen_dynamic._inertia_jcc_duplicate_raw_guard_pruned_8616 = (
                                int(getattr(codegen, "_inertia_jcc_duplicate_raw_guard_pruned_8616", 0) or 0) + 1
                            )
                            local_changed = True
                            continue
                        if decision is _JccDuplicateGuardDecision8616.PRUNE_PREVIOUS_RAW_DUPLICATE:
                            codegen_dynamic._inertia_jcc_duplicate_raw_guard_pruned_8616 = (
                                int(getattr(codegen, "_inertia_jcc_duplicate_raw_guard_pruned_8616", 0) or 0) + 1
                            )
                            rebuilt[-1] = stmt
                            local_changed = True
                            continue
                        codegen_dynamic._inertia_jcc_duplicate_raw_guard_refused_8616 = (
                            int(getattr(codegen, "_inertia_jcc_duplicate_raw_guard_refused_8616", 0) or 0) + 1
                        )
                    rebuilt.append(stmt)
                if local_changed:
                    root.statements = rebuilt
                return local_changed
            for attr in ("body", "else_node", "iftrue", "iffalse"):
                child = getattr(root, attr, None)
                if child is None:
                    continue
                if _prune_duplicate_raw_jcc_ifbreaks_8616(child, seen):
                    local_changed = True
            cond_pairs = getattr(root, "condition_and_nodes", None)
            if isinstance(cond_pairs, (list, tuple)):
                new_pairs = []
                pair_changed = False
                for cond, body in tuple(cond_pairs):
                    if _prune_duplicate_raw_jcc_ifbreaks_8616(body, seen):
                        pair_changed = True
                    new_pairs.append((cond, body))
                if pair_changed:
                    cast(Any, root).condition_and_nodes = type(cond_pairs)(new_pairs)
                    local_changed = True
            return local_changed

        if _prune_duplicate_raw_jcc_ifbreaks_8616(cfunc.statements):
            changed = True

        if changed:
            lane = getattr(codegen, "_inertia_condition_lane", None)
            if isinstance(lane, SemanticLaneState):
                lane.materialized = max(lane.materialized, materialized_count)
            codegen_dynamic._inertia_semantic_condition_materialized_count = max(
                int(getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) or 0),
                materialized_count,
            )

        return changed

    return _impl()
