"""Layer: Tail Validation.

Responsibility: build contextual condition fingerprints from recovered structured C and IR evidence.
Forbidden: semantic recovery from source, COD, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
import os
import typing
from collections.abc import Callable, Iterator
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDirtyExpression,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimRegisterVariable
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_BP, X86_REG_INVALID

from .c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from .decompiler_postprocess_flags import (
    _extract_flag_predicate_from_expr_8616,
    _extract_flag_test_info_8616,
)
from .decompiler_postprocess_jcc import (
    _JCC_COMPARE_OPS_8616,
    _condition_tags_8616,
    _decode_block_and_jcc_index_8616,
    _nearest_flag_producer_before_jcc_8616,
    _translate_cmp_jcc_guard_8616,
)
from .tail_validation_fingerprint import _expr_fingerprint
from .validation_call_return_storage import (
    direct_call_return_condition_projection_8616,
    stored_call_return_condition_projection_8616,
)

__all__ = ["build_x86_16_contextual_condition_fingerprints"]

type FlagTestInfo8616 = tuple[object, int, bool] | tuple[object, int, int, bool]


class _RegisterNameProvider8616(Protocol):
    """Dynamic capstone instruction boundary that can translate register ids."""

    def reg_name(self, reg_id: int) -> str:
        """Return the capstone register name for a numeric register id."""
        ...


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic angr/codegen/capstone compatibility boundary for optional attributes."""
    return getattr(obj, name, default)


def _last_assignment_in_stmt(stmt: object) -> object | None:
    """Return a statement when it is a direct assignment."""
    if isinstance(stmt, CAssignment):
        return cast(object, stmt)
    return None


def _iter_stmt_conditions(stmt: object) -> Iterator[object]:
    """Yield condition nodes owned directly by a control-flow statement."""
    if isinstance(stmt, CIfElse):
        for cond, _body in _dynamic_attr_8616(stmt, "condition_and_nodes", ()) or ():
            if cond is not None:
                yield cond
    elif isinstance(stmt, (CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop)):
        cond = _dynamic_attr_8616(stmt, "condition", None)
        if cond is not None:
            yield cond


def _contextual_condition_fingerprint(assign_stmt: object, cond: object, project: object) -> str | None:
    """Build a condition fingerprint from an adjacent flag-producing assignment."""
    lhs = _dynamic_attr_8616(assign_stmt, "lhs", None)
    if not isinstance(lhs, (CVariable, CDirtyExpression)):
        return None

    info = _extract_flag_test_info_8616(cond)
    if info is None:
        return None
    flag_info = info
    if len(flag_info) == 3:
        flag_var, bit, negate_predicate = flag_info
    else:
        flag_var, bit, _expected_value, negate_predicate = flag_info
    if not _same_c_expression_8616(lhs, flag_var):
        return None

    predicate = _extract_flag_predicate_from_expr_8616(_dynamic_attr_8616(assign_stmt, "rhs", None), bit)
    if predicate is None:
        return None
    if negate_predicate:
        predicate = CUnaryOp("Not", cast(CExpression, predicate), codegen=_dynamic_attr_8616(cond, "codegen", None))
    fingerprint = _expr_fingerprint(predicate, project)
    return fingerprint if isinstance(fingerprint, str) else None


def _owned_materialized_condition_fingerprint_8616(cond: object, project: object) -> str | None:
    """Return an explicit Lowering/Structuring condition before JCC replay.

    Tail validation may decode unresolved flag carriers from JCC evidence, but
    it must not replace an already-materialized typed condition with replayed
    register-copy state. The explicit condition owns the semantic value once
    Lowering or Structuring marks it, provided no raw carrier remains.
    """
    node = cond
    while isinstance(node, CUnaryOp) and node.op == "Not":
        node = node.operand
    tags = _dynamic_attr_8616(node, "tags", None)
    if not isinstance(tags, dict):
        return None
    materialized_markers = (
        "typed_condition",
        "inertia_jcc_materialized_8616",
        "inertia_structuring_condition_cfg_materialized_8616",
        "inertia_structuring_condition_chain_materialized_8616",
        "inertia_structuring_shared_body_condition_chain_materialized_8616",
        "inertia_structuring_single_branch_materialized_8616",
    )
    if not any(tags.get(marker) is True for marker in materialized_markers):
        return None
    raw_fingerprint = _expr_fingerprint(cond, project)
    fingerprint = raw_fingerprint if isinstance(raw_fingerprint, str) else ""
    if any(isinstance(current, CFunctionCall) for current in _iter_c_nodes_deep_8616(cond)):
        return fingerprint
    if any(
        isinstance(current, CVariable) and isinstance(current.variable, SimRegisterVariable)
        for current in _iter_c_nodes_deep_8616(cond)
    ):
        # Precision evidence is owned by Structuring and already checked at the
        # final branch boundary. Import lazily to avoid its fingerprint cycle.
        from .validation_condition_precision import matches_recorded_condition_precision_8616

        codegen = _dynamic_attr_8616(project, "_inertia_tail_validation_active_codegen", None) or _dynamic_attr_8616(node, "codegen", None)
        jcc_addr = tags.get("ins_addr")
        if isinstance(jcc_addr, int) and matches_recorded_condition_precision_8616(codegen, jcc_addr, fingerprint):
            return fingerprint
        return None
    if _fingerprint_contains_raw_register_8616(fingerprint) or "virtual:" in fingerprint:
        return None
    return fingerprint


def _decoded_jcc_condition_fingerprint(cond: object, project: object) -> str | None:
    """Build a validation fingerprint from JCC evidence owned by this node."""
    key = _condition_tags_8616(cond)
    if key is None:
        return None
    ins_addr, block_addr = key
    codegen = _dynamic_attr_8616(project, "_inertia_tail_validation_active_codegen", None) or _dynamic_attr_8616(
        cond, "codegen", None
    )
    direct_return = direct_call_return_condition_projection_8616(
        project,
        codegen,
        jcc_addr=ins_addr,
        block_addr=block_addr,
        structured_condition=cond,
    )
    if direct_return is not None:
        return direct_return.fingerprint
    materialized_fingerprint = _owned_materialized_condition_fingerprint_8616(cond, project)
    if materialized_fingerprint is not None:
        return materialized_fingerprint
    stored_return = stored_call_return_condition_projection_8616(
        project,
        codegen,
        jcc_addr=ins_addr,
        block_addr=block_addr,
        structured_condition=cond,
    )
    if stored_return is not None:
        return stored_return.fingerprint
    direct_cmp_fingerprint = _direct_cmp_immediate_jcc_fingerprint(cond, project, codegen, block_addr, ins_addr)
    decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
    if decoded is None:
        if direct_cmp_fingerprint is not None:
            return direct_cmp_fingerprint
        if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            import sys

            print(
                f"[tv-condition-context] decode_failed block={block_addr:#x} ins={ins_addr:#x} "
                f"active_codegen={_dynamic_attr_8616(project, '_inertia_tail_validation_active_codegen', None) is not None} "
                f"cond_codegen={_dynamic_attr_8616(cond, 'codegen', None) is not None}",
                file=sys.stderr,
                flush=True,
            )
        return None
    lhs = _expr_fingerprint(decoded.lhs, project)
    rhs = _expr_fingerprint(decoded.rhs, project)
    if direct_cmp_fingerprint is None and (
        _fingerprint_contains_raw_register_8616(lhs) or _fingerprint_contains_raw_register_8616(rhs)
    ):
        if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            import sys

            print(
                f"[tv-condition-context] decoded refuse raw-register block={block_addr:#x} ins={ins_addr:#x} "
                f"lhs={lhs} rhs={rhs}",
                file=sys.stderr,
                flush=True,
            )
        return None
    decoded_fingerprint = f"{decoded.op}({lhs},{rhs})"
    if direct_cmp_fingerprint is not None and direct_cmp_fingerprint != decoded_fingerprint:
        if codegen is not None:
            typing.cast(typing.Any, codegen)._inertia_tail_validation_direct_cmp_jcc_overrides_8616 = (
                int(
                    _dynamic_attr_8616(
                        codegen,
                        "_inertia_tail_validation_direct_cmp_jcc_overrides_8616",
                        0,
                    )
                    or 0
                )
                + 1
            )
        if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            import sys

            print(
                f"[tv-condition-context] direct-cmp override block={block_addr:#x} ins={ins_addr:#x} "
                f"decoded={decoded_fingerprint} direct={direct_cmp_fingerprint}",
                file=sys.stderr,
                flush=True,
            )
        return direct_cmp_fingerprint
    if os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
        import sys

        print(
            f"[tv-condition-context] decoded block={block_addr:#x} ins={ins_addr:#x} "
            f"op={decoded.op} lhs={lhs} rhs={rhs} "
            f"rhs_node={type(decoded.rhs).__module__}.{type(decoded.rhs).__name__}:"
            f"{_dynamic_attr_8616(decoded.rhs, 'op', None)!r} "
            f"expr={type(decoded.expr).__name__ if decoded.expr is not None else 'None'}",
            file=sys.stderr,
            flush=True,
        )
    if lhs == rhs:
        return None
    return decoded_fingerprint


def _fingerprint_contains_raw_register_8616(fingerprint: object) -> bool:
    """Return whether a validation fingerprint still exposes a raw register."""
    if not isinstance(fingerprint, str):
        return False
    return "reg:" in fingerprint


def _direct_cmp_operand_fingerprint_8616(
    operand: object,
    *,
    insn: object,
    debug_refuse: Callable[[str], None],
) -> str | None:
    """Fingerprint one narrow direct-cmp operand for validation context."""
    operand_type = int(_dynamic_attr_8616(operand, "type", -1))
    if operand_type == X86_OP_IMM:
        value = _dynamic_attr_8616(operand, "imm", None)
        return f"const:{int(value)}" if isinstance(value, int) else None
    if operand_type != X86_OP_MEM:
        debug_refuse(f"unsupported_operand_type:{operand_type}")
        return None
    mem = _dynamic_attr_8616(operand, "mem", None)
    if mem is None:
        debug_refuse("missing_memory_operand")
        return None
    base = int(_dynamic_attr_8616(mem, "base", X86_REG_INVALID) or X86_REG_INVALID)
    index = int(_dynamic_attr_8616(mem, "index", X86_REG_INVALID) or X86_REG_INVALID)
    disp = _dynamic_attr_8616(mem, "disp", None)
    if not isinstance(disp, int):
        debug_refuse("missing_memory_displacement")
        return None
    if index not in {0, X86_REG_INVALID}:
        debug_refuse(f"indexed_memory:index={index}")
        return None
    size = _dynamic_attr_8616(operand, "size", None)
    size_suffix = f":size{int(size)}" if isinstance(size, int) and int(size) > 0 else ""
    base_name = ""
    if base not in {0, X86_REG_INVALID}:
        with contextlib.suppress(Exception):
            base_name = str(cast(_RegisterNameProvider8616, insn).reg_name(base)).lower()
    if base == X86_REG_BP or base_name == "bp":
        return f"stack_slot:SS:BP{int(disp):+#x}{size_suffix}"
    if base not in {0, X86_REG_INVALID}:
        debug_refuse(f"based_memory:base={base}")
        return None
    return f"global:{int(disp) & 0xFFFF:#x}"


def _direct_cmp_immediate_jcc_fingerprint(
    cond: object,
    project: object,
    codegen: object,
    block_addr: int,
    ins_addr: int,
) -> str | None:
    """Return instruction-backed cmp-immediate condition evidence for validation.

    This is deliberately narrow: it only handles a direct ``cmp`` whose operand
    is an immediate.  Those branches do not require replayed register state, so
    the validation context should prefer the instruction operand over decoded
    register state.  Build the fingerprint directly from capstone operand facts:
    temporary C AST nodes may reuse Python object ids and collide with the
    expression fingerprint cache.
    """
    _ = cond
    debug = os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}

    def _debug_refuse(reason: str) -> None:
        if not debug:
            return
        import sys

        print(
            f"[tv-condition-context] direct-cmp refuse block={block_addr:#x} ins={ins_addr:#x} reason={reason}",
            file=sys.stderr,
            flush=True,
        )

    if codegen is None:
        _debug_refuse("missing_codegen")
        return None
    insns, jcc_index = _decode_block_and_jcc_index_8616(project, int(block_addr), int(ins_addr), False)
    if insns is None or jcc_index is None:
        _debug_refuse("missing_jcc")
        return None
    jcc_insn = insns[jcc_index]
    op = _JCC_COMPARE_OPS_8616.get(str(_dynamic_attr_8616(jcc_insn, "mnemonic", "") or "").lower())
    if op is None:
        _debug_refuse("unsupported_jcc")
        return None
    cmp_insn = _nearest_flag_producer_before_jcc_8616(insns, jcc_index)
    if cmp_insn is None or str(_dynamic_attr_8616(cmp_insn, "mnemonic", "") or "").lower() != "cmp":
        _debug_refuse("not_cmp")
        return None
    operands = tuple(cast(tuple[Any, ...], _dynamic_attr_8616(cmp_insn, "operands", ()) or ()))
    if len(operands) != 2:
        _debug_refuse("bad_operand_count")
        return None
    immediate_operands = tuple(
        operand
        for operand in operands
        if int(_dynamic_attr_8616(operand, "type", -1)) == 2
        and isinstance(_dynamic_attr_8616(operand, "imm", None), int)
    )
    if len(immediate_operands) != 1:
        _debug_refuse(
            "no_immediate:"
            + ",".join(
                f"type={_dynamic_attr_8616(operand, 'type', None)} "
                f"imm={_dynamic_attr_8616(operand, 'imm', None)!r}"
                for operand in operands
            )
        )
        return None
    if any(int(_dynamic_attr_8616(operand, "type", -1)) == 1 for operand in operands):
        _debug_refuse("register_operand")
        return None
    lhs = _direct_cmp_operand_fingerprint_8616(operands[0], insn=cmp_insn, debug_refuse=_debug_refuse)
    rhs = _direct_cmp_operand_fingerprint_8616(operands[1], insn=cmp_insn, debug_refuse=_debug_refuse)
    if lhs is None or rhs is None:
        _debug_refuse(f"unresolved_operands lhs={lhs!r} rhs={rhs!r}")
        return None
    if not (lhs.startswith("const:") or rhs.startswith("const:")):
        _debug_refuse("no_constant_expr")
        return None
    fingerprint = f"{op}({lhs},{rhs})"
    if debug:
        import sys

        print(
            f"[tv-condition-context] direct-cmp fingerprint block={block_addr:#x} ins={ins_addr:#x} value={fingerprint}",
            file=sys.stderr,
            flush=True,
        )
    return fingerprint


def build_x86_16_contextual_condition_fingerprints(root: object, project: object) -> dict[int, str]:
    """Build contextual condition fingerprints keyed by current C AST node id."""
    mapping: dict[int, str] = {}

    def visit(node: object) -> None:
        """Walk the current C AST and collect owned condition fingerprints."""
        if isinstance(node, CStatements):
            statements = list(node.statements)
            for index, stmt in enumerate(statements[:-1]):
                assign_stmt = _last_assignment_in_stmt(stmt)
                if assign_stmt is None:
                    continue
                next_stmt = statements[index + 1]
                for cond in _iter_stmt_conditions(next_stmt):
                    fingerprint = _decoded_jcc_condition_fingerprint(cond, project)
                    if fingerprint is None:
                        fingerprint = _contextual_condition_fingerprint(assign_stmt, cond, project)
                    if fingerprint is not None:
                        mapping[id(cond)] = fingerprint
            for stmt in statements:
                for cond in _iter_stmt_conditions(stmt):
                    fingerprint = _decoded_jcc_condition_fingerprint(cond, project)
                    if fingerprint is not None:
                        mapping[id(cond)] = fingerprint
            for stmt in statements:
                visit(stmt)
            return

        if isinstance(node, CIfElse):
            for _cond, body in _dynamic_attr_8616(node, "condition_and_nodes", ()) or ():
                if body is not None:
                    visit(body)
            else_node = _dynamic_attr_8616(node, "else_node", None)
            if else_node is not None:
                visit(else_node)
            return

        if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
            body = _dynamic_attr_8616(node, "body", None)
            if body is not None:
                visit(body)

    if root is not None:
        visit(root)
    return mapping
