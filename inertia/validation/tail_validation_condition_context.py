# cython: language_level=3, infer_types=True
"""Layer: Tail Validation.

Responsibility: build contextual condition fingerprints from recovered structured C and IR evidence.
Forbidden: semantic recovery from source, COD, assembly, or rendered C text.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations
import cython

import contextlib
import os
import typing
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
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

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from inertia.postprocess.decompiler_postprocess_jcc import (
    _JCC_COMPARE_OPS_8616,
    _condition_tags_8616,
    _decode_block_and_jcc_index_8616,
    _nearest_flag_producer_before_jcc_8616,
    _translate_cmp_jcc_guard_8616,
)
from inertia.postprocess.flags_cleanup import (
    _extract_flag_predicate_from_expr_8616,
    _extract_flag_test_info_8616,
)

from .tail_validation_fingerprint import _expr_fingerprint
from .validation_call_return_storage import (
    direct_call_return_condition_projection_8616,
    stored_call_return_condition_projection_8616,
)
import dataclasses
import operator
import builtins

__all__ = ["build_x86_16_contextual_condition_fingerprints"]

FlagTestInfo8616 = typing.TypeAliasType("FlagTestInfo8616", tuple[object, int, bool] | tuple[object, int, int, bool])


class _RegisterNameProvider8616(Protocol):
    """Dynamic capstone instruction boundary that can translate register ids."""

    def reg_name(self, reg_id: cython.longlong) -> object:
        """Return the capstone register name for a numeric register id."""
        ...


class _DecodedCmpGuardLike8616(Protocol):
    """Decoded cmp/jcc guard fields consumed from the postprocess boundary."""

    lhs: object
    rhs: object
    op: object
    expr: object | None


@cython.ccall
def _dynamic_attr_8616(obj: object, name: object, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic angr/codegen/capstone compatibility boundary for optional attributes."""
    return getattr(obj, name, default)


@cython.ccall
def _last_assignment_in_stmt(stmt: object) -> object | None:
    """Return a statement when it is a direct assignment."""
    if isinstance(stmt, CAssignment):
        return cast(object, stmt)
    return None


def _iter_stmt_conditions(stmt: object) -> Iterator[object]:
    """Yield condition nodes owned directly by a control-flow statement."""
    cond: object
    _body: object
    if isinstance(stmt, CIfElse):
        for cond, _body in _dynamic_attr_8616(stmt, "condition_and_nodes", ()) or ():
            if cond is not None:
                yield cond
    elif isinstance(stmt, (CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop)):
        cond = _dynamic_attr_8616(stmt, "condition", None)
        if cond is not None:
            yield cond


@cython.ccall
def _contextual_condition_fingerprint(assign_stmt: object, cond: object, project: object) -> object:
    """Build a condition fingerprint from an adjacent flag-producing assignment."""
    info: object
    predicate: object
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


def _owned_materialized_condition_fingerprint_8616(cond: object, project: object) -> object:
    """Return an explicit Lowering/Structuring condition before JCC replay.

    Tail validation may decode unresolved flag carriers from JCC evidence, but
    it must not replace an already-materialized typed condition with replayed
    register-copy state. The explicit condition owns the semantic value once
    Lowering or Structuring marks it, provided no raw carrier remains.
    """
    jcc_addr: object
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
    if not any(tags.get(marker) is True for marker in iter(materialized_markers)):
        return None
    raw_fingerprint = _expr_fingerprint(cond, project)
    fingerprint = raw_fingerprint if isinstance(raw_fingerprint, str) else ""
    if any(isinstance(current, CFunctionCall) for current in builtins.iter(_iter_c_nodes_deep_8616(cond))):
        return fingerprint
    if any(
        isinstance(current, CVariable) and isinstance(current.variable, SimRegisterVariable)
        for current in builtins.iter(_iter_c_nodes_deep_8616(cond))
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


@cython.ccall
def _tv_condition_debug_enabled_8616() -> cython.bint:
    """Return whether tail-validation condition-context debug output is on."""
    return os.environ.get("INERTIA_DEBUG_TV_CONDITION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}


@cython.ccall
def _tv_debug_8616(message: object) -> None:
    """Emit one tail-validation condition-context debug line."""
    import sys

    print(message, file=sys.stderr, flush=True)


@cython.ccall
def _projection_condition_fingerprint_8616(
    cond: object,
    project: object,
    codegen: object,
    ins_addr: cython.longlong,
    block_addr: cython.longlong,
) -> object:
    """Return the first available call-return/materialized fingerprint."""
    direct_return: object
    materialized_fingerprint: object
    stored_return: object
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
    return None


@cython.ccall
def _decoded_condition_fingerprint_tail_8616(
    decoded: object,
    cond: object,
    project: object,
    codegen: object,
    ins_addr: cython.longlong,
    block_addr: cython.longlong,
    direct_cmp_fingerprint: object,
) -> object:
    """Return the decoded-condition fingerprint or a refused None."""
    guard = cast(_DecodedCmpGuardLike8616, decoded)
    lhs = _expr_fingerprint(guard.lhs, project)
    rhs = _expr_fingerprint(guard.rhs, project)
    if direct_cmp_fingerprint is None and (
        _fingerprint_contains_raw_register_8616(lhs) or _fingerprint_contains_raw_register_8616(rhs)
    ):
        if _tv_condition_debug_enabled_8616():
            _tv_debug_8616(
                f"[tv-condition-context] decoded refuse raw-register block={block_addr:#x} ins={ins_addr:#x} "
                f"lhs={lhs} rhs={rhs}"
            )
        return None
    decoded_fingerprint = f"{guard.op}({lhs},{rhs})"
    if direct_cmp_fingerprint is not None and operator.ne(direct_cmp_fingerprint, decoded_fingerprint):
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
        if _tv_condition_debug_enabled_8616():
            _tv_debug_8616(
                f"[tv-condition-context] direct-cmp override block={block_addr:#x} ins={ins_addr:#x} "
                f"decoded={decoded_fingerprint} direct={direct_cmp_fingerprint}"
            )
        return direct_cmp_fingerprint
    if _tv_condition_debug_enabled_8616():
        _tv_debug_8616(
            f"[tv-condition-context] decoded block={block_addr:#x} ins={ins_addr:#x} "
            f"op={guard.op} lhs={lhs} rhs={rhs} "
            f"rhs_node={type(guard.rhs).__module__}.{type(guard.rhs).__name__}:"
            f"{_dynamic_attr_8616(guard.rhs, 'op', None)!r} "
            f"expr={type(guard.expr).__name__ if guard.expr is not None else 'None'}"
        )
    if lhs == rhs:
        return None
    return decoded_fingerprint


@cython.ccall
def _decoded_jcc_condition_fingerprint(cond: object, project: object) -> object:
    """Build a validation fingerprint from JCC evidence owned by this node."""
    decoded: object
    direct_cmp_fingerprint: object
    key: object
    projection: object
    key = _condition_tags_8616(cond)
    if key is None:
        return None
    ins_addr, block_addr = key
    codegen = _dynamic_attr_8616(project, "_inertia_tail_validation_active_codegen", None) or _dynamic_attr_8616(
        cond, "codegen", None
    )
    projection = _projection_condition_fingerprint_8616(cond, project, codegen, ins_addr, block_addr)
    if projection is not None:
        return projection
    direct_cmp_fingerprint = _direct_cmp_immediate_jcc_fingerprint(cond, project, codegen, block_addr, ins_addr)
    decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
    if decoded is None:
        if direct_cmp_fingerprint is not None:
            return direct_cmp_fingerprint
        if _tv_condition_debug_enabled_8616():
            _tv_debug_8616(
                f"[tv-condition-context] decode_failed block={block_addr:#x} ins={ins_addr:#x} "
                f"active_codegen={_dynamic_attr_8616(project, '_inertia_tail_validation_active_codegen', None) is not None} "
                f"cond_codegen={_dynamic_attr_8616(cond, 'codegen', None) is not None}"
            )
        return None
    return _decoded_condition_fingerprint_tail_8616(
        decoded, cond, project, codegen, ins_addr, block_addr, direct_cmp_fingerprint,
    )


@cython.ccall
def _fingerprint_contains_raw_register_8616(fingerprint: object) -> cython.bint:
    """Return whether a validation fingerprint still exposes a raw register."""
    if not isinstance(fingerprint, str):
        return False
    return "reg:" in fingerprint


@cython.ccall
def _direct_cmp_operand_fingerprint_8616(
    operand: object,
    *,
    insn: object,
    debug_refuse: Callable[[str], None],
) -> object:
    """Fingerprint one narrow direct-cmp operand for validation context."""
    mem: object
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


@cython.ccall
def _direct_cmp_source_8616(
    project: object,
    block_addr: cython.longlong,
    ins_addr: cython.longlong,
    debug_refuse: Callable[[str], None],
) -> tuple[object | None, str | None]:
    """Return the flag-producing cmp instruction and decoded jcc op, or refuse."""
    cmp_insn: object
    insns: object
    jcc_index: object
    op: object
    insns, jcc_index = _decode_block_and_jcc_index_8616(project, int(block_addr), int(ins_addr), False)
    if insns is None or jcc_index is None:
        debug_refuse("missing_jcc")
        return None, None
    jcc_insn = insns[jcc_index]
    op = _JCC_COMPARE_OPS_8616.get(str(_dynamic_attr_8616(jcc_insn, "mnemonic", "") or "").lower())
    if op is None:
        debug_refuse("unsupported_jcc")
        return None, None
    cmp_insn = _nearest_flag_producer_before_jcc_8616(insns, jcc_index)
    if cmp_insn is None or str(_dynamic_attr_8616(cmp_insn, "mnemonic", "") or "").lower() != "cmp":
        debug_refuse("not_cmp")
        return None, None
    return cmp_insn, op


def _direct_cmp_operand_gate_8616(
    cmp_insn: object,
    debug_refuse: Callable[[str], None],
) -> object:
    """Return the two cmp operands, or refuse on unsupported shapes."""
    operands = tuple(cast(tuple[Any, ...], _dynamic_attr_8616(cmp_insn, "operands", ()) or ()))
    if len(operands) != 2:
        debug_refuse("bad_operand_count")
        return None
    immediate_operands = tuple(
        operand
        for operand in iter(operands)
        if int(_dynamic_attr_8616(operand, "type", -1)) == 2
        and isinstance(_dynamic_attr_8616(operand, "imm", None), int)
    )
    if len(immediate_operands) != 1:
        debug_refuse(
            "no_immediate:"
            + ",".join(
                f"type={_dynamic_attr_8616(operand, 'type', None)} "
                f"imm={_dynamic_attr_8616(operand, 'imm', None)!r}"
                for operand in iter(operands)
            )
        )
        return None
    if any(int(_dynamic_attr_8616(operand, "type", -1)) == 1 for operand in iter(operands)):
        debug_refuse("register_operand")
        return None
    return operands


@cython.ccall
def _direct_cmp_operand_pair_8616(
    operands: object,
    cmp_insn: object,
    debug_refuse: Callable[[str], None],
) -> object:
    """Return the (lhs, rhs) operand fingerprints, or refuse."""
    lhs: object
    rhs: object
    lhs = _direct_cmp_operand_fingerprint_8616(operands[0], insn=cmp_insn, debug_refuse=debug_refuse)
    rhs = _direct_cmp_operand_fingerprint_8616(operands[1], insn=cmp_insn, debug_refuse=debug_refuse)
    if lhs is None or rhs is None:
        debug_refuse(f"unresolved_operands lhs={lhs!r} rhs={rhs!r}")
        return None
    if not (lhs.startswith("const:") or rhs.startswith("const:")):
        debug_refuse("no_constant_expr")
        return None
    return lhs, rhs


def _direct_cmp_immediate_jcc_fingerprint(
    cond: object,
    project: object,
    codegen: object,
    block_addr: cython.longlong,
    ins_addr: cython.longlong,
) -> object:
    """Return instruction-backed cmp-immediate condition evidence for validation.

    This is deliberately narrow: it only handles a direct ``cmp`` whose operand
    is an immediate.  Those branches do not require replayed register state, so
    the validation context should prefer the instruction operand over decoded
    register state.  Build the fingerprint directly from capstone operand facts:
    temporary C AST nodes may reuse Python object ids and collide with the
    expression fingerprint cache.
    """
    cmp_insn: object
    op: object
    operands: object
    pair: object
    _ = cond
    debug = _tv_condition_debug_enabled_8616()

    def _debug_refuse(reason: object) -> None:
        if not debug:
            return
        _tv_debug_8616(
            f"[tv-condition-context] direct-cmp refuse block={block_addr:#x} ins={ins_addr:#x} reason={reason}"
        )

    if codegen is None:
        _debug_refuse("missing_codegen")
        return None
    cmp_insn, op = _direct_cmp_source_8616(project, block_addr, ins_addr, _debug_refuse)
    if cmp_insn is None or op is None:
        return None
    operands = _direct_cmp_operand_gate_8616(cmp_insn, _debug_refuse)
    if operands is None:
        return None
    pair = _direct_cmp_operand_pair_8616(operands, cmp_insn, _debug_refuse)
    if pair is None:
        return None
    lhs, rhs = pair
    fingerprint = f"{op}({lhs},{rhs})"
    if debug:
        _tv_debug_8616(
            f"[tv-condition-context] direct-cmp fingerprint block={block_addr:#x} ins={ins_addr:#x} value={fingerprint}"
        )
    return fingerprint


@cython.dataclasses.dataclass
class _ConditionFingerprintVisitor8616:
    """Collect owned condition fingerprints across the structured C AST."""

    project: object
    mapping: object = field(default_factory=dict)

    @cython.ccall
    def visit_statements(self, node: CStatements) -> None:
        """Collect fingerprints for conditions inside one statement list."""
        assign_stmt: object
        fingerprint: object
        cond: object
        index: object
        stmt: object
        statements = list(node.statements)
        for index, stmt in enumerate(statements[:-1]):
            assign_stmt = _last_assignment_in_stmt(stmt)
            if assign_stmt is None:
                continue
            next_stmt = statements[index + 1]
            for cond in _iter_stmt_conditions(next_stmt):
                fingerprint = _decoded_jcc_condition_fingerprint(cond, self.project)
                if fingerprint is None:
                    fingerprint = _contextual_condition_fingerprint(assign_stmt, cond, self.project)
                if fingerprint is not None:
                    self.mapping[id(cond)] = fingerprint
        for stmt in statements:
            for cond in _iter_stmt_conditions(stmt):
                fingerprint = _decoded_jcc_condition_fingerprint(cond, self.project)
                if fingerprint is not None:
                    self.mapping[id(cond)] = fingerprint
        for stmt in statements:
            self.visit(stmt)

    @cython.ccall
    def visit(self, node: object) -> None:
        """Walk the current C AST and collect owned condition fingerprints."""
        body: object
        else_node: object
        _cond: object
        if isinstance(node, CStatements):
            self.visit_statements(node)
            return

        if isinstance(node, CIfElse):
            for _cond, body in _dynamic_attr_8616(node, "condition_and_nodes", ()) or ():
                if body is not None:
                    self.visit(body)
            else_node = _dynamic_attr_8616(node, "else_node", None)
            if else_node is not None:
                self.visit(else_node)
            return

        if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
            body = _dynamic_attr_8616(node, "body", None)
            if body is not None:
                self.visit(body)


@cython.ccall
def build_x86_16_contextual_condition_fingerprints(root: object, project: object) -> object:
    """Build contextual condition fingerprints keyed by current C AST node id."""
    visitor = _ConditionFingerprintVisitor8616(project=project)
    if root is not None:
        visitor.visit(root)
    return visitor.mapping
