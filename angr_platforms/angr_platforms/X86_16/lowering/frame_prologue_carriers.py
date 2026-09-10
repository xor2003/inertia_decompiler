"""Classify exact canonical x86-16 frame-prologue C AST carriers.

Layer: Types/Lowering.
Responsibility: prove structured entry carriers for decoded ``push bp`` and
``mov bp, sp`` before Lowering consumes compiler frame scaffolding.
Consumes alias, widening, and typed facts plus exact physical register views.
Owned GP-state projections retain their register identity after lowering;
matching one is not permission to infer or discard additional frame effects.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Protocol

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..ir.core import MemSpace
from .frame_carrier_liveness import _scalar_identity_8616
from .frame_register_carriers import FrameRegisterCarrierResolution8616
from .gp_register_state import runtime_gp_expression_view_8616
from .physical_registers import physical_register_view_8616
from .runtime_segment_access import RuntimeSegmentAccessContext8616, runtime_segment_access_space_8616

_WORD_BYTES: Final = 2
_BYTE_BITS: Final = 8
_SEGMENTED_ACCESS_ARITY: Final = 2


class _ArchitectureRegisters8616(Protocol):
    """Architecture register contracts required by frame classification."""

    registers: Mapping[str, tuple[int, int]]


class _ProjectRegisters8616(Protocol):
    """Project surface required by frame classification."""

    arch: _ArchitectureRegisters8616


def _unwrap_casts_8616(value: object) -> object:
    """Remove type-only wrappers from one structured expression."""
    while isinstance(value, CTypeCast):
        value = value.expr
    return value


def _constant_8616(value: object) -> int | None:
    """Return one explicit structured integer constant."""
    value = _unwrap_casts_8616(value)
    return value.value if isinstance(value, CConstant) and isinstance(value.value, int) else None


def _matches_register_8616(
    value: object,
    project: _ProjectRegisters8616,
    register_name: str,
    register_carriers: FrameRegisterCarrierResolution8616 | None = None,
) -> bool:
    """Return whether one carrier exactly covers the named physical register."""
    expected = project.arch.registers.get(register_name)
    view = (
        register_carriers.resolve(value)
        if register_carriers is not None
        else physical_register_view_8616(_unwrap_casts_8616(value))
    )
    if expected is None:
        return False
    if view is not None:
        return (view.reg_offset, view.width) == expected
    runtime_view = runtime_gp_expression_view_8616(value)
    return (
        runtime_view is not None
        and runtime_view.width == expected[1]
        and project.arch.registers.get(runtime_view.register_name) == expected
    )


def _statement_addr_8616(statement: CAssignment) -> int | None:
    """Return the exact machine instruction tag on one structured assignment."""
    value = statement.tags.get("ins_addr")
    return value if isinstance(value, int) else None


def _is_entry_sp_decrement_8616(
    statement: object,
    project: _ProjectRegisters8616,
    function_addr: int,
    register_carriers: FrameRegisterCarrierResolution8616 | None = None,
) -> bool:
    """Match the exact ``SP = SP - 2`` carrier emitted for ``push bp``."""
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != function_addr:
        return False
    rhs = _unwrap_casts_8616(statement.rhs)
    return (
        _matches_register_8616(statement.lhs, project, "sp", register_carriers)
        and isinstance(rhs, CBinaryOp)
        and rhs.op == "Sub"
        and _matches_register_8616(rhs.lhs, project, "sp", register_carriers)
        and _constant_8616(rhs.rhs) == _WORD_BYTES
    )


def _flatten_frame_address_8616(term: object, sign: int = 1) -> list[tuple[object, int]]:
    """Flatten structured addition/subtraction without changing address meaning."""
    term = _unwrap_casts_8616(term)
    if isinstance(term, CBinaryOp) and term.op == "Add":
        return _flatten_frame_address_8616(term.lhs, sign) + _flatten_frame_address_8616(term.rhs, sign)
    if isinstance(term, CBinaryOp) and term.op == "Sub":
        return _flatten_frame_address_8616(term.lhs, sign) + _flatten_frame_address_8616(term.rhs, -sign)
    return [(term, sign)]


def _entry_ss_sp_displacement_8616(
    value: object,
    root: object,
    project: _ProjectRegisters8616,
    codegen: object | None,
    register_carriers: FrameRegisterCarrierResolution8616 | None,
) -> int | None:
    """Return displacement for an exact ``SS:SP+constant`` dereference."""
    value = _unwrap_casts_8616(value)
    required_ss_terms = 1
    if isinstance(value, CFunctionCall):
        args = tuple(value.args or ())
        if len(args) != _SEGMENTED_ACCESS_ARITY:
            return None
        segment_space = (
            runtime_segment_access_space_8616(
                project,
                codegen,
                value,
                context=RuntimeSegmentAccessContext8616(root),
            )
            if codegen is not None
            else None
        )
        if segment_space is not MemSpace.SS and not _matches_register_8616(args[0], project, "ss"):
            return None
        address = args[1]
        required_ss_terms = 0
    elif isinstance(value, CUnaryOp) and value.op == "Dereference":
        address = value.operand
    else:
        return None

    displacement = 0
    ss_terms = 0
    sp_terms = 0
    for term, sign in _flatten_frame_address_8616(address):
        constant = _constant_8616(term)
        if constant is not None:
            displacement += sign * constant
            continue
        term = _unwrap_casts_8616(term)
        if isinstance(term, CBinaryOp) and term.op in {"Mul", "Shl"} and sign == 1:
            scale = 16 if term.op == "Mul" else 4
            if (
                _matches_register_8616(term.lhs, project, "ss", register_carriers)
                and _constant_8616(term.rhs) == scale
            ) or (
                _matches_register_8616(term.rhs, project, "ss", register_carriers)
                and _constant_8616(term.lhs) == scale
            ):
                ss_terms += 1
                continue
        anchor = term.operand if isinstance(term, CUnaryOp) and term.op in {"Reference", "AddressOf"} else None
        entry_anchor = (
            isinstance(anchor, CVariable) and isinstance(anchor.variable, SimStackVariable)
            and anchor.variable.base == "bp" and anchor.variable.offset == 0
        )
        if sign == 1 and (entry_anchor or _matches_register_8616(term, project, "sp", register_carriers)):
            sp_terms += 1
            continue
        return None
    return displacement if ss_terms == required_ss_terms and sp_terms == 1 else None


def is_exact_push_bp_store_carrier_8616(
    statement: object,
    root: object,
    project: _ProjectRegisters8616,
    function_addr: int,
    *,
    canonical_frame_proven: bool = False,
    codegen: object | None = None,
    register_carriers: FrameRegisterCarrierResolution8616 | None = None,
) -> bool:
    """Prove one saved-BP store from AST pairing or decoded frame evidence."""
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != function_addr:
        return False
    if not _matches_register_8616(statement.rhs, project, "bp", register_carriers):
        return False
    if _entry_ss_sp_displacement_8616(
        statement.lhs,
        root,
        project,
        codegen,
        register_carriers,
    ) != -_WORD_BYTES:
        return False
    return canonical_frame_proven or any(
        _is_entry_sp_decrement_8616(node, project, function_addr, register_carriers)
        for node in _iter_c_nodes_deep_8616(root)
    )


def _paired_bp_byte_store_8616(
    statement: CAssignment,
    root: object,
    project: _ProjectRegisters8616,
    function_addr: int,
    codegen: object | None,
    register_carriers: FrameRegisterCarrierResolution8616 | None,
) -> bool:
    """Require both exact saved-word byte slots and the same captured BP value."""
    lhs = _unwrap_casts_8616(statement.lhs)
    if not (isinstance(lhs, CVariable) and isinstance(lhs.variable, SimStackVariable)
            and lhs.variable.size == 1 and lhs.variable.offset == -_WORD_BYTES):
        return False
    source = _unwrap_casts_8616(statement.rhs)
    source_id = _scalar_identity_8616(source)
    if not isinstance(source_id, int) or not _matches_register_8616(source, project, "bp", register_carriers):
        return False
    matches = 0
    for candidate in _iter_c_nodes_deep_8616(root):
        if not isinstance(candidate, CAssignment) or _statement_addr_8616(candidate) != function_addr:
            continue
        other = _unwrap_casts_8616(candidate.lhs)
        duplicate_low = (candidate is not statement and isinstance(other, CVariable)
                         and isinstance(other.variable, SimStackVariable) and other.variable.offset == -_WORD_BYTES)
        if duplicate_low:
            return False
        if _entry_ss_sp_displacement_8616(candidate.lhs, root, project, codegen, register_carriers) != -1:
            continue
        high = _unwrap_casts_8616(candidate.rhs)
        if not (isinstance(high, CBinaryOp) and high.op == "Shr" and _constant_8616(high.rhs) == _BYTE_BITS
                and _scalar_identity_8616(high.lhs) == source_id
                and _matches_register_8616(high.lhs, project, "bp", register_carriers)):
            return False
        try:
            store_type = candidate.lhs.type
            byte_store = store_type is not None and store_type.size == _BYTE_BITS
        except (AttributeError, TypeError, ValueError):
            byte_store = False
        if not byte_store:
            return False
        matches += 1
    return matches == 1


def is_exact_push_bp_carrier_8616(
    statement: object,
    root: object,
    project: _ProjectRegisters8616,
    function_addr: int,
    *,
    canonical_frame_proven: bool = False,
    codegen: object | None = None,
    register_carriers: FrameRegisterCarrierResolution8616 | None = None,
) -> bool:
    """Prove one stack-update or saved-BP carrier of the entry ``push bp``."""
    if _is_entry_sp_decrement_8616(
        statement,
        project,
        function_addr,
        register_carriers,
    ) or is_exact_push_bp_store_carrier_8616(
        statement,
        root,
        project,
        function_addr,
        canonical_frame_proven=canonical_frame_proven,
        codegen=codegen,
        register_carriers=register_carriers,
    ):
        return True
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != function_addr:
        return False
    lhs = _unwrap_casts_8616(statement.lhs)
    if not (
        isinstance(lhs, CVariable)
        and isinstance(lhs.variable, SimStackVariable)
        and lhs.variable.base == "bp"
    ):
        return False
    rhs = statement.rhs
    if canonical_frame_proven and _paired_bp_byte_store_8616(
        statement, root, project, function_addr, codegen, register_carriers,
    ):
        return True
    expected_bp = project.arch.registers.get("bp")
    if (
        expected_bp is not None
        and lhs.variable.size == expected_bp[1]
        and _matches_register_8616(rhs, project, "bp", register_carriers)
    ):
        return True
    if not isinstance(rhs, CUnaryOp) or rhs.op not in {"Reference", "AddressOf"}:
        return False
    anchor = rhs.operand
    return (
        isinstance(anchor, CVariable)
        and isinstance(anchor.variable, SimStackVariable)
        and anchor.variable.base == "bp"
        and anchor.variable.offset == 0
    )


def is_exact_bp_frame_setup_carrier_8616(
    statement: object,
    project: _ProjectRegisters8616,
    setup_addr: int,
    *,
    register_carriers: FrameRegisterCarrierResolution8616 | None = None,
) -> bool:
    """Match one owned BP write at a decoded ``mov bp, sp`` instruction.

    GP-state lowering represents a 16-bit BP write as a coherent 32-bit EBP
    lane assignment. That typed owner remains valid evidence after an earlier
    pass has consumed every structured carrier for the preceding ``push bp``.
    """
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != setup_addr:
        return False
    if _matches_register_8616(statement.lhs, project, "bp", register_carriers):
        return True
    runtime_view = runtime_gp_expression_view_8616(statement.lhs)
    return runtime_view is not None and runtime_view.parent_name == "ebp"


__all__ = [
    "is_exact_bp_frame_setup_carrier_8616",
    "is_exact_push_bp_carrier_8616",
    "is_exact_push_bp_store_carrier_8616",
]
