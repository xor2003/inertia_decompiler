"""Prune C carriers for caller stack cleanup consumed by structured calls.

Layer: Types/Lowering.
Responsibility: remove AST assignments that model an exact ``add sp, N`` after
the corresponding typed callsite has consumed that cleanup effect.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This pass does not infer calls or arguments. It consumes callsite summaries and
exact instruction provenance. A cleanup carrier is deleted only when the
binary instruction is the summary's exact ``ADD SP, immediate`` and the C
assignment has a pure RHS plus a stack/SP carrier destination.

Dynamic boundary: angr structured-C nodes, codegen objects, Capstone
instructions, and function inventories expose version-dependent attributes.
Dynamic access below is restricted to those third-party surfaces.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from capstone.x86_const import (
    X86_INS_ADD,
    X86_OP_IMM,
    X86_OP_REG,
    X86_REG_SP,
)

from ..callsite_summary import CallsiteSummary8616, callsite_summary_inventory_8616

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CallCleanupCarrierPruneStats8616:
    """Closed evidence counters for one cleanup-carrier replay."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _boundary_tuple_8616(value: object) -> tuple[Any, ...]:
    """Convert one dynamic angr collection to a stable tuple."""
    return tuple(cast(Iterable[Any], value))


def _candidate_addresses_8616(project: object, address: int) -> frozenset[int]:
    """Return current/original address-domain candidates for one instruction."""
    candidates = {address}
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        candidates.update((address + delta, address - delta))
    return frozenset(candidates)


def _decode_instruction_8616(project: object, address: int) -> object | None:
    """Decode one exact instruction through the active/original project."""
    projects = (project, getattr(project, "_inertia_original_project", None))
    delta = getattr(project, "_inertia_original_linear_delta", None)
    for candidate_project in projects:
        if candidate_project is None:
            continue
        candidate_address = address
        if candidate_project is not project and isinstance(delta, int):
            candidate_address += delta
        factory = getattr(candidate_project, "factory", None)
        if factory is None:
            continue
        with contextlib.suppress(Exception):
            block = factory.block(candidate_address, num_inst=1, opt_level=0)
            wrappers = _boundary_tuple_8616(
                getattr(getattr(block, "capstone", None), "insns", ()) or ()
            )
            if wrappers:
                return cast(object, getattr(wrappers[0], "insn", wrappers[0]))
    return None


def _is_exact_cleanup_instruction_8616(
    project: object,
    address: int,
    amount: int,
) -> bool:
    """Return whether one address is exactly ``ADD SP, amount``."""
    insn = _decode_instruction_8616(project, address)
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    return bool(
        getattr(insn, "id", None) == X86_INS_ADD
        and len(operands) == 2
        and getattr(operands[0], "type", None) == X86_OP_REG
        and getattr(operands[0], "reg", None) == X86_REG_SP
        and getattr(operands[1], "type", None) == X86_OP_IMM
        and getattr(operands[1], "imm", None) == amount
    )


def _pure_expression_8616(node: object) -> bool:
    """Return whether evaluating an angr C expression has no C side effect."""
    if isinstance(
        node,
        (
            structured_c.CConstant,
            structured_c.CVariable,
            structured_c.CDirtyExpression,
        ),
    ):
        return True
    if isinstance(node, structured_c.CBinaryOp):
        return _pure_expression_8616(node.lhs) and _pure_expression_8616(node.rhs)
    if isinstance(node, structured_c.CTypeCast):
        return _pure_expression_8616(node.expr)
    if isinstance(node, structured_c.CUnaryOp):
        return node.op != "Dereference" and _pure_expression_8616(node.operand)
    return False


def _stack_cleanup_carrier_lhs_8616(node: object, project: object) -> bool:
    """Return whether an assignment destination is a stack/SP carrier."""
    if isinstance(node, structured_c.CDirtyExpression):
        return True
    if not isinstance(node, structured_c.CVariable):
        return False
    variable = node.variable
    registers = getattr(getattr(project, "arch", None), "registers", {})
    sp_register = registers.get("sp") if isinstance(registers, dict) else None
    sp_offset = sp_register[0] if isinstance(sp_register, tuple) and sp_register else None
    return bool(
        (isinstance(variable, SimStackVariable)
        and variable.base == "bp")
        or (isinstance(variable, SimRegisterVariable)
        and variable.reg == sp_offset)
    )


def _expression_instruction_addresses_8616(node: object) -> frozenset[int]:
    """Collect instruction provenance from one supported structured-C tree."""
    addresses: set[int] = set()
    seen: set[int] = set()

    def visit(current: object) -> None:
        if current is None or id(current) in seen:
            return
        seen.add(id(current))
        tags = getattr(current, "tags", None)
        ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
        if isinstance(ins_addr, int):
            addresses.add(ins_addr)
        if isinstance(current, (structured_c.CAssignment, structured_c.CBinaryOp)):
            visit(current.lhs)
            visit(current.rhs)
        elif isinstance(current, structured_c.CTypeCast):
            visit(current.expr)
        elif isinstance(current, structured_c.CUnaryOp):
            visit(current.operand)

    visit(node)
    return frozenset(addresses)


def _debug_render_8616(node: object) -> str:
    """Render one third-party node for opt-in diagnostics only."""
    chunks = getattr(node, "c_repr_chunks", None)
    if not callable(chunks):
        return repr(node)
    with contextlib.suppress(Exception):
        rendered_chunks = cast(Iterable[tuple[str, object]], chunks(asexpr=True))
        return "".join(text for text, _item in rendered_chunks)
    return repr(node)


def _provenance_is_one_call_cleanup_8616(
    project: object,
    provenance: frozenset[int],
    cleanup_address: int,
    summary: CallsiteSummary8616,
) -> bool:
    """Prove that every contributing instruction belongs to one call cleanup."""
    sequence_addresses = {
        summary.callsite_addr,
        cleanup_address,
        *summary.push_arg_instruction_addrs,
    }
    allowed = frozenset(
        candidate
        for address in sequence_addresses
        for candidate in _candidate_addresses_8616(project, address)
    )
    return bool(
        provenance
        and provenance
        & _candidate_addresses_8616(project, cleanup_address)
        and provenance <= allowed
    )


def _statement_prune_verdict_8616(
    project: object,
    normalized: dict[int, CallsiteSummary8616],
    statement: object,
) -> tuple[bool, bool]:
    """Classify one statement; return ``(matched, drop)`` for prune decision."""
    provenance = _expression_instruction_addresses_8616(statement)
    matching_addrs = tuple(
        address
        for address, summary in normalized.items()
        if _provenance_is_one_call_cleanup_8616(
            project,
            provenance,
            address,
            summary,
        )
    )
    matched_addr = matching_addrs[0] if len(matching_addrs) == 1 else None
    if os.environ.get("INERTIA_DEBUG_CALL_CLEANUP_CARRIER"):
        log.warning(
            "[call-cleanup-carrier] statement=%s provenance=%s "
            "matching=%s lhs=%s rhs=%s rendered=%s",
            type(statement).__name__,
            tuple(hex(address) for address in sorted(provenance)),
            tuple(hex(address) for address in matching_addrs),
            type(getattr(statement, "lhs", None)).__name__,
            type(getattr(statement, "rhs", None)).__name__,
            _debug_render_8616(statement),
        )
    if matched_addr is None:
        return False, False
    drop = (
        isinstance(statement, structured_c.CAssignment)
        and _stack_cleanup_carrier_lhs_8616(statement.lhs, project)
        and _pure_expression_8616(statement.rhs)
    )
    return True, drop


def prune_consumed_call_cleanup_carriers_8616(
    project: object,
    codegen: object,
) -> bool:
    """Delete exact, pure cleanup carriers already consumed by typed calls."""
    consumed = frozenset(
        address
        for address in _boundary_tuple_8616(
            getattr(
                codegen,
                "_inertia_consumed_call_cleanup_carrier_ins_addrs_8616",
                (),
            )
            or ()
        )
        if isinstance(address, int)
    )
    inventory = callsite_summary_inventory_8616(codegen)
    cleanup_summary_by_addr = {
        summary.stack_cleanup_instruction_addr: summary
        for summary in inventory.values()
        if isinstance(summary.stack_cleanup_instruction_addr, int)
        and summary.stack_cleanup_instruction_addr in consumed
        and isinstance(summary.stack_cleanup, int)
        and summary.stack_cleanup > 0
    }
    normalized = {
        address: summary
        for address, summary in cleanup_summary_by_addr.items()
        if _is_exact_cleanup_instruction_8616(
            project,
            address,
            cast(int, summary.stack_cleanup),
        )
    }
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    classified = 0
    materialized = 0
    seen: set[int] = set()

    def visit(node: object) -> None:
        """Prune matching assignments from mutable structured statement lists."""
        nonlocal classified, materialized
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            retained: list[object] = []
            for statement in tuple(statements):
                matched, drop = _statement_prune_verdict_8616(
                    project, normalized, statement
                )
                if matched:
                    classified += 1
                if drop:
                    materialized += 1
                    continue
                retained.append(statement)
                visit(statement)
            statements[:] = retained
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in _boundary_tuple_8616(pairs):
                visit(body)
        for attribute in ("body", "else_node"):
            visit(getattr(node, attribute, None))

    visit(root)
    stats = CallCleanupCarrierPruneStats8616(
        raw_fact_count=len(consumed),
        normalized_fact_count=len(normalized),
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=max(len(consumed) - len(normalized), 0)
        + max(classified - materialized, 0),
    )
    cast(Any, codegen)._inertia_call_cleanup_carrier_prune_8616 = stats
    return materialized > 0
