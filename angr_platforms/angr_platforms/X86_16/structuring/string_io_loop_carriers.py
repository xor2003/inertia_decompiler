"""Canonicalize typed REP INS/OUTS loop-carried register identities.

Layer: Structuring.
Responsibility: project frontend-proven string-I/O semantics onto angr's C AST
without allowing SSA identities or preheader constants to escape loop scope.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.

Dynamic boundary: third-party angr C-AST, project, knowledge-base, and codegen
objects expose version-dependent child slots and analysis attachments.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..string_instruction_artifact import (
    StringInstructionArtifact,
    StringInstructionRecord,
    build_x86_16_string_instruction_artifact,
)

__all__ = ["StringIOLoopCarrierStats8616", "materialize_string_io_loop_carriers_8616"]

_LOG = logging.getLogger(__name__)


class _StringIOArch8616(Protocol):
    """Architecture register map consumed at the angr boundary."""

    registers: Mapping[str, tuple[int, int]]


class _StringIOProject8616(Protocol):
    """Project architecture consumed by string-I/O structuring."""

    arch: _StringIOArch8616


class _StringIOCFunction8616(Protocol):
    """Structured function surface mutated by string-I/O structuring."""

    addr: int
    statements: object


class _StringIOCodegen8616(Protocol):
    """Dynamic codegen boundary consumed by string-I/O structuring."""

    project: _StringIOProject8616 | None
    cfunc: _StringIOCFunction8616 | None
    _inertia_string_instruction_artifact: StringInstructionArtifact
    _inertia_string_io_loop_carrier_stats_8616: StringIOLoopCarrierStats8616


@dataclass(frozen=True, slots=True)
class StringIOLoopCarrierStats8616:
    """Closed evidence counters for typed string-I/O loop repair."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _register_shape_8616(node: object) -> tuple[int, int] | None:
    """Return one exact structured physical-register view."""
    if not isinstance(node, structured_c.CVariable):
        return None
    for variable in (node.unified_variable, node.variable):
        if isinstance(variable, SimRegisterVariable) and isinstance(variable.reg, int) and isinstance(variable.size, int):
            return variable.reg, variable.size
    return None


def _named_register_shape_8616(
    node: object,
    named_shapes: Mapping[str, tuple[int, int]],
) -> tuple[int, int] | None:
    """Resolve a late unified C variable through its architectural display name."""
    shape = _register_shape_8616(node)
    if shape is not None or not isinstance(node, structured_c.CVariable):
        return shape
    variable_name = node.name or node.variable.name
    return named_shapes.get(variable_name.lower()) if isinstance(variable_name, str) else None


def _call_name_8616(node: structured_c.CFunctionCall) -> str | None:
    """Return a stable name from angr's dynamic call boundary."""
    for candidate in (node.callee_target, node.callee_func):
        if isinstance(candidate, str):
            return candidate
        name = getattr(candidate, "name", None)
        if isinstance(name, str):
            return name
    return None


def _contains_io_call_8616(node: object, record: StringInstructionRecord) -> bool:
    """Match one loop to its typed port-I/O family and element width."""
    prefix = "inertia_io_out" if record.family == "outs" else "inertia_io_in"
    wanted = f"{prefix}{record.width * 8}"
    return any(
        isinstance(item, structured_c.CFunctionCall) and _call_name_8616(item) == wanted
        for item in _iter_c_nodes_deep_8616(node)
    )


def _constant_one_8616(node: object) -> bool:
    """Return whether one C expression is the exact REP decrement constant."""
    return isinstance(node, structured_c.CConstant) and node.value == 1


@dataclass(frozen=True, slots=True)
class _LoopRewriteContext8616:
    """Immutable canonical bindings for one typed REP loop rewrite."""

    canonical: Mapping[tuple[int, int], structured_c.CVariable]
    named_shapes: Mapping[str, tuple[int, int]]
    count_shape: tuple[int, int]
    index_shape: tuple[int, int]
    record: StringInstructionRecord


def _rewrite_assignment_8616(node: object, ctx: _LoopRewriteContext8616) -> int:
    """Rewrite an assignment lhs and canonicalize the REP decrement shape."""
    if not isinstance(node, structured_c.CAssignment):
        return 0
    node.lhs, delta = _rewrite_loop_node_8616(node.lhs, ctx)
    changed = delta
    if (
        _named_register_shape_8616(node.lhs, ctx.named_shapes) == ctx.count_shape
        and isinstance(node.rhs, structured_c.CBinaryOp)
        and node.rhs.op in {"Sub", "Subtract"}
        and _constant_one_8616(node.rhs.rhs)
        and _named_register_shape_8616(node.rhs.lhs, ctx.named_shapes) != ctx.count_shape
    ):
        node.rhs.lhs = copy.copy(ctx.canonical[ctx.count_shape])
        changed += 1
    return changed


def _rewrite_outs_call_arg_8616(node: object, ctx: _LoopRewriteContext8616) -> int:
    """Replace the SEG_Ux source argument of a proven outs call."""
    if not isinstance(node, structured_c.CFunctionCall):
        return 0
    expected_load = f"SEG_U{ctx.record.width * 8}"
    if ctx.record.family != "outs" or _call_name_8616(node) != expected_load or len(node.args) < 2:
        return 0
    args = list(node.args)
    args[1] = copy.copy(ctx.canonical[ctx.index_shape])
    node.args = args
    return 1


def _rewrite_child_attrs_8616(node: object, ctx: _LoopRewriteContext8616) -> int:
    """Recursively rewrite every scalar child attribute of a node."""
    changed = 0
    for attr in ("lhs", "rhs", "operand", "cond", "iftrue", "iffalse", "expr", "condition", "retval", "body", "else_node"):
        if isinstance(node, structured_c.CAssignment) and attr == "lhs":
            continue
        child = getattr(node, attr, None)
        if child is None or isinstance(child, (str, bytes, int, float, bool)):
            continue
        rewritten, delta = _rewrite_loop_node_8616(child, ctx)
        if delta:
            setattr(node, attr, rewritten)
            changed += delta
    return changed


def _rewrite_child_sequences_8616(node: object, ctx: _LoopRewriteContext8616) -> int:
    """Recursively rewrite every sequence child attribute of a node."""
    changed = 0
    for attr in ("statements", "operands", "args"):
        sequence = getattr(node, attr, None)
        if not isinstance(sequence, (list, tuple)):
            continue
        rewritten_items = []
        sequence_changed = 0
        for item in sequence:
            rewritten, delta = _rewrite_loop_node_8616(item, ctx)
            rewritten_items.append(rewritten)
            sequence_changed += delta
        if sequence_changed:
            setattr(node, attr, rewritten_items)
            changed += sequence_changed
    return changed


def _rewrite_loop_node_8616(node: object, ctx: _LoopRewriteContext8616) -> tuple[object, int]:
    """Rewrite one typed REP loop subtree and return its materialization count."""
    if isinstance(node, structured_c.CVariable):
        shape = _named_register_shape_8616(node, ctx.named_shapes)
        replacement = ctx.canonical.get(shape) if shape is not None else None
        return (copy.copy(replacement), 1) if replacement is not None else (node, 0)

    changed = _rewrite_assignment_8616(node, ctx)
    changed += _rewrite_outs_call_arg_8616(node, ctx)
    changed += _rewrite_child_attrs_8616(node, ctx)
    changed += _rewrite_child_sequences_8616(node, ctx)
    return node, changed


def _string_io_artifact_8616(
    boundary: _StringIOCodegen8616,
    project: object,
    cfunc: _StringIOCFunction8616 | None,
) -> object:
    """Return the cached artifact, building it from function evidence if absent."""
    artifact = getattr(boundary, "_inertia_string_instruction_artifact", None)
    if cfunc is None or isinstance(artifact, StringInstructionArtifact):
        return artifact
    functions = getattr(getattr(project, "kb", None), "functions", None)
    function_lookup = getattr(functions, "function", None)
    function = function_lookup(addr=cfunc.addr, create=False) if callable(function_lookup) else None
    if function is None:
        return artifact
    artifact = build_x86_16_string_instruction_artifact(project, function)
    boundary._inertia_string_instruction_artifact = artifact
    return artifact


def _rep_io_records_8616(artifact: object) -> tuple[StringInstructionRecord, ...]:
    """Keep only repeated INS/OUTS records from the string artifact."""
    if not isinstance(artifact, StringInstructionArtifact):
        return ()
    return tuple(
        record
        for record in artifact.records
        if record.family in {"ins", "outs"} and record.repeat_kind != "none"
    )


def _register_name_shapes_8616(arch: _StringIOArch8616) -> dict[str, tuple[int, int]]:
    """Collect exact (offset, size) shapes for the REP carrier register names."""
    register_names = ("cx", "ecx", "si", "esi", "di", "edi", "dx", "edx", "d")
    return {
        name: shape[:2]
        for name in register_names
        if (shape := arch.registers.get(name)) is not None and len(shape) >= 2
    }


@dataclass(slots=True)
class _StringIOLoopScan8616:
    """Mutable census and evidence state for one REP-loop carrier traversal."""

    shapes: Mapping[str, tuple[int, int]]
    records: tuple[StringInstructionRecord, ...]
    materialized: int = 0
    classified: int = 0
    loop_count: int = 0
    matched_loop_count: int = 0
    missing_shapes: set[tuple[int, int]] = field(default_factory=set)


def _rewrite_matched_loop_8616(
    scan: _StringIOLoopScan8616,
    statement: object,
    record: StringInstructionRecord,
    prior: dict[tuple[int, int], structured_c.CVariable],
) -> None:
    """Rewrite one I/O-backed loop or record which carrier shapes are missing."""
    scan.matched_loop_count += 1
    count_shape = scan.shapes.get("cx") or scan.shapes.get("ecx")
    index_shape = (
        (scan.shapes.get("si") or scan.shapes.get("esi"))
        if record.family == "outs"
        else (scan.shapes.get("di") or scan.shapes.get("edi"))
    )
    if count_shape is None or index_shape is None:
        return
    required_names = (
        ("cx", "si", "dx", "d")
        if record.family == "outs"
        else ("cx", "di", "dx", "d")
    )
    required_shapes = {scan.shapes[name] for name in required_names if name in scan.shapes}
    canonical = {
        shape: variable for shape, variable in prior.items() if shape in required_shapes
    }
    if count_shape in canonical and index_shape in canonical:
        scan.classified += 1
        _, delta = _rewrite_loop_node_8616(
            statement,
            _LoopRewriteContext8616(
                canonical=canonical,
                named_shapes=scan.shapes,
                count_shape=count_shape,
                index_shape=index_shape,
                record=record,
            ),
        )
        scan.materialized += delta
    else:
        scan.missing_shapes.update(required_shapes - canonical.keys())


def _process_statements_block_8616(
    scan: _StringIOLoopScan8616,
    node: structured_c.CStatements,
    inherited: Mapping[tuple[int, int], structured_c.CVariable],
) -> dict[tuple[int, int], structured_c.CVariable]:
    """Track preheader assignments and rewrite matched loops in one block."""
    prior = dict(inherited)
    for statement in node.statements:
        if isinstance(statement, structured_c.CAssignment):
            shape = _named_register_shape_8616(statement.lhs, scan.shapes)
            if shape is not None:
                prior[shape] = statement.lhs
            continue
        if isinstance(statement, (structured_c.CDoWhileLoop, structured_c.CWhileLoop, structured_c.CForLoop)):
            scan.loop_count += 1
            record = next(
                (item for item in scan.records if _contains_io_call_8616(statement, item)),
                None,
            )
            if record is not None:
                _rewrite_matched_loop_8616(scan, statement, record, prior)
            _process_string_io_node_8616(scan, statement.body, prior)
            continue
        prior.update(_process_string_io_node_8616(scan, statement, prior))
    return prior


def _process_string_io_node_8616(
    scan: _StringIOLoopScan8616,
    node: object,
    inherited: Mapping[tuple[int, int], structured_c.CVariable],
) -> dict[tuple[int, int], structured_c.CVariable]:
    """Propagate preheader definitions into nested structured wrappers."""
    if isinstance(node, structured_c.CStatements):
        return _process_statements_block_8616(scan, node, inherited)
    for attr in ("body", "else_node"):
        child = getattr(node, attr, None)
        if child is not None:
            _process_string_io_node_8616(scan, child, inherited)
    pairs = getattr(node, "condition_and_nodes", None)
    if isinstance(pairs, (list, tuple)):
        for _condition, body in pairs:
            _process_string_io_node_8616(scan, body, inherited)
    return dict(inherited)


def materialize_string_io_loop_carriers_8616(project: object, codegen: object) -> bool:
    """Repair only REP port-I/O loops backed by decoded instruction evidence."""
    boundary = cast(_StringIOCodegen8616, codegen)
    typed_project = cast(_StringIOProject8616, project)
    cfunc = boundary.cfunc
    artifact = _string_io_artifact_8616(boundary, project, cfunc)
    records = _rep_io_records_8616(artifact)
    empty = StringIOLoopCarrierStats8616(0, 0, 0, 0, 0)
    if cfunc is None or not isinstance(cfunc.statements, structured_c.CStatements) or not records:
        boundary._inertia_string_io_loop_carrier_stats_8616 = empty
        if os.environ.get("INERTIA_DEBUG_STRING_IO_LOOP_CARRIERS"):
            _LOG.warning(
                "[string-io-loop] refused cfunc=%s statements=%s records=%d",
                cfunc is not None,
                type(cfunc.statements).__name__ if cfunc is not None else "none",
                len(records),
            )
        return False

    scan = _StringIOLoopScan8616(_register_name_shapes_8616(typed_project.arch), records)
    _process_string_io_node_8616(scan, cfunc.statements, {})
    materialized = scan.materialized
    classified = scan.classified
    loop_count = scan.loop_count
    matched_loop_count = scan.matched_loop_count
    missing_shapes = scan.missing_shapes

    raw = len(records)
    boundary._inertia_string_io_loop_carrier_stats_8616 = StringIOLoopCarrierStats8616(
        raw_fact_count=raw,
        normalized_fact_count=raw,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=raw - classified,
    )
    if os.environ.get("INERTIA_DEBUG_STRING_IO_LOOP_CARRIERS"):
        _LOG.warning(
            "[string-io-loop] records=%d loops=%d matched=%d classified=%d materialized=%d failures=%d missing=%s",
            raw,
            loop_count,
            matched_loop_count,
            classified,
            materialized,
            raw - classified,
            sorted(missing_shapes),
        )
    return materialized > 0
