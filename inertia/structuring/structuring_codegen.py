# cython: language_level=3, infer_types=True
"""Structuring-based code generation for control flow.

Layer: Structuring.
Responsibility: lower already-structured regions and typed switch artifacts into
C AST/codegen metadata without recovering new semantics.

This module demonstrates how structured regions (Loop, IncSwitch) are converted
to C control flow constructs. Integration with full decompiler codegen happens
in Phase 1.4+.

Dynamic attribute access in this module is limited to the third-party angr
C AST/codegen boundary; owned Inertia region metadata is narrowed before use.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

import logging
import os
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from inertia.ir.core import IRValue
from inertia.lowering.c_ast_utils import (
    _clone_c_ast_tree_8616,
    _same_c_expression_8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
    rebind_cloned_structured_callsite_identity_8616,
    structured_callsite_addr_8616,
)
from inertia.structuring.condition_lowering import lower_ir_value_to_c_expr_8616
from inertia.structuring.condition_rendering import render_condition_operand_8616
from inertia.structuring.structuring_region import Region, RegionGraph, RegionType
import dataclasses
import operator
import builtins

if TYPE_CHECKING:
    pass

logger: logging.Logger = logging.getLogger(__name__)
_MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616 = 64


@cython.ccall
def _metadata_sequence_8616(value: object) -> tuple[object, ...]:
    """Return tuple metadata only when the region metadata value is sequence-like."""
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


@cython.ccall
def _metadata_str_8616(value: object) -> object:
    """Return string metadata values without guessing from arbitrary objects."""
    return value if isinstance(value, str) else None


@cython.ccall
def _metadata_bool_8616(value: object) -> cython.bint:
    """Return boolean metadata values without truthiness coercion."""
    return value if isinstance(value, bool) else False


@cython.ccall
def _metadata_region_8616(value: object) -> Region | None:
    """Return region metadata values after narrowing to Region."""
    return value if isinstance(value, Region) else None


def _metadata_regions_8616(value: object) -> tuple[Region, ...]:
    """Return only Region values from sequence-like metadata."""
    return tuple(item for item in builtins.iter(_metadata_sequence_8616(value)) if isinstance(item, Region))


def _metadata_ints_8616(value: object) -> tuple[cython.longlong, ...]:
    """Return only integer values from sequence-like metadata."""
    return tuple(item for item in builtins.iter(_metadata_sequence_8616(value)) if isinstance(item, int))


@cython.ccall
def _metadata_provenance_keys_8616(value: object) -> tuple[tuple[str, cython.longlong, cython.longlong], ...]:
    """Return typed provenance keys from sequence-like metadata."""
    item: object
    result: list[tuple[str, cython.longlong, cython.longlong]] = []
    for item in _metadata_sequence_8616(value):
        if (
            isinstance(item, tuple)
            and len(item) == 3
            and isinstance(item[0], str)
            and isinstance(item[1], int)
            and isinstance(item[2], int)
        ):
            result.append((item[0], item[1], item[2]))
    return tuple(result)


@cython.ccall
def _debug_list_8616(mapping: object, key: object) -> object:
    """Return a list-valued debug field without relying on object truthiness."""
    value = mapping.setdefault(key, [])
    if isinstance(value, list):
        return value
    replacement: list[object] = []
    mapping[key] = replacement
    return replacement


@cython.ccall
def _c_statements_items_8616(node: structured_c.CStatements) -> object:
    """Return child statements from a third-party angr C AST statements boundary."""
    statements = node.statements
    return tuple(statements) if isinstance(statements, (list, tuple)) else ()


@cython.ccall
def _c_ifelse_pairs_8616(
    node: structured_c.CIfElse,
) -> tuple[tuple[structured_c.CExpression, structured_c.CStatement | None], ...]:
    """Return condition/body pairs from a third-party angr C AST if/else boundary."""
    pair: object
    pairs = node.condition_and_nodes
    if not isinstance(pairs, (list, tuple)):
        return ()
    result: list[tuple[structured_c.CExpression, structured_c.CStatement | None]] = []
    for pair in pairs:
        if (
            isinstance(pair, tuple)
            and len(pair) == 2
            and isinstance(pair[0], structured_c.CExpression)
            and (pair[1] is None or isinstance(pair[1], structured_c.CStatement))
        ):
            result.append((pair[0], pair[1]))
    return tuple(result)


@cython.ccall
def _c_switch_cases_8616(node: object) -> tuple[tuple[object, object], ...]:
    """Return switch case/body pairs from a third-party angr C AST boundary."""
    cases: object
    case: object
    cases = getattr(cast(Any, node), "cases", ())
    if not isinstance(cases, (list, tuple)):
        return ()
    result: list[tuple[object, object]] = []
    for case in cases:
        if isinstance(case, tuple) and len(case) == 2:
            result.append((case[0], case[1]))
    return tuple(result)


class TypedEdgeSwitchSafetyStatus8616(Enum):
    """Typed status for edge-guard switch replacement safety."""

    NoCandidates = "no_candidates"
    Safe = "safe"
    Blocked = "blocked"


class TypedEdgeSwitchLoweringStatus8616(Enum):
    """Typed status for production lowering of edge-guard switch artifacts."""

    NoCandidates = "no_candidates"
    BlockedPostCAst = "blocked_post_c_ast"


@cython.dataclasses.dataclass
class LoopCodegenInfo:
    """Information for rendering a loop region as C code."""

    loop_type: object  # "while", "do_while", "for"
    condition_expr: object  # Condition to evaluate
    init_stmt: object  # Initialization (for loops)
    increment_stmt: object  # Increment (for loops)
    body_regions: object  # Regions in loop body
    exit_label: object  # Label for break target (if needed)
    uses_goto: cython.bint  # True if fallback gotos needed
    structuring_variables: object  # Explicit abnormal loop selectors


@cython.dataclasses.dataclass
class SwitchCodegenInfo:
    """Information for rendering a switch region as C code."""

    switch_expr: object  # Expression being switched on
    case_targets: object  # Constant->Region mapping
    default_target: Region | None  # Default case target
    uses_fallthrough: cython.bint  # True if case fallthrough
    uses_goto: cython.bint  # True if complex gotos needed


@dataclasses.dataclass(frozen=True, )
class TypedEdgeSwitchAstMaterializationResult8616:
    """Result of building typed edge-guard switch AST artifacts."""

    attempted_count: cython.longlong
    materialized_count: cython.longlong
    refused_count: cython.longlong
    refusal_reasons: object

    @property
    def changed(self) -> cython.bint:
        """Return True when production C AST was modified."""
        return False


@dataclasses.dataclass(frozen=True, )
class TypedEdgeSwitchReplacementSafetyResult8616:
    """Dry-run verdict for replacing top-level C AST with typed switch artifacts."""

    attempted_count: cython.longlong
    safe_count: cython.longlong
    refused_count: cython.longlong
    refusal_reasons: object

    @property
    def status(self) -> TypedEdgeSwitchSafetyStatus8616:
        """Return the typed safety verdict."""
        if self.attempted_count <= 0:
            return TypedEdgeSwitchSafetyStatus8616.NoCandidates
        if self.safe_count > 0 and self.refused_count == 0:
            return TypedEdgeSwitchSafetyStatus8616.Safe
        return TypedEdgeSwitchSafetyStatus8616.Blocked

    @property
    def blocker_layer(self) -> object:
        """Return the owning layer when replacement is blocked."""
        if self.status is not TypedEdgeSwitchSafetyStatus8616.Blocked:
            return None
        return "structuring.codegen.c_ast_replacement"

    @property
    def changed(self) -> cython.bint:
        """Return True when production C AST was modified."""
        return False


@dataclasses.dataclass(frozen=True, )
class TypedEdgeSwitchAstReplacementResult8616:
    """Result of replacing safe typed edge-guard cascades in the C AST."""

    attempted_count: cython.longlong
    replaced_count: cython.longlong
    refused_count: cython.longlong
    refusal_reasons: object

    @property
    def changed(self) -> cython.bint:
        """Return True when production C AST was modified."""
        return self.replaced_count > 0


@cython.cclass
class StructuringCodegenPass:
    """Convertstructured regions to C code.

    This pass walks Loop and IncSwitch regions and emits appropriate C constructs.
    For Phase 1.3, this is a demonstration pass. Full integration with codegen
    happens in later phases.
    """
    stats = cython.declare(dict, visibility = "public")

    def __init__(self) -> None:
        """Initialize the codegen pass."""
        self.stats = {
            "loops_rendered": 0,
            "switches_rendered": 0,
            "gotos_emitted": 0,
        }

    @cython.ccall
    def render_loop(self, region: Region) -> object:
        """Render a loop region as C code.

        Args:
            region: Loop region to render

        Returns:
            C code string for the loop (simplified format)
        """
        loop_info = self._extract_loop_info(region)

        if loop_info.loop_type == "while":
            code = f"while ({loop_info.condition_expr or '1'}) {{\n"
            code += "  // loop body\n"
            code += "}"
        elif loop_info.loop_type == "do_while":
            code = "do {\n"
            code += "  // loop body\n"
            code += f"}} while ({loop_info.condition_expr});\n"
        elif loop_info.loop_type == "for":
            init = loop_info.init_stmt or ""
            cond = loop_info.condition_expr or "1"
            incr = loop_info.increment_stmt or ""
            code = f"for ({init}; {cond}; {incr}) {{\n"
            code += "  // loop body\n"
            code += "}"
        else:
            code = "// unknown loop type\n"

        if loop_info.uses_goto:
            code += f"\n{loop_info.exit_label}: // loop exit label\n"
        if loop_info.structuring_variables:
            joined = ", ".join(loop_info.structuring_variables)
            code += f"// structuring variables: {joined}\n"

        self.stats["loops_rendered"] += 1
        return code

    @cython.ccall
    def render_switch(self, region: Region) -> object:
        """Render a switch region as C code.

        Args:
            region: IncSwitch region to render

        Returns:
            C code string for the switch
        """
        case_label: object
        switch_info = self._extract_switch_info(region)

        code = f"switch ({switch_info.switch_expr or 'value'}) {{\n"

        for case_label in switch_info.case_targets:
            code += f"  case {case_label}:\n"
            code += "    // case body\n"
            if switch_info.uses_fallthrough:
                code += "    // fall through\n"
            else:
                code += "    break;\n"

        if switch_info.default_target:
            code += "  default:\n"
            code += "    // default case\n"
            code += "    break;\n"

        code += "}\n"

        if switch_info.uses_goto:
            code += "// complex switch with gotos\n"

        self.stats["switches_rendered"] += 1
        return code

    def _extract_loop_info(self, region: Region) -> LoopCodegenInfo:
        def _condition_expr_from_metadata() -> object:
            candidate: object
            edge_guard_hints = _metadata_sequence_8616(region.metadata.get("typed_condition_edge_guard_hints"))
            edge_guard_hint = _metadata_str_8616(edge_guard_hints[0]) if edge_guard_hints else None
            for candidate in (
                region.metadata.get("condition"),
                region.metadata.get("typed_ir_condition_hint"),
                edge_guard_hint,
            ):
                narrowed = _metadata_str_8616(candidate)
                if narrowed:
                    return narrowed
            return "cond"

        def _impl() -> LoopCodegenInfo:
            """Extract loop information from a Loop region.

            Args:
                region: Loop region

            Returns:
                LoopCodegenInfo with rendering parameters
            """
            abnormal_plan: object
            loop_meta: object
            loop_meta = region.metadata.get("loop_info")
            exit_label = None

            if loop_meta and hasattr(loop_meta, "exit_edges"):
                loop_meta_dynamic = cast(Any, loop_meta)
                exit_edges = _metadata_sequence_8616(loop_meta_dynamic.exit_edges)
                if len(exit_edges) == 1:
                    loop_type = "while"
                else:
                    loop_type = "do_while"
                    exit_label = f"__loop_exit_{region.region_id:x}"
            else:
                loop_type = "while"

            unstructured_exits = _metadata_sequence_8616(region.metadata.get("unstructured_exits"))
            unstructured_entries = _metadata_sequence_8616(region.metadata.get("unstructured_entries"))
            abnormal_plan = region.metadata.get("abnormal_loop_plan", {})
            structuring_variables = tuple(
                item
                for item in builtins.iter(_metadata_sequence_8616(region.metadata.get("structuring_variables")))
                if isinstance(item, str)
            )
            uses_goto = len(unstructured_exits) > 0 or len(unstructured_entries) > 0
            if abnormal_plan and not exit_label and uses_goto:
                exit_label = f"__loop_exit_{region.region_id:x}"

            # Handle NaturalLoopInfo dataclass
            body_regions: list[Region] = []
            if loop_meta and hasattr(loop_meta, "body_regions"):
                loop_meta_dynamic = cast(Any, loop_meta)
                body_regions = [
                    item for item in builtins.iter(_metadata_sequence_8616(loop_meta_dynamic.body_regions)) if isinstance(item, Region)
                ]

            return LoopCodegenInfo(
                loop_type=loop_type,
                condition_expr=_condition_expr_from_metadata(),
                init_stmt=_metadata_str_8616(region.metadata.get("init")),
                increment_stmt=_metadata_str_8616(region.metadata.get("increment")),
                body_regions=body_regions,
                exit_label=exit_label,
                uses_goto=uses_goto,
                structuring_variables=structuring_variables,
            )

        return _impl()

    @cython.ccall
    def _extract_switch_info(self, region: Region) -> SwitchCodegenInfo:
        """Extract switch information from an IncSwitch region.

        Args:
            region: IncSwitch region

        Returns:
            SwitchCodegenInfo with rendering parameters
        """
        switch_expr: object
        switch_lhs: object
        switch_candidates = _metadata_sequence_8616(region.metadata.get("switch_candidates"))
        case_values = _metadata_sequence_8616(region.metadata.get("switch_case_values"))
        if operator.eq(len(case_values), len(switch_candidates)):
            raw_case_targets = {
                str(value): target for value, target in builtins.iter(zip(case_values, switch_candidates, strict=True))
            }
        else:
            raw_case_targets = {f"0x{i:x}": target for i, target in builtins.iter(enumerate(switch_candidates))}
        case_targets = {label: target for label, target in builtins.iter(raw_case_targets.items()) if isinstance(target, Region)}
        uses_goto = _metadata_bool_8616(region.metadata.get("uses_goto"))
        switch_lhs = region.metadata.get("switch_condition_lhs")
        switch_expr = _metadata_str_8616(region.metadata.get("switch_expr")) or _metadata_str_8616(
            region.metadata.get("typed_ir_condition_hint")
        )
        if switch_expr is None and switch_lhs is not None:
            switch_expr = render_condition_operand_8616(switch_lhs)

        return SwitchCodegenInfo(
            switch_expr=switch_expr or "value",
            case_targets=case_targets,
            default_target=_metadata_region_8616(region.metadata.get("switch_default_target")),
            uses_fallthrough=_metadata_bool_8616(region.metadata.get("uses_fallthrough")),
            uses_goto=uses_goto,
        )

    @cython.ccall
    def apply(self, graph: RegionGraph) -> object:
        """Apply codegen to a structured region graph.

        Args:
            graph: The structured region graph

        Returns:
            Generated C code (simplified representation)
        """
        region: object
        code = []

        for region in graph.nodes:
            if operator.eq(region.region_type, RegionType.Loop):
                code.append(self.render_loop(region))
            elif operator.eq(region.region_type, RegionType.IncSwitch):
                code.append(self.render_switch(region))

        result = "\n".join(code)
        logger.info(
            f"Codegen complete: {self.stats['loops_rendered']} loops, {self.stats['switches_rendered']} switches"
        )
        return result


def _typed_edge_switch_regions_8616(graph: object) -> tuple[Region, ...]:
    if graph is None:
        return ()

    def _is_ready_typed_edge_switch(region: Region) -> cython.bint:
        artifact: object
        artifact = region.metadata.get("typed_edge_switch_region_artifact")
        if isinstance(artifact, dict):
            return artifact.get("status") == "ready"
        return bool(region.metadata.get("switch_detection") == "typed_condition_edge_cascade")

    return tuple(
        region
        for region in iter(graph.nodes)
        if operator.eq(region.region_type, RegionType.IncSwitch) and _is_ready_typed_edge_switch(region)
    )


@cython.ccall
def _statements_node_from_region_8616(region: Region, codegen: object) -> structured_c.CStatements | None:
    statements = tuple(region.statements or ())
    if not statements:
        return None
    if len(statements) == 1 and isinstance(statements[0], structured_c.CStatements):
        return statements[0]
    return structured_c.CStatements(list(statements), addr=region.block_addr, codegen=codegen)


@cython.ccall
def _region_by_id_8616(graph: object, region_id: object) -> Region | None:
    region: object
    if graph is None or not isinstance(region_id, int):
        return None
    for region in graph.nodes:
        if operator.eq(region.region_id, region_id):
            return region
    return None


def _typed_edge_switch_case_values_8616(region: Region) -> tuple[cython.longlong, ...]:
    artifact: object
    values: object
    artifact = region.metadata.get("typed_edge_switch_region_artifact")
    if isinstance(artifact, dict):
        values = artifact.get("case_values")
        if isinstance(values, (list, tuple)) and all(isinstance(value, int) for value in iter(values)):
            return tuple(int(value) for value in iter(values))
    return tuple(int(value) for value in builtins.iter(_metadata_sequence_8616(region.metadata.get("switch_case_values"))) if isinstance(value, int))


@cython.ccall
def _typed_edge_switch_default_region_8616(graph: RegionGraph | None, region: Region) -> Region | None:
    artifact: object
    default_region: object
    legacy_default: object
    artifact = region.metadata.get("typed_edge_switch_region_artifact")
    if isinstance(artifact, dict):
        default_region = _region_by_id_8616(graph, artifact.get("default_region_id"))
        if default_region is not None:
            return default_region
    legacy_default = region.metadata.get("switch_default_target")
    return legacy_default if isinstance(legacy_default, Region) else None


def _iter_non_statement_children_8616(node: object) -> tuple[object, ...]:
    child: object
    attr: object
    children: list[object] = []
    for attr in (
        "args",
        "callee_func",
        "callee_target",
        "condition",
        "initializer",
        "iterator",
        "lhs",
        "operand",
        "rhs",
        "switch",
        "variable",
        "index",
    ):
        child = getattr(node, attr, None)
        if child is not None:
            children.append(child)
    if isinstance(node, structured_c.CIfElse):
        children.extend(condition for condition, _ in builtins.iter(_c_ifelse_pairs_8616(node)))
    return tuple(children)


@cython.ccall
def _c_statement_owned_ins_addrs_8616(stmt: structured_c.CStatement) -> tuple[cython.longlong, ...]:
    current: object
    tags: object
    addrs: list[cython.longlong] = []
    pending: list[object] = [stmt]
    seen: set[cython.longlong] = set()
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
        if current is not stmt and isinstance(current, (structured_c.CStatement, structured_c.CStatements)):
            continue
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict) and isinstance(tags.get("ins_addr"), int):
            addrs.append(int(tags["ins_addr"]))
        pending.extend(reversed(_iter_non_statement_children_8616(current)))
    return tuple(dict.fromkeys(addrs))


@cython.ccall
def _c_node_provenance_key_8616(node: object) -> object:
    block_idx: object
    ins_addr: object
    stmt_idx: object
    tags: object
    vex_block_addr: object
    vex_stmt_idx: object
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return None
    vex_block_addr = tags.get("vex_block_addr")
    vex_stmt_idx = tags.get("vex_stmt_idx")
    if isinstance(vex_block_addr, int) and isinstance(vex_stmt_idx, int):
        return ("vex", int(vex_block_addr), int(vex_stmt_idx))
    block_idx = tags.get("block_idx")
    stmt_idx = tags.get("stmt_idx")
    if isinstance(block_idx, int) and isinstance(stmt_idx, int):
        return ("ail", int(block_idx), int(stmt_idx))
    ins_addr = tags.get("ins_addr")
    if isinstance(ins_addr, int) and isinstance(stmt_idx, int):
        return ("stmt", int(ins_addr), int(stmt_idx))
    return None


@cython.ccall
def _c_statement_owned_provenance_keys_8616(
    stmt: structured_c.CStatement,
) -> tuple[tuple[str, cython.longlong, cython.longlong], ...]:
    current: object
    key: object
    keys: list[tuple[str, cython.longlong, cython.longlong]] = []
    pending: list[object] = [stmt]
    seen: set[cython.longlong] = set()
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
        if current is not stmt and isinstance(current, (structured_c.CStatement, structured_c.CStatements)):
            continue
        key = _c_node_provenance_key_8616(current)
        if key is not None:
            keys.append(key)
        pending.extend(reversed(_iter_non_statement_children_8616(current)))
    return tuple(dict.fromkeys(keys))


def _iter_statement_tree_8616(node: object) -> tuple[structured_c.CStatement, ...]:
    """Return C statements nested under ``node`` without inspecting rendered text."""
    result: list[structured_c.CStatement] = []

    def _visit(current: object) -> None:
        _: object
        attr: object
        branch: object
        case_body: object
        child: object
        if isinstance(current, structured_c.CStatements):
            for child in _c_statements_items_8616(current):
                _visit(child)
            return
        if not isinstance(current, structured_c.CStatement):
            return
        result.append(current)
        if isinstance(current, structured_c.CIfElse):
            for _, branch in _c_ifelse_pairs_8616(current):
                _visit(branch)
            _visit(current.else_node)
            return
        for attr in ("body", "default"):
            _visit(getattr(current, attr, None))
        for _, case_body in _c_switch_cases_8616(current):
            _visit(case_body)

    _visit(node)
    return tuple(result)


@cython.ccall
def _iter_child_statement_lists_8616(stmt: structured_c.CStatement) -> tuple[structured_c.CStatements, ...]:
    child: object
    _: object
    attr: object
    branch: object
    case_body: object
    if isinstance(stmt, structured_c.CStatements):
        return (stmt,)
    children: list[structured_c.CStatements] = []
    if isinstance(stmt, structured_c.CIfElse):
        for _, branch in _c_ifelse_pairs_8616(stmt):
            if isinstance(branch, structured_c.CStatements):
                children.append(branch)
        else_node = stmt.else_node
        if isinstance(else_node, structured_c.CStatements):
            children.append(else_node)
    for attr in ("body", "default"):
        child = getattr(stmt, attr, None)
        if isinstance(child, structured_c.CStatements):
            children.append(child)
    for _, case_body in _c_switch_cases_8616(stmt):
        if isinstance(case_body, structured_c.CStatements):
            children.append(case_body)
    return tuple(children)


@cython.ccall
def _iter_child_statement_paths_8616(
    stmt: structured_c.CStatement,
    control_path: object,
) -> tuple[tuple[structured_c.CStatements, tuple[tuple[cython.longlong, str, cython.longlong], ...]], ...]:
    """Return child statement lists and distinguish control-flow alternatives."""
    child: object
    _: object
    attr: object
    branch: object
    branch_index: object
    case_body: object
    case_index: object
    child_index: object
    if isinstance(stmt, structured_c.CStatements):
        return ((stmt, control_path),)

    children: list[tuple[structured_c.CStatements, tuple[tuple[cython.longlong, str, cython.longlong], ...]]] = []
    marker = id(stmt)
    if isinstance(stmt, structured_c.CIfElse):
        for branch_index, (_, branch) in enumerate(_c_ifelse_pairs_8616(stmt)):
            if isinstance(branch, structured_c.CStatements):
                children.append((branch, (*control_path, (marker, "if", branch_index))))
        if isinstance(stmt.else_node, structured_c.CStatements):
            children.append((stmt.else_node, (*control_path, (marker, "else", 0))))
    for child_index, attr in enumerate(("body", "default")):
        child = getattr(stmt, attr, None)
        if isinstance(child, structured_c.CStatements):
            children.append((child, (*control_path, (marker, attr, child_index))))
    for case_index, (_, case_body) in enumerate(_c_switch_cases_8616(stmt)):
        if isinstance(case_body, structured_c.CStatements):
            children.append((case_body, (*control_path, (marker, "case", case_index))))
    return tuple(children)


@cython.ccall
def _c_statement_list_positions_8616(
    codegen: object,
) -> object:
    cfunc: object
    current: object
    index: object
    stmt: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    pending: object = [root] if isinstance(root, structured_c.CStatements) else []
    positions: dict[cython.longlong, tuple[list[object], cython.longlong]] = {}
    seen_lists: set[cython.longlong] = set()
    while pending:
        current = pending.pop()
        statements = current.statements
        if not isinstance(statements, list):
            continue
        list_id = id(statements)
        if list_id in seen_lists:
            continue
        seen_lists.add(list_id)
        for index, stmt in enumerate(statements):
            if isinstance(stmt, structured_c.CStatements):
                pending.append(stmt)
                continue
            if not isinstance(stmt, structured_c.CStatement):
                continue
            positions[id(stmt)] = (statements, index)
            pending.extend(reversed(_iter_child_statement_lists_8616(stmt)))
    return positions


@cython.ccall
def _c_statements_node_positions_8616(
    codegen: object,
) -> object:
    cfunc: object
    current: object
    index: object
    stmt: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    pending: object = [root] if isinstance(root, structured_c.CStatements) else []
    positions: dict[cython.longlong, tuple[list[object], cython.longlong]] = {}
    seen_lists: set[cython.longlong] = set()
    while pending:
        current = pending.pop()
        statements = current.statements
        if not isinstance(statements, list):
            continue
        list_id = id(statements)
        if list_id in seen_lists:
            continue
        seen_lists.add(list_id)
        for index, stmt in enumerate(statements):
            if isinstance(stmt, structured_c.CStatements):
                positions[id(stmt)] = (statements, index)
                pending.append(stmt)
                continue
            if not isinstance(stmt, structured_c.CStatement):
                continue
            pending.extend(reversed(_iter_child_statement_lists_8616(stmt)))
    return positions


def _c_statement_list_paths_8616(
    codegen: object,
) -> object:
    cfunc: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    paths: dict[cython.longlong, tuple[str, ...]] = {}
    seen_nodes: set[cython.longlong] = set()

    def _visit(current: object, path: object) -> None:
        child: object
        child_list: object
        index: object
        if not isinstance(current, structured_c.CStatements):
            return
        marker = id(current)
        if marker in seen_nodes:
            return
        seen_nodes.add(marker)
        statements = current.statements
        if isinstance(statements, list):
            paths[id(statements)] = path
        for index, child in enumerate(_c_statements_items_8616(current)):
            if isinstance(child, structured_c.CStatements):
                _visit(child, tuple(path) + (f"CStatements[{index}]",))
                continue
            if not isinstance(child, structured_c.CStatement):
                continue
            for child_list in _iter_child_statement_lists_8616(child):
                _visit(child_list, tuple(path) + (f"{type(child).__name__}[{index}]", "child"))

    _visit(root, ("root",))
    return paths


@cython.ccall
def _c_statement_container_shapes_8616(
    codegen: object,
) -> object:
    cfunc: object
    current: object
    index: object
    stmt: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    pending: object = [root] if isinstance(root, structured_c.CStatements) else []
    shapes: dict[cython.longlong, dict[str, object]] = {}
    seen_lists: set[cython.longlong] = set()
    while pending:
        current = pending.pop()
        statements = current.statements
        if not isinstance(statements, (list, tuple)):
            continue
        list_id = id(statements)
        if list_id in seen_lists:
            continue
        seen_lists.add(list_id)
        for index, stmt in enumerate(statements):
            if isinstance(stmt, structured_c.CStatements):
                pending.append(stmt)
                continue
            if not isinstance(stmt, structured_c.CStatement):
                continue
            shapes[id(stmt)] = {
                "container_type": type(statements).__name__,
                "index": int(index),
                "mutable": isinstance(statements, list),
            }
            pending.extend(reversed(_iter_child_statement_lists_8616(stmt)))
    return shapes


@cython.ccall
def _walk_c_statement_paths_8616(
    current: object,
    path: object,
    paths: object,
    seen: object,
) -> None:
    """Record the structured-C parent path for each reachable statement."""
    _: object
    attr: object
    branch: object
    case_body: object
    child: object
    index: object
    if current is None:
        return
    if isinstance(current, structured_c.CStatements):
        statements = _c_statements_items_8616(current)
        for index, child in enumerate(statements):
            _walk_c_statement_paths_8616(child, tuple(path) + (f"CStatements[{index}]",), paths, seen)
        return
    if not isinstance(current, structured_c.CStatement):
        return
    marker = id(current)
    if marker in seen:
        return
    seen.add(marker)
    paths[marker] = (*path, type(current).__name__)
    if isinstance(current, structured_c.CIfElse):
        for index, (_, branch) in enumerate(_c_ifelse_pairs_8616(current)):
            _walk_c_statement_paths_8616(branch, tuple(paths[marker]) + (f"if_branch[{index}]",), paths, seen)
        _walk_c_statement_paths_8616(current.else_node, tuple(paths[marker]) + ("else",), paths, seen)
        return
    for attr in ("body", "default"):
        _walk_c_statement_paths_8616(getattr(current, attr, None), tuple(paths[marker]) + (attr,), paths, seen)
    for index, (_, case_body) in enumerate(_c_switch_cases_8616(current)):
        _walk_c_statement_paths_8616(case_body, tuple(paths[marker]) + (f"case[{index}]",), paths, seen)


@cython.dataclasses.dataclass()
class _CStatementOwnership8616:
    """Address/provenance ownership maps built during one statement walk."""

    by_addr: object = field(default_factory=dict)
    by_key: object = field(default_factory=dict)

    @cython.ccall
    def _record(self, owner: structured_c.CStatement, stmt: structured_c.CStatement) -> None:
        ins_addr: object
        key: object
        for ins_addr in _c_statement_owned_ins_addrs_8616(stmt):
            self.by_addr.setdefault(ins_addr, []).append(owner)
        for key in _c_statement_owned_provenance_keys_8616(stmt):
            self.by_key.setdefault(key, []).append(owner)

    @cython.ccall
    def visit(
        self,
        current: object,
        positioned_owner: structured_c.CStatement | None,
        statement_positions: object,
    ) -> None:
        """Attribute each statement to the nearest positioned owner."""
        owner: object
        _: object
        attr: object
        branch: object
        case_body: object
        child: object
        if isinstance(current, structured_c.CStatements):
            for child in _c_statements_items_8616(current):
                self.visit(child, positioned_owner, statement_positions)
            return
        if not isinstance(current, structured_c.CStatement):
            return
        owner = current if id(current) in statement_positions else positioned_owner
        if owner is not None:
            self._record(owner, current)
        if isinstance(current, structured_c.CIfElse):
            for _, branch in _c_ifelse_pairs_8616(current):
                self.visit(branch, owner, statement_positions)
            self.visit(current.else_node, owner, statement_positions)
            return
        for attr in ("body", "default"):
            self.visit(getattr(current, attr, None), owner, statement_positions)
        for _, case_body in _c_switch_cases_8616(current):
            self.visit(case_body, owner, statement_positions)


@cython.ccall
def _c_statement_parent_paths_8616(
    codegen: object,
) -> object:
    cfunc: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    paths: dict[cython.longlong, tuple[str, ...]] = {}
    seen: set[cython.longlong] = set()
    _walk_c_statement_paths_8616(root, ("root",), paths, seen)
    return paths


@cython.ccall
def _c_positioned_statement_ownership_8616(
    codegen: object,
    statement_positions: object,
) -> tuple[
    dict[cython.longlong, tuple[structured_c.CStatement, ...]],
    dict[tuple[str, cython.longlong, cython.longlong], tuple[structured_c.CStatement, ...]],
]:
    top_level_statement: object
    top_level_statements = _top_level_c_statements_8616(codegen)
    ownership = _CStatementOwnership8616()
    for top_level_statement in top_level_statements:
        ownership.visit(top_level_statement, None, statement_positions)
    statements_by_addr = ownership.by_addr
    statements_by_key = ownership.by_key
    return (
        {
            addr: _dedupe_c_statements_by_identity_8616(tuple(statements))
            for addr, statements in builtins.iter(statements_by_addr.items())
        },
        {
            key: _dedupe_c_statements_by_identity_8616(tuple(statements))
            for key, statements in builtins.iter(statements_by_key.items())
        },
    )


def _statement_scope_debug_summary_8616(
    covered_statements: object,
    statement_positions: object,
    *,
    top_level_statements: object,
) -> tuple[dict[str, object], ...]:
    position: object
    addr: object
    group: object
    stmt: object
    groups: dict[cython.longlong, dict[str, Any]] = {}
    top_level_ids = {id(stmt) for stmt in iter(top_level_statements)}
    for stmt in covered_statements:
        position = statement_positions.get(id(stmt))
        if position is None:
            continue
        statements, index = position
        group = groups.setdefault(
            id(statements),
            {
                "addr_counts": {},
                "count": 0,
                "indexes": set(),
                "top_level": statements is getattr(
                    getattr(getattr(stmt, "codegen", None), "cfunc", None),
                    "statements",
                    None,
                ),
                "top_level_statement_count": 0,
                "structured_count": 0,
            },
        )
        group["count"] = int(group["count"]) + 1
        group["indexes"].add(int(index))
        if id(stmt) in top_level_ids:
            group["top_level_statement_count"] = int(group["top_level_statement_count"]) + 1
        if _structured_control_statement_8616(stmt):
            group["structured_count"] = int(group["structured_count"]) + 1
        for addr in _c_statement_owned_ins_addrs_8616(stmt):
            addr_counts: object = group["addr_counts"]
            addr_counts[int(addr)] = int(addr_counts.get(int(addr), 0) or 0) + 1
    result: list[dict[str, object]] = []
    for group in sorted(tuple(groups.values()), key=lambda item: int(item["count"]), reverse=True)[:8]:
        indexes = sorted(group["indexes"])
        addr_counts = group["addr_counts"]
        top_addrs = sorted(tuple(addr_counts.items()), key=lambda item: (-int(item[1]), int(item[0])))[:12]
        result.append(
            {
                "addr_counts": [[int(addr), int(count)] for addr, count in iter(top_addrs)],
                "count": int(group["count"]),
                "index_count": len(indexes),
                "span": [indexes[0], indexes[-1] + 1] if indexes else None,
                "top_level_statement_count": int(group["top_level_statement_count"]),
                "structured_count": int(group["structured_count"]),
            }
        )
    return tuple(result)


@cython.ccall
def _owner_node_position_8616(
    statements_node_positions: object,
    container: object,
) -> object:
    """Find the CStatements node whose ``statements`` list is ``container``."""
    node_id: object
    position: object
    for node_id, position in statements_node_positions.items():
        candidate_parent, candidate_index = position
        if 0 <= candidate_index < len(candidate_parent) and operator.eq(id(candidate_parent[candidate_index]), node_id):
            candidate_node = candidate_parent[candidate_index]
            if isinstance(candidate_node, structured_c.CStatements) and candidate_node.statements is container:
                return (candidate_parent, int(candidate_index))
    return None


def _statement_container_parent_span_8616(
    covered_statements: object,
    statement_positions: object,
    statements_node_positions: object,
) -> object:
    owner_node_position: object
    position: object
    container: object
    container_id: object
    stmt: object
    container_by_id: dict[cython.longlong, list[object]] = {}
    covered_by_container: dict[cython.longlong, set[cython.longlong]] = {}
    for stmt in covered_statements:
        position = statement_positions.get(id(stmt))
        if position is None:
            return None
        container, index = position
        container_by_id[id(container)] = container
        covered_by_container.setdefault(id(container), set()).add(int(index))
    if not container_by_id:
        return None

    parent_positions: list[tuple[list[object], cython.longlong, list[object], cython.longlong, cython.longlong, cython.longlong]] = []
    for container_id, container in container_by_id.items():
        owner_node_position = _owner_node_position_8616(statements_node_positions, container)
        if owner_node_position is None:
            return None
        indexes = covered_by_container[container_id]
        parent, parent_index = owner_node_position
        parent_positions.append((parent, parent_index, container, min(indexes), max(indexes) + 1, len(indexes)))

    parent_ids = {id(item[0]) for item in iter(parent_positions)}
    if len(parent_ids) != 1:
        return None
    parent = parent_positions[0][0]
    parent_indexes = sorted(item[1] for item in iter(parent_positions))
    if operator.ne(set(parent_indexes), set(range(parent_indexes[0], parent_indexes[-1] + 1))):
        return None
    return {
        "parent": parent,
        "span": [parent_indexes[0], parent_indexes[-1] + 1],
        "container_count": len(parent_positions),
        "containers": [
            {
                "parent_index": int(parent_index),
                "covered_span": [int(start), int(end)],
                "covered_count": int(count),
                "container_len": len(container),
            }
            for _, parent_index, container, start, end, count in builtins.iter(sorted(parent_positions, key=lambda item: item[1]))
        ],
    }


@cython.ccall
def _statement_container_path_summary_8616(
    covered_statements: object,
    statement_positions: object,
    statement_list_paths: object,
) -> dict[str, object]:
    path: object
    position: object
    container_id: object
    count: object
    parts: object
    stmt: object
    containers: dict[cython.longlong, list[object]] = {}
    counts: Counter[cython.longlong] = Counter()
    paths: list[tuple[str, ...]] = []
    for stmt in covered_statements:
        position = statement_positions.get(id(stmt))
        if position is None:
            continue
        container, _ = position
        containers[id(container)] = container
        counts[id(container)] += 1
    samples: list[dict[str, object]] = []
    for container_id, count in counts.most_common(12):
        path = statement_list_paths.get(container_id, ())
        if path:
            paths.append(path)
        samples.append(
            {
                "count": int(count),
                "path_tail": list(path[-8:]) if path else [],
            }
        )
    common_prefix: tuple[str, ...] = ()
    if paths:
        common: list[str] = []
        for parts in zip(*paths, strict=False):
            if len(set(parts)) != 1:
                break
            common.append(parts[0])
        common_prefix = tuple(common)
    return {
        "container_count": len(containers),
        "common_prefix_tail": list(common_prefix[-8:]),
        "common_prefix_len": len(common_prefix),
        "samples": samples,
    }


def _container_path_summary_has_divergent_structured_children_8616(summary: object) -> cython.bint:
    common_prefix_len: object
    path_tail: object
    samples: object
    sample: object
    common_prefix_len = summary.get("common_prefix_len")
    if not isinstance(common_prefix_len, int) or common_prefix_len > 1:
        return False
    samples = summary.get("samples")
    if not isinstance(samples, list):
        return False
    structured_markers = ("CDoWhileLoop", "CForLoop", "CIfElse", "CSwitchCase", "CWhileLoop")
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        path_tail = sample.get("path_tail")
        if not isinstance(path_tail, list):
            continue
        if any(isinstance(part, str) and part.startswith(structured_markers) for part in iter(path_tail)):
            return True
    return False


@cython.ccall
def _debug_tag_value_8616(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_debug_tag_value_8616(item) for item in iter(tuple(value)[:8])]
    return type(value).__name__


def _statement_provenance_debug_summary_8616(
    covered_statements: object,
    statement_positions: object,
) -> dict[str, object]:
    idx_value: object
    position: object
    tags: object
    ordinal: object
    stmt: object
    class_counts: Counter[str] = Counter(type(stmt).__name__ for stmt in iter(covered_statements))
    tag_key_counts: Counter[str] = Counter()
    idx_counts: Counter[object] = Counter()
    samples: list[dict[str, object]] = []
    sample_budget = 16
    for ordinal, stmt in enumerate(covered_statements):
        tags = getattr(stmt, "tags", None)
        tag_keys: tuple[str, ...] = ()
        if isinstance(tags, dict):
            tag_keys = tuple(sorted(str(key) for key in iter(tags)))
            tag_key_counts.update(tag_keys)
        idx_value = getattr(stmt, "idx", None)
        idx_counts[_debug_tag_value_8616(idx_value)] += 1
        if len(samples) >= sample_budget:
            continue
        position = statement_positions.get(id(stmt))
        sample: dict[str, object] = {
            "ordinal": ordinal,
            "class": type(stmt).__name__,
            "idx": _debug_tag_value_8616(idx_value),
            "owned_ins_addrs": list(_c_statement_owned_ins_addrs_8616(stmt)),
        }
        if position is not None:
            sample["position"] = [int(position[1])]
        if isinstance(tags, dict):
            sample["tags"] = {str(key): _debug_tag_value_8616(value) for key, value in builtins.iter(sorted(tuple(tags.items())))}
        samples.append(sample)
    top_idx_counts = sorted(tuple(idx_counts.items()), key=lambda item: (-int(item[1]), str(item[0])))[:16]
    return {
        "class_counts": dict(sorted(tuple(class_counts.items()))),
        "tag_key_counts": dict(sorted(tuple(tag_key_counts.items()))),
        "idx_counts_top": {str(key): int(value) for key, value in iter(top_idx_counts)},
        "idx_unique_count": len(idx_counts),
        "samples": samples,
        "sample_limit": sample_budget,
        "total": len(covered_statements),
    }


@cython.ccall
def _statement_position_debug_samples_8616(
    statements: object,
    statement_positions: object,
    statement_container_shapes: object,
    statement_parent_paths: object,
    *,
    limit: cython.longlong = 8,
) -> object:
    parent_path: object
    position: object
    shape: object
    ordinal: object
    stmt: object
    samples: list[dict[str, object]] = []
    for ordinal, stmt in enumerate(statements[:limit]):
        position = statement_positions.get(id(stmt))
        sample: dict[str, object] = {
            "ordinal": ordinal,
            "class": type(stmt).__name__,
            "has_position": position is not None,
            "owned_ins_addrs": list(_c_statement_owned_ins_addrs_8616(stmt)),
            "owned_key_count": len(_c_statement_owned_provenance_keys_8616(stmt)),
        }
        if position is not None:
            sample["position"] = [int(position[1])]
        shape = statement_container_shapes.get(id(stmt))
        if isinstance(shape, dict):
            sample["container"] = dict(shape)
        parent_path = statement_parent_paths.get(id(stmt))
        if parent_path:
            sample["parent_path_tail"] = list(parent_path[-8:])
        samples.append(sample)
    return samples


@cython.ccall
def _c_statement_ownership_8616(
    codegen: object,
) -> tuple[
    dict[cython.longlong, tuple[structured_c.CStatement, ...]],
    dict[tuple[str, cython.longlong, cython.longlong], tuple[structured_c.CStatement, ...]],
    dict[cython.longlong, cython.longlong],
]:
    ins_addr: object
    key: object
    stmt: object
    top_level_index: object
    top_level_statement: object
    top_level_statements = _top_level_c_statements_8616(codegen)
    statements_by_addr: dict[cython.longlong, list[structured_c.CStatement]] = {}
    statements_by_key: dict[tuple[str, cython.longlong, cython.longlong], list[structured_c.CStatement]] = {}
    owner_index_by_statement_id: dict[cython.longlong, cython.longlong] = {}
    for top_level_index, top_level_statement in enumerate(top_level_statements):
        for stmt in _iter_statement_tree_8616(top_level_statement):
            owner_index_by_statement_id[id(stmt)] = top_level_index
            for ins_addr in _c_statement_owned_ins_addrs_8616(stmt):
                statements_by_addr.setdefault(ins_addr, []).append(stmt)
            for key in _c_statement_owned_provenance_keys_8616(stmt):
                statements_by_key.setdefault(key, []).append(stmt)
    return (
        {addr: tuple(statements) for addr, statements in builtins.iter(statements_by_addr.items())},
        {key: tuple(statements) for key, statements in builtins.iter(statements_by_key.items())},
        owner_index_by_statement_id,
    )


def _top_level_c_statements_8616(codegen: object) -> tuple[structured_c.CStatement, ...]:
    cfunc: object
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if not isinstance(root, structured_c.CStatements):
        return ()
    return tuple(
        stmt
        for stmt in builtins.iter(tuple(root.statements or ()))
        if isinstance(stmt, structured_c.CStatement)
    )


@cython.ccall
def _switch_case_target_regions_8616(graph: RegionGraph) -> object:
    """Collect switch case and default regions hidden outside graph nodes."""
    default_region: object
    case_region: object
    switch_region: object
    regions: list[Region] = []
    for switch_region in _typed_edge_switch_regions_8616(graph):
        for case_region in _metadata_regions_8616(switch_region.metadata.get("switch_candidates")):
            regions.append(case_region)  # noqa: PERF402
        default_region = switch_region.metadata.get("switch_default_target")
        if isinstance(default_region, Region):
            regions.append(default_region)
    return regions


def _populate_linear_region_statements_8616(
    region: Region,
    statements_by_addr: object,
    statements_by_key: object,
) -> cython.bint:
    """Attach owned statements to one empty linear region; return success."""
    if operator.ne(region.region_type, RegionType.Linear) or region.block_addr is None:
        return False
    if _region_raw_statements_8616(region):
        return False
    region_keys = _metadata_provenance_keys_8616(region.metadata.get("region_statement_provenance_keys"))
    region_addrs = _metadata_ints_8616(region.metadata.get("region_statement_ins_addrs"))
    if not region_addrs:
        region_addrs = (int(region.block_addr),)
    statements = tuple(stmt for key in iter(region_keys) for stmt in builtins.iter(statements_by_key.get(key, ())))
    if not statements:
        statements = tuple(
            stmt
            for addr in iter(region_addrs)
            for stmt in builtins.iter(statements_by_addr.get(int(addr), ()))
        )
    if not statements:
        return False
    region.statements.extend(statements)
    return True


def _populate_region_statements_from_cfunc_8616(graph: RegionGraph, codegen: object) -> cython.longlong:
    """Attach exact-address C statements to empty linear regions.

    This is a guarded bridge from the current decompiler C AST into the
    structuring graph. It deliberately uses only statement-owned ``ins_addr``
    tags that exactly match a region block address; rendered C and AIL
    statements are refused until region span evidence exists.
    """
    region: object
    statements_by_addr, statements_by_key, _ = _c_statement_ownership_8616(codegen)
    if not statements_by_addr and not statements_by_key:
        return 0

    regions: list[Region] = list(graph.nodes)
    regions.extend(_switch_case_target_regions_8616(graph))

    populated = 0
    for region in sorted(tuple(dict.fromkeys(regions)), key=lambda item: int(item.region_id or 0)):
        populated += int(
            _populate_linear_region_statements_8616(region, statements_by_addr, statements_by_key)
        )
    return populated


@cython.ccall
def _populate_switch_expr_ast_from_typed_lhs_8616(region: Region, codegen: object) -> cython.bint:
    lhs: object
    project: object
    if isinstance(region.metadata.get("switch_expr_ast"), structured_c.CExpression):
        return False
    lhs = region.metadata.get("switch_condition_lhs")
    if not isinstance(lhs, IRValue):
        return False
    project = getattr(codegen, "project", None)
    if project is None:
        return False
    expr = lower_ir_value_to_c_expr_8616(lhs, project, codegen, resolve_register_name=True)
    if not isinstance(expr, structured_c.CExpression):
        return False
    region.metadata["switch_expr_ast"] = expr
    region.metadata["switch_expr_ast_source"] = "typed_switch_condition_lhs"
    return True


def _region_raw_statements_8616(region: Region) -> tuple[structured_c.CStatement, ...]:
    stmt: object
    result: list[structured_c.CStatement] = []
    for stmt in tuple(region.statements or ()):
        if isinstance(stmt, structured_c.CStatements):
            result.extend(
                child
                for child in builtins.iter(tuple(stmt.statements or ()))
                if isinstance(child, structured_c.CStatement)
            )
        elif isinstance(stmt, structured_c.CStatement):
            result.append(stmt)
    return tuple(result)


@cython.ccall
def _top_level_statements_for_addrs_8616(
    statements_by_addr: object,
    addrs: object,
) -> object:
    statements: object
    addr: object
    result: list[structured_c.CStatement] = []
    for addr in addrs:
        statements = statements_by_addr.get(int(addr), ())
        if not statements:
            return None
        result.extend(statements)
    return tuple(result)


@cython.ccall
def _available_statements_for_addrs_8616(
    statements_by_addr: object,
    addrs: object,
) -> object:
    addr: object
    result: list[structured_c.CStatement] = []
    for addr in addrs:
        result.extend(statements_by_addr.get(int(addr), ()))
    return tuple(result) if result else None


@cython.ccall
def _available_statements_for_keys_8616(
    statements_by_key: object,
    keys: object,
) -> object:
    key: object
    result: list[structured_c.CStatement] = []
    for key in keys:
        result.extend(statements_by_key.get(key, ()))
    return tuple(result) if result else None


@cython.ccall
def _dedupe_c_statements_by_identity_8616(
    statements: object,
) -> tuple[structured_c.CStatement, ...]:
    stmt: object
    result: list[structured_c.CStatement] = []
    seen: set[cython.longlong] = set()
    for stmt in statements:
        marker = id(stmt)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(stmt)
    return tuple(result)


@cython.dataclasses.dataclass
class SharedCallOccurrenceStats8616:
    """Evidence loop for shared call-expression occurrence normalization."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@cython.dataclasses.dataclass
class DistinctConditionCallOccurrenceStats8616:
    """Evidence loop for separating distinct binary calls aliased in one C AST node."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class _ConditionRoot8616:
    """One writable condition-expression root at the third-party C AST boundary."""

    statement: structured_c.CStatement
    branch_index: int | None
    expression: structured_c.CExpression


class _SharedCallCFunctionSurface8616(Protocol):
    """Third-party C-function field consumed by shared-call normalization."""

    statements: object


class _SharedCallCodegenSurface8616(Protocol):
    """Typed view of angr codegen fields used by shared-call normalization."""

    cfunc: _SharedCallCFunctionSurface8616
    _inertia_callsite_summaries: object
    _inertia_callsite_summary_inventory_8616: object
    _inertia_distinct_condition_call_occurrence_stats_8616: (
        DistinctConditionCallOccurrenceStats8616
    )
    _inertia_shared_call_occurrence_stats_8616: SharedCallOccurrenceStats8616


@cython.ccall
def _direct_statement_call_8616(
    statement: structured_c.CStatement,
) -> structured_c.CFunctionCall | None:
    """Return a direct call carried by an angr expression statement or assignment."""
    if isinstance(statement, structured_c.CExpressionStatement):
        return statement.expr if isinstance(statement.expr, structured_c.CFunctionCall) else None
    if isinstance(statement, structured_c.CAssignment):
        return statement.rhs if isinstance(statement.rhs, structured_c.CFunctionCall) else None
    return None


@cython.ccall
def _expression_calls_8616(expression: object) -> tuple[structured_c.CFunctionCall, ...]:
    """Return calls from a typed subset of the third-party angr expression tree."""
    current: object
    calls: list[structured_c.CFunctionCall] = []
    pending: list[object] = [expression]
    seen: set[cython.longlong] = set()
    while pending:
        current = pending.pop()
        if current is None:
            continue
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        if isinstance(current, structured_c.CFunctionCall):
            calls.append(current)
            pending.extend(reversed(tuple(current.args or ())))
        elif isinstance(current, structured_c.CBinaryOp):
            pending.extend((current.rhs, current.lhs))
        elif isinstance(current, structured_c.CUnaryOp):
            pending.append(current.operand)
        elif isinstance(current, structured_c.CTypeCast):
            pending.append(current.expr)
        elif isinstance(current, structured_c.CITE):
            pending.extend((current.iffalse, current.iftrue, current.cond))
    return tuple(calls)


def _condition_roots_8616(statement: structured_c.CStatement) -> tuple[_ConditionRoot8616, ...]:
    """Return writable condition roots from one third-party structured statement."""
    if isinstance(statement, structured_c.CIfElse):
        return tuple(
            _ConditionRoot8616(statement, branch_index, condition)
            for branch_index, (condition, _branch) in builtins.iter(enumerate(_c_ifelse_pairs_8616(statement)))
        )
    if isinstance(
        statement,
        (
            structured_c.CIfBreak,
            structured_c.CDoWhileLoop,
            structured_c.CForLoop,
            structured_c.CWhileLoop,
        ),
    ):
        return (_ConditionRoot8616(statement, None, statement.condition),)
    return ()


def _condition_calls_8616(statement: structured_c.CStatement) -> object:
    """Return calls embedded in one structured statement condition."""
    if isinstance(statement, structured_c.CStatements):
        children = _c_statements_items_8616(statement)
        if len(children) == 1 and isinstance(children[0], structured_c.CStatement):
            return _condition_calls_8616(children[0])
        return ()
    return tuple(
        call
        for condition_root in builtins.iter(_condition_roots_8616(statement))
        for call in builtins.iter(_expression_calls_8616(condition_root.expression))
    )


@cython.ccall
def _replace_condition_root_8616(
    root: _ConditionRoot8616,
    replacement: structured_c.CExpression,
) -> cython.bint:
    """Replace one complete condition subtree at its third-party owner."""
    branch_index: object
    statement = root.statement
    if isinstance(statement, structured_c.CIfElse):
        branch_index = root.branch_index
        pairs = list(_c_ifelse_pairs_8616(statement))
        if branch_index is None or branch_index >= len(pairs):
            return False
        condition, branch = pairs[branch_index]
        if condition is not root.expression:
            return False
        pairs[branch_index] = (replacement, branch)
        statement.condition_and_nodes = pairs
        return True
    if isinstance(
        statement,
        (
            structured_c.CIfBreak,
            structured_c.CDoWhileLoop,
            structured_c.CForLoop,
            structured_c.CWhileLoop,
        ),
    ):
        statement.condition = replacement
        return True
    return False


@cython.ccall
def _validated_callsite_inventory_8616(
    carrier: _SharedCallCodegenSurface8616,
) -> object:
    """Return the authoritative owned callsite inventory or fail its contract."""
    callsite_addr: object
    summary: object
    try:
        inventory = carrier._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return {}
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory carrier must be a dict")
    for callsite_addr, summary in inventory.items():
        if not isinstance(callsite_addr, int) or not isinstance(summary, CallsiteSummary8616):
            raise TypeError("callsite summary inventory contains an invalid owned contract")
        if operator.ne(summary.callsite_addr, callsite_addr):
            raise TypeError(
                "callsite summary inventory key does not match the summary callsite address"
            )
    return inventory


@cython.ccall
def _summary_for_direct_call_occurrence_8616(
    call: structured_c.CFunctionCall,
    summary_map: object,
    inventory: Mapping[cython.longlong, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve one call occurrence from node identity or an exact instruction tag.

    AST regeneration may clone a call after summary attachment. The immutable
    machine-call inventory remains authoritative in that case; target names and
    source order are deliberately insufficient evidence.
    """
    callsite_addr: object
    summary: object
    summary = summary_map.get(id(call))
    if summary is not None:
        return summary
    callsite_addr = structured_callsite_addr_8616(call)
    if callsite_addr is None:
        return None
    summary = inventory.get(callsite_addr)
    if summary is None:
        return None
    summary_map[id(call)] = summary
    return summary


def _inventory_has_unique_target_callsite_8616(
    inventory: Mapping[cython.longlong, CallsiteSummary8616],
    target_addr: cython.longlong,
) -> cython.bint:
    """Return whether one machine callsite uniquely owns a direct target."""
    return (
        sum(
            1
            for inventory_summary in builtins.iter(inventory.values())
            if operator.eq(inventory_summary.target_addr, target_addr)
        )
        == 1
    )


def _same_regenerated_call_surface_8616(
    lhs: structured_c.CFunctionCall,
    rhs: structured_c.CFunctionCall,
) -> cython.bint:
    """Compare a bound call with a clone that lost only its angr Function carrier.

    Equal string targets are clone evidence here, not semantic target recovery:
    the caller must separately require a typed predecessor and a unique binary
    callsite for its proven numeric target.
    """
    if _same_c_expression_8616(lhs, rhs):
        return True
    if (
        not isinstance(lhs.callee_target, str)
        or not lhs.callee_target
        or operator.ne(lhs.callee_target, rhs.callee_target)
    ):
        return False
    lhs_args = tuple(lhs.args or ())
    rhs_args = tuple(rhs.args or ())
    return operator.eq(len(lhs_args), len(rhs_args)) and all(
        _same_c_expression_8616(lhs_arg, rhs_arg)
        for lhs_arg, rhs_arg in builtins.iter(zip(lhs_args, rhs_args, strict=True))
    )


@cython.ccall
def _retag_cloned_callsite_8616(
    call: structured_c.CFunctionCall,
    inherited_summary: CallsiteSummary8616,
    replacement_summary: CallsiteSummary8616,
) -> None:
    """Replace only the proven identity inherited by a cloned call node."""
    rebind_cloned_structured_callsite_identity_8616(
        call,
        inherited_summary,
        replacement_summary,
    )


@cython.ccall
def _collect_condition_call_occurrences_8616(
    block: structured_c.CStatements,
    occurrences_by_call: object,
    seen_statement_lists: object,
) -> None:
    """Collect condition calls in deterministic structured execution order."""
    _control_path: object
    call: object
    child: object
    condition_root: object
    statement: object
    statements = block.statements
    if not isinstance(statements, list) or id(statements) in seen_statement_lists:
        return
    seen_statement_lists.add(id(statements))
    for statement in statements:
        if not isinstance(
            statement,
            (structured_c.CStatement, structured_c.CDirtyStatement),
        ):
            raise TypeError(
                "angr CStatements contains a non-CStatement value: "
                f"{type(statement).__module__}.{type(statement).__qualname__}"
            )
        for condition_root in _condition_roots_8616(statement):
            for call in _expression_calls_8616(condition_root.expression):
                occurrences_by_call.setdefault(id(call), []).append((condition_root, call))
        for child, _control_path in _iter_child_statement_paths_8616(statement, ()):
            _collect_condition_call_occurrences_8616(child, occurrences_by_call, seen_statement_lists)


@cython.ccall
def _clone_occurrence_conditions_8616(
    occurrences: object,
    existing_summary: CallsiteSummary8616,
    candidates: object,
) -> object:
    """Clone each extra occurrence's condition and retag its callsite."""
    clone: object
    condition_root: object
    original: object
    summary: object
    replacements: list[
        tuple[
            _ConditionRoot8616,
            structured_c.CExpression,
            structured_c.CFunctionCall,
            CallsiteSummary8616,
        ]
    ] = []
    for (condition_root, original), summary in zip(
        occurrences[1:],
        candidates[1:],
        strict=True,
    ):
        clone_memo: dict[cython.longlong, object] = {}
        cloned_condition = _clone_c_ast_tree_8616(
            condition_root.expression,
            clone_memo,
        )
        clone = clone_memo.get(id(original))
        if not isinstance(cloned_condition, structured_c.CExpression) or not isinstance(
            clone,
            structured_c.CFunctionCall,
        ):
            return []
        _retag_cloned_callsite_8616(clone, existing_summary, summary)
        replacements.append((condition_root, cloned_condition, clone, summary))
    return replacements


def _split_call_occurrences_8616(
    call_id: cython.longlong,
    occurrences: object,
    summary_map: object,
    inventory: Mapping[cython.longlong, CallsiteSummary8616],
    represented_elsewhere: object,
    stats: DistinctConditionCallOccurrenceStats8616,
    debug_groups: object,
) -> cython.bint:
    """Split one call's occurrences; return True when materialized."""
    existing_summary: object
    _cloned_condition: object
    _condition_root: object
    clone: object
    summary: object
    if len(occurrences) < 2:
        return False
    stats.raw_fact_count += 1
    existing_summary = summary_map.get(call_id)
    if existing_summary is None or not isinstance(existing_summary.target_addr, int):
        stats.failure_count += 1
        debug_groups.append((call_id, len(occurrences), None, (), "missing-summary"))
        return False
    candidates = tuple(
        summary
        for callsite_addr, summary in builtins.iter(sorted(tuple(inventory.items())))
        if operator.eq(summary.target_addr, existing_summary.target_addr)
        and callsite_addr not in represented_elsewhere
    )

    def _fail(reason: object) -> cython.bint:
        stats.failure_count += 1
        debug_groups.append(
            (
                call_id,
                len(occurrences),
                existing_summary.callsite_addr,
                tuple(summary.callsite_addr for summary in iter(candidates)),
                reason,
            )
        )
        return False

    if existing_summary not in candidates:
        return _fail("existing-summary-not-candidate")
    stats.normalized_fact_count += 1
    if operator.ne(len(candidates), len(occurrences)) or operator.ne(candidates[0], existing_summary):
        return _fail("ambiguous-candidates")
    stats.classified_fact_count += 1
    bind_structured_callsite_identity_8616(occurrences[0][1], existing_summary)

    replacements = _clone_occurrence_conditions_8616(occurrences, existing_summary, candidates)
    if operator.ne(len(replacements), len(occurrences) - 1):
        return _fail("clone-failed")
    if not all(
        _replace_condition_root_8616(condition_root, cloned_condition)
        for condition_root, cloned_condition, _clone, _summary in iter(replacements)
    ):
        return _fail("replacement-failed")
    for _condition_root, _cloned_condition, clone, summary in replacements:
        summary_map[id(clone)] = summary
    stats.materialized_count += 1
    debug_groups.append(
        (
            call_id,
            len(occurrences),
            existing_summary.callsite_addr,
            tuple(summary.callsite_addr for summary in iter(candidates)),
            "materialized",
        )
    )
    return True


def split_distinct_condition_call_occurrences_8616(codegen: object) -> cython.bint:
    """Give distinct proven binary condition calls independent C AST nodes.

    angr may reuse one mutable ``CFunctionCall`` object in multiple structured
    conditions. Later widening then aliases those syntactic occurrences and can
    rewrite one binary callsite with facts from another. This pass consumes only
    the authoritative typed callsite inventory and splits the object when the
    occurrence-to-callsite correspondence is exact and deterministic.

    Dynamic boundary: the input and condition mutation are third-party angr
    C-AST operations. Summary and inventory fields are owned typed contracts.
    """
    call_id: object
    occurrences: object
    carrier = cast(_SharedCallCodegenSurface8616, codegen)
    stats = DistinctConditionCallOccurrenceStats8616()
    carrier._inertia_distinct_condition_call_occurrence_stats_8616 = stats
    try:
        cfunc = carrier.cfunc
        summary_map = carrier._inertia_callsite_summaries
    except AttributeError:
        return False
    if not isinstance(summary_map, dict):
        raise TypeError("callsite summary carrier must be a dict")
    if any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in builtins.iter(summary_map.items())
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")
    inventory = _validated_callsite_inventory_8616(carrier)
    if not inventory:
        return False
    root = cfunc.statements
    if not isinstance(root, structured_c.CStatements):
        return False

    occurrences_by_call: dict[
        cython.longlong,
        list[tuple[_ConditionRoot8616, structured_c.CFunctionCall]],
    ] = {}
    _collect_condition_call_occurrences_8616(root, occurrences_by_call, set())
    represented_elsewhere = {
        summary.callsite_addr
        for node_id, summary in builtins.iter(summary_map.items())
        if node_id not in {
            call_id
            for call_id, occurrences in builtins.iter(occurrences_by_call.items())
            if len(occurrences) > 1
        }
    }
    changed = False
    debug_groups: list[tuple[cython.longlong, cython.longlong, int | None, tuple[cython.longlong, ...], str]] = []
    for call_id, occurrences in occurrences_by_call.items():
        changed = _split_call_occurrences_8616(
            call_id,
            occurrences,
            summary_map,
            inventory,
            represented_elsewhere,
            stats,
            debug_groups,
        ) or changed

    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified distinct condition call occurrences were not materialized"
        )
    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        logger.warning(
            "[distinct-condition-calls] raw=%d normalized=%d classified=%d "
            "materialized=%d failed=%d groups=%r",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            tuple(debug_groups),
        )
    return changed


@cython.ccall
def _same_zero_argument_call_target_8616(
    lhs: structured_c.CFunctionCall,
    rhs: structured_c.CFunctionCall,
) -> cython.bint:
    """Return whether two zero-argument calls have the same explicit target."""
    lhs_target: object
    if tuple(lhs.args or ()) or tuple(rhs.args or ()):
        return False
    if lhs.callee_func is not None and lhs.callee_func is rhs.callee_func:
        return True
    lhs_target = _explicit_call_target_key_8616(lhs)
    rhs_target = _explicit_call_target_key_8616(rhs)
    return lhs_target is not None and operator.eq(lhs_target, rhs_target)


@cython.ccall
def _explicit_call_target_key_8616(
    call: structured_c.CFunctionCall,
) -> object:
    """Return explicit address or symbolic identity from an angr call node."""
    callee_func: object
    callee_func = call.callee_func
    if callee_func is not None and isinstance(callee_func.addr, int):
        return ("address", callee_func.addr)
    target = call.callee_target
    if isinstance(target, int):
        return ("address", target)
    if isinstance(target, str):
        return ("symbol", target)
    if isinstance(target, structured_c.CConstant):
        value = target.value
        if isinstance(value, int):
            return ("address", value)
        if isinstance(value, str):
            return ("symbol", value)
    return None


@cython.ccall
def _condition_return_carrier_call_8616(
    statement: structured_c.CStatement,
) -> structured_c.CFunctionCall | None:
    """Return a standalone or AX-assigned call through transparent statement shells."""
    current = statement
    while isinstance(current, structured_c.CStatements):
        children = _c_statements_items_8616(current)
        if len(children) != 1 or not isinstance(children[0], structured_c.CStatement):
            return None
        current = children[0]
    if isinstance(current, structured_c.CExpressionStatement):
        return current.expr if isinstance(current.expr, structured_c.CFunctionCall) else None
    if not isinstance(current, structured_c.CAssignment) or not isinstance(
        current.rhs, structured_c.CFunctionCall
    ):
        return None
    lhs = current.lhs
    if not isinstance(lhs, structured_c.CVariable):
        return None
    lhs_name = lhs.name
    return current.rhs if isinstance(lhs_name, str) and lhs_name.lower().split("#", 1)[0] == "ax" else None


def _same_callsite_statement_effect_8616(
    lhs_statement: structured_c.CStatement,
    lhs_call: structured_c.CFunctionCall,
    lhs_summary: CallsiteSummary8616,
    rhs_statement: structured_c.CStatement,
    rhs_call: structured_c.CFunctionCall,
    rhs_summary: CallsiteSummary8616,
) -> cython.bint:
    """Compare two regenerated occurrences of one typed machine callsite."""
    if (
        not isinstance(lhs_summary.target_addr, int)
        or operator.ne(lhs_summary.target_addr, rhs_summary.target_addr)
    ):
        return False
    lhs_args = tuple(lhs_call.args or ())
    rhs_args = tuple(rhs_call.args or ())
    if operator.ne(len(lhs_args), len(rhs_args)) or any(
        not _same_c_expression_8616(lhs_arg, rhs_arg)
        for lhs_arg, rhs_arg in builtins.iter(zip(lhs_args, rhs_args, strict=True))
    ):
        return False
    if isinstance(lhs_statement, structured_c.CExpressionStatement):
        return isinstance(rhs_statement, structured_c.CExpressionStatement)
    if isinstance(lhs_statement, structured_c.CAssignment):
        return isinstance(rhs_statement, structured_c.CAssignment) and _same_c_expression_8616(
            lhs_statement.lhs,
            rhs_statement.lhs,
        )
    return False


@cython.dataclasses.dataclass()
class _SharedCallCoalesce8616:
    """Scan state for shared-callsite occurrence coalescing."""

    summary_map: object
    inventory: Mapping[cython.longlong, CallsiteSummary8616]
    stats: SharedCallOccurrenceStats8616
    changed: cython.bint = False
    pending: object = field(
        default_factory=list
    )
    seen_statement_lists: object = field(default_factory=set)
    debug_duplicates: object = field(default_factory=list)
    seen_call_locations: object = field(default_factory=dict)
    seen_typed_callsites: object = field(default_factory=dict)

    @cython.ccall
    def _debug_shared_scan_8616(
        self,
        statement: structured_c.CStatement,
        statements: object,
        statement_index: cython.longlong,
        summary: object,
        condition_carrier_call_id: int | None,
    ) -> None:
        """Emit opt-in diagnostics for one scanned statement."""
        if not os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            return
        logger.warning(
            "[shared-call-scan] statement=%s carrier=%r summary=%r next=%s",
            type(statement).__name__,
            condition_carrier_call_id,
            (
                summary.callsite_addr,
                summary.return_used,
                summary.return_use_kind,
            )
            if summary is not None
            else None,
            type(statements[statement_index + 1]).__name__
            if statement_index + 1 < len(statements)
            else None,
        )

    @cython.ccall
    def _debug_direct_call_8616(
        self,
        statement: structured_c.CStatement,
        call: structured_c.CFunctionCall,
        call_id: cython.longlong,
        summary: object,
    ) -> None:
        """Emit opt-in diagnostics for one direct call statement."""
        if not os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            return
        logger.warning(
            "[shared-direct-call] statement=%s call=%#x tags=%r "
            "callee_func=(%s,%r,%r) callee_target=(%s,%r) summary=%r",
            type(statement).__name__,
            call_id,
            call.tags,
            type(call.callee_func).__name__,
            getattr(call.callee_func, "addr", None),
            getattr(call.callee_func, "name", None),
            type(call.callee_target).__name__,
            getattr(call.callee_target, "value", call.callee_target),
            (
                summary.callsite_addr,
                summary.target_addr,
                summary.return_used,
            )
            if summary is not None
            else None,
        )

    def _bind_condition_carrier_8616(
        self,
        statement: structured_c.CStatement,
        statements: object,
        statement_index: cython.longlong,
        condition_carrier_call: object,
        summary: object,
    ) -> cython.bint:
        """Bind a CONDITION return-use carrier to the next statement's call."""
        condition_summary: object
        if not _condition_carrier_bind_candidate_8616(
            condition_carrier_call, summary, statements, statement_index
        ):
            return False
        assert summary is not None and condition_carrier_call is not None
        condition_calls = _condition_calls_8616(statements[statement_index + 1])
        if not condition_calls:
            return False
        self.stats.raw_fact_count += 1
        matches = tuple(
            condition_call
            for condition_call in iter(condition_calls)
            if _same_zero_argument_call_target_8616(condition_carrier_call, condition_call)
        )
        if len(matches) == 1:
            self.stats.normalized_fact_count += 1
            condition_call = matches[0]
            condition_summary = self.summary_map.get(id(condition_call))
            if condition_summary is None or operator.eq(condition_summary.callsite_addr, summary.callsite_addr):
                self.summary_map[id(condition_call)] = summary
                self.stats.classified_fact_count += 1
                self.stats.materialized_count += 1
                self.debug_duplicates.append(
                    (type(statement).__name__, id(condition_carrier_call), True, True)
                )
                self.changed = True
                return True
        self.stats.failure_count += 1
        return False

    def _inherit_prior_callsite_8616(
        self,
        statement: structured_c.CStatement,
        call: structured_c.CFunctionCall,
        control_path: object,
    ) -> cython.bint:
        """Adopt a proven prior typed callsite; return True to drop the statement."""
        prior_matches = tuple(
            (previous_statement, previous_call, previous_summary)
            for (previous_path, _callsite_addr), (
                previous_statement,
                previous_call,
                previous_summary,
            ) in builtins.iter(self.seen_typed_callsites.items())
            if previous_path == control_path
            and _same_regenerated_call_surface_8616(previous_call, call)
            and _same_callsite_statement_effect_8616(
                previous_statement,
                previous_call,
                previous_summary,
                statement,
                call,
                previous_summary,
            )
        )
        if not prior_matches:
            return False
        self.stats.raw_fact_count += 1
        normalized_matches = tuple(
            match
            for match in iter(prior_matches)
            if isinstance(match[2].target_addr, int)
            and _inventory_has_unique_target_callsite_8616(
                self.inventory,
                match[2].target_addr,
            )
        )
        if len(normalized_matches) == 1:
            self.stats.normalized_fact_count += 1
            previous_summary = normalized_matches[0][2]
            self.summary_map[id(call)] = previous_summary
            self.stats.classified_fact_count += 1
            self.stats.materialized_count += 1
            self.changed = True
            return True
        self.stats.failure_count += 1
        return False

    @cython.ccall
    def _coalesce_call_location_8616(
        self,
        statement: structured_c.CStatement,
        call: structured_c.CFunctionCall,
        call_id: cython.longlong,
        summary: object,
        control_path: object,
    ) -> cython.bint:
        """Drop duplicate occurrences at one call location; False to continue."""
        previous_occurrence: object
        call_location = (control_path, call_id)
        previous_occurrence = self.seen_call_locations.get(call_location)
        if previous_occurrence is None:
            self.seen_call_locations[call_location] = (statement, call, summary)
            return False
        previous_statement, previous_call, previous_summary_optional = previous_occurrence
        self.stats.raw_fact_count += 1
        self.stats.normalized_fact_count += 1
        self.debug_duplicates.append(
            (
                type(statement).__name__,
                call_id,
                summary is not None,
                summary.return_used if summary is not None else None,
            )
        )
        if (
            summary is not None
            and summary.return_used is False
            and isinstance(summary.callsite_addr, int)
        ):
            self.stats.classified_fact_count += 1
            self.stats.materialized_count += 1
            self.changed = True
            return True
        if _same_drop_surface_8616(
            statement, previous_statement, call, previous_call, summary, previous_summary_optional
        ):
            self.stats.classified_fact_count += 1
            self.stats.materialized_count += 1
            self.changed = True
            return True
        self.stats.failure_count += 1
        return True

    @cython.ccall
    def _coalesce_typed_callsite_8616(
        self,
        statement: structured_c.CStatement,
        call: structured_c.CFunctionCall,
        call_id: cython.longlong,
        summary: object,
        control_path: object,
    ) -> cython.bint:
        """Coalesce regenerated occurrences of one typed callsite; True = keep."""
        previous: object
        if summary is None or not isinstance(summary.callsite_addr, int):
            return True
        callsite_location = (control_path, summary.callsite_addr)
        previous = self.seen_typed_callsites.get(callsite_location)
        if previous is None:
            self.seen_typed_callsites[callsite_location] = (statement, call, summary)
            return True
        previous_statement, previous_call, previous_summary = previous
        self.stats.raw_fact_count += 1
        self.stats.normalized_fact_count += 1
        self.debug_duplicates.append(
            (
                type(statement).__name__,
                call_id,
                True,
                summary.return_used,
            )
        )
        if _same_callsite_statement_effect_8616(
            previous_statement,
            previous_call,
            previous_summary,
            statement,
            call,
            summary,
        ):
            self.stats.classified_fact_count += 1
            self.stats.materialized_count += 1
            self.changed = True
            return False
        self.stats.failure_count += 1
        return True

    @cython.ccall
    def process_statement(
        self,
        statement: structured_c.CStatement,
        statement_index: cython.longlong,
        statements: object,
        control_path: object,
    ) -> cython.bint:
        """Process one statement; return True to retain it in the block."""
        call: object
        condition_carrier_call: object
        summary: object
        call = _direct_statement_call_8616(statement)
        condition_carrier_call = _condition_return_carrier_call_8616(statement)
        condition_carrier_call_id = id(condition_carrier_call) if condition_carrier_call is not None else None
        summary = (
            self.summary_map.get(condition_carrier_call_id)
            if isinstance(condition_carrier_call_id, int)
            else None
        )
        self._debug_shared_scan_8616(
            statement, statements, statement_index, summary, condition_carrier_call_id
        )
        if self._bind_condition_carrier_8616(
            statement, statements, statement_index, condition_carrier_call, summary
        ):
            return False
        if call is None:
            return True
        call_id = id(call)
        summary = _summary_for_direct_call_occurrence_8616(
            call,
            self.summary_map,
            self.inventory,
        )
        self._debug_direct_call_8616(statement, call, call_id, summary)
        if summary is None and self._inherit_prior_callsite_8616(statement, call, control_path):
            return False
        if self._coalesce_call_location_8616(statement, call, call_id, summary, control_path):
            return False
        return self._coalesce_typed_callsite_8616(statement, call, call_id, summary, control_path)

    @cython.ccall
    def process_block(
        self,
        block: structured_c.CStatements,
        control_path: object,
    ) -> None:
        """Coalesce duplicate call statements inside one block."""
        statement: object
        statement_index: object
        statements = block.statements
        if not isinstance(statements, list) or id(statements) in self.seen_statement_lists:
            return
        self.seen_statement_lists.add(id(statements))
        retained: list[structured_c.CStatement] = []
        child_statement_paths: list[
            tuple[structured_c.CStatements, tuple[tuple[cython.longlong, str, cython.longlong], ...]]
        ] = []
        for statement_index, statement in enumerate(statements):
            if not isinstance(
                statement,
                (structured_c.CStatement, structured_c.CDirtyStatement),
            ):
                raise TypeError(
                    "angr CStatements contains a non-CStatement value: "
                    f"{type(statement).__module__}.{type(statement).__qualname__}"
                )
            child_statement_paths.extend(_iter_child_statement_paths_8616(statement, control_path))
            if self.process_statement(statement, statement_index, statements, control_path):
                retained.append(statement)
        if operator.ne(len(retained), len(statements)):
            block.statements = retained
        self.pending.extend(reversed(child_statement_paths))


@cython.ccall
def _condition_carrier_bind_candidate_8616(
    condition_carrier_call: object,
    summary: object,
    statements: object,
    statement_index: cython.longlong,
) -> cython.bint:
    """Gate for binding a CONDITION return-use carrier to the next statement."""
    return (
        condition_carrier_call is not None
        and summary is not None
        and summary.return_used is True
        and summary.return_use_kind is CallsiteReturnUseKind8616.CONDITION
        and isinstance(summary.callsite_addr, int)
        and statement_index + 1 < len(statements)
    )


@cython.ccall
def _same_drop_surface_8616(
    statement: structured_c.CStatement,
    previous_statement: structured_c.CStatement,
    call: structured_c.CFunctionCall,
    previous_call: structured_c.CFunctionCall,
    summary: object,
    previous_summary_optional: object,
) -> cython.bint:
    """Return whether a duplicate call can be dropped for an earlier occurrence."""
    if not (
        summary is not None
        and previous_summary_optional is not None
        and summary.return_used is True
        and isinstance(summary.callsite_addr, int)
    ):
        return False
    return (statement is previous_statement and call is previous_call) or _same_callsite_statement_effect_8616(
        previous_statement,
        previous_call,
        previous_summary_optional,
        statement,
        call,
        summary,
    )


def coalesce_shared_call_side_effect_statements_8616(codegen: object) -> cython.bint:
    """Keep one physical AST occurrence for one proven binary callsite.

    Dynamic boundary: the input is a third-party angr codegen/C-AST graph.
    Typed callsite summaries are owned contracts and use direct attributes.
    """
    block: object
    control_path: object
    carrier = cast(_SharedCallCodegenSurface8616, codegen)
    stats = SharedCallOccurrenceStats8616()
    carrier._inertia_shared_call_occurrence_stats_8616 = stats
    try:
        cfunc = carrier.cfunc
        summary_map = carrier._inertia_callsite_summaries
    except AttributeError:
        return False
    if not isinstance(summary_map, dict):
        raise TypeError("callsite summary carrier must be a dict")
    if any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in builtins.iter(summary_map.items())
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")
    inventory = _validated_callsite_inventory_8616(carrier)
    root = cfunc.statements
    if not isinstance(root, structured_c.CStatements):
        return False

    scan = _SharedCallCoalesce8616(
        summary_map=summary_map,
        inventory=inventory,
        stats=stats,
        pending=[(root, ())],
    )
    while scan.pending:
        block, control_path = scan.pending.pop()
        scan.process_block(block, control_path)

    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified shared call occurrences were not materialized")
    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        logger.warning(
            "[shared-call-occurrences] raw=%d classified=%d materialized=%d failed=%d duplicates=%r",
            stats.raw_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            tuple(scan.debug_duplicates),
        )
    return scan.changed


@cython.ccall
def _structured_control_statement_8616(stmt: object) -> cython.bint:
    return isinstance(
        stmt,
        (
            structured_c.CDoWhileLoop,
            structured_c.CForLoop,
            structured_c.CIfElse,
            structured_c.CSwitchCase,
            structured_c.CWhileLoop,
        ),
    )


@cython.dataclasses.dataclass()
class _OwnedRegionStatements8616:
    """Resolved owned statements for one switch region participant."""

    addrs: object
    keys: object
    statements: object
    raw_key_statements: object
    raw_addr_statements: object


@cython.dataclasses.dataclass()
class _SwitchSafetyScan8616:
    """Indexed C-AST evidence for one replacement-safety dry run."""

    statements_by_addr: object
    statements_by_key: object
    owner_index_by_statement_id: object
    statement_positions: object
    statements_node_positions: object
    statement_list_paths: object
    statement_container_shapes: object
    statement_parent_paths: object
    positioned_statements_by_addr: object
    positioned_statements_by_key: object
    top_level_statements: object
    root_statements: object
    safe_count: cython.longlong = 0
    refusal_reasons: object = field(default_factory=list)
    debug_regions: object = field(default_factory=list)
    replacement_spans: object = field(default_factory=list)

    @property
    def top_level_statement_ids(self) -> set[cython.longlong]:
        """Return the identity set of top-level statements."""
        return {id(stmt) for stmt in iter(self.top_level_statements)}

    @cython.ccall
    def _refuse(self, reason: object, debug_region: object) -> None:
        """Record one refusal reason on the region and the scan."""
        self.refusal_reasons.append(reason)
        debug_region["refusal_reason"] = reason
        self.debug_regions.append(debug_region)

    @cython.ccall
    def _resolve_owned_statements_8616(
        self, region: Region, *, provenance_backed_span: cython.bint
    ) -> tuple[_OwnedRegionStatements8616, cython.bint]:
        """Resolve a region's owned statements through keys then addresses."""
        addrs = _metadata_ints_8616(region.metadata.get("region_statement_ins_addrs"))
        if not addrs and isinstance(region.block_addr, int):
            addrs = (int(region.block_addr),)
        keys = _metadata_provenance_keys_8616(region.metadata.get("region_statement_provenance_keys"))
        provenance_backed_span = provenance_backed_span or bool(keys)
        statements = _available_statements_for_keys_8616(self.positioned_statements_by_key, keys) or ()
        if not statements:
            statements = _available_statements_for_addrs_8616(self.positioned_statements_by_addr, addrs) or ()
        raw_key_statements = _available_statements_for_keys_8616(self.statements_by_key, keys) or ()
        raw_addr_statements = _available_statements_for_addrs_8616(self.statements_by_addr, addrs) or ()
        return (
            _OwnedRegionStatements8616(
                addrs=addrs,
                keys=keys,
                statements=statements,
                raw_key_statements=raw_key_statements,
                raw_addr_statements=raw_addr_statements,
            ),
            provenance_backed_span,
        )

    def _record_case_debug_8616(
        self,
        case_region: Region,
        owned: _OwnedRegionStatements8616,
        debug_region: object,
    ) -> None:
        """Record per-case statement coverage diagnostics."""
        _debug_list_8616(debug_region, "case_statement_counts").append(len(owned.statements))
        _debug_list_8616(debug_region, "case_statement_key_counts").append(len(owned.keys))
        _debug_list_8616(debug_region, "case_raw_key_statement_counts").append(len(owned.raw_key_statements))
        _debug_list_8616(debug_region, "case_raw_addr_statement_counts").append(len(owned.raw_addr_statements))
        if (
            not owned.statements
            and os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_SAFETY") == "1"
            and (owned.raw_key_statements or owned.raw_addr_statements)
        ):
            _debug_list_8616(debug_region, "case_missing_position_samples").append(
                _statement_position_debug_samples_8616(
                    _dedupe_c_statements_by_identity_8616(
                        tuple(owned.raw_key_statements) + tuple(owned.raw_addr_statements)
                    ),
                    self.statement_positions,
                    self.statement_container_shapes,
                    self.statement_parent_paths,
                )
            )
        _debug_list_8616(debug_region, "case_region_types").append(case_region.region_type.value)
        _debug_list_8616(debug_region, "case_statement_addrs").append(list(owned.addrs))
        if owned.addrs:
            start = min(int(addr) for addr in iter(owned.addrs))
            end = max(int(addr) for addr in iter(owned.addrs)) + 0x20
            _debug_list_8616(debug_region, "case_available_statement_addrs").append(
                [addr for addr in builtins.iter(sorted(self.positioned_statements_by_addr)) if start <= addr <= end]
            )

    @cython.ccall
    def _collect_body_statements_8616(
        self,
        region: Region,
        switch_candidates: object,
        provenance_backed_span: cython.bint,
        debug_region: object,
    ) -> tuple[list[structured_c.CStatement], cython.bint, cython.bint, cython.bint]:
        """Collect case/default body statements; report missing coverage."""
        default_region: object
        case_region: object
        body_statements: list[structured_c.CStatement] = []
        missing_body_statement = False
        missing_positioned_body_statement = False
        for case_region in switch_candidates:
            owned, provenance_backed_span = self._resolve_owned_statements_8616(
                case_region, provenance_backed_span=provenance_backed_span
            )
            self._record_case_debug_8616(case_region, owned, debug_region)
            if not owned.statements:
                if owned.raw_key_statements or owned.raw_addr_statements:
                    missing_positioned_body_statement = True
                missing_body_statement = True
                break
            body_statements.extend(owned.statements)

        default_region = region.metadata.get("switch_default_target")
        if isinstance(default_region, Region):
            owned, provenance_backed_span = self._resolve_owned_statements_8616(
                default_region, provenance_backed_span=provenance_backed_span
            )
            debug_region["default_statement_count"] = len(owned.statements)
            debug_region["default_statement_key_count"] = len(owned.keys)
            debug_region["default_raw_key_statement_count"] = len(owned.raw_key_statements)
            debug_region["default_raw_addr_statement_count"] = len(owned.raw_addr_statements)
            if (
                not owned.statements
                and os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_SAFETY") == "1"
                and (owned.raw_key_statements or owned.raw_addr_statements)
            ):
                debug_region["default_missing_position_samples"] = _statement_position_debug_samples_8616(
                    _dedupe_c_statements_by_identity_8616(
                        tuple(owned.raw_key_statements) + tuple(owned.raw_addr_statements)
                    ),
                    self.statement_positions,
                    self.statement_container_shapes,
                    self.statement_parent_paths,
                )
            debug_region["default_region_type"] = default_region.region_type.value
            debug_region["default_statement_addrs"] = list(owned.addrs)
            if owned.addrs:
                start = min(owned.addrs)
                end = max(owned.addrs) + 0x20
                debug_region["default_available_statement_addrs"] = [
                    addr for addr in builtins.iter(sorted(self.positioned_statements_by_addr)) if start <= addr <= end
                ]
            if not owned.statements:
                if owned.raw_key_statements or owned.raw_addr_statements:
                    missing_positioned_body_statement = True
                missing_body_statement = True
            body_statements.extend(owned.statements)
        return body_statements, missing_body_statement, missing_positioned_body_statement, provenance_backed_span

    def _single_container_span_8616(
        self,
        container: object,
        concrete_positions: object,
        debug_region: object,
    ) -> cython.bint:
        """Classify a span contained in one statement list; True = handled."""
        child_indexes = [int(position[1]) for position in iter(concrete_positions)]
        unique_child_indexes = set(child_indexes)
        if len(unique_child_indexes) == 1:
            index = child_indexes[0]
            self._refuse("single_statement_switch_span_unmaterialized", debug_region)
            debug_region["span"] = [index, index + 1]
            debug_region["statement_count"] = len(child_indexes)
            debug_region["span_source"] = "statement_list_single_statement"
            return True
        expected_child_indexes = set(range(min(unique_child_indexes), max(unique_child_indexes) + 1))
        if unique_child_indexes != expected_child_indexes:
            self._refuse("non_contiguous_switch_statement_list_span", debug_region)
            return True
        start_index = min(child_indexes)
        end_index = max(child_indexes) + 1
        if container is self.root_statements and any(
            _structured_control_statement_8616(stmt) for stmt in iter(container[start_index:end_index])
        ):
            self._refuse("structured_control_in_switch_span_unmaterialized", debug_region)
            debug_region["span"] = [start_index, end_index]
            debug_region["statement_count"] = len(child_indexes)
            debug_region["span_source"] = "top_level_statement_sequence"
            return True
        if any(
            isinstance(
                stmt,
                (
                    structured_c.CDoWhileLoop,
                    structured_c.CForLoop,
                    structured_c.CSwitchCase,
                    structured_c.CWhileLoop,
                ),
            )
            for stmt in iter(container[start_index:end_index])
        ):
            self._refuse("loop_control_in_switch_span_unmaterialized", debug_region)
            debug_region["span"] = [start_index, end_index]
            debug_region["statement_count"] = len(child_indexes)
            debug_region["span_source"] = "statement_list_sequence"
            return True
        if end_index - start_index > _MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616:
            self._refuse("dominant_switch_span_too_large", debug_region)
            debug_region["span"] = [start_index, end_index]
            debug_region["statement_count"] = len(child_indexes)
            debug_region["span_source"] = "statement_list_sequence"
            debug_region["max_dominant_span"] = _MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616
            return True
        debug_region["span"] = [start_index, end_index]
        debug_region["statement_count"] = len(child_indexes)
        debug_region["span_source"] = "statement_list_sequence"
        self.debug_regions.append(debug_region)
        self.replacement_spans.append(
            {
                "statements": container,
                "start": start_index,
                "end": end_index,
                "source": "statement_list_sequence",
            }
        )
        self.safe_count += 1
        return True

    def _dominant_container_span_8616(
        self,
        container_ids: object,
        concrete_positions: object,
        debug_region: object,
    ) -> cython.bint:
        """Classify via the largest valid non-root container span."""
        container_id: object
        dominant_spans: list[tuple[cython.longlong, list[object], cython.longlong, cython.longlong, cython.longlong]] = []
        for container_id in container_ids:
            container_positions = [
                position for position in iter(concrete_positions) if operator.eq(id(position[0]), container_id)
            ]
            if not container_positions:
                continue
            container = container_positions[0][0]
            if container is self.root_statements:
                continue
            child_indexes = [int(position[1]) for position in iter(container_positions)]
            unique_child_indexes = set(child_indexes)
            if len(unique_child_indexes) <= 1:
                continue
            expected_child_indexes = set(range(min(unique_child_indexes), max(unique_child_indexes) + 1))
            if unique_child_indexes != expected_child_indexes:
                continue
            start_index = min(child_indexes)
            end_index = max(child_indexes) + 1
            if any(_structured_control_statement_8616(stmt) for stmt in iter(container[start_index:end_index])):
                continue
            dominant_spans.append((len(unique_child_indexes), container, start_index, end_index, len(child_indexes)))
        if not dominant_spans:
            return False
        _, container, start_index, end_index, statement_count = max(
            dominant_spans,
            key=lambda item: (item[0], item[4]),
        )
        max_dominant_span = _MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616
        if end_index - start_index > max_dominant_span:
            self._refuse("dominant_switch_span_too_large", debug_region)
            debug_region["span"] = [start_index, end_index]
            debug_region["statement_count"] = statement_count
            debug_region["span_source"] = "dominant_statement_list_sequence"
            debug_region["max_dominant_span"] = max_dominant_span
            return True
        debug_region["span"] = [start_index, end_index]
        debug_region["statement_count"] = statement_count
        debug_region["span_source"] = "dominant_statement_list_sequence"
        self.debug_regions.append(debug_region)
        self.replacement_spans.append(
            {
                "statements": container,
                "start": start_index,
                "end": end_index,
                "source": "dominant_statement_list_sequence",
            }
        )
        self.safe_count += 1
        return True

    def _owner_index_span_8616(
        self,
        covered_statements: object,
        debug_region: object,
    ) -> None:
        """Classify the covered span via top-level owner indexes."""
        index: object
        covered_indexes = [self.owner_index_by_statement_id.get(id(stmt)) for stmt in iter(covered_statements)]
        if any(index is None for index in iter(covered_indexes)):
            self._refuse("non_top_level_switch_statement", debug_region)
            return
        concrete_indexes = [int(index) for index in iter(covered_indexes) if index is not None]
        unique_indexes = set(concrete_indexes)
        if len(unique_indexes) == 1:
            index = concrete_indexes[0]
            self._refuse("single_statement_switch_span_unmaterialized", debug_region)
            debug_region["span"] = [index, index + 1]
            debug_region["statement_count"] = len(concrete_indexes)
            debug_region["span_source"] = (
                "top_level_single_statement"
                if all(id(stmt) in self.top_level_statement_ids for stmt in iter(covered_statements))
                else "nested_top_level_owner"
            )
            return
        expected_indexes = set(range(min(unique_indexes), max(unique_indexes) + 1))
        if unique_indexes != expected_indexes:
            self._refuse("non_contiguous_switch_statement_span", debug_region)
            return
        start_index = min(concrete_indexes)
        end_index = max(concrete_indexes) + 1
        if any(_structured_control_statement_8616(stmt) for stmt in iter(self.top_level_statements[start_index:end_index])):
            self._refuse("structured_control_in_switch_span_unmaterialized", debug_region)
            debug_region["span"] = [start_index, end_index]
            debug_region["statement_count"] = len(concrete_indexes)
            debug_region["span_source"] = "top_level_statement_sequence"
            return

        debug_region["span"] = [start_index, end_index]
        debug_region["statement_count"] = len(concrete_indexes)
        debug_region["span_source"] = "top_level_statement_sequence"
        self.debug_regions.append(debug_region)
        self.safe_count += 1

    @cython.ccall
    def _classify_covered_span_8616(
        self,
        covered_statements: object,
        debug_region: object,
    ) -> None:
        """Classify the covered statement span into safe/refused outcomes."""
        container_parent_span = _statement_container_parent_span_8616(
            covered_statements,
            self.statement_positions,
            self.statements_node_positions,
        )
        if isinstance(container_parent_span, dict):
            debug_region["container_parent_span"] = {
                key: value
                for key, value in builtins.iter(container_parent_span.items())
                if key != "parent"
            }
        container_path_summary = _statement_container_path_summary_8616(
            covered_statements,
            self.statement_positions,
            self.statement_list_paths,
        )
        debug_region["container_path_summary"] = container_path_summary
        if os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_SAFETY") == "1":
            debug_region["provenance_summary"] = _statement_provenance_debug_summary_8616(
                covered_statements,
                self.statement_positions,
            )
        covered_positions = [self.statement_positions.get(id(stmt)) for stmt in iter(covered_statements)]
        concrete_positions = [position for position in iter(covered_positions) if position is not None]
        debug_region["missing_statement_position_count"] = len(covered_positions) - len(concrete_positions)
        if concrete_positions:
            container_ids = {id(position[0]) for position in iter(concrete_positions)}
            if len(container_ids) > 1 and not isinstance(container_parent_span, dict):
                reason = (
                    "switch_spans_divergent_structured_children"
                    if _container_path_summary_has_divergent_structured_children_8616(container_path_summary)
                    else "multi_container_switch_span_unmaterialized"
                )
                self._refuse(reason, debug_region)
                debug_region["container_count"] = len(container_ids)
                return
            if len(container_ids) == 1:
                container = concrete_positions[0][0]
                if self._single_container_span_8616(container, concrete_positions, debug_region):
                    return
            elif self._dominant_container_span_8616(container_ids, concrete_positions, debug_region):
                return

        self._owner_index_span_8616(covered_statements, debug_region)

    def evaluate_region_8616(self, region: Region) -> None:
        """Evaluate one typed edge-guard switch region's replacement safety."""
        guard_statements: object
        guard_addrs = _metadata_ints_8616(region.metadata.get("switch_guard_statement_ins_addrs"))
        guard_keys = _metadata_provenance_keys_8616(region.metadata.get("switch_guard_statement_provenance_keys"))
        switch_candidates = _metadata_regions_8616(region.metadata.get("switch_candidates"))
        debug_region: dict[str, object] = {
            "region_addr": region.block_addr,
            "guard_addrs": list(guard_addrs),
            "guard_key_count": len(guard_keys),
            "case_addrs": [case_region.block_addr for case_region in iter(switch_candidates)],
            "default_addr": getattr(region.metadata.get("switch_default_target"), "block_addr", None),
        }
        provenance_backed_span = bool(guard_keys)
        if not guard_addrs:
            self._refuse("missing_switch_guard_statement_span", debug_region)
            return
        missing_guard_addrs = tuple(
            addr for addr in iter(guard_addrs) if int(addr) not in self.positioned_statements_by_addr
        )
        debug_region["missing_guard_addrs"] = list(missing_guard_addrs)
        guard_statements = _available_statements_for_keys_8616(self.positioned_statements_by_key, guard_keys)
        if guard_statements is None:
            guard_statements = _available_statements_for_addrs_8616(self.positioned_statements_by_addr, guard_addrs)
        if guard_statements is None:
            self._refuse("missing_switch_guard_statements", debug_region)
            return

        (
            body_statements,
            missing_body_statement,
            missing_positioned_body_statement,
            provenance_backed_span,
        ) = self._collect_body_statements_8616(
            region, switch_candidates, provenance_backed_span, debug_region
        )
        if missing_body_statement:
            reason = (
                "missing_positioned_switch_body_statements"
                if missing_positioned_body_statement
                else "missing_switch_body_statements"
            )
            self._refuse(reason, debug_region)
            return

        covered_statements = _dedupe_c_statements_by_identity_8616(tuple(guard_statements) + tuple(body_statements))
        debug_region["provenance_backed_span"] = provenance_backed_span
        if any(id(stmt) not in self.top_level_statement_ids for stmt in iter(covered_statements)):
            covered_statements = tuple(
                stmt
                for stmt in iter(covered_statements)
                if not (id(stmt) in self.top_level_statement_ids and _structured_control_statement_8616(stmt))
            )
        debug_region["covered_statement_count"] = len(covered_statements)
        debug_region["scope_summaries"] = list(
            _statement_scope_debug_summary_8616(
                covered_statements,
                self.statement_positions,
                top_level_statements=self.top_level_statements,
            )
        )
        self._classify_covered_span_8616(covered_statements, debug_region)


@cython.ccall
def evaluate_typed_edge_switch_replacement_safety_8616(
    codegen: object,
) -> TypedEdgeSwitchReplacementSafetyResult8616:
    """Dry-run whether typed switch artifacts have enough evidence to replace C AST."""
    cfunc: object
    graph: object
    region: object
    graph = getattr(codegen, "_inertia_grouped_structuring_graph", None)
    regions = _typed_edge_switch_regions_8616(graph if isinstance(graph, RegionGraph) else None)
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    root_statements = root.statements if isinstance(root, structured_c.CStatements) else None
    statements_by_addr, statements_by_key, owner_index_by_statement_id = _c_statement_ownership_8616(codegen)
    statement_positions = _c_statement_list_positions_8616(codegen)
    statements_node_positions = _c_statements_node_positions_8616(codegen)
    statement_list_paths = _c_statement_list_paths_8616(codegen)
    statement_container_shapes = _c_statement_container_shapes_8616(codegen)
    statement_parent_paths = _c_statement_parent_paths_8616(codegen)
    positioned_statements_by_addr, positioned_statements_by_key = _c_positioned_statement_ownership_8616(
        codegen,
        statement_positions,
    )
    top_level_statements = _top_level_c_statements_8616(codegen)
    scan = _SwitchSafetyScan8616(
        statements_by_addr=statements_by_addr,
        statements_by_key=statements_by_key,
        owner_index_by_statement_id=owner_index_by_statement_id,
        statement_positions=statement_positions,
        statements_node_positions=statements_node_positions,
        statement_list_paths=statement_list_paths,
        statement_container_shapes=statement_container_shapes,
        statement_parent_paths=statement_parent_paths,
        positioned_statements_by_addr=positioned_statements_by_addr,
        positioned_statements_by_key=positioned_statements_by_key,
        top_level_statements=top_level_statements,
        root_statements=root_statements,
    )

    for region in regions:
        scan.evaluate_region_8616(region)

    result = TypedEdgeSwitchReplacementSafetyResult8616(
        attempted_count=len(regions),
        safe_count=scan.safe_count,
        refused_count=len(scan.refusal_reasons),
        refusal_reasons=tuple(scan.refusal_reasons),
    )
    codegen_dynamic = cast(Any, codegen)
    codegen_dynamic._inertia_typed_edge_switch_replacement_safety_8616 = {
        "attempted_count": result.attempted_count,
        "safe_count": result.safe_count,
        "refused_count": result.refused_count,
        "refusal_reasons": result.refusal_reasons,
        "status": result.status.value,
        "blocker_layer": result.blocker_layer,
        "changed": result.changed,
        "owner": "structuring.codegen",
    }
    codegen_dynamic._inertia_typed_edge_switch_replacement_safety_debug_8616 = {"regions": tuple(scan.debug_regions)}
    codegen_dynamic._inertia_typed_edge_switch_replacement_spans_8616 = tuple(scan.replacement_spans)
    return result


@cython.ccall
def _record_typed_edge_switch_replacement_safety_stats_8616(
    codegen: object,
    result: TypedEdgeSwitchReplacementSafetyResult8616,
) -> None:
    cfunc: object
    stats: object
    payload = {
        "attempted_count": result.attempted_count,
        "safe_count": result.safe_count,
        "refused_count": result.refused_count,
        "refusal_reasons": result.refusal_reasons,
        "status": result.status.value,
        "blocker_layer": result.blocker_layer,
        "changed": result.changed,
    }
    codegen_dynamic = cast(Any, codegen)
    codegen_dynamic._inertia_typed_edge_switch_replacement_safety_8616 = dict(payload)
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    stats = getattr(cfunc, "_structuring_stats", None)
    if not isinstance(stats, dict):
        stats = {}
        try:
            cast(Any, cfunc)._structuring_stats = stats
        except AttributeError:
            return
    stats["typed_edge_switch_replacement_safety"] = dict(payload)


@cython.ccall
def _transform_blocker_reasons_8616(
    mapped_artifacts: object,
) -> object:
    """Count transform blocker reasons across normalized-ready mappings."""
    mapping: object
    blocker_reasons: dict[str, cython.longlong] = {}
    for mapping in mapped_artifacts:
        if not isinstance(mapping, dict) or mapping.get("expanded_root_normalization_ready") is not True:
            continue
        if mapping.get("expanded_root_transform_ready") is True:
            continue
        reason = mapping.get("expanded_root_transform_blocker_reason") or "unknown"
        reason_text = str(reason)
        blocker_reasons[reason_text] = blocker_reasons.get(reason_text, 0) + 1
    return blocker_reasons


@cython.ccall
def _loop_break_blocker_reasons_8616(
    stage_mappings: object,
) -> tuple[cython.longlong, dict[str, cython.longlong]]:
    """Count candidate loop-break-default plans and their blockers."""
    plan: object
    record: object
    candidate_count = 0
    blocker_reasons: dict[str, cython.longlong] = {}
    for record in stage_mappings:
        if not isinstance(record, dict):
            continue
        plan = record.get("expanded_root_loop_preserving_materialization_plan")
        if not isinstance(plan, dict):
            continue
        if plan.get("status") != "candidate_loop_break_default_switch":
            continue
        candidate_count += 1
        blocker = plan.get("blocker") or "unknown"
        blocker_text = str(blocker)
        blocker_reasons[blocker_text] = blocker_reasons.get(blocker_text, 0) + 1
    return candidate_count, blocker_reasons


def _pre_codegen_probe_counts_8616(
    project: object,
    normalization_ready_artifact_count: cython.longlong,
) -> tuple[cython.longlong, cython.longlong, dict[str, cython.longlong], cython.longlong, dict[str, cython.longlong]]:
    """Merge the latest pre-codegen probe's readiness/blocker counts."""
    pre_codegen_records: object
    pre_codegen_transform_ready_artifact_count = 0
    pre_codegen_transform_blocker_reasons: dict[str, cython.longlong] = {}
    loop_break_default_candidate_count = 0
    loop_break_default_blocker_reasons: dict[str, cython.longlong] = {}
    pre_codegen_records = getattr(project, "_inertia_pre_codegen_seqnode_probe_8616", None)
    if not (isinstance(pre_codegen_records, list) and pre_codegen_records):
        return (
            normalization_ready_artifact_count,
            pre_codegen_transform_ready_artifact_count,
            pre_codegen_transform_blocker_reasons,
            loop_break_default_candidate_count,
            loop_break_default_blocker_reasons,
        )
    latest_probe = pre_codegen_records[-1]
    if not isinstance(latest_probe, dict):
        return (
            normalization_ready_artifact_count,
            pre_codegen_transform_ready_artifact_count,
            pre_codegen_transform_blocker_reasons,
            loop_break_default_candidate_count,
            loop_break_default_blocker_reasons,
        )
    mapped_artifacts = tuple(latest_probe.get("pre_codegen_grouped_switch_artifact_mappings", ()) or ())
    mapped_ready_artifact_count = sum(
        1
        for mapping in iter(mapped_artifacts)
        if isinstance(mapping, dict)
        and isinstance(mapping.get("decision_tree_summary"), dict)
        and isinstance(
            mapping["decision_tree_summary"].get("expanded_root_normalization_readiness"),
            dict,
        )
        and mapping["decision_tree_summary"]["expanded_root_normalization_readiness"].get("ready") is True
    )
    normalization_ready_artifact_count = max(
        normalization_ready_artifact_count,
        mapped_ready_artifact_count,
    )
    pre_codegen_transform_ready_artifact_count = sum(
        1
        for mapping in iter(mapped_artifacts)
        if isinstance(mapping, dict) and mapping.get("expanded_root_transform_ready") is True
    )
    pre_codegen_transform_blocker_reasons = _transform_blocker_reasons_8616(mapped_artifacts)
    stage_mappings = tuple(latest_probe.get("pre_codegen_structuring_stage_mappings", ()) or ())
    loop_break_default_candidate_count, loop_break_default_blocker_reasons = (
        _loop_break_blocker_reasons_8616(stage_mappings)
    )
    return (
        normalization_ready_artifact_count,
        pre_codegen_transform_ready_artifact_count,
        pre_codegen_transform_blocker_reasons,
        loop_break_default_candidate_count,
        loop_break_default_blocker_reasons,
    )


def _record_typed_edge_switch_lowering_status_8616(codegen: object) -> None:
    """Record whether this pass can production-lower typed switch artifacts."""
    cfunc: object
    graph: object
    project: object
    typed_graph: object
    graph = getattr(codegen, "_inertia_grouped_structuring_graph", None)
    typed_graph = graph if isinstance(graph, RegionGraph) else None
    regions = _typed_edge_switch_regions_8616(typed_graph)
    all_artifacts: tuple[dict[str, Any], ...] = tuple(
        cast(dict[str, Any], artifact)
        for region in builtins.iter(tuple(typed_graph.nodes if typed_graph is not None else ()))
        if isinstance((artifact := region.metadata.get("typed_edge_switch_region_artifact")), dict)
    )
    artifact_count = len(all_artifacts)
    partial_artifact_count = sum(1 for artifact in iter(all_artifacts) if artifact.get("status") == "partial_ladder")
    ready_artifact_count = sum(1 for artifact in iter(all_artifacts) if artifact.get("status") == "ready")
    normalization_ready_artifact_count = sum(
        1
        for artifact in iter(all_artifacts)
        if isinstance(artifact.get("decision_tree_summary"), dict)
        and isinstance(artifact["decision_tree_summary"].get("expanded_root_normalization_readiness"), dict)
        and artifact["decision_tree_summary"]["expanded_root_normalization_readiness"].get("ready") is True
    )
    project = getattr(codegen, "project", None)
    (
        normalization_ready_artifact_count,
        pre_codegen_transform_ready_artifact_count,
        pre_codegen_transform_blocker_reasons,
        loop_break_default_candidate_count,
        loop_break_default_blocker_reasons,
    ) = _pre_codegen_probe_counts_8616(project, normalization_ready_artifact_count)
    if not regions:
        payload: dict[str, object] = {
            "attempted_count": 0,
            "status": TypedEdgeSwitchLoweringStatus8616.NoCandidates.value,
            "blocker_layer": None,
            "blocker_reason": "partial_switch_ladder_unready" if partial_artifact_count else None,
        }
    else:
        payload = {
            "attempted_count": len(regions),
            "status": TypedEdgeSwitchLoweringStatus8616.BlockedPostCAst.value,
            "blocker_layer": "structuring.codegen.production_lowering",
            "blocker_reason": "pre_c_ast_lowering_hook_unavailable",
        }
    payload.update(
        {
            "artifact_count": artifact_count,
            "loop_break_default_blocker_reasons": dict(sorted(tuple(loop_break_default_blocker_reasons.items()))),
            "loop_break_default_candidate_count": loop_break_default_candidate_count,
            "partial_artifact_count": partial_artifact_count,
            "ready_artifact_count": ready_artifact_count,
            "normalization_ready_artifact_count": normalization_ready_artifact_count,
            "pre_codegen_transform_ready_artifact_count": pre_codegen_transform_ready_artifact_count,
            "pre_codegen_transform_blocker_reasons": dict(sorted(tuple(pre_codegen_transform_blocker_reasons.items()))),
            "changed": False,
            "owner": "structuring.codegen",
        }
    )
    codegen_dynamic = cast(Any, codegen)
    codegen_dynamic._inertia_typed_edge_switch_lowering_status_8616 = dict(payload)
    cfunc = getattr(codegen, "cfunc", None)
    stats = getattr(cfunc, "_structuring_stats", None) if cfunc is not None else None
    if not isinstance(stats, dict):
        if cfunc is None:
            return
        stats = {}
        try:
            cast(Any, cfunc)._structuring_stats = stats
        except AttributeError:
            return
    stats["typed_edge_switch_lowering_status"] = dict(payload)


@cython.ccall
def _materialize_edge_switch_node_8616(
    region: Region,
    typed_graph: RegionGraph | None,
    codegen: object,
) -> object:
    """Build one region's CSwitchCase or return its refusal reason."""
    case_body: object
    default_body: object
    switch_expr: object
    case_region: object
    case_value: object
    switch_expr = region.metadata.get("switch_expr_ast")
    if not isinstance(switch_expr, structured_c.CExpression):
        return "missing_switch_expr_ast"

    switch_candidates = _metadata_regions_8616(region.metadata.get("switch_candidates"))
    case_values = _typed_edge_switch_case_values_8616(region)
    if operator.ne(len(switch_candidates), len(case_values)):
        return "case_value_count_mismatch"

    cases: list[tuple[cython.longlong, structured_c.CStatements]] = []
    missing_case_body = False
    for case_value, case_region in zip(case_values, switch_candidates, strict=True):
        case_body = _statements_node_from_region_8616(case_region, codegen)
        if case_body is None:
            missing_case_body = True
            break
        cases.append((int(case_value), case_body))
    if missing_case_body:
        return "missing_case_statements"

    default_body = None
    default_region = _typed_edge_switch_default_region_8616(typed_graph, region)
    if isinstance(default_region, Region):
        default_body = _statements_node_from_region_8616(default_region, codegen)
        if default_body is None:
            return "missing_default_statements"

    return structured_c.CSwitchCase(
        switch_expr,
        cases,
        default_body,
        codegen=codegen,
    )


@cython.ccall
def materialize_typed_edge_switch_ast_8616(codegen: object) -> TypedEdgeSwitchAstMaterializationResult8616:
    """Build CSwitchCase artifacts for typed edge-guard switch regions when safe."""
    graph: object
    typed_graph: object
    region: object
    graph = getattr(codegen, "_inertia_grouped_structuring_graph", None)
    typed_graph = graph if isinstance(graph, RegionGraph) else None
    if typed_graph is not None:
        populated_count = _populate_region_statements_from_cfunc_8616(typed_graph, codegen)
    else:
        populated_count = 0
    regions = _typed_edge_switch_regions_8616(typed_graph)
    ast_nodes: list[structured_c.CSwitchCase] = []
    refusal_reasons: list[str] = []
    switch_expr_populated_count = 0

    for region in regions:
        if _populate_switch_expr_ast_from_typed_lhs_8616(region, codegen):
            switch_expr_populated_count += 1
        node = _materialize_edge_switch_node_8616(region, typed_graph, codegen)
        if isinstance(node, structured_c.CSwitchCase):
            ast_nodes.append(node)
        else:
            refusal_reasons.append(node)

    result = TypedEdgeSwitchAstMaterializationResult8616(
        attempted_count=len(regions),
        materialized_count=len(ast_nodes),
        refused_count=len(refusal_reasons),
        refusal_reasons=tuple(refusal_reasons),
    )
    codegen_dynamic = cast(Any, codegen)
    codegen_dynamic._inertia_typed_edge_switch_ast_nodes_8616 = tuple(ast_nodes)
    codegen_dynamic._inertia_typed_edge_switch_ast_materialization_8616 = {
        "attempted_count": result.attempted_count,
        "materialized_count": result.materialized_count,
        "refused_count": result.refused_count,
        "refusal_reasons": result.refusal_reasons,
        "changed": result.changed,
        "region_statement_populated_count": populated_count,
        "switch_expr_populated_count": switch_expr_populated_count,
        "owner": "structuring.codegen",
    }
    return result


def replace_typed_edge_switch_ast_8616(codegen: object) -> TypedEdgeSwitchAstReplacementResult8616:
    """Replace safe top-level C AST spans with typed switch artifacts."""
    ast_node: object
    end: object
    replacement_span: object
    start: object
    statements: object
    safety = evaluate_typed_edge_switch_replacement_safety_8616(codegen)
    if safety.safe_count <= 0:
        result = TypedEdgeSwitchAstReplacementResult8616(
            attempted_count=safety.attempted_count,
            replaced_count=0,
            refused_count=safety.refused_count,
            refusal_reasons=safety.refusal_reasons,
        )
        codegen_dynamic = cast(Any, codegen)
        codegen_dynamic._inertia_typed_edge_switch_ast_replacement_8616 = {
            "attempted_count": result.attempted_count,
            "replaced_count": result.replaced_count,
            "refused_count": result.refused_count,
            "refusal_reasons": result.refusal_reasons,
            "changed": result.changed,
            "owner": "structuring.codegen",
        }
        return result

    materialization = materialize_typed_edge_switch_ast_8616(codegen)
    ast_nodes = tuple(getattr(codegen, "_inertia_typed_edge_switch_ast_nodes_8616", ()) or ())
    replacement_spans = tuple(getattr(codegen, "_inertia_typed_edge_switch_replacement_spans_8616", ()) or ())
    replacements: list[tuple[list[object], cython.longlong, cython.longlong, structured_c.CSwitchCase]] = []
    refusal_reasons: list[str] = list(materialization.refusal_reasons)
    for replacement_span, ast_node in zip(replacement_spans, ast_nodes, strict=False):
        span = (
            (replacement_span.get("start"), replacement_span.get("end"))
            if isinstance(replacement_span, dict)
            else None
        )
        statements = replacement_span.get("statements") if isinstance(replacement_span, dict) else None
        if not (
            isinstance(statements, list)
            and isinstance(span, tuple)
            and len(span) == 2
            and isinstance(span[0], int)
            and isinstance(span[1], int)
            and span[0] < span[1]
        ):
            refusal_reasons.append("replacement_span_unavailable")
            continue
        replacements.append((statements, int(span[0]), int(span[1]), ast_node))

    replaced_count = 0
    for statements, start, end, ast_node in sorted(
        replacements,
        key=lambda item: (id(item[0]), item[1]),
        reverse=True,
    ):
        if start < 0 or end > len(statements) or start >= end:
            refusal_reasons.append("replacement_span_out_of_range")
            continue
        statements[start:end] = [ast_node]
        replaced_count += 1

    result = TypedEdgeSwitchAstReplacementResult8616(
        attempted_count=safety.attempted_count,
        replaced_count=replaced_count,
        refused_count=len(refusal_reasons),
        refusal_reasons=tuple(refusal_reasons),
    )
    codegen_dynamic = cast(Any, codegen)
    codegen_dynamic._inertia_typed_edge_switch_ast_replacement_8616 = {
        "attempted_count": result.attempted_count,
        "replaced_count": result.replaced_count,
        "refused_count": result.refused_count,
        "refusal_reasons": result.refusal_reasons,
        "changed": result.changed,
        "owner": "structuring.codegen",
    }
    return result


@cython.ccall
def apply_structuring_codegen_8616(codegen: object) -> cython.bint:
    """Apply structuring-based code generation pass to codegen.

    This is the entry point for the decompiler framework integration,
    called after region-based structuring has completed.

    Args:
        codegen: The decompiler codegen object

    Returns:
        True if meaningful changes were made, False otherwise

    Note:
        This pass should only run after structuring analysis has completed.
        It generates information about loop/switch rendering but does not
        directly modify C text at this stage (that happens in simplification).
    """
    cfunc: object
    # Get the codegen cfunc if available
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    # Track that codegen was applied
    codegen_dynamic = cast(Any, codegen)
    codegen_dynamic._inertia_structuring_codegen_applied = True
    codegen_dynamic._inertia_structuring_codegen_stats = {"loops_rendered": 0, "switches_rendered": 0}

    try:
        StructuringCodegenPass()
        _record_typed_edge_switch_lowering_status_8616(codegen)
        if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1":
            safety = evaluate_typed_edge_switch_replacement_safety_8616(codegen)
            _record_typed_edge_switch_replacement_safety_stats_8616(codegen, safety)
        # In future phases, this will integrate with cfunc region graphs
        # For now, just track that codegen is enabled
        logger.debug("Structuring codegen pass completed")
        return False  # No direct modifications at this stage
    except Exception as ex:
        logger.warning("Structuring codegen pass failed: %s", ex)
        codegen_dynamic._inertia_structuring_codegen_error = str(ex)
        return False
