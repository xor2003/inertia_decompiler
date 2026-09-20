"""Structuring-based code generation for control flow.

Layer: Structuring.
Responsibility: lower already-structured regions and typed switch artifacts into
C AST/codegen metadata without recovering new semantics.

This module demonstrates how structured regions (Loop, IncSwitch) are converted
to C control flow constructs. Integration with full decompiler codegen happens
in Phase 1.4+.

Dynamic attribute access in this module is limited to the third-party angr
C AST/codegen boundary; owned Inertia region metadata is narrowed before use.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .c_ast_utils import (
    _clone_c_ast_tree_8616,
    _same_c_expression_8616,
)
from .callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
    rebind_cloned_structured_callsite_identity_8616,
    structured_callsite_addr_8616,
)
from .ir.core import IRValue
from .pipeline.errors import PipelineHardError
from .structuring.condition_lowering import lower_ir_value_to_c_expr_8616
from .structuring.condition_rendering import render_condition_operand_8616
from .structuring_region import Region, RegionGraph, RegionType

if TYPE_CHECKING:
    pass

logger: logging.Logger = logging.getLogger(__name__)
_MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616 = 64


def _metadata_sequence_8616(value: object) -> tuple[object, ...]:
    """Return tuple metadata only when the region metadata value is sequence-like."""
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return ()


def _metadata_str_8616(value: object) -> str | None:
    """Return string metadata values without guessing from arbitrary objects."""
    return value if isinstance(value, str) else None


def _metadata_bool_8616(value: object) -> bool:
    """Return boolean metadata values without truthiness coercion."""
    return value if isinstance(value, bool) else False


def _metadata_region_8616(value: object) -> Region | None:
    """Return region metadata values after narrowing to Region."""
    return value if isinstance(value, Region) else None


def _metadata_regions_8616(value: object) -> tuple[Region, ...]:
    """Return only Region values from sequence-like metadata."""
    return tuple(item for item in _metadata_sequence_8616(value) if isinstance(item, Region))


def _metadata_ints_8616(value: object) -> tuple[int, ...]:
    """Return only integer values from sequence-like metadata."""
    return tuple(item for item in _metadata_sequence_8616(value) if isinstance(item, int))


def _metadata_provenance_keys_8616(value: object) -> tuple[tuple[str, int, int], ...]:
    """Return typed provenance keys from sequence-like metadata."""
    result: list[tuple[str, int, int]] = []
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


def _debug_list_8616(mapping: dict[str, object], key: str) -> list[object]:
    """Return a list-valued debug field without relying on object truthiness."""
    value = mapping.setdefault(key, [])
    if isinstance(value, list):
        return value
    replacement: list[object] = []
    mapping[key] = replacement
    return replacement


def _c_statements_items_8616(node: structured_c.CStatements) -> tuple[object, ...]:
    """Return child statements from a third-party angr C AST statements boundary."""
    statements = node.statements
    return tuple(statements) if isinstance(statements, (list, tuple)) else ()


def _c_ifelse_pairs_8616(
    node: structured_c.CIfElse,
) -> tuple[tuple[structured_c.CExpression, structured_c.CStatement | None], ...]:
    """Return condition/body pairs from a third-party angr C AST if/else boundary."""
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


def _c_switch_cases_8616(node: object) -> tuple[tuple[object, object], ...]:
    """Return switch case/body pairs from a third-party angr C AST boundary."""
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


@dataclass
class LoopCodegenInfo:
    """Information for rendering a loop region as C code."""

    loop_type: str  # "while", "do_while", "for"
    condition_expr: str | None  # Condition to evaluate
    init_stmt: str | None  # Initialization (for loops)
    increment_stmt: str | None  # Increment (for loops)
    body_regions: list[Region]  # Regions in loop body
    exit_label: str | None  # Label for break target (if needed)
    uses_goto: bool  # True if fallback gotos needed
    structuring_variables: tuple[str, ...]  # Explicit abnormal loop selectors


@dataclass
class SwitchCodegenInfo:
    """Information for rendering a switch region as C code."""

    switch_expr: str | None  # Expression being switched on
    case_targets: dict[str, Region]  # Constant->Region mapping
    default_target: Region | None  # Default case target
    uses_fallthrough: bool  # True if case fallthrough
    uses_goto: bool  # True if complex gotos needed


@dataclass(frozen=True, slots=True)
class TypedEdgeSwitchAstMaterializationResult8616:
    """Result of building typed edge-guard switch AST artifacts."""

    attempted_count: int
    materialized_count: int
    refused_count: int
    refusal_reasons: tuple[str, ...]

    @property
    def changed(self) -> bool:
        """Return True when production C AST was modified."""
        return False


@dataclass(frozen=True, slots=True)
class TypedEdgeSwitchReplacementSafetyResult8616:
    """Dry-run verdict for replacing top-level C AST with typed switch artifacts."""

    attempted_count: int
    safe_count: int
    refused_count: int
    refusal_reasons: tuple[str, ...]

    @property
    def status(self) -> TypedEdgeSwitchSafetyStatus8616:
        """Return the typed safety verdict."""
        if self.attempted_count <= 0:
            return TypedEdgeSwitchSafetyStatus8616.NoCandidates
        if self.safe_count > 0 and self.refused_count == 0:
            return TypedEdgeSwitchSafetyStatus8616.Safe
        return TypedEdgeSwitchSafetyStatus8616.Blocked

    @property
    def blocker_layer(self) -> str | None:
        """Return the owning layer when replacement is blocked."""
        if self.status is not TypedEdgeSwitchSafetyStatus8616.Blocked:
            return None
        return "structuring.codegen.c_ast_replacement"

    @property
    def changed(self) -> bool:
        """Return True when production C AST was modified."""
        return False


@dataclass(frozen=True, slots=True)
class TypedEdgeSwitchAstReplacementResult8616:
    """Result of replacing safe typed edge-guard cascades in the C AST."""

    attempted_count: int
    replaced_count: int
    refused_count: int
    refusal_reasons: tuple[str, ...]

    @property
    def changed(self) -> bool:
        """Return True when production C AST was modified."""
        return self.replaced_count > 0


class StructuringCodegenPass:
    """Convertstructured regions to C code.

    This pass walks Loop and IncSwitch regions and emits appropriate C constructs.
    For Phase 1.3, this is a demonstration pass. Full integration with codegen
    happens in later phases.
    """

    def __init__(self) -> None:
        """Initialize the codegen pass."""
        self.stats = {
            "loops_rendered": 0,
            "switches_rendered": 0,
            "gotos_emitted": 0,
        }

    def render_loop(self, region: Region) -> str:
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

    def render_switch(self, region: Region) -> str:
        """Render a switch region as C code.

        Args:
            region: IncSwitch region to render

        Returns:
            C code string for the switch
        """
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
        def _condition_expr_from_metadata() -> str:
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
                for item in _metadata_sequence_8616(region.metadata.get("structuring_variables"))
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
                    item for item in _metadata_sequence_8616(loop_meta_dynamic.body_regions) if isinstance(item, Region)
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

    def _extract_switch_info(self, region: Region) -> SwitchCodegenInfo:
        """Extract switch information from an IncSwitch region.

        Args:
            region: IncSwitch region

        Returns:
            SwitchCodegenInfo with rendering parameters
        """
        switch_candidates = _metadata_sequence_8616(region.metadata.get("switch_candidates"))
        case_values = _metadata_sequence_8616(region.metadata.get("switch_case_values"))
        if len(case_values) == len(switch_candidates):
            raw_case_targets = {
                str(value): target for value, target in zip(case_values, switch_candidates, strict=True)
            }
        else:
            raw_case_targets = {f"0x{i:x}": target for i, target in enumerate(switch_candidates)}
        case_targets = {label: target for label, target in raw_case_targets.items() if isinstance(target, Region)}
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

    def apply(self, graph: RegionGraph) -> str:
        """Apply codegen to a structured region graph.

        Args:
            graph: The structured region graph

        Returns:
            Generated C code (simplified representation)
        """
        code = []

        for region in graph.nodes:
            if region.region_type == RegionType.Loop:
                code.append(self.render_loop(region))
            elif region.region_type == RegionType.IncSwitch:
                code.append(self.render_switch(region))

        result = "\n".join(code)
        logger.info(
            f"Codegen complete: {self.stats['loops_rendered']} loops, {self.stats['switches_rendered']} switches"
        )
        return result


def _typed_edge_switch_regions_8616(graph: RegionGraph | None) -> tuple[Region, ...]:
    if graph is None:
        return ()

    def _is_ready_typed_edge_switch(region: Region) -> bool:
        artifact = region.metadata.get("typed_edge_switch_region_artifact")
        if isinstance(artifact, dict):
            return artifact.get("status") == "ready"
        return bool(region.metadata.get("switch_detection") == "typed_condition_edge_cascade")

    return tuple(
        region
        for region in graph.nodes
        if region.region_type == RegionType.IncSwitch and _is_ready_typed_edge_switch(region)
    )


def _statements_node_from_region_8616(region: Region, codegen: object) -> structured_c.CStatements | None:
    statements = tuple(region.statements or ())
    if not statements:
        return None
    if len(statements) == 1 and isinstance(statements[0], structured_c.CStatements):
        return statements[0]
    return structured_c.CStatements(list(statements), addr=region.block_addr, codegen=codegen)


def _region_by_id_8616(graph: RegionGraph | None, region_id: object) -> Region | None:
    if graph is None or not isinstance(region_id, int):
        return None
    for region in graph.nodes:
        if region.region_id == region_id:
            return region
    return None


def _typed_edge_switch_case_values_8616(region: Region) -> tuple[int, ...]:
    artifact = region.metadata.get("typed_edge_switch_region_artifact")
    if isinstance(artifact, dict):
        values = artifact.get("case_values")
        if isinstance(values, (list, tuple)) and all(isinstance(value, int) for value in values):
            return tuple(int(value) for value in values)
    return tuple(int(value) for value in _metadata_sequence_8616(region.metadata.get("switch_case_values")) if isinstance(value, int))


def _typed_edge_switch_default_region_8616(graph: RegionGraph | None, region: Region) -> Region | None:
    artifact = region.metadata.get("typed_edge_switch_region_artifact")
    if isinstance(artifact, dict):
        default_region = _region_by_id_8616(graph, artifact.get("default_region_id"))
        if default_region is not None:
            return default_region
    legacy_default = region.metadata.get("switch_default_target")
    return legacy_default if isinstance(legacy_default, Region) else None


def _iter_non_statement_children_8616(node: object) -> tuple[object, ...]:
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
        children.extend(condition for condition, _ in _c_ifelse_pairs_8616(node))
    return tuple(children)


def _c_statement_owned_ins_addrs_8616(stmt: structured_c.CStatement) -> tuple[int, ...]:
    addrs: list[int] = []
    pending: list[object] = [stmt]
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
        if current is not stmt and isinstance(current, (structured_c.CStatement, structured_c.CStatements)):
            continue
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict) and isinstance(tags.get("ins_addr"), int):
            addrs.append(int(tags["ins_addr"]))
        pending.extend(reversed(_iter_non_statement_children_8616(current)))
    return tuple(dict.fromkeys(addrs))


def _c_node_provenance_key_8616(node: object) -> tuple[str, int, int] | None:
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


def _c_statement_owned_provenance_keys_8616(
    stmt: structured_c.CStatement,
) -> tuple[tuple[str, int, int], ...]:
    keys: list[tuple[str, int, int]] = []
    pending: list[object] = [stmt]
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


def _iter_child_statement_lists_8616(stmt: structured_c.CStatement) -> tuple[structured_c.CStatements, ...]:
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


def _iter_child_statement_paths_8616(
    stmt: structured_c.CStatement,
    control_path: tuple[tuple[int, str, int], ...],
) -> tuple[tuple[structured_c.CStatements, tuple[tuple[int, str, int], ...]], ...]:
    """Return child statement lists and distinguish control-flow alternatives."""
    if isinstance(stmt, structured_c.CStatements):
        return ((stmt, control_path),)

    children: list[tuple[structured_c.CStatements, tuple[tuple[int, str, int], ...]]] = []
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


def _c_statement_list_positions_8616(
    codegen: object,
) -> dict[int, tuple[list[object], int]]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    pending: list[structured_c.CStatements] = [root] if isinstance(root, structured_c.CStatements) else []
    positions: dict[int, tuple[list[object], int]] = {}
    seen_lists: set[int] = set()
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


def _c_statements_node_positions_8616(
    codegen: object,
) -> dict[int, tuple[list[object], int]]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    pending: list[structured_c.CStatements] = [root] if isinstance(root, structured_c.CStatements) else []
    positions: dict[int, tuple[list[object], int]] = {}
    seen_lists: set[int] = set()
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
) -> dict[int, tuple[str, ...]]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    paths: dict[int, tuple[str, ...]] = {}
    seen_nodes: set[int] = set()

    def _visit(current: object, path: tuple[str, ...]) -> None:
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
                _visit(child, (*path, f"CStatements[{index}]"))
                continue
            if not isinstance(child, structured_c.CStatement):
                continue
            for child_list in _iter_child_statement_lists_8616(child):
                _visit(child_list, (*path, f"{type(child).__name__}[{index}]", "child"))

    _visit(root, ("root",))
    return paths


def _c_statement_container_shapes_8616(
    codegen: object,
) -> dict[int, dict[str, object]]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    pending: list[structured_c.CStatements] = [root] if isinstance(root, structured_c.CStatements) else []
    shapes: dict[int, dict[str, object]] = {}
    seen_lists: set[int] = set()
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


def _c_statement_parent_paths_8616(
    codegen: object,
) -> dict[int, tuple[str, ...]]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    paths: dict[int, tuple[str, ...]] = {}
    seen: set[int] = set()

    def _visit(current: object, path: tuple[str, ...]) -> None:
        if current is None:
            return
        if isinstance(current, structured_c.CStatements):
            statements = _c_statements_items_8616(current)
            for index, child in enumerate(statements):
                _visit(child, (*path, f"CStatements[{index}]"))
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
                _visit(branch, (*paths[marker], f"if_branch[{index}]"))
            _visit(current.else_node, (*paths[marker], "else"))
            return
        for attr in ("body", "default"):
            _visit(getattr(current, attr, None), (*paths[marker], attr))
        for index, (_, case_body) in enumerate(_c_switch_cases_8616(current)):
            _visit(case_body, (*paths[marker], f"case[{index}]"))

    _visit(root, ("root",))
    return paths


def _c_positioned_statement_ownership_8616(
    codegen: object,
    statement_positions: dict[int, tuple[list[object], int]],
) -> tuple[
    dict[int, tuple[structured_c.CStatement, ...]],
    dict[tuple[str, int, int], tuple[structured_c.CStatement, ...]],
]:
    top_level_statements = _top_level_c_statements_8616(codegen)
    statements_by_addr: dict[int, list[structured_c.CStatement]] = {}
    statements_by_key: dict[tuple[str, int, int], list[structured_c.CStatement]] = {}

    def _record(owner: structured_c.CStatement, stmt: structured_c.CStatement) -> None:
        for ins_addr in _c_statement_owned_ins_addrs_8616(stmt):
            statements_by_addr.setdefault(ins_addr, []).append(owner)
        for key in _c_statement_owned_provenance_keys_8616(stmt):
            statements_by_key.setdefault(key, []).append(owner)

    def _visit(current: object, positioned_owner: structured_c.CStatement | None) -> None:
        if isinstance(current, structured_c.CStatements):
            for child in _c_statements_items_8616(current):
                _visit(child, positioned_owner)
            return
        if not isinstance(current, structured_c.CStatement):
            return
        owner = current if id(current) in statement_positions else positioned_owner
        if owner is not None:
            _record(owner, current)
        if isinstance(current, structured_c.CIfElse):
            for _, branch in _c_ifelse_pairs_8616(current):
                _visit(branch, owner)
            _visit(current.else_node, owner)
            return
        for attr in ("body", "default"):
            _visit(getattr(current, attr, None), owner)
        for _, case_body in _c_switch_cases_8616(current):
            _visit(case_body, owner)

    for top_level_statement in top_level_statements:
        _visit(top_level_statement, None)
    return (
        {
            addr: _dedupe_c_statements_by_identity_8616(tuple(statements))
            for addr, statements in statements_by_addr.items()
        },
        {
            key: _dedupe_c_statements_by_identity_8616(tuple(statements))
            for key, statements in statements_by_key.items()
        },
    )


def _statement_scope_debug_summary_8616(
    covered_statements: tuple[structured_c.CStatement, ...],
    statement_positions: dict[int, tuple[list[object], int]],
    *,
    top_level_statements: tuple[structured_c.CStatement, ...],
) -> tuple[dict[str, object], ...]:
    groups: dict[int, dict[str, Any]] = {}
    top_level_ids = {id(stmt) for stmt in top_level_statements}
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
            addr_counts: dict[int, int] = group["addr_counts"]
            addr_counts[int(addr)] = int(addr_counts.get(int(addr), 0) or 0) + 1
    result: list[dict[str, object]] = []
    for group in sorted(groups.values(), key=lambda item: int(item["count"]), reverse=True)[:8]:
        indexes = sorted(group["indexes"])
        addr_counts = group["addr_counts"]
        top_addrs = sorted(addr_counts.items(), key=lambda item: (-int(item[1]), int(item[0])))[:12]
        result.append(
            {
                "addr_counts": [[int(addr), int(count)] for addr, count in top_addrs],
                "count": int(group["count"]),
                "index_count": len(indexes),
                "span": [indexes[0], indexes[-1] + 1] if indexes else None,
                "top_level_statement_count": int(group["top_level_statement_count"]),
                "structured_count": int(group["structured_count"]),
            }
        )
    return tuple(result)


def _statement_container_parent_span_8616(
    covered_statements: tuple[structured_c.CStatement, ...],
    statement_positions: dict[int, tuple[list[object], int]],
    statements_node_positions: dict[int, tuple[list[object], int]],
) -> dict[str, object] | None:
    container_by_id: dict[int, list[object]] = {}
    covered_by_container: dict[int, set[int]] = {}
    for stmt in covered_statements:
        position = statement_positions.get(id(stmt))
        if position is None:
            return None
        container, index = position
        container_by_id[id(container)] = container
        covered_by_container.setdefault(id(container), set()).add(int(index))
    if not container_by_id:
        return None

    parent_positions: list[tuple[list[object], int, list[object], int, int, int]] = []
    for container_id, container in container_by_id.items():
        owner_node_position = None
        for node_id, position in statements_node_positions.items():
            candidate_parent, candidate_index = position
            if 0 <= candidate_index < len(candidate_parent) and id(candidate_parent[candidate_index]) == node_id:
                candidate_node = candidate_parent[candidate_index]
                if isinstance(candidate_node, structured_c.CStatements) and candidate_node.statements is container:
                    owner_node_position = (candidate_parent, int(candidate_index))
                    break
        if owner_node_position is None:
            return None
        indexes = covered_by_container[container_id]
        parent, parent_index = owner_node_position
        parent_positions.append((parent, parent_index, container, min(indexes), max(indexes) + 1, len(indexes)))

    parent_ids = {id(item[0]) for item in parent_positions}
    if len(parent_ids) != 1:
        return None
    parent = parent_positions[0][0]
    parent_indexes = sorted(item[1] for item in parent_positions)
    if set(parent_indexes) != set(range(parent_indexes[0], parent_indexes[-1] + 1)):
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
            for _, parent_index, container, start, end, count in sorted(parent_positions, key=lambda item: item[1])
        ],
    }


def _statement_container_path_summary_8616(
    covered_statements: tuple[structured_c.CStatement, ...],
    statement_positions: dict[int, tuple[list[object], int]],
    statement_list_paths: dict[int, tuple[str, ...]],
) -> dict[str, object]:
    containers: dict[int, list[object]] = {}
    counts: Counter[int] = Counter()
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


def _container_path_summary_has_divergent_structured_children_8616(summary: dict[str, object]) -> bool:
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
        if any(isinstance(part, str) and part.startswith(structured_markers) for part in path_tail):
            return True
    return False


def _debug_tag_value_8616(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_debug_tag_value_8616(item) for item in tuple(value)[:8]]
    return type(value).__name__


def _statement_provenance_debug_summary_8616(
    covered_statements: tuple[structured_c.CStatement, ...],
    statement_positions: dict[int, tuple[list[object], int]],
) -> dict[str, object]:
    class_counts: Counter[str] = Counter(type(stmt).__name__ for stmt in covered_statements)
    tag_key_counts: Counter[str] = Counter()
    idx_counts: Counter[object] = Counter()
    samples: list[dict[str, object]] = []
    sample_budget = 16
    for ordinal, stmt in enumerate(covered_statements):
        tags = getattr(stmt, "tags", None)
        tag_keys: tuple[str, ...] = ()
        if isinstance(tags, dict):
            tag_keys = tuple(sorted(str(key) for key in tags))
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
            sample["tags"] = {str(key): _debug_tag_value_8616(value) for key, value in sorted(tags.items())}
        samples.append(sample)
    top_idx_counts = sorted(idx_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))[:16]
    return {
        "class_counts": dict(sorted(class_counts.items())),
        "tag_key_counts": dict(sorted(tag_key_counts.items())),
        "idx_counts_top": {str(key): int(value) for key, value in top_idx_counts},
        "idx_unique_count": len(idx_counts),
        "samples": samples,
        "sample_limit": sample_budget,
        "total": len(covered_statements),
    }


def _statement_position_debug_samples_8616(
    statements: tuple[structured_c.CStatement, ...],
    statement_positions: dict[int, tuple[list[object], int]],
    statement_container_shapes: dict[int, dict[str, object]],
    statement_parent_paths: dict[int, tuple[str, ...]],
    *,
    limit: int = 8,
) -> list[dict[str, object]]:
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


def _c_statement_ownership_8616(
    codegen: object,
) -> tuple[
    dict[int, tuple[structured_c.CStatement, ...]],
    dict[tuple[str, int, int], tuple[structured_c.CStatement, ...]],
    dict[int, int],
]:
    top_level_statements = _top_level_c_statements_8616(codegen)
    statements_by_addr: dict[int, list[structured_c.CStatement]] = {}
    statements_by_key: dict[tuple[str, int, int], list[structured_c.CStatement]] = {}
    owner_index_by_statement_id: dict[int, int] = {}
    for top_level_index, top_level_statement in enumerate(top_level_statements):
        for stmt in _iter_statement_tree_8616(top_level_statement):
            owner_index_by_statement_id[id(stmt)] = top_level_index
            for ins_addr in _c_statement_owned_ins_addrs_8616(stmt):
                statements_by_addr.setdefault(ins_addr, []).append(stmt)
            for key in _c_statement_owned_provenance_keys_8616(stmt):
                statements_by_key.setdefault(key, []).append(stmt)
    return (
        {addr: tuple(statements) for addr, statements in statements_by_addr.items()},
        {key: tuple(statements) for key, statements in statements_by_key.items()},
        owner_index_by_statement_id,
    )


def _top_level_c_statements_8616(codegen: object) -> tuple[structured_c.CStatement, ...]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if not isinstance(root, structured_c.CStatements):
        return ()
    return tuple(
        stmt
        for stmt in tuple(root.statements or ())
        if isinstance(stmt, structured_c.CStatement)
    )


def _populate_region_statements_from_cfunc_8616(graph: RegionGraph, codegen: object) -> int:
    """Attach exact-address C statements to empty linear regions.

    This is a guarded bridge from the current decompiler C AST into the
    structuring graph. It deliberately uses only statement-owned ``ins_addr``
    tags that exactly match a region block address; rendered C and AIL
    statements are refused until region span evidence exists.
    """
    statements_by_addr, statements_by_key, _ = _c_statement_ownership_8616(codegen)
    if not statements_by_addr and not statements_by_key:
        return 0

    regions: list[Region] = list(graph.nodes)
    for switch_region in _typed_edge_switch_regions_8616(graph):
        for case_region in _metadata_regions_8616(switch_region.metadata.get("switch_candidates")):
            regions.append(case_region)  # noqa: PERF402
        default_region = switch_region.metadata.get("switch_default_target")
        if isinstance(default_region, Region):
            regions.append(default_region)

    populated = 0
    for region in sorted(dict.fromkeys(regions), key=lambda item: int(item.region_id or 0)):
        if region.region_type != RegionType.Linear or region.block_addr is None:
            continue
        if _region_raw_statements_8616(region):
            continue
        region_keys = _metadata_provenance_keys_8616(region.metadata.get("region_statement_provenance_keys"))
        region_addrs = _metadata_ints_8616(region.metadata.get("region_statement_ins_addrs"))
        if not region_addrs:
            region_addrs = (int(region.block_addr),)
        statements = tuple(stmt for key in region_keys for stmt in statements_by_key.get(key, ()))
        if not statements:
            statements = tuple(
                stmt
                for addr in region_addrs
                for stmt in statements_by_addr.get(int(addr), ())
            )
        if not statements:
            continue
        region.statements.extend(statements)
        populated += 1
    return populated


def _populate_switch_expr_ast_from_typed_lhs_8616(region: Region, codegen: object) -> bool:
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
    result: list[structured_c.CStatement] = []
    for stmt in tuple(region.statements or ()):
        if isinstance(stmt, structured_c.CStatements):
            result.extend(
                child
                for child in tuple(stmt.statements or ())
                if isinstance(child, structured_c.CStatement)
            )
        elif isinstance(stmt, structured_c.CStatement):
            result.append(stmt)
    return tuple(result)


def _top_level_statements_for_addrs_8616(
    statements_by_addr: dict[int, tuple[structured_c.CStatement, ...]],
    addrs: tuple[int, ...],
) -> tuple[structured_c.CStatement, ...] | None:
    result: list[structured_c.CStatement] = []
    for addr in addrs:
        statements = statements_by_addr.get(int(addr), ())
        if not statements:
            return None
        result.extend(statements)
    return tuple(result)


def _available_statements_for_addrs_8616(
    statements_by_addr: dict[int, tuple[structured_c.CStatement, ...]],
    addrs: tuple[int, ...],
) -> tuple[structured_c.CStatement, ...] | None:
    result: list[structured_c.CStatement] = []
    for addr in addrs:
        result.extend(statements_by_addr.get(int(addr), ()))
    return tuple(result) if result else None


def _available_statements_for_keys_8616(
    statements_by_key: dict[tuple[str, int, int], tuple[structured_c.CStatement, ...]],
    keys: tuple[tuple[str, int, int], ...],
) -> tuple[structured_c.CStatement, ...] | None:
    result: list[structured_c.CStatement] = []
    for key in keys:
        result.extend(statements_by_key.get(key, ()))
    return tuple(result) if result else None


def _dedupe_c_statements_by_identity_8616(
    statements: tuple[structured_c.CStatement, ...],
) -> tuple[structured_c.CStatement, ...]:
    result: list[structured_c.CStatement] = []
    seen: set[int] = set()
    for stmt in statements:
        marker = id(stmt)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(stmt)
    return tuple(result)


@dataclass
class SharedCallOccurrenceStats8616:
    """Evidence loop for shared call-expression occurrence normalization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass
class DistinctConditionCallOccurrenceStats8616:
    """Evidence loop for separating distinct binary calls aliased in one C AST node."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
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
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_distinct_condition_call_occurrence_stats_8616: (
        DistinctConditionCallOccurrenceStats8616
    )
    _inertia_shared_call_occurrence_stats_8616: SharedCallOccurrenceStats8616


def _direct_statement_call_8616(
    statement: structured_c.CStatement,
) -> structured_c.CFunctionCall | None:
    """Return a direct call carried by an angr expression statement or assignment."""
    if isinstance(statement, structured_c.CExpressionStatement):
        return statement.expr if isinstance(statement.expr, structured_c.CFunctionCall) else None
    if isinstance(statement, structured_c.CAssignment):
        return statement.rhs if isinstance(statement.rhs, structured_c.CFunctionCall) else None
    return None


def _expression_calls_8616(expression: object) -> tuple[structured_c.CFunctionCall, ...]:
    """Return calls from a typed subset of the third-party angr expression tree."""
    calls: list[structured_c.CFunctionCall] = []
    pending: list[object] = [expression]
    seen: set[int] = set()
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
            for branch_index, (condition, _branch) in enumerate(_c_ifelse_pairs_8616(statement))
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


def _condition_calls_8616(statement: structured_c.CStatement) -> tuple[structured_c.CFunctionCall, ...]:
    """Return calls embedded in one structured statement condition."""
    if isinstance(statement, structured_c.CStatements):
        children = _c_statements_items_8616(statement)
        if len(children) == 1 and isinstance(children[0], structured_c.CStatement):
            return _condition_calls_8616(children[0])
        return ()
    return tuple(
        call
        for condition_root in _condition_roots_8616(statement)
        for call in _expression_calls_8616(condition_root.expression)
    )


def _replace_condition_root_8616(
    root: _ConditionRoot8616,
    replacement: structured_c.CExpression,
) -> bool:
    """Replace one complete condition subtree at its third-party owner."""
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


def _validated_callsite_inventory_8616(
    carrier: _SharedCallCodegenSurface8616,
) -> dict[int, CallsiteSummary8616]:
    """Return the authoritative owned callsite inventory or fail its contract."""
    try:
        inventory = carrier._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return {}
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory carrier must be a dict")
    for callsite_addr, summary in inventory.items():
        if not isinstance(callsite_addr, int) or not isinstance(summary, CallsiteSummary8616):
            raise TypeError("callsite summary inventory contains an invalid owned contract")
        if summary.callsite_addr != callsite_addr:
            raise TypeError(
                "callsite summary inventory key does not match the summary callsite address"
            )
    return inventory


def _summary_for_direct_call_occurrence_8616(
    call: structured_c.CFunctionCall,
    summary_map: dict[int, CallsiteSummary8616],
    inventory: dict[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve one call occurrence from node identity or an exact instruction tag.

    AST regeneration may clone a call after summary attachment. The immutable
    machine-call inventory remains authoritative in that case; target names and
    source order are deliberately insufficient evidence.
    """
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
    inventory: dict[int, CallsiteSummary8616],
    target_addr: int,
) -> bool:
    """Return whether one machine callsite uniquely owns a direct target."""
    return (
        sum(
            1
            for inventory_summary in inventory.values()
            if inventory_summary.target_addr == target_addr
        )
        == 1
    )


def _same_regenerated_call_surface_8616(
    lhs: structured_c.CFunctionCall,
    rhs: structured_c.CFunctionCall,
) -> bool:
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
        or lhs.callee_target != rhs.callee_target
    ):
        return False
    lhs_args = tuple(lhs.args or ())
    rhs_args = tuple(rhs.args or ())
    return len(lhs_args) == len(rhs_args) and all(
        _same_c_expression_8616(lhs_arg, rhs_arg)
        for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True)
    )


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


def split_distinct_condition_call_occurrences_8616(codegen: object) -> bool:
    """Give distinct proven binary condition calls independent C AST nodes.

    angr may reuse one mutable ``CFunctionCall`` object in multiple structured
    conditions. Later widening then aliases those syntactic occurrences and can
    rewrite one binary callsite with facts from another. This pass consumes only
    the authoritative typed callsite inventory and splits the object when the
    occurrence-to-callsite correspondence is exact and deterministic.

    Dynamic boundary: the input and condition mutation are third-party angr
    C-AST operations. Summary and inventory fields are owned typed contracts.
    """
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
        for key, summary in summary_map.items()
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")
    inventory = _validated_callsite_inventory_8616(carrier)
    if not inventory:
        return False
    root = cfunc.statements
    if not isinstance(root, structured_c.CStatements):
        return False

    occurrences_by_call: dict[
        int,
        list[tuple[_ConditionRoot8616, structured_c.CFunctionCall]],
    ] = {}
    seen_statement_lists: set[int] = set()

    def _collect_block(block: structured_c.CStatements) -> None:
        """Collect condition calls in deterministic structured execution order."""
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
                _collect_block(child)

    _collect_block(root)
    represented_elsewhere = {
        summary.callsite_addr
        for node_id, summary in summary_map.items()
        if node_id not in {
            call_id
            for call_id, occurrences in occurrences_by_call.items()
            if len(occurrences) > 1
        }
    }
    changed = False
    debug_groups: list[tuple[int, int, int | None, tuple[int, ...], str]] = []
    for call_id, occurrences in occurrences_by_call.items():
        if len(occurrences) < 2:
            continue
        stats.raw_fact_count += 1
        existing_summary = summary_map.get(call_id)
        if existing_summary is None or not isinstance(existing_summary.target_addr, int):
            stats.failure_count += 1
            debug_groups.append((call_id, len(occurrences), None, (), "missing-summary"))
            continue
        candidates = tuple(
            summary
            for callsite_addr, summary in sorted(inventory.items())
            if summary.target_addr == existing_summary.target_addr
            and callsite_addr not in represented_elsewhere
        )
        if existing_summary not in candidates:
            stats.failure_count += 1
            debug_groups.append(
                (
                    call_id,
                    len(occurrences),
                    existing_summary.callsite_addr,
                    tuple(summary.callsite_addr for summary in candidates),
                    "existing-summary-not-candidate",
                )
            )
            continue
        stats.normalized_fact_count += 1
        if len(candidates) != len(occurrences) or candidates[0] != existing_summary:
            stats.failure_count += 1
            debug_groups.append(
                (
                    call_id,
                    len(occurrences),
                    existing_summary.callsite_addr,
                    tuple(summary.callsite_addr for summary in candidates),
                    "ambiguous-candidates",
                )
            )
            continue
        stats.classified_fact_count += 1
        bind_structured_callsite_identity_8616(occurrences[0][1], existing_summary)

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
            clone_memo: dict[int, object] = {}
            cloned_condition = _clone_c_ast_tree_8616(
                condition_root.expression,
                clone_memo,
            )
            clone = clone_memo.get(id(original))
            if not isinstance(cloned_condition, structured_c.CExpression) or not isinstance(
                clone,
                structured_c.CFunctionCall,
            ):
                replacements = []
                break
            _retag_cloned_callsite_8616(clone, existing_summary, summary)
            replacements.append((condition_root, cloned_condition, clone, summary))
        if len(replacements) != len(occurrences) - 1:
            stats.failure_count += 1
            debug_groups.append(
                (
                    call_id,
                    len(occurrences),
                    existing_summary.callsite_addr,
                    tuple(summary.callsite_addr for summary in candidates),
                    "clone-failed",
                )
            )
            continue
        if not all(
            _replace_condition_root_8616(condition_root, cloned_condition)
            for condition_root, cloned_condition, _clone, _summary in replacements
        ):
            stats.failure_count += 1
            debug_groups.append(
                (
                    call_id,
                    len(occurrences),
                    existing_summary.callsite_addr,
                    tuple(summary.callsite_addr for summary in candidates),
                    "replacement-failed",
                )
            )
            continue
        for _condition_root, _cloned_condition, clone, summary in replacements:
            summary_map[id(clone)] = summary
        stats.materialized_count += 1
        debug_groups.append(
            (
                call_id,
                len(occurrences),
                existing_summary.callsite_addr,
                tuple(summary.callsite_addr for summary in candidates),
                "materialized",
            )
        )
        changed = True

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


def _same_zero_argument_call_target_8616(
    lhs: structured_c.CFunctionCall,
    rhs: structured_c.CFunctionCall,
) -> bool:
    """Return whether two zero-argument calls have the same explicit target."""
    if tuple(lhs.args or ()) or tuple(rhs.args or ()):
        return False
    if lhs.callee_func is not None and lhs.callee_func is rhs.callee_func:
        return True
    lhs_target = _explicit_call_target_key_8616(lhs)
    rhs_target = _explicit_call_target_key_8616(rhs)
    return lhs_target is not None and lhs_target == rhs_target


def _explicit_call_target_key_8616(
    call: structured_c.CFunctionCall,
) -> tuple[str, int | str] | None:
    """Return explicit address or symbolic identity from an angr call node."""
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
) -> bool:
    """Compare two regenerated occurrences of one typed machine callsite."""
    if (
        not isinstance(lhs_summary.target_addr, int)
        or lhs_summary.target_addr != rhs_summary.target_addr
    ):
        return False
    lhs_args = tuple(lhs_call.args or ())
    rhs_args = tuple(rhs_call.args or ())
    if len(lhs_args) != len(rhs_args) or any(
        not _same_c_expression_8616(lhs_arg, rhs_arg)
        for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True)
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


def coalesce_shared_call_side_effect_statements_8616(codegen: object) -> bool:
    """Keep one physical AST occurrence for one proven binary callsite.

    Dynamic boundary: the input is a third-party angr codegen/C-AST graph.
    Typed callsite summaries are owned contracts and use direct attributes.
    """
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
        for key, summary in summary_map.items()
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")
    inventory = _validated_callsite_inventory_8616(carrier)
    root = cfunc.statements
    if not isinstance(root, structured_c.CStatements):
        return False

    changed = False
    debug_duplicates: list[tuple[str, int, bool, bool | None]] = []
    pending: list[tuple[structured_c.CStatements, tuple[tuple[int, str, int], ...]]] = [(root, ())]
    seen_statement_lists: set[int] = set()
    seen_call_locations: dict[
        tuple[tuple[tuple[int, str, int], ...], int],
        tuple[
            structured_c.CStatement,
            structured_c.CFunctionCall,
            CallsiteSummary8616 | None,
        ],
    ] = {}
    seen_typed_callsites: dict[
        tuple[tuple[tuple[int, str, int], ...], int],
        tuple[structured_c.CStatement, structured_c.CFunctionCall, CallsiteSummary8616],
    ] = {}
    while pending:
        block, control_path = pending.pop()
        statements = block.statements
        if not isinstance(statements, list) or id(statements) in seen_statement_lists:
            continue
        seen_statement_lists.add(id(statements))
        retained: list[structured_c.CStatement] = []
        child_statement_paths: list[
            tuple[structured_c.CStatements, tuple[tuple[int, str, int], ...]]
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
            call = _direct_statement_call_8616(statement)
            condition_carrier_call = _condition_return_carrier_call_8616(statement)
            condition_carrier_call_id = id(condition_carrier_call) if condition_carrier_call is not None else None
            summary = (
                summary_map.get(condition_carrier_call_id)
                if isinstance(condition_carrier_call_id, int)
                else None
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
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
            if (
                condition_carrier_call is not None
                and summary is not None
                and summary.return_used is True
                and summary.return_use_kind is CallsiteReturnUseKind8616.CONDITION
                and isinstance(summary.callsite_addr, int)
                and statement_index + 1 < len(statements)
            ):
                condition_calls = _condition_calls_8616(statements[statement_index + 1])
                if condition_calls:
                    stats.raw_fact_count += 1
                    matches = tuple(
                        condition_call
                        for condition_call in condition_calls
                        if _same_zero_argument_call_target_8616(condition_carrier_call, condition_call)
                    )
                    if len(matches) == 1:
                        stats.normalized_fact_count += 1
                        condition_call = matches[0]
                        condition_summary = summary_map.get(id(condition_call))
                        if condition_summary is None or condition_summary.callsite_addr == summary.callsite_addr:
                            summary_map[id(condition_call)] = summary
                            stats.classified_fact_count += 1
                            stats.materialized_count += 1
                            debug_duplicates.append(
                                (type(statement).__name__, id(condition_carrier_call), True, True)
                            )
                            changed = True
                            continue
                    stats.failure_count += 1
            if call is None:
                retained.append(statement)
                continue
            call_id = id(call)
            summary = _summary_for_direct_call_occurrence_8616(
                call,
                summary_map,
                inventory,
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
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
            if summary is None:
                prior_matches = tuple(
                    (previous_statement, previous_call, previous_summary)
                    for (previous_path, _callsite_addr), (
                        previous_statement,
                        previous_call,
                        previous_summary,
                    ) in seen_typed_callsites.items()
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
                if prior_matches:
                    stats.raw_fact_count += 1
                    normalized_matches = tuple(
                        match
                        for match in prior_matches
                        if isinstance(match[2].target_addr, int)
                        and _inventory_has_unique_target_callsite_8616(
                            inventory,
                            match[2].target_addr,
                        )
                    )
                    if len(normalized_matches) == 1:
                        stats.normalized_fact_count += 1
                        previous_summary = normalized_matches[0][2]
                        summary_map[call_id] = previous_summary
                        stats.classified_fact_count += 1
                        stats.materialized_count += 1
                        changed = True
                        continue
                    stats.failure_count += 1
            call_location = (control_path, call_id)
            previous_occurrence = seen_call_locations.get(call_location)
            if previous_occurrence is None:
                seen_call_locations[call_location] = (statement, call, summary)
            else:
                previous_statement, previous_call, previous_summary_optional = previous_occurrence
                stats.raw_fact_count += 1
                stats.normalized_fact_count += 1
                debug_duplicates.append(
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
                    stats.classified_fact_count += 1
                    stats.materialized_count += 1
                    changed = True
                    continue
                if (
                    summary is not None
                    and previous_summary_optional is not None
                    and summary.return_used is True
                    and isinstance(summary.callsite_addr, int)
                    and (
                        (statement is previous_statement and call is previous_call)
                        or _same_callsite_statement_effect_8616(
                            previous_statement,
                            previous_call,
                            previous_summary_optional,
                            statement,
                            call,
                            summary,
                        )
                    )
                ):
                    stats.classified_fact_count += 1
                    stats.materialized_count += 1
                    changed = True
                    continue
                stats.failure_count += 1
                retained.append(statement)
                continue

            if summary is not None and isinstance(summary.callsite_addr, int):
                callsite_location = (control_path, summary.callsite_addr)
                previous = seen_typed_callsites.get(callsite_location)
                if previous is None:
                    seen_typed_callsites[callsite_location] = (statement, call, summary)
                else:
                    previous_statement, previous_call, previous_summary = previous
                    stats.raw_fact_count += 1
                    stats.normalized_fact_count += 1
                    debug_duplicates.append(
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
                        stats.classified_fact_count += 1
                        stats.materialized_count += 1
                        changed = True
                        continue
                    stats.failure_count += 1
            retained.append(statement)
        if len(retained) != len(statements):
            block.statements = retained
        pending.extend(reversed(child_statement_paths))

    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified shared call occurrences were not materialized")
    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        logger.warning(
            "[shared-call-occurrences] raw=%d classified=%d materialized=%d failed=%d duplicates=%r",
            stats.raw_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            tuple(debug_duplicates),
        )
    return changed


def _structured_control_statement_8616(stmt: object) -> bool:
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


def evaluate_typed_edge_switch_replacement_safety_8616(
    codegen: object,
) -> TypedEdgeSwitchReplacementSafetyResult8616:
    """Dry-run whether typed switch artifacts have enough evidence to replace C AST."""
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
    top_level_statement_ids = {id(stmt) for stmt in top_level_statements}
    safe_count = 0
    refusal_reasons: list[str] = []
    debug_regions: list[dict[str, object]] = []
    replacement_spans: list[dict[str, object]] = []

    for region in regions:
        guard_addrs = _metadata_ints_8616(region.metadata.get("switch_guard_statement_ins_addrs"))
        guard_keys = _metadata_provenance_keys_8616(region.metadata.get("switch_guard_statement_provenance_keys"))
        switch_candidates = _metadata_regions_8616(region.metadata.get("switch_candidates"))
        debug_region: dict[str, object] = {
            "region_addr": region.block_addr,
            "guard_addrs": list(guard_addrs),
            "guard_key_count": len(guard_keys),
            "case_addrs": [case_region.block_addr for case_region in switch_candidates],
            "default_addr": getattr(region.metadata.get("switch_default_target"), "block_addr", None),
        }
        provenance_backed_span = bool(guard_keys)
        if not guard_addrs:
            refusal_reasons.append("missing_switch_guard_statement_span")
            debug_region["refusal_reason"] = "missing_switch_guard_statement_span"
            debug_regions.append(debug_region)
            continue
        missing_guard_addrs = tuple(addr for addr in guard_addrs if int(addr) not in positioned_statements_by_addr)
        debug_region["missing_guard_addrs"] = list(missing_guard_addrs)
        guard_statements = _available_statements_for_keys_8616(positioned_statements_by_key, guard_keys)
        if guard_statements is None:
            guard_statements = _available_statements_for_addrs_8616(positioned_statements_by_addr, guard_addrs)
        if guard_statements is None:
            refusal_reasons.append("missing_switch_guard_statements")
            debug_region["refusal_reason"] = "missing_switch_guard_statements"
            debug_regions.append(debug_region)
            continue

        body_statements: list[structured_c.CStatement] = []
        missing_body_statement = False
        missing_positioned_body_statement = False
        for case_region in switch_candidates:
            case_addrs = _metadata_ints_8616(case_region.metadata.get("region_statement_ins_addrs"))
            if not case_addrs and isinstance(case_region.block_addr, int):
                case_addrs = (int(case_region.block_addr),)
            case_keys = _metadata_provenance_keys_8616(case_region.metadata.get("region_statement_provenance_keys"))
            provenance_backed_span = provenance_backed_span or bool(case_keys)
            case_statements = _available_statements_for_keys_8616(positioned_statements_by_key, case_keys) or ()
            if not case_statements:
                case_statements = _available_statements_for_addrs_8616(positioned_statements_by_addr, case_addrs) or ()
            raw_case_key_statements = _available_statements_for_keys_8616(statements_by_key, case_keys) or ()
            raw_case_addr_statements = _available_statements_for_addrs_8616(statements_by_addr, case_addrs) or ()
            _debug_list_8616(debug_region, "case_statement_counts").append(len(case_statements))
            _debug_list_8616(debug_region, "case_statement_key_counts").append(len(case_keys))
            _debug_list_8616(debug_region, "case_raw_key_statement_counts").append(len(raw_case_key_statements))
            _debug_list_8616(debug_region, "case_raw_addr_statement_counts").append(len(raw_case_addr_statements))
            if (
                not case_statements
                and os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_SAFETY") == "1"
                and (raw_case_key_statements or raw_case_addr_statements)
            ):
                _debug_list_8616(debug_region, "case_missing_position_samples").append(
                    _statement_position_debug_samples_8616(
                        _dedupe_c_statements_by_identity_8616(
                            tuple(raw_case_key_statements) + tuple(raw_case_addr_statements)
                        ),
                        statement_positions,
                        statement_container_shapes,
                        statement_parent_paths,
                    )
                )
            _debug_list_8616(debug_region, "case_region_types").append(case_region.region_type.value)
            _debug_list_8616(debug_region, "case_statement_addrs").append(list(case_addrs))
            if case_addrs:
                start = min(int(addr) for addr in case_addrs)
                end = max(int(addr) for addr in case_addrs) + 0x20
                _debug_list_8616(debug_region, "case_available_statement_addrs").append(
                    [addr for addr in sorted(positioned_statements_by_addr) if start <= addr <= end]
                )
            if not case_statements:
                if raw_case_key_statements or raw_case_addr_statements:
                    missing_positioned_body_statement = True
                missing_body_statement = True
                break
            body_statements.extend(case_statements)
        default_region = region.metadata.get("switch_default_target")
        if isinstance(default_region, Region):
            default_addrs = _metadata_ints_8616(default_region.metadata.get("region_statement_ins_addrs"))
            if not default_addrs and isinstance(default_region.block_addr, int):
                default_addrs = (int(default_region.block_addr),)
            default_keys = _metadata_provenance_keys_8616(default_region.metadata.get("region_statement_provenance_keys"))
            provenance_backed_span = provenance_backed_span or bool(default_keys)
            default_statements = _available_statements_for_keys_8616(positioned_statements_by_key, default_keys) or ()
            if not default_statements:
                default_statements = _available_statements_for_addrs_8616(positioned_statements_by_addr, default_addrs) or ()
            raw_default_key_statements = _available_statements_for_keys_8616(statements_by_key, default_keys) or ()
            raw_default_addr_statements = _available_statements_for_addrs_8616(statements_by_addr, default_addrs) or ()
            debug_region["default_statement_count"] = len(default_statements)
            debug_region["default_statement_key_count"] = len(default_keys)
            debug_region["default_raw_key_statement_count"] = len(raw_default_key_statements)
            debug_region["default_raw_addr_statement_count"] = len(raw_default_addr_statements)
            if (
                not default_statements
                and os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_SAFETY") == "1"
                and (raw_default_key_statements or raw_default_addr_statements)
            ):
                debug_region["default_missing_position_samples"] = _statement_position_debug_samples_8616(
                    _dedupe_c_statements_by_identity_8616(
                        tuple(raw_default_key_statements) + tuple(raw_default_addr_statements)
                    ),
                    statement_positions,
                    statement_container_shapes,
                    statement_parent_paths,
                )
            debug_region["default_region_type"] = default_region.region_type.value
            debug_region["default_statement_addrs"] = list(default_addrs)
            if default_addrs:
                start = min(default_addrs)
                end = max(default_addrs) + 0x20
                debug_region["default_available_statement_addrs"] = [
                    addr for addr in sorted(positioned_statements_by_addr) if start <= addr <= end
                ]
            if not default_statements:
                if raw_default_key_statements or raw_default_addr_statements:
                    missing_positioned_body_statement = True
                missing_body_statement = True
            body_statements.extend(default_statements)
        if missing_body_statement:
            reason = (
                "missing_positioned_switch_body_statements"
                if missing_positioned_body_statement
                else "missing_switch_body_statements"
            )
            refusal_reasons.append(reason)
            debug_region["refusal_reason"] = reason
            debug_regions.append(debug_region)
            continue

        covered_statements = _dedupe_c_statements_by_identity_8616(tuple(guard_statements) + tuple(body_statements))
        debug_region["provenance_backed_span"] = provenance_backed_span
        if any(id(stmt) not in top_level_statement_ids for stmt in covered_statements):
            covered_statements = tuple(
                stmt
                for stmt in covered_statements
                if not (id(stmt) in top_level_statement_ids and _structured_control_statement_8616(stmt))
            )
        debug_region["covered_statement_count"] = len(covered_statements)
        debug_region["scope_summaries"] = list(
            _statement_scope_debug_summary_8616(
                covered_statements,
                statement_positions,
                top_level_statements=top_level_statements,
            )
        )
        container_parent_span = _statement_container_parent_span_8616(
            covered_statements,
            statement_positions,
            statements_node_positions,
        )
        if isinstance(container_parent_span, dict):
            debug_region["container_parent_span"] = {
                key: value
                for key, value in container_parent_span.items()
                if key != "parent"
            }
        container_path_summary = _statement_container_path_summary_8616(
            covered_statements,
            statement_positions,
            statement_list_paths,
        )
        debug_region["container_path_summary"] = container_path_summary
        if os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_SAFETY") == "1":
            debug_region["provenance_summary"] = _statement_provenance_debug_summary_8616(
                covered_statements,
                statement_positions,
            )
        covered_positions = [statement_positions.get(id(stmt)) for stmt in covered_statements]
        concrete_positions = [position for position in covered_positions if position is not None]
        debug_region["missing_statement_position_count"] = len(covered_positions) - len(concrete_positions)
        if concrete_positions:
            container_ids = {id(position[0]) for position in concrete_positions}
            if len(container_ids) > 1 and not isinstance(container_parent_span, dict):
                reason = (
                    "switch_spans_divergent_structured_children"
                    if _container_path_summary_has_divergent_structured_children_8616(container_path_summary)
                    else "multi_container_switch_span_unmaterialized"
                )
                refusal_reasons.append(reason)
                debug_region["refusal_reason"] = reason
                debug_region["container_count"] = len(container_ids)
                debug_regions.append(debug_region)
                continue
            if len(container_ids) == 1:
                container = concrete_positions[0][0]
                child_indexes = [int(position[1]) for position in concrete_positions]
                unique_child_indexes = set(child_indexes)
                if len(unique_child_indexes) == 1:
                    index = child_indexes[0]
                    refusal_reasons.append("single_statement_switch_span_unmaterialized")
                    debug_region["refusal_reason"] = "single_statement_switch_span_unmaterialized"
                    debug_region["span"] = [index, index + 1]
                    debug_region["statement_count"] = len(child_indexes)
                    debug_region["span_source"] = "statement_list_single_statement"
                    debug_regions.append(debug_region)
                    continue
                expected_child_indexes = set(range(min(unique_child_indexes), max(unique_child_indexes) + 1))
                if unique_child_indexes != expected_child_indexes:
                    refusal_reasons.append("non_contiguous_switch_statement_list_span")
                    debug_region["refusal_reason"] = "non_contiguous_switch_statement_list_span"
                    debug_regions.append(debug_region)
                    continue
                start_index = min(child_indexes)
                end_index = max(child_indexes) + 1
                if container is root_statements and any(
                    _structured_control_statement_8616(stmt) for stmt in container[start_index:end_index]
                ):
                    refusal_reasons.append("structured_control_in_switch_span_unmaterialized")
                    debug_region["refusal_reason"] = "structured_control_in_switch_span_unmaterialized"
                    debug_region["span"] = [start_index, end_index]
                    debug_region["statement_count"] = len(child_indexes)
                    debug_region["span_source"] = "top_level_statement_sequence"
                    debug_regions.append(debug_region)
                    continue
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
                    for stmt in container[start_index:end_index]
                ):
                    refusal_reasons.append("loop_control_in_switch_span_unmaterialized")
                    debug_region["refusal_reason"] = "loop_control_in_switch_span_unmaterialized"
                    debug_region["span"] = [start_index, end_index]
                    debug_region["statement_count"] = len(child_indexes)
                    debug_region["span_source"] = "statement_list_sequence"
                    debug_regions.append(debug_region)
                    continue
                if end_index - start_index > _MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616:
                    refusal_reasons.append("dominant_switch_span_too_large")
                    debug_region["refusal_reason"] = "dominant_switch_span_too_large"
                    debug_region["span"] = [start_index, end_index]
                    debug_region["statement_count"] = len(child_indexes)
                    debug_region["span_source"] = "statement_list_sequence"
                    debug_region["max_dominant_span"] = _MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616
                    debug_regions.append(debug_region)
                    continue
                debug_region["span"] = [start_index, end_index]
                debug_region["statement_count"] = len(child_indexes)
                debug_region["span_source"] = "statement_list_sequence"
                debug_regions.append(debug_region)
                replacement_spans.append(
                    {
                        "statements": container,
                        "start": start_index,
                        "end": end_index,
                        "source": "statement_list_sequence",
                    }
                )
                safe_count += 1
                continue
            dominant_spans: list[tuple[int, list[object], int, int, int]] = []
            for container_id in container_ids:
                container_positions = [
                    position for position in concrete_positions if id(position[0]) == container_id
                ]
                if not container_positions:
                    continue
                container = container_positions[0][0]
                if container is root_statements:
                    continue
                child_indexes = [int(position[1]) for position in container_positions]
                unique_child_indexes = set(child_indexes)
                if len(unique_child_indexes) <= 1:
                    continue
                expected_child_indexes = set(range(min(unique_child_indexes), max(unique_child_indexes) + 1))
                if unique_child_indexes != expected_child_indexes:
                    continue
                start_index = min(child_indexes)
                end_index = max(child_indexes) + 1
                if any(_structured_control_statement_8616(stmt) for stmt in container[start_index:end_index]):
                    continue
                dominant_spans.append((len(unique_child_indexes), container, start_index, end_index, len(child_indexes)))
            if dominant_spans:
                _, container, start_index, end_index, statement_count = max(
                    dominant_spans,
                    key=lambda item: (item[0], item[4]),
                )
                max_dominant_span = _MAX_DOMINANT_SWITCH_REPLACEMENT_SPAN_8616
                if end_index - start_index > max_dominant_span:
                    refusal_reasons.append("dominant_switch_span_too_large")
                    debug_region["refusal_reason"] = "dominant_switch_span_too_large"
                    debug_region["span"] = [start_index, end_index]
                    debug_region["statement_count"] = statement_count
                    debug_region["span_source"] = "dominant_statement_list_sequence"
                    debug_region["max_dominant_span"] = max_dominant_span
                    debug_regions.append(debug_region)
                    continue
                debug_region["span"] = [start_index, end_index]
                debug_region["statement_count"] = statement_count
                debug_region["span_source"] = "dominant_statement_list_sequence"
                debug_regions.append(debug_region)
                replacement_spans.append(
                    {
                        "statements": container,
                        "start": start_index,
                        "end": end_index,
                        "source": "dominant_statement_list_sequence",
                    }
                )
                safe_count += 1
                continue

        covered_indexes = [owner_index_by_statement_id.get(id(stmt)) for stmt in covered_statements]
        if any(index is None for index in covered_indexes):
            refusal_reasons.append("non_top_level_switch_statement")
            debug_region["refusal_reason"] = "non_top_level_switch_statement"
            debug_regions.append(debug_region)
            continue
        concrete_indexes = [int(index) for index in covered_indexes if index is not None]
        unique_indexes = set(concrete_indexes)
        if len(unique_indexes) == 1:
            index = concrete_indexes[0]
            refusal_reasons.append("single_statement_switch_span_unmaterialized")
            debug_region["refusal_reason"] = "single_statement_switch_span_unmaterialized"
            debug_region["span"] = [index, index + 1]
            debug_region["statement_count"] = len(concrete_indexes)
            debug_region["span_source"] = (
                "top_level_single_statement"
                if all(id(stmt) in top_level_statement_ids for stmt in covered_statements)
                else "nested_top_level_owner"
            )
            debug_regions.append(debug_region)
            continue
        expected_indexes = set(range(min(unique_indexes), max(unique_indexes) + 1))
        if unique_indexes != expected_indexes:
            refusal_reasons.append("non_contiguous_switch_statement_span")
            debug_region["refusal_reason"] = "non_contiguous_switch_statement_span"
            debug_regions.append(debug_region)
            continue
        start_index = min(concrete_indexes)
        end_index = max(concrete_indexes) + 1
        if any(_structured_control_statement_8616(stmt) for stmt in top_level_statements[start_index:end_index]):
            refusal_reasons.append("structured_control_in_switch_span_unmaterialized")
            debug_region["refusal_reason"] = "structured_control_in_switch_span_unmaterialized"
            debug_region["span"] = [start_index, end_index]
            debug_region["statement_count"] = len(concrete_indexes)
            debug_region["span_source"] = "top_level_statement_sequence"
            debug_regions.append(debug_region)
            continue

        debug_region["span"] = [start_index, end_index]
        debug_region["statement_count"] = len(concrete_indexes)
        debug_region["span_source"] = "top_level_statement_sequence"
        debug_regions.append(debug_region)
        safe_count += 1

    result = TypedEdgeSwitchReplacementSafetyResult8616(
        attempted_count=len(regions),
        safe_count=safe_count,
        refused_count=len(refusal_reasons),
        refusal_reasons=tuple(refusal_reasons),
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
    codegen_dynamic._inertia_typed_edge_switch_replacement_safety_debug_8616 = {"regions": tuple(debug_regions)}
    codegen_dynamic._inertia_typed_edge_switch_replacement_spans_8616 = tuple(replacement_spans)
    return result


def _record_typed_edge_switch_replacement_safety_stats_8616(
    codegen: object,
    result: TypedEdgeSwitchReplacementSafetyResult8616,
) -> None:
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


def _record_typed_edge_switch_lowering_status_8616(codegen: object) -> None:
    """Record whether this pass can production-lower typed switch artifacts."""
    graph = getattr(codegen, "_inertia_grouped_structuring_graph", None)
    typed_graph = graph if isinstance(graph, RegionGraph) else None
    regions = _typed_edge_switch_regions_8616(typed_graph)
    all_artifacts: tuple[dict[str, Any], ...] = tuple(
        cast(dict[str, Any], artifact)
        for region in tuple(typed_graph.nodes if typed_graph is not None else ())
        if isinstance((artifact := region.metadata.get("typed_edge_switch_region_artifact")), dict)
    )
    artifact_count = len(all_artifacts)
    partial_artifact_count = sum(1 for artifact in all_artifacts if artifact.get("status") == "partial_ladder")
    ready_artifact_count = sum(1 for artifact in all_artifacts if artifact.get("status") == "ready")
    normalization_ready_artifact_count = sum(
        1
        for artifact in all_artifacts
        if isinstance(artifact.get("decision_tree_summary"), dict)
        and isinstance(artifact["decision_tree_summary"].get("expanded_root_normalization_readiness"), dict)
        and artifact["decision_tree_summary"]["expanded_root_normalization_readiness"].get("ready") is True
    )
    pre_codegen_transform_ready_artifact_count = 0
    pre_codegen_transform_blocker_reasons: dict[str, int] = {}
    loop_break_default_candidate_count = 0
    loop_break_default_blocker_reasons: dict[str, int] = {}
    project = getattr(codegen, "project", None)
    pre_codegen_records = getattr(project, "_inertia_pre_codegen_seqnode_probe_8616", None)
    if isinstance(pre_codegen_records, list) and pre_codegen_records:
        latest_probe = pre_codegen_records[-1]
        if isinstance(latest_probe, dict):
            mapped_artifacts = tuple(latest_probe.get("pre_codegen_grouped_switch_artifact_mappings", ()) or ())
            mapped_ready_artifact_count = sum(
                1
                for mapping in mapped_artifacts
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
                for mapping in mapped_artifacts
                if isinstance(mapping, dict) and mapping.get("expanded_root_transform_ready") is True
            )
            for mapping in mapped_artifacts:
                if not isinstance(mapping, dict) or mapping.get("expanded_root_normalization_ready") is not True:
                    continue
                if mapping.get("expanded_root_transform_ready") is True:
                    continue
                reason = mapping.get("expanded_root_transform_blocker_reason") or "unknown"
                reason_text = str(reason)
                pre_codegen_transform_blocker_reasons[reason_text] = (
                    pre_codegen_transform_blocker_reasons.get(reason_text, 0) + 1
                )
            stage_mappings = tuple(latest_probe.get("pre_codegen_structuring_stage_mappings", ()) or ())
            for record in stage_mappings:
                if not isinstance(record, dict):
                    continue
                plan = record.get("expanded_root_loop_preserving_materialization_plan")
                if not isinstance(plan, dict):
                    continue
                if plan.get("status") != "candidate_loop_break_default_switch":
                    continue
                loop_break_default_candidate_count += 1
                blocker = plan.get("blocker") or "unknown"
                blocker_text = str(blocker)
                loop_break_default_blocker_reasons[blocker_text] = (
                    loop_break_default_blocker_reasons.get(blocker_text, 0) + 1
                )
    if not regions:
        payload: dict[str, object] = {
            "attempted_count": 0,
            "artifact_count": artifact_count,
            "loop_break_default_blocker_reasons": dict(sorted(loop_break_default_blocker_reasons.items())),
            "loop_break_default_candidate_count": loop_break_default_candidate_count,
            "partial_artifact_count": partial_artifact_count,
            "ready_artifact_count": ready_artifact_count,
            "normalization_ready_artifact_count": normalization_ready_artifact_count,
            "pre_codegen_transform_ready_artifact_count": pre_codegen_transform_ready_artifact_count,
            "pre_codegen_transform_blocker_reasons": dict(sorted(pre_codegen_transform_blocker_reasons.items())),
            "status": TypedEdgeSwitchLoweringStatus8616.NoCandidates.value,
            "blocker_layer": None,
            "blocker_reason": "partial_switch_ladder_unready" if partial_artifact_count else None,
            "changed": False,
            "owner": "structuring.codegen",
        }
    else:
        payload = {
            "attempted_count": len(regions),
            "artifact_count": artifact_count,
            "loop_break_default_blocker_reasons": dict(sorted(loop_break_default_blocker_reasons.items())),
            "loop_break_default_candidate_count": loop_break_default_candidate_count,
            "partial_artifact_count": partial_artifact_count,
            "ready_artifact_count": ready_artifact_count,
            "normalization_ready_artifact_count": normalization_ready_artifact_count,
            "pre_codegen_transform_ready_artifact_count": pre_codegen_transform_ready_artifact_count,
            "pre_codegen_transform_blocker_reasons": dict(sorted(pre_codegen_transform_blocker_reasons.items())),
            "status": TypedEdgeSwitchLoweringStatus8616.BlockedPostCAst.value,
            "blocker_layer": "structuring.codegen.production_lowering",
            "blocker_reason": "pre_c_ast_lowering_hook_unavailable",
            "changed": False,
            "owner": "structuring.codegen",
        }
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


def materialize_typed_edge_switch_ast_8616(codegen: object) -> TypedEdgeSwitchAstMaterializationResult8616:
    """Build CSwitchCase artifacts for typed edge-guard switch regions when safe."""
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
        switch_expr = region.metadata.get("switch_expr_ast")
        if not isinstance(switch_expr, structured_c.CExpression):
            refusal_reasons.append("missing_switch_expr_ast")
            continue

        switch_candidates = _metadata_regions_8616(region.metadata.get("switch_candidates"))
        case_values = _typed_edge_switch_case_values_8616(region)
        if len(switch_candidates) != len(case_values):
            refusal_reasons.append("case_value_count_mismatch")
            continue

        cases: list[tuple[int, structured_c.CStatements]] = []
        missing_case_body = False
        for case_value, case_region in zip(case_values, switch_candidates, strict=True):
            case_body = _statements_node_from_region_8616(case_region, codegen)
            if case_body is None:
                missing_case_body = True
                break
            cases.append((int(case_value), case_body))
        if missing_case_body:
            refusal_reasons.append("missing_case_statements")
            continue

        default_body = None
        default_region = _typed_edge_switch_default_region_8616(typed_graph, region)
        if isinstance(default_region, Region):
            default_body = _statements_node_from_region_8616(default_region, codegen)
            if default_body is None:
                refusal_reasons.append("missing_default_statements")
                continue

        ast_nodes.append(
            structured_c.CSwitchCase(
                switch_expr,
                cases,
                default_body,
                codegen=codegen,
            )
        )

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
    replacements: list[tuple[list[object], int, int, structured_c.CSwitchCase]] = []
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


def apply_structuring_codegen_8616(codegen: object) -> bool:
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
