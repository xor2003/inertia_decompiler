"""Layer: Structuring.

Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

Responsibility: materialize a typed, evidence-complete switch plan in angr's
pre-codegen SeqNode tree. The runtime hook may bridge angr lifecycle metadata
into this module, but switch proof validation and AST mutation belong here.
No rendered C, source text, COD text, or CLI fallback policy is consumed.
Preserve the reaching SSA selector and decline already structured switches:
simplification may have folded a side-effecting call into their selector.

Dynamic boundary: project architecture and angr SeqNode objects are third-party
surfaces, so narrowly scoped dynamic attribute reads are required here.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from angr.analyses.decompiler.structurer_nodes import SequenceNode

from .switch_definition_coverage import missing_switch_definition_ids_8616

__all__ = [
    "TypedSwitchSeqNodeRefusal8616",
    "TypedSwitchSeqNodeResult8616",
    "materialize_typed_switch_seqnode_8616",
]


class TypedSwitchSeqNodeRefusal8616(Enum):
    """Structured refusal classes for typed SeqNode switch materialization."""

    OWNER_PATHS_NOT_READY = "owner_paths_not_ready"
    ALREADY_STRUCTURED = "already_structured"
    NOT_LOOP_BREAK_DEFAULT_CANDIDATE = "not_loop_break_default_candidate"
    MISSING_AIL_SWITCH_EXPRESSION = "missing_ail_switch_expr"
    MISSING_LOOP_SEQUENCE = "missing_loop_sequence"
    CASE_PATH_VALUE_COUNT_MISMATCH = "case_path_value_count_mismatch"
    NON_INTEGER_CASE_VALUE = "non_integer_case_value"
    DUPLICATE_CASE_VALUE = "duplicate_case_value"
    MISSING_CASE_NODE = "missing_case_node"
    MISSING_UNIQUE_DEFAULT_BREAK_PATH = "missing_unique_default_break_path"
    DEFAULT_BREAK_NODE_UNAVAILABLE = "default_break_node_unavailable"
    MISSING_REPLACEMENT_PATH = "missing_replacement_path"
    SWITCH_CASE_NODE_UNAVAILABLE = "switch_case_node_unavailable"
    REPLACEMENT_PATH_UNAVAILABLE = "replacement_path_unavailable"
    LIVE_DEFINITION_LOSS = "live_definition_loss"


@dataclass(frozen=True, slots=True)
class TypedSwitchSeqNodeResult8616:
    """Typed outcome of one evidence-gated SeqNode switch attempt."""

    attempted_count: int
    changed: bool
    replaced_count: int
    refusal: TypedSwitchSeqNodeRefusal8616 | None = None
    refusal_detail: str | None = None
    case_count: int = 0
    default_target_addr: int | None = None

    def as_runtime_record(self) -> dict[str, object]:
        """Render the typed result for existing runtime diagnostics."""
        refusal_reasons: tuple[str, ...] = ()
        if self.refusal is not None:
            refusal_reasons = (
                f"{self.refusal.value}:{self.refusal_detail}"
                if self.refusal_detail
                else self.refusal.value,
            )
        record: dict[str, object] = {
            "attempted_count": self.attempted_count,
            "changed": self.changed,
            "refusal_reasons": refusal_reasons,
            "replaced_count": self.replaced_count,
            # Count complete switch plans, not individual register writes.
            "selector_binding": {
                "raw_fact_count": self.attempted_count,
                "normalized_fact_count": self.replaced_count,
                "classified_fact_count": self.replaced_count,
                "materialized_count": self.replaced_count,
                "failure_count": self.attempted_count - self.replaced_count,
            },
        }
        if self.changed:
            record["case_count"] = self.case_count
            record["default_target_addr"] = self.default_target_addr
        return record


def _refusal_8616(
    refusal: TypedSwitchSeqNodeRefusal8616,
    *,
    attempted: bool,
    detail: str | None = None,
) -> TypedSwitchSeqNodeResult8616:
    """Build one typed refusal result."""
    return TypedSwitchSeqNodeResult8616(
        attempted_count=int(attempted),
        changed=False,
        replaced_count=0,
        refusal=refusal,
        refusal_detail=detail,
    )


def _int_path_8616(value: object) -> tuple[int, ...] | None:
    """Return a validated SeqNode path from typed artifact metadata."""
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, int) for item in value):
        return None
    return tuple(value)


def _children_8616(node: object) -> tuple[object, ...]:
    """Enumerate the dynamic boundary: third-party angr structurer node children."""
    children: list[object] = []
    for attr in (
        "node",
        "nodes",
        "sequence_node",
        "true_node",
        "false_node",
        "else_node",
        "default_node",
        "head",
    ):
        value = getattr(node, attr, None)
        if value is None:
            continue
        if isinstance(value, dict):
            children.extend(child for child in value.values() if child is not None)
        elif isinstance(value, (list, tuple, set)):
            children.extend(child for child in value if child is not None)
        else:
            children.append(value)
    condition_and_nodes = getattr(node, "condition_and_nodes", None)
    if isinstance(condition_and_nodes, (list, tuple)):
        children.extend(child for _condition, child in condition_and_nodes if child is not None)
    cases = getattr(node, "cases", None)
    if isinstance(cases, dict):
        children.extend(child for child in cases.values() if child is not None)
    elif isinstance(cases, (list, tuple)):
        for item in cases:
            if isinstance(item, tuple) and item:
                child = item[-1]
                if child is not None:
                    children.append(child)
            elif item is not None:
                children.append(item)
    return tuple(children)


def _node_at_path_8616(sequence: object, path: object) -> object | None:
    """Resolve one child path through dynamic angr sequence nodes."""
    normalized = _int_path_8616(path)
    if normalized is None:
        return None
    current = sequence
    for index in normalized:
        children = _children_8616(current)
        if index < 0 or index >= len(children):
            return None
        current = children[index]
    return current


def _register_view_8616(project: object | None, payload: object) -> tuple[int, int] | None:
    """Read the physical view of an already proven typed switch selector."""
    if not isinstance(payload, Mapping) or payload.get("space") != "reg":
        return None
    name = payload.get("name")
    size = payload.get("size")
    if not isinstance(name, str) or not name or not isinstance(size, int) or size <= 0:
        return None
    registers = getattr(getattr(project, "arch", None), "registers", None)
    reg_info = registers.get(name) if isinstance(registers, dict) else None
    offset = reg_info[0] if isinstance(reg_info, tuple) and reg_info else payload.get("offset")
    if not isinstance(offset, int):
        return None
    return offset, size


def _switch_case_body_8616(node: object) -> SequenceNode:
    """Wrap a non-sequence child for angr SwitchCaseNode consumption."""
    if isinstance(node, SequenceNode):
        return node

    return SequenceNode(getattr(node, "addr", None), [node])


def _replace_child_at_path_8616(sequence: object, path: tuple[int, ...], replacement: object) -> bool:
    """Replace one exact SeqNode child without crossing its parent scope."""
    if not path:
        return False
    parent = _node_at_path_8616(sequence, path[:-1])
    nodes = getattr(parent, "nodes", None)
    index = path[-1]
    if not isinstance(nodes, list) or index < 0 or index >= len(nodes):
        return False
    nodes[index] = replacement
    return True


def materialize_typed_switch_seqnode_8616(
    project: object | None,
    sequence: object,
    *,
    first_mapping: Mapping[str, object],
    owner_paths: Mapping[str, object],
    loop_mapping: Mapping[str, object],
    materialization_plan: Mapping[str, object],
) -> TypedSwitchSeqNodeResult8616:
    """Validate and materialize one typed loop-preserving switch plan."""
    if owner_paths.get("ready") is not True:
        detail = owner_paths.get("blocker")
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.OWNER_PATHS_NOT_READY,
            attempted=False,
            detail=detail if isinstance(detail, str) else None,
        )
    if materialization_plan.get("status") != "candidate_loop_break_default_switch":
        detail = materialization_plan.get("blocker")
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.NOT_LOOP_BREAK_DEFAULT_CANDIDATE,
            attempted=True,
            detail=detail if isinstance(detail, str) else None,
        )
    switch_view = _register_view_8616(project, first_mapping.get("switch_condition_lhs"))
    if switch_view is None:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.MISSING_AIL_SWITCH_EXPRESSION,
            attempted=True,
        )
    ladder_node = _node_at_path_8616(sequence, owner_paths.get("ladder_owner_path"))
    loop_sequence = getattr(ladder_node, "sequence_node", None)
    if loop_sequence is None:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.MISSING_LOOP_SEQUENCE,
            attempted=True,
        )

    raw_case_values = loop_mapping.get("expanded_root_normalized_case_values")
    case_values = tuple(raw_case_values) if isinstance(raw_case_values, (list, tuple)) else ()
    raw_case_paths = materialization_plan.get("case_paths")
    case_paths = tuple(
        path
        for value in (raw_case_paths if isinstance(raw_case_paths, (list, tuple)) else ())
        if (path := _int_path_8616(value)) is not None
    )
    if not case_values or len(case_values) != len(case_paths):
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.CASE_PATH_VALUE_COUNT_MISMATCH,
            attempted=True,
        )
    if not all(isinstance(value, int) for value in case_values):
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.NON_INTEGER_CASE_VALUE,
            attempted=True,
        )
    typed_case_values = tuple(int(value) for value in case_values)
    if len(set(typed_case_values)) != len(typed_case_values):
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.DUPLICATE_CASE_VALUE,
            attempted=True,
        )

    case_nodes: OrderedDict[int | tuple[int, ...], SequenceNode] = OrderedDict()
    for case_value, case_path in zip(typed_case_values, case_paths, strict=True):
        node = _node_at_path_8616(loop_sequence, case_path)
        if node is None:
            return _refusal_8616(
                TypedSwitchSeqNodeRefusal8616.MISSING_CASE_NODE,
                attempted=True,
            )
        case_nodes[case_value] = _switch_case_body_8616(node)

    raw_break_paths = materialization_plan.get("break_paths")
    break_paths = tuple(
        path
        for value in (raw_break_paths if isinstance(raw_break_paths, (list, tuple)) else ())
        if (path := _int_path_8616(value)) is not None
    )
    if len(break_paths) != 1:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.MISSING_UNIQUE_DEFAULT_BREAK_PATH,
            attempted=True,
        )
    default_node = _node_at_path_8616(loop_sequence, break_paths[0])
    if default_node is None or type(default_node).__name__ not in {"BreakNode", "ConditionalBreakNode"}:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.DEFAULT_BREAK_NODE_UNAVAILABLE,
            attempted=True,
        )
    replace_path = _int_path_8616(materialization_plan.get("case_path_common_parent"))
    if not replace_path:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.MISSING_REPLACEMENT_PATH,
            attempted=True,
        )
    try:
        from angr.analyses.decompiler.structurer_nodes import SwitchCaseNode
    except ImportError as exc:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.SWITCH_CASE_NODE_UNAVAILABLE,
            attempted=True,
            detail=type(exc).__name__,
        )
    if isinstance(_node_at_path_8616(loop_sequence, replace_path), SwitchCaseNode):
        return _refusal_8616(TypedSwitchSeqNodeRefusal8616.ALREADY_STRUCTURED, attempted=False)
    from .switch_selector_binding import bind_switch_selector_value_8616

    switch_expr = bind_switch_selector_value_8616(
        loop_sequence, replace_path,
        register_offset=switch_view[0], size=switch_view[1],
    )
    if switch_expr is None:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.MISSING_AIL_SWITCH_EXPRESSION,
            attempted=True,
        )
    missing_definitions = missing_switch_definition_ids_8616(
        sequence, _node_at_path_8616(loop_sequence, replace_path),
        (*case_nodes.values(), default_node, switch_expr), children=_children_8616,
    )
    if missing_definitions:
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.LIVE_DEFINITION_LOSS,
            attempted=True, detail=f"varids={missing_definitions}",
        )
    switch_node = SwitchCaseNode(
        switch_expr,
        case_nodes,
        default_node,
        addr=getattr(ladder_node, "addr", None),
    )
    if not _replace_child_at_path_8616(loop_sequence, replace_path, switch_node):
        return _refusal_8616(
            TypedSwitchSeqNodeRefusal8616.REPLACEMENT_PATH_UNAVAILABLE,
            attempted=True,
        )
    default_target = materialization_plan.get("external_default_addr")
    return TypedSwitchSeqNodeResult8616(
        attempted_count=1,
        changed=True,
        replaced_count=1,
        case_count=len(case_nodes),
        default_target_addr=default_target if isinstance(default_target, int) else None,
    )
