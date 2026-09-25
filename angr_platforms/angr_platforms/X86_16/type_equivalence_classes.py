"""Layer: Helper boundary.

Responsibility: summarize typed IR equivalence evidence for later type/object recovery.
Forbidden: guessing objects or types from names, source text, or rendered C shape.
"""

from __future__ import annotations

import logging
import typing
from dataclasses import dataclass, field
from typing import Any, cast

from .ir.core import IRAddress, IRCondition, IRValue, MemSpace, SegmentOrigin

logger: logging.Logger = logging.getLogger(__name__)


def _dynamic_codegen_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic angr/codegen compatibility boundary for optional typed-IR metadata."""
    return getattr(obj, name, default)


def _int_summary_value_8616(summary: dict[str, object], key: str) -> int:
    """Read an integer summary counter from dynamic codegen metadata."""
    value = summary.get(key, 0)
    return int(value) if isinstance(value, int | str | float | bool) else 0


def _dict_summary_value_8616(summary: dict[str, object], key: str) -> dict[str, object]:
    """Read a dictionary summary value from dynamic codegen metadata."""
    value = summary.get(key, {})
    return dict(value) if isinstance(value, dict) else {}


def _ir_atom_census_8616(
    artifact: object,
) -> tuple[int, int, dict[str, int], dict[str, int]]:
    """Count provisional/multi-base addresses, segment origins, and condition ops."""
    provisional_addresses = 0
    multi_base_addresses = 0
    segment_origin_counts = {origin.value: 0 for origin in SegmentOrigin}
    condition_counts: dict[str, int] = {}
    for block in tuple(_dynamic_codegen_attr_8616(artifact, "blocks", ()) or ()):
        for instr in tuple(block.instrs or ()):
            for atom in tuple(instr.args or ()):
                if isinstance(atom, IRAddress):
                    if atom.status.value == "provisional":
                        provisional_addresses += 1
                    if len(atom.base or ()) > 1:
                        multi_base_addresses += 1
                    origin = atom.segment_origin.value
                    segment_origin_counts[origin] = segment_origin_counts.get(origin, 0) + 1
                elif isinstance(atom, IRCondition):
                    op = str(atom.op)
                    condition_counts[op] = condition_counts.get(op, 0) + 1
    return provisional_addresses, multi_base_addresses, segment_origin_counts, condition_counts


def _typed_ir_summary_from_codegen(codegen: object) -> dict[str, object]:
    """Summarize typed-IR evidence already attached to a structured codegen."""
    artifact = _dynamic_codegen_attr_8616(codegen, "_inertia_vex_ir_artifact", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        summary = _dynamic_codegen_attr_8616(codegen, "_inertia_vex_ir_summary", None)
        return dict(summary) if isinstance(summary, dict) else {}

    provisional_addresses, multi_base_addresses, segment_origin_counts, condition_counts = (
        _ir_atom_census_8616(artifact)
    )

    summary = _dynamic_codegen_attr_8616(codegen, "_inertia_vex_ir_summary", None)
    base = dict(summary) if isinstance(summary, dict) else {}
    base["provisional_address_count"] = provisional_addresses
    base["multi_base_address_count"] = multi_base_addresses
    base["segment_origin_counts"] = dict(sorted(segment_origin_counts.items()))
    if condition_counts:
        base["condition_counts"] = dict(sorted(condition_counts.items()))
    return base


@dataclass(frozen=True)
class ExpressionPattern:
    """Normalized expression shape used by the equivalence-class builder."""

    pattern_type: str
    base_expr: str | None
    offset: int | None
    stride: int | None
    width: int

    def __repr__(self) -> str:
        """Render a compact deterministic debug representation."""
        if self.pattern_type == "pointer_add":
            return f"ptr({self.base_expr} + {self.offset} * {self.stride})"
        if self.pattern_type == "memory_load":
            return f"mem[{self.base_expr}]:{self.width}"
        return f"{self.pattern_type}:{self.width}"


@dataclass
class EquivalenceClass:
    """Group of expressions proven equivalent by typed IR evidence."""

    class_id: int
    expressions: set[str] = field(default_factory=set)
    type_constraints: set[str] = field(default_factory=set)
    width: int = 0

    def add_expression(self, expr: str) -> None:
        """Record an expression key in this class."""
        self.expressions.add(expr)

    def add_type_constraint(self, constraint: str) -> None:
        """Record a type constraint proven for this class."""
        self.type_constraints.add(constraint)

    def merge(self, other: EquivalenceClass) -> None:
        """Merge another class into this one."""
        self.expressions.update(other.expressions)
        self.type_constraints.update(other.type_constraints)
        self.width = max(self.width, other.width)


class ExpressionNormalizer:
    """Normalize expression text into simple typed-pattern evidence."""

    def normalize(self, expr: str) -> ExpressionPattern:
        """Return a conservative variable-pattern fallback."""
        return ExpressionPattern(
            pattern_type="variable",
            base_expr=expr,
            offset=None,
            stride=None,
            width=16,
        )


class EquivalenceClassBuilder:
    """Build and merge deterministic expression equivalence classes."""

    def __init__(self) -> None:
        """Initialize an empty equivalence-class builder."""
        self.next_class_id = 0
        self.expr_to_class: dict[str, int] = {}
        self.classes: dict[int, EquivalenceClass] = {}

    def build(self, expressions: list[str]) -> dict[int, EquivalenceClass]:
        """Create one class per new expression key."""
        for expr in expressions:
            if expr not in self.expr_to_class:
                class_id = self.next_class_id
                self.classes[class_id] = EquivalenceClass(class_id=class_id)
                self.classes[class_id].add_expression(expr)
                self.expr_to_class[expr] = class_id
                self.next_class_id += 1
        return self.classes

    def merge_classes(self, expr1: str, expr2: str) -> None:
        """Merge classes containing two expression keys when both exist."""
        if expr1 not in self.expr_to_class or expr2 not in self.expr_to_class:
            return

        class_id1 = self.expr_to_class[expr1]
        class_id2 = self.expr_to_class[expr2]

        if class_id1 == class_id2:
            return

        class1 = self.classes[class_id1]
        class2 = self.classes[class_id2]
        class1.merge(class2)
        for expr in class2.expressions:
            self.expr_to_class[expr] = class_id1
        self.classes.pop(class_id2)


class TypeCollector:
    """Attach simple type constraints to equivalence classes."""

    def collect(self, expr_classes: dict[int, EquivalenceClass]) -> None:
        """Classify expression text into conservative type constraints."""
        for eq_class in expr_classes.values():
            for expr in eq_class.expressions:
                if "_offset" in expr or "+" in expr:
                    eq_class.add_type_constraint("pointer")
                elif any(op in expr for op in ["*", "<<", ">>"]):
                    eq_class.add_type_constraint("integer")


def _expr_key_for_value(value: object) -> str | None:
    """Return a deterministic key for typed IR values, refusing missing fields."""
    if not isinstance(value, IRValue):
        return None
    name = value.name
    if name:
        space_value = value.space.value
        if space_value is None:
            return None
        return f"value:memspace.{str(space_value).lower()}:{name}"
    const = value.const
    if const is not None:
        return f"const:{int(const)}"
    return None


def _expr_key_for_address(address: IRAddress) -> str | None:
    base = tuple(address.base or ())
    if not base:
        return None
    space = address.space.value
    return f"base:{space}:{'+'.join(base)}"


@dataclass(slots=True)
class _ExprCensus8616:
    """Mutable expression/constraint/merge collector for the IR census."""

    exprs: list[str] = field(default_factory=list)
    typed_constraints: dict[str, set[str]] = field(default_factory=dict)
    merges: list[tuple[str, str]] = field(default_factory=list)

    def ensure_expr(self, expr: str | None) -> None:
        """Register one expression key in deterministic first-seen order."""
        if expr is None or expr in self.exprs:
            return
        self.exprs.append(expr)

    def add_constraint(self, expr: str | None, constraint: str) -> None:
        """Attach one typed constraint to a registered expression key."""
        if expr is None:
            return
        self.ensure_expr(expr)
        self.typed_constraints.setdefault(expr, set()).add(constraint)

    def add_merge(self, left: str | None, right: str | None) -> None:
        """Record one equivalence merge between two expression keys."""
        if left is None or right is None or left == right:
            return
        self.ensure_expr(left)
        self.ensure_expr(right)
        self.merges.append((left, right))


def _census_ir_blocks_8616(census: _ExprCensus8616, artifact: object) -> None:
    """Collect expression, constraint, and merge evidence from IR blocks."""
    for block in tuple(_dynamic_codegen_attr_8616(artifact, "blocks", ()) or ()):
        for instr in tuple(block.instrs or ()):
            dst_key = _expr_key_for_value(instr.dst)
            census.ensure_expr(dst_key)
            for atom in tuple(instr.args or ()):
                if isinstance(atom, IRAddress):
                    base_key = _expr_key_for_address(atom)
                    status_value = atom.status.value
                    if base_key is not None and status_value not in {"unknown", "provisional"}:
                        census.add_constraint(base_key, "pointer")
                    elif base_key is not None:
                        census.add_constraint(base_key, "address_like")
                elif isinstance(atom, IRCondition):
                    census.add_constraint(f"cond:{atom.op}", "boolean")
                    for cond_arg in tuple(atom.args or ()):
                        census.add_constraint(_expr_key_for_value(cond_arg), "integer")
                else:
                    census.ensure_expr(_expr_key_for_value(atom))


def _census_phi_nodes_8616(census: _ExprCensus8616, function_ssa: object) -> None:
    """Collect phi-target constraints and incoming merges from SSA evidence."""
    for phi in tuple(
        _dynamic_codegen_attr_8616(function_ssa, "phi_nodes", ())
        if function_ssa is not None
        else ()
    ):
        target = phi.target
        phi_key = _expr_key_for_value(target)
        census.add_constraint(phi_key, "ssa_join")
        if target.space == MemSpace.REG:
            census.add_constraint(phi_key, "integer")
        for incoming in tuple(phi.incoming or ()):
            incoming_key = _expr_key_for_value(incoming.value)
            census.add_merge(phi_key, incoming_key)


def _typed_ir_equivalence_from_codegen(codegen: object) -> tuple[dict[int, EquivalenceClass], dict[str, str]]:
    """Build expression equivalence classes from typed-IR artifacts."""
    artifact = _dynamic_codegen_attr_8616(codegen, "_inertia_vex_ir_artifact", None)
    if artifact is None or not hasattr(artifact, "blocks"):
        return {}, {}
    function_ssa = _dynamic_codegen_attr_8616(codegen, "_inertia_vex_ir_function_ssa", None)

    census = _ExprCensus8616()
    _census_ir_blocks_8616(census, artifact)
    _census_phi_nodes_8616(census, function_ssa)

    if not census.exprs:
        return {}, {}

    builder = EquivalenceClassBuilder()
    classes = builder.build(census.exprs)
    for left, right in census.merges:
        builder.merge_classes(left, right)
    for expr, constraints in census.typed_constraints.items():
        class_id = builder.expr_to_class.get(expr)
        if class_id is None:
            continue
        for constraint in sorted(constraints):
            classes[class_id].add_type_constraint(constraint)

    resolved = TypeVariableReplacer().replace(classes)
    resolved_by_expr = {
        expr: resolved[class_id] for expr, class_id in builder.expr_to_class.items() if class_id in resolved
    }
    return classes, dict(sorted(resolved_by_expr.items()))


class TypeVariableReplacer:
    """Resolve type-variable classes into coarse C type labels."""

    def replace(self, expr_classes: dict[int, EquivalenceClass]) -> dict[int, str]:
        """Return a resolved type label for each equivalence class."""
        resolved_types: dict[int, str] = {}

        for class_id, eq_class in expr_classes.items():
            if "pointer" in eq_class.type_constraints:
                resolved_types[class_id] = "ptr_t"
            elif "boolean" in eq_class.type_constraints:
                resolved_types[class_id] = "bool_t"
            elif "address_like" in eq_class.type_constraints:
                resolved_types[class_id] = "address_like_t"
            elif "integer" in eq_class.type_constraints:
                resolved_types[class_id] = "int_t"
            else:
                resolved_types[class_id] = "void_t"

        return resolved_types


def apply_x86_16_type_equivalence_classes(codegen: object) -> bool:
    """Attach typed-IR equivalence-class diagnostics to structured codegen."""

    def _impl() -> bool:
        if _dynamic_codegen_attr_8616(codegen, "cfunc", None) is None:
            return False

        try:
            typing.cast(typing.Any, codegen)._inertia_type_equivalence_applied = True
            ir_summary = _typed_ir_summary_from_codegen(codegen)
            typed_classes, resolved_by_expr = _typed_ir_equivalence_from_codegen(codegen)
            if isinstance(ir_summary, dict):
                typing.cast(typing.Any, codegen)._inertia_type_equivalence_ir_summary = {
                        "aliasable_value_count": _int_summary_value_8616(ir_summary, "aliasable_value_count"),
                        "frame_slot_count": _int_summary_value_8616(ir_summary, "frame_slot_count"),
                        "space_counts": _dict_summary_value_8616(ir_summary, "space_counts"),
                        "provisional_address_count": _int_summary_value_8616(ir_summary, "provisional_address_count"),
                        "multi_base_address_count": _int_summary_value_8616(ir_summary, "multi_base_address_count"),
                        "segment_origin_counts": _dict_summary_value_8616(ir_summary, "segment_origin_counts"),
                        "condition_counts": _dict_summary_value_8616(ir_summary, "condition_counts"),
                    }
            function_ssa = _dynamic_codegen_attr_8616(codegen, "_inertia_vex_ir_function_ssa", None)
            typing.cast(typing.Any, codegen)._inertia_type_equivalence_resolved_types = resolved_by_expr
            typing.cast(typing.Any, codegen)._inertia_type_equivalence_classes = {
                    class_id: {
                        "expressions": tuple(sorted(eq_class.expressions)),
                        "type_constraints": tuple(sorted(eq_class.type_constraints)),
                        "width": eq_class.width,
                    }
                    for class_id, eq_class in sorted(typed_classes.items())
                }
            function_ssa_summary = (
                cast(dict[str, object], function_ssa.summary)
                if function_ssa is not None and isinstance(_dynamic_codegen_attr_8616(function_ssa, "summary", None), dict)
                else {}
            )
            typing.cast(typing.Any, codegen)._inertia_type_equivalence_stats = {
                "equivalence_classes": len(typed_classes),
                "type_constraints": sum(len(eq_class.type_constraints) for eq_class in typed_classes.values()),
                "resolved_types": len(resolved_by_expr),
                "ir_aliasable_values": _int_summary_value_8616(ir_summary, "aliasable_value_count"),
                "ir_frame_slots": _int_summary_value_8616(ir_summary, "frame_slot_count"),
                "ir_provisional_addresses": _int_summary_value_8616(ir_summary, "provisional_address_count"),
                "ir_multi_base_addresses": _int_summary_value_8616(ir_summary, "multi_base_address_count"),
                "ir_phi_nodes": _int_summary_value_8616(function_ssa_summary, "phi_node_count"),
            }

            logger.debug("Type equivalence class pass completed")
            return False
        except Exception as ex:
            logger.warning("Type equivalence class pass failed: %s", ex)
            typing.cast(typing.Any, codegen)._inertia_type_equivalence_error = str(ex)
            return False

    return _impl()
