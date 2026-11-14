# cython: language_level=3, infer_types=True
"""Grouped region graph construction for the 16-bit decompiler pipeline.

Layer: Structuring.
Responsibility: attach typed-IR and cross-entry grouping evidence to region graphs before structuring.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import cython

import builtins
import typing
from dataclasses import dataclass
from typing import Any, cast

from inertia.ir.condition_ir import ConditionEdgeEvidence, ConditionIR, condition_compare_symbol_8616
from inertia.ir.core import AddressStatus, IRAddress, IRAtom, IRCondition, IRValue, MemSpace, SegmentOrigin
from inertia.structuring.condition_rendering import render_condition_ir_8616, render_condition_ir_native_8616
from inertia.structuring.structuring_graph_builder import RegionGraphBuildResult, build_region_graph
from inertia.structuring.structuring_grouped_units import (
    CrossEntryGroupedUnitArtifact,
    build_x86_16_cross_entry_grouped_units,
)
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class GroupedRegionGraphBuildResult:
    """Region graph plus optional cross-entry grouping evidence."""

    graph_result: RegionGraphBuildResult
    grouped_units: CrossEntryGroupedUnitArtifact | None


@cython.ccall
def _dynamic_grouped_graph_getattr_8616(obj: object, name: object, default: object = None) -> Any:  # noqa: ANN401
    """Read an attribute across the dynamic codegen/Capstone/graph boundary."""
    return builtins.getattr(obj, name, default)


@cython.ccall
def _object_tuple_8616(value: object) -> object:
    """Return tuple-like dynamic metadata as a tuple."""
    try:
        return tuple(cast(Any, value)) if value is not None else ()
    except TypeError:
        return ()


@cython.ccall
def _object_tuple_attr_8616(obj: object, name: object) -> object:
    """Return a tuple attribute from dynamic codegen metadata."""
    return _object_tuple_8616(_dynamic_grouped_graph_getattr_8616(obj, name, ()))


@cython.ccall
def _dict_tuple_8616(entry: object, key: object) -> object:
    """Return a tuple-valued metadata entry."""
    return _object_tuple_8616(entry.get(key, ()))


@cython.ccall
def _dict_set_8616(entry: object, key: object) -> set[object]:
    """Return a set-valued metadata entry."""
    return set(_dict_tuple_8616(entry, key))


def _dict_str_tuple_8616(entry: object, key: object) -> tuple[str, ...]:
    """Return a sorted string tuple metadata entry."""
    return tuple(sorted(str(item) for item in builtins.iter(_dict_tuple_8616(entry, key))))


@cython.ccall
def _value_str_set_8616(value: object) -> set[str]:
    """Return a string set from dynamic metadata."""
    return {str(item) for item in builtins.iter(_object_tuple_8616(value))}


@cython.ccall
def _dict_int_8616(entry: object, key: object) -> cython.longlong:
    """Return an integer metadata entry with zero as the absent value."""
    value: object
    value = entry.get(key, 0)
    return int(value) if isinstance(value, int) else 0


@cython.ccall
def _graph_nodes_8616(graph: object) -> object:
    """Return graph nodes from a dynamic NetworkX-like graph object."""
    return _object_tuple_8616(_dynamic_grouped_graph_getattr_8616(graph, "nodes", ()))


@cython.ccall
def _region_metadata_8616(region: object) -> object:
    """Return the mutable metadata dictionary on a dynamic region node."""
    metadata = _dynamic_grouped_graph_getattr_8616(region, "metadata", None)
    if isinstance(metadata, dict):
        return metadata
    metadata = {}
    typing.cast(typing.Any, region).metadata = metadata
    return metadata


@cython.ccall
def _format_ir_value_8616(value: IRAtom) -> object:
    if not isinstance(value, IRValue):
        return None
    if operator.eq(value.space, MemSpace.CONST):
        return str(int(value.const)) if isinstance(value.const, int) else None
    if value.space in {MemSpace.REG, MemSpace.TMP} and isinstance(value.name, str) and value.name:
        if int(value.offset or 0) == 0:
            return value.name
        sign = "+" if value.offset > 0 else "-"
        return f"{value.name} {sign} {abs(int(value.offset))}"
    return None


def _format_ir_address_hint_8616(address: IRAddress) -> object:
    def _impl() -> object:
        base = tuple(address.base or ())
        if not base:
            return None
        parts = [str(item) for item in iter(base) if isinstance(item, str) and item]
        if not parts:
            return None
        offset = int(address.offset or 0)
        if offset > 0:
            parts.append(str(offset))
        elif offset < 0:
            parts.append(f"- {abs(offset)}")
        base_text = " + ".join(parts)
        if " + - " in base_text:
            base_text = base_text.replace(" + - ", " - ")
        space = address.space.value
        return f"{space}:[{base_text}]"

    return _impl()


def _format_ir_condition_hint_8616(condition: IRCondition) -> object:
    def _impl() -> object:
        logical: object
        args = tuple(condition.args or ())
        op = str(condition.op)
        logical = _logical_condition_hint_8616(op, args)
        if logical is not None:
            return logical
        return _comparison_condition_hint_8616(op, args)

    return _impl()


@cython.ccall
def _logical_condition_hint_8616(op: object, args: object) -> object:
    """Render the not/and/or condition shapes as a hint."""
    inner: object
    left: object
    right: object
    if op == "not" and len(args) == 1 and isinstance(args[0], IRCondition):
        inner = _format_ir_condition_hint_8616(args[0])
        if inner is None:
            return None
        return f"!({inner})"
    if (
        op in {"and", "or"}
        and len(args) == 2
        and isinstance(args[0], IRCondition)
        and isinstance(args[1], IRCondition)
    ):
        left = _format_ir_condition_hint_8616(args[0])
        right = _format_ir_condition_hint_8616(args[1])
        if left is None or right is None:
            return None
        join = " && " if op == "and" else " || "
        return f"({left}){join}({right})"
    return None


@cython.ccall
def _comparison_condition_hint_8616(op: object, args: object) -> object:
    """Render the zero/masked/compare condition shapes as a hint."""
    cmp_symbol: object
    left: object
    right: object
    value: object
    if op in {"zero", "nonzero"} and len(args) == 1:
        value = _format_ir_value_8616(args[0])
        if value is None:
            return None
        return f"{value} == 0" if op == "zero" else f"{value} != 0"
    if op == "masked_nonzero" and len(args) == 2:
        left = _format_ir_value_8616(args[0])
        right = _format_ir_value_8616(args[1])
        if left is None or right is None:
            return None
        return f"({left} & {right}) != 0"
    cmp_symbol = condition_compare_symbol_8616(op)
    if cmp_symbol is not None and len(args) == 2:
        left = _format_ir_value_8616(args[0])
        right = _format_ir_value_8616(args[1])
        if left is None or right is None:
            return None
        return f"{left} {cmp_symbol} {right}"
    return None


@cython.ccall
def _edge_jump_target_region_id_8616(codegen: object, edge_block_addr: cython.longlong) -> int | None:
    project: object
    project = _dynamic_grouped_graph_getattr_8616(codegen, "project", None)
    factory = _dynamic_grouped_graph_getattr_8616(project, "factory", None) if project is not None else None
    block_lifter = _dynamic_grouped_graph_getattr_8616(factory, "block", None)
    if not callable(block_lifter):
        return None
    try:
        block = block_lifter(edge_block_addr, num_inst=1, opt_level=0)
    except TypeError:
        try:
            block = block_lifter(edge_block_addr, num_inst=1)
        except Exception:
            return None
    except Exception:
        return None
    insns = _object_tuple_8616(
        _dynamic_grouped_graph_getattr_8616(
            _dynamic_grouped_graph_getattr_8616(block, "capstone", None), "insns", ()
        )
    )
    if not insns:
        return None
    operands = _object_tuple_attr_8616(insns[0], "operands")
    if not operands:
        return None
    imm = _dynamic_grouped_graph_getattr_8616(operands[0], "imm", None)
    return int(imm) if isinstance(imm, int) else None


@cython.ccall
def _edge_producer_semantics_payload_8616(edge: ConditionEdgeEvidence) -> object:
    semantics = edge.producer_semantics
    if not isinstance(semantics, tuple):
        return None
    return tuple(semantics)


def _typed_ir_support_by_region_id(codegen: object) -> object:
    def _impl() -> object:
        artifact: object
        condition_ir_support: object
        block: object
        phi: object
        artifact = _dynamic_grouped_graph_getattr_8616(codegen, "_inertia_vex_ir_artifact", None)
        function_ssa = _dynamic_grouped_graph_getattr_8616(codegen, "_inertia_vex_ir_function_ssa", None)
        support: object = _condition_ir_support_by_region_id_8616(codegen)
        if artifact is None or not hasattr(artifact, "blocks"):
            return support

        for block in _object_tuple_attr_8616(artifact, "blocks"):
            region_id = _dynamic_grouped_graph_getattr_8616(block, "addr", None)
            if not isinstance(region_id, int):
                continue
            block_scan = _scan_typed_ir_block_8616(block)
            cjmp_condition_hint = block_scan["condition_hint"]
            address_spaces = _value_str_set_8616(block_scan["address_spaces"])
            stable_address_spaces = _value_str_set_8616(block_scan["stable_address_spaces"])
            segment_origin_kinds = _value_str_set_8616(block_scan["segment_origin_kinds"])
            address_hint = block_scan["address_hint"]
            condition_ir_support = support.get(region_id, {})
            condition_ir_ops = _dict_tuple_8616(condition_ir_support, "condition_ir_ops")
            condition_edge_ops = _dict_tuple_8616(condition_ir_support, "condition_edge_guard_ops")
            has_condition = any(
                any(isinstance(arg, IRCondition) for arg in builtins.iter(_object_tuple_attr_8616(instr, "args")))
                for instr in builtins.iter(_object_tuple_attr_8616(block, "instrs"))
            )
            condition_kinds = tuple(
                sorted(
                    {
                        str(arg.op)
                        for instr in builtins.iter(_object_tuple_attr_8616(block, "instrs"))
                        for arg in builtins.iter(_object_tuple_attr_8616(instr, "args"))
                        if isinstance(arg, IRCondition)
                    }
                )
            )
            support[region_id] = {
                **condition_ir_support,
                "has_condition": any(
                    (
                        has_condition,
                        bool(condition_ir_support.get("condition_ir_has_condition", False)),
                        bool(condition_ir_support.get("condition_edge_has_guard", False)),
                    )
                ),
                "condition_kinds": tuple(sorted(str(item) for item in iter(tuple(condition_kinds) + tuple(condition_ir_ops) + tuple(condition_edge_ops)))),
                "condition_hint": cjmp_condition_hint
                or condition_ir_support.get("condition_ir_hint")
                or condition_ir_support.get("condition_hint"),
                "has_address": bool(address_spaces),
                "address_spaces": tuple(sorted(address_spaces)),
                "stable_address_spaces": tuple(sorted(stable_address_spaces)),
                "segment_origin_kinds": tuple(sorted(segment_origin_kinds)),
                "address_hint": address_hint,
                "has_phi": False,
            }
        for phi in _object_tuple_attr_8616(function_ssa, "phi_nodes"):
            region_id = _dynamic_grouped_graph_getattr_8616(phi, "block_addr", None)
            if not isinstance(region_id, int):
                continue
            support.setdefault(
                region_id,
                {
                    "has_condition": False,
                    "condition_kinds": (),
                    "condition_hint": None,
                    "condition_ir_has_condition": False,
                    "condition_ir_ops": (),
                    "condition_ir_hint": None,
                    "condition_ir_count": 0,
                    "condition_edge_has_guard": False,
                    "condition_edge_guard_ops": (),
                    "condition_edge_guard_hints": (),
                    "condition_edge_guards": (),
                    "condition_edge_guard_count": 0,
                    "condition_edge_producer_semantics": (),
                    "has_address": False,
                    "address_spaces": (),
                    "stable_address_spaces": (),
                    "segment_origin_kinds": (),
                    "address_hint": None,
                    "has_phi": False,
                },
            )["has_phi"] = True
        return support

    return _impl()


def _condition_ir_support_by_region_id_8616(codegen: object) -> object:
    def _impl() -> object:
        support: dict[cython.longlong, dict[str, object]] = {}
        conditions = _dynamic_grouped_graph_getattr_8616(codegen, "_inertia_typed_conditions", None)
        if isinstance(conditions, (list, tuple)):
            _collect_condition_ir_support_8616(support, conditions)
        edge_evidence = _dynamic_grouped_graph_getattr_8616(codegen, "_inertia_condition_edge_evidence", None)
        if isinstance(edge_evidence, (list, tuple)):
            _collect_edge_evidence_support_8616(codegen, support, edge_evidence)
        return support

    return _impl()


@cython.ccall
def _empty_support_entry_8616(*, has_condition: cython.bint, condition_ir: cython.bint, edge_guard: cython.bint) -> dict[str, object]:
    """Return the canonical empty per-region support record."""
    return {
        "has_condition": has_condition,
        "condition_kinds": (),
        "condition_hint": None,
        "condition_ir_has_condition": condition_ir,
        "condition_ir_ops": (),
        "condition_ir_hint": None,
        "condition_ir_count": 0,
        "condition_edge_has_guard": edge_guard,
        "condition_edge_guard_ops": (),
        "condition_edge_guard_hints": (),
        "condition_edge_guards": (),
        "condition_edge_guard_count": 0,
        "condition_edge_producer_semantics": (),
        "has_address": False,
        "address_spaces": (),
        "stable_address_spaces": (),
        "segment_origin_kinds": (),
        "address_hint": None,
        "has_phi": False,
    }


def _collect_condition_ir_support_8616(
    support: object, conditions: typing.Iterable[object]
) -> None:
    """Fold typed-IR conditions into the per-region support map."""
    hint: object
    cond: object
    region_id: object
    for cond in conditions:
        if not isinstance(cond, ConditionIR):
            continue
        region_ids = tuple(
            dict.fromkeys(
                region_id
                for region_id in iter((cond.block_addr, cond.src_insn))
                if isinstance(region_id, int)
            )
        )
        if not region_ids:
            continue
        for region_id in region_ids:
            entry = support.setdefault(
                region_id,
                _empty_support_entry_8616(has_condition=True, condition_ir=True, edge_guard=False),
            )
            ops = _dict_set_8616(entry, "condition_ir_ops")
            ops.add(str(cond.op))
            entry["condition_ir_ops"] = tuple(sorted(str(item) for item in iter(ops)))
            entry["condition_kinds"] = tuple(
                sorted(str(item) for item in iter(tuple(_dict_tuple_8616(entry, "condition_kinds")) + (str(cond.op),)))
            )
            entry["condition_ir_count"] = _dict_int_8616(entry, "condition_ir_count") + 1
            if entry.get("condition_ir_hint") is None:
                hint = render_condition_ir_native_8616(cond) or render_condition_ir_8616(cond)
                if hint is not None:
                    entry["condition_ir_hint"] = hint
                    entry["condition_hint"] = hint


def _record_edge_guard_8616(
    support: object,
    region_id: cython.longlong,
    condition: ConditionIR,
    producer_semantics: object,
) -> None:
    """Fold one guarded-edge condition into a region's support record."""
    hint: object
    entry = support.setdefault(
        region_id,
        _empty_support_entry_8616(has_condition=True, condition_ir=False, edge_guard=True),
    )
    entry["has_condition"] = True
    entry["condition_edge_has_guard"] = True
    edge_ops = _dict_set_8616(entry, "condition_edge_guard_ops")
    edge_ops.add(str(condition.op))
    entry["condition_edge_guard_ops"] = tuple(sorted(str(item) for item in iter(edge_ops)))
    entry["condition_kinds"] = tuple(
        sorted(str(item) for item in iter(tuple(_dict_tuple_8616(entry, "condition_kinds")) + (str(condition.op),)))
    )
    edge_guards = _dict_tuple_8616(entry, "condition_edge_guards")
    if condition not in edge_guards:
        entry["condition_edge_guards"] = (*edge_guards, condition)
    entry["condition_edge_guard_count"] = _dict_int_8616(entry, "condition_edge_guard_count") + 1
    if producer_semantics is not None:
        current_semantics = _dict_tuple_8616(entry, "condition_edge_producer_semantics")
        if producer_semantics not in current_semantics:
            entry["condition_edge_producer_semantics"] = (*current_semantics, producer_semantics)
    hint = render_condition_ir_native_8616(condition) or render_condition_ir_8616(condition)
    if hint is not None:
        hints = _dict_tuple_8616(entry, "condition_edge_guard_hints")
        if hint not in hints:
            entry["condition_edge_guard_hints"] = (*hints, hint)
        if entry.get("condition_hint") is None:
            entry["condition_hint"] = hint


@cython.ccall
def _record_producer_semantics_8616(
    support: object,
    producer_region_ids: object,
    producer_semantics: object,
) -> None:
    """Fold producer-side semantics into each producer region's support record."""
    producer_region_id: object
    for producer_region_id in producer_region_ids:
        entry = support.setdefault(
            producer_region_id,
            _empty_support_entry_8616(has_condition=False, condition_ir=False, edge_guard=False),
        )
        current_semantics = _dict_tuple_8616(entry, "condition_edge_producer_semantics")
        if producer_semantics not in current_semantics:
            entry["condition_edge_producer_semantics"] = (*current_semantics, producer_semantics)


def _collect_edge_evidence_support_8616(
    codegen: object, support: object, edge_evidence: typing.Iterable[object]
) -> None:
    """Fold guarded-edge evidence into the per-region support map."""
    producer_semantics: object
    edge: object
    region_id: object
    for edge in edge_evidence:
        if not isinstance(edge, ConditionEdgeEvidence):
            continue
        edge_region_ids: list[cython.longlong] = [edge.edge_block_addr]
        target_region_id = _edge_jump_target_region_id_8616(codegen, edge.edge_block_addr)
        if isinstance(target_region_id, int):
            edge_region_ids.append(target_region_id)
        condition = edge.condition
        producer_semantics = _edge_producer_semantics_payload_8616(edge)
        for region_id in dict.fromkeys(edge_region_ids):
            _record_edge_guard_8616(support, region_id, condition, producer_semantics)
        producer_region_ids = tuple(
            dict.fromkeys(
                region_id
                for region_id in iter((
                    edge.producer_insn,
                    _dynamic_grouped_graph_getattr_8616(condition, "producer_insn", None),
                ))
                if isinstance(region_id, int)
            )
        )
        if producer_semantics is not None:
            _record_producer_semantics_8616(support, producer_region_ids, producer_semantics)


def _scan_typed_ir_block_8616(block: object) -> object:
    def _impl() -> dict[str, object]:
        address_hint: object
        cjmp_condition_hint: object
        arg: object
        instr: object
        cjmp_condition_hint = None
        address_spaces: set[str] = set()
        stable_address_spaces: set[str] = set()
        segment_origin_kinds: set[str] = set()
        address_hint = None
        for instr in _object_tuple_attr_8616(block, "instrs"):
            for arg in _object_tuple_attr_8616(instr, "args"):
                if not isinstance(arg, IRAddress):
                    continue
                address_spaces.add(arg.space.value)
                if operator.eq(arg.status, AddressStatus.STABLE):
                    stable_address_spaces.add(arg.space.value)
                segment_origin_kinds.add(arg.segment_origin.value)
                if (address_hint is None and (operator.eq(arg.status, AddressStatus.STABLE) or operator.eq(arg.segment_origin, SegmentOrigin.PROVEN))) or address_hint is None:
                    address_hint = _format_ir_address_hint_8616(arg)
            if _dynamic_grouped_graph_getattr_8616(instr, "op", None) != "CJMP":
                continue
            args = _object_tuple_attr_8616(instr, "args")
            if not args or not isinstance(args[0], IRCondition):
                continue
            cjmp_condition_hint = _format_ir_condition_hint_8616(args[0])
            if cjmp_condition_hint is not None:
                break
        return {
            "condition_hint": cjmp_condition_hint,
            "address_spaces": address_spaces,
            "stable_address_spaces": stable_address_spaces,
            "segment_origin_kinds": segment_origin_kinds,
            "address_hint": address_hint,
        }

    return _impl()


@cython.ccall
def _annotate_typed_ir_support_on_graph(graph: object, typed_ir_support: object) -> None:
    ir_support: object
    region: object
    for region in _graph_nodes_8616(graph):
        region_id = _dynamic_grouped_graph_getattr_8616(region, "region_id", None)
        if not isinstance(region_id, int):
            continue
        ir_support = typed_ir_support.get(region_id)
        if ir_support is None:
            continue
        metadata = _region_metadata_8616(region)
        metadata["typed_ir_has_condition"] = ir_support["has_condition"]
        metadata["typed_ir_condition_kinds"] = _dict_tuple_8616(ir_support, "condition_kinds")
        metadata["typed_ir_condition_hint"] = ir_support.get("condition_hint")
        metadata["typed_condition_ir_has_condition"] = bool(
            ir_support.get("condition_ir_has_condition", False)
        )
        metadata["typed_condition_ir_ops"] = _dict_tuple_8616(ir_support, "condition_ir_ops")
        metadata["typed_condition_ir_hint"] = ir_support.get("condition_ir_hint")
        metadata["typed_condition_ir_count"] = _dict_int_8616(ir_support, "condition_ir_count")
        metadata["typed_condition_edge_has_guard"] = bool(ir_support.get("condition_edge_has_guard", False))
        metadata["typed_condition_edge_guard_ops"] = tuple(
            _dict_tuple_8616(ir_support, "condition_edge_guard_ops")
        )
        metadata["typed_condition_edge_guard_hints"] = tuple(
            _dict_tuple_8616(ir_support, "condition_edge_guard_hints")
        )
        metadata["typed_condition_edge_guards"] = _dict_tuple_8616(ir_support, "condition_edge_guards")
        metadata["typed_condition_edge_guard_count"] = int(
            _dict_int_8616(ir_support, "condition_edge_guard_count")
        )
        metadata["typed_condition_edge_producer_semantics"] = tuple(
            _dict_tuple_8616(ir_support, "condition_edge_producer_semantics")
        )
        metadata["typed_ir_has_address"] = bool(ir_support.get("has_address", False))
        metadata["typed_ir_address_spaces"] = _dict_tuple_8616(ir_support, "address_spaces")
        metadata["typed_ir_stable_address_spaces"] = _dict_tuple_8616(ir_support, "stable_address_spaces")
        metadata["typed_ir_segment_origin_kinds"] = _dict_tuple_8616(ir_support, "segment_origin_kinds")
        metadata["typed_ir_address_hint"] = ir_support.get("address_hint")
        metadata["typed_ir_has_phi"] = ir_support["has_phi"]
        metadata["typed_ir_allow_abnormal_loop_normalization"] = bool(
            ir_support["has_condition"] or ir_support["has_phi"]
        )


def build_grouped_region_graph(codegen: object) -> GroupedRegionGraphBuildResult:
    """Build the region graph and attach grouped/typed-IR evidence metadata."""

    def _impl() -> GroupedRegionGraphBuildResult:
        graph: object
        grouped_units: object
        role: object
        region: object
        graph_result = build_region_graph(codegen)
        grouped_units = build_x86_16_cross_entry_grouped_units(codegen)
        graph = graph_result.graph
        if graph is None:
            return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)

        typed_ir_support = _typed_ir_support_by_region_id(codegen)
        _annotate_typed_ir_support_on_graph(graph, typed_ir_support)
        if grouped_units is None or not grouped_units.units:
            return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)

        role_by_region_id = _role_by_region_id_8616(grouped_units)
        for region in _graph_nodes_8616(graph):
            region_id = _dynamic_grouped_graph_getattr_8616(region, "region_id", None)
            if not isinstance(region_id, int):
                continue
            role = role_by_region_id.get(region_id)
            if role is None:
                continue
            grouping_kind, unit_index = role
            metadata = _region_metadata_8616(region)
            metadata["cross_entry_grouping_kind"] = grouping_kind
            metadata["cross_entry_unit_index"] = unit_index

        return GroupedRegionGraphBuildResult(graph_result=graph_result, grouped_units=grouped_units)

    return _impl()


@cython.ccall
def _role_by_region_id_8616(grouped_units: CrossEntryGroupedUnitArtifact) -> object:
    """Map each region id to its (grouping kind, unit index) role."""
    region_id: object
    unit: object
    unit_index: object
    role_by_region_id: dict[cython.longlong, tuple[str, cython.longlong]] = {}
    for unit_index, unit in enumerate(grouped_units.units):
        for region_id in unit.primary_entry_region_ids:
            role_by_region_id[region_id] = ("primary_entry", unit_index)
        for region_id in unit.entry_fragment_region_ids:
            role_by_region_id[region_id] = ("entry_fragment", unit_index)
        for region_id in unit.shared_region_ids:
            role_by_region_id[region_id] = ("grouped_entry_candidate", unit_index)
    return role_by_region_id


@cython.ccall
def describe_x86_16_grouped_region_graph_surface() -> dict[str, object]:
    """Describe the stable metadata surface produced by this builder."""
    return {
        "producer": "build_grouped_region_graph",
        "graph_surface": "Region.metadata[cross_entry_*, typed_ir_*, typed_condition_edge_*]",
        "unit_surface": "CrossEntryGroupedUnitArtifact",
        "purpose": "Materialize cross-entry grouping directly onto the region graph before structuring.",
    }


__all__ = [
    "GroupedRegionGraphBuildResult",
    "build_grouped_region_graph",
    "describe_x86_16_grouped_region_graph_surface",
]
