"""Layer: validation CFG composition.

Responsibility: compare complete acyclic flat-i386 SSA regions across CFG shapes.
Calls, loops, indirect edges, partial scans, and budget exhaustion refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from flat32_adapter import REG32, S
from flat32_verdict import Status


@dataclass(frozen=True)
class RegionLimits:
    """Bound work before constructing a Z3 formula for one function."""

    max_blocks: int = 64
    max_compositions: int = 128
    max_term_nodes: int = 12000
    max_solver_inputs: int = 64
    max_memory_stores: int = 128


class RegionRefusal(ValueError):
    """An incomplete or unsupported region, never an equivalence verdict."""


def _linear(part: dict[str, Any]) -> int:
    """Read the full block VA, refusing absent or malformed entry evidence."""
    raw_entry = part.get("entry")
    entry = raw_entry if isinstance(raw_entry, dict) else {}
    value = entry.get("linear")
    if not isinstance(value, (int, str)):
        raise RegionRefusal("missing_full_linear_entry")
    return int(value, 0) if isinstance(value, str) else value


def _constant_target(term: Any) -> int | None:  # noqa: ANN401
    """Accept only a full-width constant successor, without a low-word alias."""
    if not isinstance(term, dict) or term.get("op") != "const" or term.get("width") != 32:
        return None
    value = term.get("value")
    if not isinstance(value, (int, str)):
        return None
    parsed = int(value, 0) if isinstance(value, str) else value
    return parsed if 0 <= parsed <= 0xFFFFFFFF else None


def _term_nodes(terms: object, limit: int) -> int:
    """Count inlined JSON expression nodes, stopping at the resource limit."""
    pending = [terms]
    count = 0
    while pending:
        term = pending.pop()
        if isinstance(term, dict):
            count += 1
            if count > limit:
                return count
            pending.extend(term.values())
        elif isinstance(term, (list, tuple)):
            pending.extend(term)
    return count


def _initial_state() -> dict[str, dict[str, Any]]:
    """Give both binaries the same unconstrained flat machine inputs."""
    state = {name: {"op": "input", "name": name, "width": width} for name, width in REG32.values()}
    state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    state["io"] = {"op": "mem_input", "name": "io", "addr_width": 32, "value_width": 8}
    return state


def summarize(  # noqa: C901
    parts: list[dict[str, Any]],
    *,
    outputs: tuple[str, ...],
    limits: RegionLimits,
) -> dict[str, Any]:
    """Compose every reachable acyclic path to a near return or refuse."""
    if not parts or len(parts) > limits.max_blocks:
        raise RegionRefusal("region_block_limit_or_missing")
    blocks: dict[int, dict[str, Any]] = {}
    for part in parts:
        address = _linear(part)
        if address in blocks:
            raise RegionRefusal("duplicate_linear_block")
        blocks[address] = part
    function_entry = parts[0].get("function_entry")
    start_text = function_entry.get("linear") if isinstance(function_entry, dict) else None
    if not isinstance(start_text, (int, str)):
        raise RegionRefusal("missing_full_linear_function_entry")
    start = int(start_text, 0) if isinstance(start_text, str) else start_text
    if start not in blocks:
        raise RegionRefusal("entry_block_missing")
    compositions = 0

    def walk(  # noqa: C901
        address: int, incoming: dict[str, dict[str, Any]], path: frozenset[int]
    ) -> dict[str, dict[str, Any]]:
        """Compose one path and merge both arms of each typed direct branch."""
        nonlocal compositions
        if address in path:
            raise RegionRefusal("loop_requires_inductive_proof")
        block = blocks.get(address)
        if block is None:
            raise RegionRefusal("successor_outside_complete_region")
        compositions += 1
        if compositions > limits.max_compositions:
            raise RegionRefusal("region_composition_limit")
        raw_source = block.get("source")
        source = raw_source if isinstance(raw_source, dict) else {}
        jumpkind = source.get("jumpkind")
        if jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
            raise RegionRefusal("call_or_exception_boundary")
        state = S._compose_block_outputs(block, block.get("outputs", {}), incoming)
        if _term_nodes(state, limits.max_term_nodes) > limits.max_term_nodes:
            raise RegionRefusal("region_expression_limit")
        ip = state.get("ip")
        if not isinstance(ip, dict):
            raise RegionRefusal("full_width_ip_unobserved")
        if jumpkind == "Ijk_Ret":
            if ip.get("op") == "ite":
                raise RegionRefusal("conditional_exit_in_return_block")
            state["eip"] = ip
            return state
        next_path = path | {address}
        target = _constant_target(ip)
        if target is not None:
            return walk(target, state, next_path)
        args = ip.get("args")
        if ip.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
            raise RegionRefusal("indirect_or_unmodeled_branch")
        true_target, false_target = _constant_target(args[1]), _constant_target(args[2])
        if true_target is None or false_target is None or not isinstance(args[0], dict):
            raise RegionRefusal("indirect_or_unmodeled_branch")
        true_state = walk(true_target, state, next_path)
        false_state = walk(false_target, state, next_path)
        merged = S._merge_abi_states(args[0], true_state, false_state)
        if _term_nodes(merged, limits.max_term_nodes) > limits.max_term_nodes:
            raise RegionRefusal("region_expression_limit")
        return merged

    final_state = walk(start, _initial_state(), frozenset())
    observed = tuple(dict.fromkeys((*outputs, "eip", "memory", "io")))
    if any(name not in final_state for name in observed):
        raise RegionRefusal("observable_state_missing")
    terms = {name: final_state[name] for name in observed}
    if _term_nodes(terms, limits.max_term_nodes) > limits.max_term_nodes:
        raise RegionRefusal("region_expression_limit")
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized = {
        name: S._materialize_json_term(term, assignments=assignments, memo=memo, term_cache=term_cache)
        for name, term in terms.items()
    }
    return {
        "inputs": S._term_input_items(list(materialized.values()), assignments),
        "outputs": materialized,
        "assignments": assignments,
        "blocks_composed": compositions,
    }


def _has_lazy_flags(summary: dict[str, Any], limit: int) -> bool:
    """Treat SAT with an uninterpreted x86 flag helper as inconclusive."""
    helpers = S.X86_LAZY_FLAG_SUMMARY_OPS
    assignments = {
        item["id"]: item for item in summary.get("assignments", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    pending = [summary.get("outputs", {}), summary.get("assignments", [])]
    seen = 0
    while pending and seen <= limit:
        item = pending.pop()
        if isinstance(item, dict):
            seen += 1
            if item.get("op") in helpers and S._x86_lazy_flag_summary_is_uninterpreted(item, assignments):
                return True
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return bool(pending)


def compare_region(
    oracle_parts: list[dict[str, Any]],
    candidate_parts: list[dict[str, Any]],
    *,
    outputs: tuple[str, ...],
    timeout_ms: int,
    limits: RegionLimits | None = None,
) -> dict[str, Any]:
    """Use dosunit Z3 on complete composed regions with bounded resources."""
    limits = limits or RegionLimits()
    try:
        oracle = summarize(oracle_parts, outputs=outputs, limits=limits)
        candidate = summarize(candidate_parts, outputs=outputs, limits=limits)
        gate = S._ssa_solver_gate(
            oracle, candidate,
            max_solver_assignments=limits.max_term_nodes,
            max_solver_inputs=limits.max_solver_inputs,
            max_solver_memory_stores=limits.max_memory_stores,
        )
        if gate is not None:
            raise RegionRefusal(str(gate["reason"]))
    except RegionRefusal as error:
        return {"status": Status.REFUSED, "reason": str(error)}
    comparison = S._compare_functions(oracle, candidate, timeout_ms=timeout_ms)
    if comparison.get("skipped_layout_outputs"):
        return {"status": Status.REFUSED, "reason": "observable_output_skipped"}
    if comparison["status"] == Status.FAILED and (
        _has_lazy_flags(oracle, limits.max_term_nodes) or _has_lazy_flags(candidate, limits.max_term_nodes)
    ):
        comparison["status"] = Status.REFUSED
        comparison["reason"] = "uninterpreted_x86_flags"
    return {
        **comparison,
        "oracle_blocks_composed": oracle["blocks_composed"],
        "candidate_blocks_composed": candidate["blocks_composed"],
    }
