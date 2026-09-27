"""Layer: validation CFG composition.

Responsibility: compare complete acyclic flat-i386 SSA regions across CFG shapes.
Calls, loops, indirect edges, partial scans, and budget exhaustion refuse.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from flat32_adapter import REG32, S
from flat32_verdict import Status

type CallResolver = Callable[[int], str | None]


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


def _optional_linear(value: Any) -> int | None:  # noqa: ANN401
    """Accept only a full-width integer or 0x-prefixed linear address."""
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.startswith("0x"):
        parsed = int(value, 16)
    else:
        return None
    return parsed if 0 <= parsed <= 0xFFFFFFFF else None


def _const_term_int(term: Any) -> int | None:  # noqa: ANN401
    """Read a full-width constant term's value."""
    return _constant_target(term)


def _esp_delta(term: Any, base: Any) -> int | None:  # noqa: ANN401
    """Return c when term is base +/- constants, else None (unbalanced/unknown)."""
    if term == base:
        return 0
    if not isinstance(term, dict) or term.get("op") not in {"add", "sub"}:
        return None
    args = term.get("args")
    if not isinstance(args, list) or len(args) != 2 or not isinstance(args[0], dict):
        return None
    inner = _esp_delta(args[0], base)
    const = _const_term_int(args[1])
    if inner is None or const is None:
        return None
    return inner + const if term["op"] == "add" else inner - const


def _apply_bounded_call(
    block: dict[str, Any],
    state: dict[str, dict[str, Any]],
    incoming: dict[str, dict[str, Any]],
    call_index: int,
    call_resolver: CallResolver,
    calls: list[dict[str, Any]],
) -> int:
    """Model one paired direct call as an effects-complete boundary; return the fallthrough VA.

    The call block's own SSA already pushed the return address and set `ip` to the
    constant callee target.  Post-call, every register other than esp, plus memory
    and io, is havoced to a fresh per-callsite input: the callee may clobber any of
    them, so the solver checks the caller for all callee results.  esp becomes
    `post_block_esp + delta` where delta is a fresh shared variable modeling the
    unknown-but-paired callee stack effect; caller-visible esp evidence is kept.
    """
    raw_source = block.get("source")
    source = raw_source if isinstance(raw_source, dict) else {}
    raw_transfer = source.get("transfer")
    transfer = raw_transfer if isinstance(raw_transfer, dict) else {}
    if transfer.get("kind") != "direct_call":
        raise RegionRefusal("call_indirect_or_unmodeled_target")
    raw_target = transfer.get("target")
    target_raw = raw_target if isinstance(raw_target, dict) else {}
    raw_fallthrough = transfer.get("fallthrough")
    fallthrough_raw = raw_fallthrough if isinstance(raw_fallthrough, dict) else {}
    target = _optional_linear(target_raw.get("linear") or target_raw.get("raw"))
    fallthrough = _optional_linear(fallthrough_raw.get("linear"))
    if target is None:
        raise RegionRefusal("call_indirect_or_unmodeled_target")
    if fallthrough is None:
        raise RegionRefusal("call_missing_full_fallthrough")
    callee = call_resolver(target)
    if callee is None:
        raise RegionRefusal("call_target_unmapped")
    ip = state.get("ip")
    if _const_term_int(ip) != target:
        raise RegionRefusal("call_target_mismatch")
    if _esp_delta(state.get("esp"), incoming.get("esp")) is None:
        raise RegionRefusal("call_esp_unbalanced")
    for name in list(state):
        if name in {"esp", "ip", "memory", "io"}:
            continue
        term = state[name]
        width = term.get("width") if isinstance(term, dict) else None
        state[name] = {"op": "input", "name": f"call{call_index}_{name}", "width": width or 32}
    state["memory"] = {"op": "mem_input", "name": f"call{call_index}_mem", "addr_width": 32, "value_width": 8}
    state["io"] = {"op": "mem_input", "name": f"call{call_index}_io", "addr_width": 32, "value_width": 8}
    state["esp"] = {
        "op": "add",
        "width": 32,
        "args": [state["esp"], {"op": "input", "name": f"call{call_index}_espdelta", "width": 32}],
    }
    state["ip"] = {"op": "const", "value": hex(fallthrough), "width": 32}
    calls.append({"callee": callee, "target": hex(target), "entry": hex(_linear(block))})
    return fallthrough


def summarize(  # noqa: C901
    parts: list[dict[str, Any]],
    *,
    outputs: tuple[str, ...],
    limits: RegionLimits,
    call_resolver: CallResolver | None = None,
) -> dict[str, Any]:
    """Compose every reachable acyclic path to a near return or refuse.

    With `call_resolver` (linear VA -> mapped callee name), direct calls to known
    mapped callees compose as bounded effect boundaries whose post-state is fully
    unconstrained except esp; the composed `call_sites` must be paired by the
    caller and the resulting verdict can never be unconditional PASSED.
    """
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
    calls: list[dict[str, Any]] = []

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
        if jumpkind not in {"Ijk_Boring", "Ijk_Ret", "Ijk_Call"}:
            raise RegionRefusal("call_or_exception_boundary")
        state = S._compose_block_outputs(block, block.get("outputs", {}), incoming)
        if _term_nodes(state, limits.max_term_nodes) > limits.max_term_nodes:
            raise RegionRefusal("region_expression_limit")
        ip = state.get("ip")
        if not isinstance(ip, dict):
            raise RegionRefusal("full_width_ip_unobserved")
        if jumpkind == "Ijk_Call":
            if call_resolver is None:
                raise RegionRefusal("call_or_exception_boundary")
            next_path = path | {address}
            fallthrough = _apply_bounded_call(block, state, incoming, len(calls), call_resolver, calls)
            return walk(fallthrough, state, next_path)
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
        "call_sites": calls,
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
    normalization: dict[int, int] | None = None,
    call_resolver_oracle: CallResolver | None = None,
    call_resolver_candidate: CallResolver | None = None,
) -> dict[str, Any]:
    """Use dosunit Z3 on complete composed regions with bounded resources.

    With per-side call resolvers, paired direct calls to the same mapped callee
    name compose as havoced effect boundaries. Equality can only yield
    Status.CONDITIONAL under explicit paired post-call-state equality assumptions;
    unmatched calls and unsupported transfers refuse. A mismatch with havoced
    callee results is inconclusive for the real binaries and also refuses.
    """
    limits = limits or RegionLimits()
    try:
        oracle = summarize(oracle_parts, outputs=outputs, limits=limits, call_resolver=call_resolver_oracle)
        candidate = summarize(
            candidate_parts, outputs=outputs, limits=limits, call_resolver=call_resolver_candidate
        )
        oracle_calls = oracle["call_sites"]
        candidate_calls = candidate["call_sites"]
        if len(oracle_calls) != len(candidate_calls) or any(
            site["callee"] != pair["callee"]
            for site, pair in zip(oracle_calls, candidate_calls, strict=True)
        ):
            raise RegionRefusal("unmatched_call_order")
        if normalization:
            candidate["_constant_normalization"] = normalization
            candidate["_constant_normalization_reasons"] = dict.fromkeys(normalization, "global_reloc")
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
    if oracle["call_sites"]:
        paired_assumptions = {
                "kind": "paired_post_call_state_equality",
                "paired_callees": [
                    {
                        "callee": site["callee"],
                        "oracle_target": site["target"],
                        "oracle_callsite": site["entry"],
                        "candidate_target": pair["target"],
                        "candidate_callsite": pair["entry"],
                    }
                    for site, pair in zip(oracle["call_sites"], candidate["call_sites"], strict=True)
                ],
                "scope": (
                    "each paired call is assumed to return with equal post-call register, memory, io, "
                    "flag and stack effects, even when its pre-call states differ; matching names alone "
                    "do not establish this relation"
                ),
        }
        comparison["paired_call_assumptions"] = paired_assumptions
        if comparison["status"] == Status.PASSED:
            comparison.update(
                status=Status.CONDITIONAL,
                reason="paired_call_assumptions",
                assumptions=paired_assumptions,
            )
        elif comparison["status"] == Status.FAILED:
            comparison.update(
                status=Status.REFUSED,
                reason="paired_call_model_counterexample",
                backend_status=Status.FAILED,
            )
    return {
        **comparison,
        "oracle_blocks_composed": oracle["blocks_composed"],
        "candidate_blocks_composed": candidate["blocks_composed"],
        "paired_calls": len(oracle["call_sites"]),
    }
