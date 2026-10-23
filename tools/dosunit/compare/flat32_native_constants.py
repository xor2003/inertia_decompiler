"""Layer: dosunit relational loop proofs.

Responsibility: infer and independently prove scratch constants at physical
native block entries before paired control tokens can merge distinct entries.
"""
from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from tools.comparator.verdict import Status
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _initial_state,
    _LiftedBlock,
    _term_nodes,
)
from tools.dosunit.compare.flat32_constant_registers import _document
from tools.dosunit.compare.flat32_dead_flags import _targets
from tools.dosunit.compare.flat32_loop_graph_search import _attempt_record, _check_graph
from tools.dosunit.compare.region_pairing import PairedRegions
from tools.dosunit.contracts.register_affine_relations import _linear_effect
from tools.dosunit.contracts.register_state_relations import RegisterRelationRefusal
from tools.dosunit.ssa.composition import _abi_terms_equal, compose_block_outputs

SCRATCH: tuple[str, ...] = ("eax", "ecx", "edx")


@dataclass(frozen=True, slots=True)
class NativeConstantProof:
    """Closed native-graph invariants with every incoming-edge proof retained."""

    constants: dict[int, dict[str, int]]
    evidence: dict[str, Any]


def constant_term(value: int) -> dict[str, Any]:
    """Represent an exact 32-bit literal, without relocation assumptions."""
    return {"op": "const", "width": 32, "value": hex(value)}


def _transfer(
    block: _LiftedBlock, incoming: dict[str, int], session: _ComposeSession,
) -> dict[str, dict[str, Any]]:
    """Expand only scratch/control dependencies under proposed entry constants."""
    _check_compose_deadline(session.compose_stats)
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        raise CallCompositionRefusal("region_composition_limit")
    initial = _initial_state(session.reg_widths)
    initial.update({key: constant_term(value) for key, value in incoming.items()})
    selected = {key: term for key, term in block.part["outputs"].items() if key in (*SCRATCH, "ip")}
    state = compose_block_outputs(block.part, selected, initial, compose_stats=session.compose_stats)
    if _term_nodes(state, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise S.LowerFailure("native_constant_expression_limit", "native constant expression budget")
    return state


def _constant(term: dict[str, Any]) -> int | None:
    """Recognize modular constants only as proposals pending independent proof."""
    args = term.get("args", [])
    if term.get("op") == "xor" and len(args) == 2 and _abi_terms_equal(args[0], args[1], {}):
        return 0
    try:
        effect = _linear_effect(term, 32)
    except RegisterRelationRefusal:
        return None
    return effect.offset if effect.multiplier == 0 else None


def _closed(blocks: Mapping[int, _LiftedBlock], entry: int, session: _ComposeSession) -> bool:
    """Require modeled call-free effects and exact native SSA successor coverage."""
    if entry not in blocks or len(blocks) > 64:
        return False
    for block in blocks.values():
        if block.jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
            return False
        if block.part.get("trap_exits") or "io" in block.part["outputs"]:
            return False
        if not set(block.successors).issubset(blocks):
            return False
        if block.jumpkind == "Ijk_Boring":
            state = _transfer(block, {}, session)
            if _targets(state.get("ip", {})) != frozenset(block.successors):
                return False
        elif block.successors:
            return False
    return True


def _infer(
    blocks: Mapping[int, _LiftedBlock], entry: int, session: _ComposeSession,
) -> dict[int, dict[str, int]] | None:
    """Meet predecessor constants to a fixed point; root inputs stay arbitrary."""
    incoming: dict[int, dict[str, int]] = {entry: {}}
    pending = deque([entry])
    while pending:
        address = pending.popleft()
        block = blocks[address]
        if not block.successors:
            continue
        state = _transfer(block, incoming[address], session)
        values = {key: _constant(state[key]) for key in SCRATCH}
        known = {key: value for key, value in values.items() if value is not None}
        for successor in block.successors:
            previous = incoming.get(successor)
            merged = known.copy() if previous is None else {
                key: value for key, value in previous.items() if known.get(key) == value}
            if previous != merged:
                incoming[successor] = merged
                pending.append(successor)
    return incoming if incoming.keys() == blocks.keys() else None


def _prove(
    blocks: Mapping[int, _LiftedBlock], incoming: dict[int, dict[str, int]],
    session: _ComposeSession, deadline: float,
    *, normalization: Mapping[int, int] | None = None,
) -> list[dict[str, Any]] | None:
    """Discharge all successor invariants under only proved incoming candidates.

    With ``normalization`` the right-hand document is compared inside the
    certified relocation domain: every edge must still hold, but the proof may
    return ``conditional`` on the declared constant map.
    """
    proofs = []
    reasons = dict.fromkeys(normalization, "global_reloc") if normalization else {}
    accepted = {Status.PASSED.value, Status.CONDITIONAL.value} if normalization else {
        Status.PASSED.value}
    for address, block in blocks.items():
        needed = [(target, incoming[target]) for target in block.successors if incoming[target]]
        if not needed:
            continue
        state = _transfer(block, incoming[address], session)
        for target, values in needed:
            timeout_ms = min(250, int((deadline - time.monotonic()) * 1000))
            if timeout_ms <= 0:
                return None
            transported = _document({}, {key: state[key] for key in values})
            if normalization:
                transported["_constant_normalization"] = dict(normalization)
                transported["_constant_normalization_reasons"] = dict(reasons)
            proof = S._compare_functions(
                _document({}, {key: constant_term(value) for key, value in values.items()}),
                transported, timeout_ms=timeout_ms,
            )
            if proof["status"] not in accepted:
                return None
            proofs.append({"from": hex(address), "to": hex(target), "proof": proof})
    return proofs


def _stable_scalar_values(
    incoming: dict[int, dict[str, int]], normalization: Mapping[int, int],
) -> tuple[dict[int, dict[str, int]], dict[int, dict[str, int]]]:
    """Drop only literals the certified relocation map would re-encode.

    A native fact records a candidate-domain literal. If that literal is itself
    a relocation key, binding it would silently survive the map and rewrite the
    fact mid-comparison; conservative scalar-only admission rejects it instead.
    """
    document = {
        "_constant_normalization": dict(normalization),
        "_constant_normalization_reasons": dict.fromkeys(normalization, "global_reloc"),
    }
    kept: dict[int, dict[str, int]] = {}
    rejected: dict[int, dict[str, int]] = {}
    for address, values in incoming.items():
        stable: dict[str, int] = {}
        for name, value in values.items():
            if S._normalized_constant_value(value, width=32, document=document) == value:
                stable[name] = value
            else:
                rejected.setdefault(address, {})[name] = value
        kept[address] = stable
    return kept, rejected


def prove_native_constants(
    blocks: Mapping[int, _LiftedBlock], entry: int, session: _ComposeSession, *, deadline: float,
    candidate_normalization: Mapping[int, int] | None = None,
) -> NativeConstantProof | None:
    """Prove physical-entry facts independently of any cross-image graph relation.

    Every reachable incoming edge participates, including backedges. Entry has
    no constant assumptions. Proposed facts never grant a comparison verdict:
    specialized transitions still expose full memory and all final outputs.
    Relocated semantics must not consume these literal-domain facts.

    When ``candidate_normalization`` is supplied, inferred literals are first
    reduced to the subset stable under the certified map, then every incoming
    edge is re-proved with that exact map on the transferred SSA. The returned
    evidence serializes the map so the caller can admit transported facts only
    when the certified map matches the one it intends to apply.
    """
    try:
        if not _closed(blocks, entry, session):
            return None
        incoming = _infer(blocks, entry, session)
        if incoming is None or not any(incoming.values()):
            return None
        raw_count = sum(len(values) for values in incoming.values())
        normalization = dict(candidate_normalization) if candidate_normalization else None
        rejected: dict[int, dict[str, int]] = {}
        if normalization is not None:
            incoming, rejected = _stable_scalar_values(incoming, normalization)
            if not any(incoming.values()):
                return None
            proofs = _prove(blocks, incoming, session, deadline, normalization=normalization)
        else:
            proofs = _prove(blocks, incoming, session, deadline)
    except (S.LowerFailure, CallCompositionRefusal):
        return None
    if not proofs:
        return None
    constants = {address: values for address, values in incoming.items() if values}
    count = sum(len(values) for values in constants.values())
    rejected_count = sum(len(values) for values in rejected.values())
    evidence: dict[str, Any] = {
        "method": "native_entry_constant_induction",
        "entry": hex(entry), "entry_inputs_unrestricted": True,
        "all_outputs_preserved": True,
        "entry_values": {hex(address): values for address, values in constants.items()},
        "incoming_edge_proofs": proofs,
        "raw_fact_count": raw_count, "normalized_fact_count": count,
        "classified_fact_count": count, "materialized_count": count,
        "failure_count": rejected_count,
    }
    if normalization is not None:
        evidence["scalar_domain"] = "candidate_normalization"
        evidence["candidate_normalization"] = {
            hex(key): hex(value) for key, value in sorted(normalization.items())}
        evidence["normalization_domain_size"] = len(normalization)
        evidence["rejected_relocated_values"] = {
            hex(address): {name: hex(value) for name, value in sorted(values.items())}
            for address, values in sorted(rejected.items())}
        evidence["normalized_edge_proof_count"] = len(proofs)
    return NativeConstantProof(constants, evidence)



def _retain_attempts(
    plain: dict[str, Any], refined: dict[str, Any],
) -> dict[str, Any]:
    """Return the richer result while keeping the losing route's evidence."""
    if plain["status"] in {Status.PASSED, Status.CONDITIONAL} or "block_verdicts" not in refined:
        return {**plain, "native_constant_attempt": _attempt_record(refined)}
    return {**refined, "unrestricted_native_attempt": _attempt_record(plain)}


def native_constant_checker(
    check: Callable[[PairedRegions, tuple[NativeConstantProof | None, NativeConstantProof | None]], dict[str, Any]],
    infer: Callable[[], tuple[NativeConstantProof | None, NativeConstantProof | None]], *,
    enabled: bool, prefer_facts_first: bool = False,
) -> Callable[[PairedRegions], dict[str, Any]]:
    """Try literal native facts lazily after an unrestricted comparison fails.

    With ``prefer_facts_first`` the validated facts are inferred once and
    checked before the costly unrestricted pass; a failed refined attempt is
    still recorded beside the plain result. Inference and both comparisons
    share the caller's deadline and work counters unchanged.
    """
    native_constants: tuple[NativeConstantProof | None, NativeConstantProof | None] | None = None

    def checked(graph: PairedRegions) -> dict[str, Any]:
        """Preserve existing proofs and retain both unsuccessful proof routes."""
        nonlocal native_constants
        if enabled and prefer_facts_first:
            if native_constants is None:
                native_constants = infer()
            if any(native_constants):
                facts = native_constants
                refined = _check_graph(
                    graph, lambda selected: check(selected, facts))
                if refined["status"] in {Status.PASSED, Status.CONDITIONAL}:
                    return {**refined, "prefer_facts_first": True}
                return _retain_attempts(check(graph, (None, None)), refined)
        plain = check(graph, (None, None))
        if plain["status"] in {Status.PASSED, Status.CONDITIONAL} or not enabled:
            return plain
        if native_constants is None:
            native_constants = infer()
        facts = native_constants
        if not any(facts):
            return plain
        refined = _check_graph(graph, lambda selected: check(selected, facts))
        return _retain_attempts(plain, refined)

    return checked
