"""Closed matched-loop induction over flat32 CFGs containing direct calls.

Layer: dosunit relational loop proofs.
Responsibility: prove paired flat32 CFGs whose superblock transitions may end
in admitted direct calls. A call member is never an assumed boundary: the
caller's call-block continuation is composed with the callee's checked
complete body from ``flat32_call_execution`` and the callee return is proved
by the shared ``_prove_return_target`` back to the recorded fallthrough, so a
call transition is an honest SSA transfer over the full machine state. The
composed transitions are then discharged by the common matched-CFG induction
(``region_pairing.propose_paired_regions`` + ``flat32_region_attempts``),
which gives initiation, preservation over every reachable transition,
branch/successor agreement, every normal and early exit, full
register/flags/memory state, and divergence equivalence for the synchronized
paired graph. Cyclic/recursive or incomplete callees, indirect calls,
unproved return targets, unmapped edges and exhausted budgets keep the
existing typed refusals; no premise is ever invented.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from enum import StrEnum
from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import (
    PRESERVED_OUTPUTS,
    CallCompositionLimits,
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _const_term_int,
    _initial_state,
    _LiftedBlock,
    _normalize_function_map,
    _register_widths,
    _ret_proof_timeout_ms,
    _term_nodes,
)
from tools.dosunit.flat32_call_execution import (
    _callee_term,
    _compose_function,
    _prove_return_target,
)
from tools.dosunit.flat32_call_lowering import _lift_function
from tools.dosunit.flat32_cfg_regions import _seams
from tools.dosunit.flat32_environment_coverage import environment_parts
from tools.dosunit.flat32_region_attempts import (
    compare_attempt as _compare_attempt,
)
from tools.dosunit.flat32_region_attempts import (
    comparison_deadline,
)
from tools.dosunit.flat32_relation_evidence import attempt_record as _attempt_record
from tools.dosunit.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphRefusal,
    RegionNode,
)
from tools.dosunit.proof_scope import ProofScope
from tools.dosunit.region_pairing import propose_paired_regions
from tools.dosunit.register_state_relations import IDENTITY_RELATION
from tools.dosunit.ssa_constant_terms import constant_bitvector

CONTROL_WIDTH: int = 32


class Flat32LoopCallReason(StrEnum):
    """Named verdict/refusal reasons owned by the flat32 call-loop lane."""

    INDUCTION = "call_loop_induction"
    TRANSITIONS_UNPROVED = "call_loop_transitions_unproved"
    CONTROL_LEAF_UNMAPPED = "call_loop_unmapped_successor"
    CONTROL_SHAPE = "call_loop_control_shape_unexpected"
    IP_UNOBSERVED = "call_loop_ip_unobserved"


def _nodes(blocks: Mapping[int, _LiftedBlock]) -> dict[int, RegionNode]:
    """Project a lifted closed block map onto typed region-graph nodes."""
    return {
        address: RegionNode(
            address,
            block.successors,
            RegionExitKind(block.jumpkind),
        )
        for address, block in blocks.items()
    }


def _cutpoint_tokens(
    regions: list[CollapsedRegion],
    ordered_indices: list[int],
    blocks: Mapping[int, _LiftedBlock],
) -> dict[int, int]:
    """Assign transition tokens: pair position for region heads, extra ids for interiors."""
    pair_index = {region_index: index for index, region_index in enumerate(ordered_indices)}
    tokens = {
        regions[region_index].members[0]: pair_index[region_index]
        for region_index in ordered_indices
    }
    for address in sorted(set(blocks) - set(tokens)):
        tokens[address] = len(tokens)
    return tokens


def _map_exit_tokens(term: dict[str, Any], tokens: Mapping[int, int]) -> dict[str, Any]:
    """Lower a transition's exit ``ip`` term from binary addresses to cutpoint tokens."""
    const = constant_bitvector(term)
    if const is not None:
        value, width = const
        if width != CONTROL_WIDTH or value not in tokens:
            raise CallCompositionRefusal(Flat32LoopCallReason.CONTROL_LEAF_UNMAPPED.value)
        return {"op": "const", "value": hex(tokens[value]), "width": CONTROL_WIDTH}
    if term.get("op") == "ite":
        args = term.get("args")
        if (
            isinstance(args, list)
            and len(args) == 3
            and all(isinstance(arg, dict) for arg in args)
        ):
            return {
                "op": "ite",
                "width": term.get("width", CONTROL_WIDTH),
                "args": [
                    args[0],
                    _map_exit_tokens(args[1], tokens),
                    _map_exit_tokens(args[2], tokens),
                ],
            }
    raise CallCompositionRefusal(Flat32LoopCallReason.CONTROL_SHAPE.value)


def _compose_call_transition(
    session: _ComposeSession,
    call_block: _LiftedBlock,
    state: dict[str, dict[str, Any]],
    active: frozenset[int],
) -> dict[str, dict[str, Any]]:
    """Inline one proved callee and continue at the recorded fallthrough.

    Reuses the M2 machinery verbatim: the callee body is composed by
    ``_compose_function`` (which itself refuses recursion, cycles, unmapped or
    unsupported transfers) and its symbolic return target is proved to equal
    the recorded fallthrough by ``_prove_return_target`` under the shared
    deadline.  The post-state carries the proved concrete fallthrough so the
    continuation is an ordinary member/cutpoint edge, never an assumption.
    """
    target = call_block.call_target
    fallthrough = call_block.fallthrough
    if target is None or fallthrough is None:
        raise CallCompositionRefusal("call_target_unmapped")
    if _const_term_int(state.get("ip")) != target:
        raise CallCompositionRefusal("call_target_mismatch")
    if target in active:
        raise CallCompositionRefusal(f"recursive_call:{hex(target)}")
    if session.limits.max_inline_depth < 1:
        raise CallCompositionRefusal("call_inline_depth_limit")
    if session.inlined_calls >= session.limits.max_inlined_calls:
        raise CallCompositionRefusal("call_inline_budget")
    session.inlined_calls += 1
    callee_state = _compose_function(session, target, active | {target}, 1)
    callee_return = callee_state.get("eip")
    if not isinstance(callee_return, dict):
        raise CallCompositionRefusal("callee_terminal_missing")
    instruction_addresses = call_block.irsb.instruction_addresses
    if not instruction_addresses:
        raise CallCompositionRefusal("call_instruction_address_missing")
    _prove_return_target(
        _callee_term(callee_return, state, session),
        fallthrough,
        timeout_ms=_ret_proof_timeout_ms(session),
        callsite=instruction_addresses[-1],
        call_block=call_block.address,
        target=target,
        callee=session.labels.get(target, ""),
    )
    post = dict(state)
    for name, term in callee_state.items():
        if name not in {"eip", "ip"}:
            _check_compose_deadline(session.compose_stats)
            post[name] = _callee_term(term, state, session)
    proved = {"op": "const", "value": hex(fallthrough), "width": CONTROL_WIDTH}
    post["ip"] = dict(proved)
    post["eip"] = proved
    session.return_targets_proved += 1
    session.call_sites.append(
        {
            "callsite": hex(instruction_addresses[-1]),
            "call_block": hex(call_block.address),
            "target": hex(target),
            "fallthrough": hex(fallthrough),
            "depth": 1,
            "callee": session.labels.get(target, ""),
            "proved_under_entry_domain": False,
        }
    )
    return post


def _compose_region_state(
    region: CollapsedRegion,
    lifted: Mapping[int, _LiftedBlock],
    session: _ComposeSession,
    *,
    function_entry: int,
    is_entry: bool,
) -> dict[str, dict[str, Any]]:
    """Compose one region's members into the post-state before exit mapping.

    Members compose sequentially with a const-progress check so an
    unconditional chain can never silently drop a member; an ``Ijk_Call``
    member additionally composes the proved callee and leaves ``ip`` at the
    recorded fallthrough, so the residual boundary is only the region kind.
    """
    state: dict[str, dict[str, Any]] = _initial_state(session.reg_widths)
    if not is_entry:
        state = IDENTITY_RELATION.candidate_inputs(state)
    members = region.members
    for index, address in enumerate(members):
        _check_compose_deadline(session.compose_stats)
        block = lifted[address]
        member_outputs = block.part.get("outputs", {})
        if block.part.get("trap_exits") or "io" in member_outputs:
            raise CallCompositionRefusal("unsupported_effect_in_superblock")
        session.compositions += 1
        if session.compositions > session.limits.max_compositions:
            raise CallCompositionRefusal("region_composition_limit")
        state = S._compose_block_outputs(
            block.part,
            member_outputs,
            state,
            compose_stats=session.compose_stats,
        )
        if block.jumpkind == "Ijk_Call":
            state = _compose_call_transition(
                session, block, state, frozenset({function_entry})
            )
        if (
            _term_nodes(state, session.limits.max_term_nodes)
            > session.limits.max_term_nodes
        ):
            raise CallCompositionRefusal("region_expression_limit")
        if index < len(members) - 1:
            control = constant_bitvector(state.get("ip", {}))
            if control != (members[index + 1], CONTROL_WIDTH):
                raise CallCompositionRefusal(
                    Flat32LoopCallReason.CONTROL_SHAPE.value
                )
    return state


def _compose_transition(
    region: CollapsedRegion,
    lifted: Mapping[int, _LiftedBlock],
    session: _ComposeSession,
    tokens: Mapping[int, int],
    *,
    function_entry: int,
    is_entry: bool,
    module: str,
    name: str,
    outputs: tuple[str, ...],
    full_state: tuple[str, ...],
) -> dict[str, Any]:
    """Compose one paired region's members into a full-state transition document.

    ``Ijk_Ret`` exposes the return value; every other tail maps branch leaves
    onto cutpoint tokens, mirroring
    ``flat32_cfg_regions._compose_superblock``.
    """
    state = _compose_region_state(
        region, lifted, session, function_entry=function_entry, is_entry=is_entry
    )
    ip_term = state.get("ip")
    if not isinstance(ip_term, dict):
        raise CallCompositionRefusal(Flat32LoopCallReason.IP_UNOBSERVED.value)
    reenters_entry = any(tokens[target] == 0 for target in region.exits)
    if region.kind is RegionExitKind.RETURN:
        state["eip"] = ip_term
    else:
        state["eip"] = _map_exit_tokens(ip_term, tokens)
    if region.kind is not RegionExitKind.RETURN:
        state = IDENTITY_RELATION.continuing_outputs(
            state, control_field="eip", reenters_entry=reenters_entry
        )
    observed = (
        tuple(dict.fromkeys((*outputs, *PRESERVED_OUTPUTS, "eip", "memory", "io")))
        if region.kind is RegionExitKind.RETURN
        else (*full_state, "memory")
    )
    terms: dict[str, Any] = {}
    for reg in observed:
        if reg not in state:
            raise CallCompositionRefusal(f"missing_state:{reg}")
        terms[reg] = state[reg]
    if _term_nodes(terms, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    term_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized = {
        reg: S._materialize_json_term(
            term, assignments=assignments, memo=memo, term_cache=term_cache
        )
        for reg, term in terms.items()
    }
    entry = {"linear": hex(region.members[0])}
    # A CALL tail is already composed into the transition terms and discharged
    # by ``_prove_return_target``; the document's residual boundary is a
    # resolved cutpoint edge, not an unresolved call.  Emitting the machine
    # ``Ijk_Call`` would ask the document comparator to re-resolve a callee
    # that legitimately has no standalone doc entry, so the composed marker
    # carries the truth and the machine jumpkind stays as inert provenance.
    source = {
        "jumpkind": (
            "call_composed" if region.kind is RegionExitKind.CALL else region.kind.value
        ),
        "reblocked_members": len(region.members),
    }
    if region.kind is RegionExitKind.CALL:
        source["machine_jumpkind"] = region.kind.value
    return {
        "id": f"{module}:{name}",
        "function": {"id": f"{module}:{name}", "name": name},
        "part": {"kind": "superblock", "index": 0, "entry_delta": "0x0"},
        "entry": entry,
        "function_entry": entry,
        "source": source,
        "inputs": S._term_input_items(materialized.values(), assignments),
        "outputs": materialized,
        "assignments": assignments,
    }


def _lower_transitions(
    regions: list[CollapsedRegion],
    pairs: list[tuple[int, int]],
    lifted: Mapping[int, _LiftedBlock],
    session: _ComposeSession,
    tokens: Mapping[int, int],
    *,
    function_entry: int,
    module: str,
    outputs: tuple[str, ...],
    full_state: tuple[str, ...],
    left: bool,
) -> dict[str, Any]:
    """Compose every paired region for one side into transition documents."""
    functions = []
    for index, (oracle_region, candidate_region) in enumerate(pairs):
        region = regions[oracle_region if left else candidate_region]
        functions.append(
            _compose_transition(
                region,
                lifted,
                session,
                tokens,
                function_entry=function_entry,
                is_entry=index == 0,
                module=module,
                name=f"sb_{index}",
                outputs=outputs,
                full_state=full_state,
            )
        )
    return {"functions": functions}


def _lifted_map(session: _ComposeSession) -> dict[int, _LiftedBlock]:
    """Flatten a session's per-function lifted blocks for coverage evidence."""
    return {
        address: block
        for blocks in session.blocks.values()
        for address, block in blocks.items()
    }


def compare_flat32_loop_calls(
    projects: tuple[Any, Any],
    oracle_range: tuple[int, int],
    candidate_range: tuple[int, int],
    outputs: tuple[str, ...],
    timeout_ms: int,
    *,
    name: str = "call_loop",
    oracle_functions: Mapping[int, int] | None = None,
    candidate_functions: Mapping[int, int] | None = None,
    limits: CallCompositionLimits | None = None,
    oracle_labels: Mapping[int, str] | None = None,
    candidate_labels: Mapping[int, str] | None = None,
    total_deadline: float | None = None,
) -> dict[str, Any]:
    """Prove a paired flat32 CFG whose transitions may contain direct calls.

    The theorem is the common matched-CFG induction: cutpoint-pair the two
    closed graphs, compose each paired region into a transition over the
    complete machine state (with admitted ``Ijk_Call`` tails replaced by the
    proved callee continuation), then require every paired transition to
    agree on the shared post-state domain including the tokenised
    continuation ``eip`` and full memory. Initiation at pair 0 plus
    transition preservation implies the simulation at every cutpoint;
    tokenised-exit equality is branch agreement over the closed paired
    cover, so both sides diverge on the same input domain and share every
    exit. Returns a ``flat32_verdict``-shaped report; any missing premise
    refuses with the machinery's existing named reasons.
    """
    deadline = comparison_deadline(timeout_ms, total_deadline)
    adapter, _cfg, catalog, verdict = _seams()
    outputs = tuple(dict.fromkeys((*outputs, *adapter.OUTPUT_REGS[2:])))
    limits = limits or CallCompositionLimits()
    oracle_project, candidate_project = projects
    try:
        oracle_map = _normalize_function_map(
            oracle_functions
            if oracle_functions is not None
            else {oracle_range[0]: oracle_range[1]}
        )
        candidate_map = _normalize_function_map(
            candidate_functions
            if candidate_functions is not None
            else {candidate_range[0]: candidate_range[1]}
        )
        osession = _ComposeSession(
            project=oracle_project,
            functions=oracle_map,
            labels={
                address: str(label)
                for address, label in (oracle_labels or {}).items()
            },
            limits=limits,
            reg_widths=_register_widths(),
            compose_stats={"deadline": deadline},
        )
        csession = _ComposeSession(
            project=candidate_project,
            functions=candidate_map,
            labels={
                address: str(label)
                for address, label in (candidate_labels or {}).items()
            },
            limits=limits,
            reg_widths=_register_widths(),
            compose_stats={"deadline": deadline},
        )
        oracle_entry, _oracle_size = oracle_range
        candidate_entry, _candidate_size = candidate_range
        for entry, session in (
            (oracle_entry, osession),
            (candidate_entry, csession),
        ):
            if entry not in session.functions:
                raise CallCompositionRefusal("entry_not_in_functions")
        with adapter.installed(region=True):
            olifted = _lift_function(osession, oracle_entry)
            clifted = _lift_function(csession, candidate_entry)
            graph = propose_paired_regions(
                _nodes(olifted),
                _nodes(clifted),
                oracle_entry,
                candidate_entry,
            )
            oregions = list(graph.oracle.regions)
            cregions = list(graph.candidate.regions)
            pairs = list(graph.pairs)
            o_tokens = _cutpoint_tokens(
                oregions, [left for left, _ in pairs], olifted
            )
            c_tokens = _cutpoint_tokens(
                cregions, [right for _, right in pairs], clifted
            )
            full_state = tuple(name for name, _ in adapter.REG32.values())
            ossa = _lower_transitions(
                oregions, pairs, olifted, osession, o_tokens,
                function_entry=oracle_entry,
                module="oracle", outputs=outputs,
                full_state=full_state, left=True,
            )
            cssa = _lower_transitions(
                cregions, pairs, clifted, csession, c_tokens,
                function_entry=candidate_entry,
                module="candidate", outputs=outputs,
                full_state=full_state, left=False,
            )
    except CallCompositionRefusal as error:
        report = {
            "function": {"name": name},
            "status": verdict.Status.REFUSED,
            "reason": str(error),
        }
        if error.evidence is not None:
            report["return_proof_failure"] = error.evidence.to_document()
        return report
    except RegionGraphRefusal as error:
        return {
            "function": {"name": name},
            "status": verdict.Status.REFUSED,
            "reason": error.reason.value,
        }
    status, compared, verdicts = _compare_attempt(
        ossa, cssa, deadline, adapter, catalog, verdict
    )
    attempts = [
        _attempt_record(IDENTITY_RELATION, status, compared, verdicts, len(pairs))
    ]
    return {
        "function": {"name": name},
        "graph_evidence": asdict(graph.evidence),
        "status": status,
        "reason": (
            Flat32LoopCallReason.INDUCTION.value
            if status is verdict.Status.PASSED
            else Flat32LoopCallReason.TRANSITIONS_UNPROVED.value
        ),
        "proof_scope": ProofScope.CUTPOINT_SIMULATION,
        "register_relation": [],
        "memory_relation": None,
        "relation_attempts": attempts,
        "counters": attempts[0]["counters"],
        "superblock_pairs": [
            {
                "pair": index,
                "oracle_head": hex(oregions[left].members[0]),
                "oracle_members": [hex(member) for member in oregions[left].members],
                "oracle_exits": [hex(target) for target in oregions[left].exits],
                "oracle_kind": oregions[left].kind.value,
                "candidate_head": hex(cregions[right].members[0]),
                "candidate_members": [
                    hex(member) for member in cregions[right].members
                ],
                "candidate_exits": [
                    hex(target) for target in cregions[right].exits
                ],
                "candidate_kind": cregions[right].kind.value,
            }
            for index, (left, right) in enumerate(pairs)
        ],
        "call_sites": {
            "oracle": osession.call_sites,
            "candidate": csession.call_sites,
        },
        "oracle_inlined_calls": osession.inlined_calls,
        "candidate_inlined_calls": csession.inlined_calls,
        "oracle_blocks_lifted": osession.blocks_lifted,
        "candidate_blocks_lifted": csession.blocks_lifted,
        "return_targets_proved": (
            osession.return_targets_proved + csession.return_targets_proved
        ),
        "oracle_tail_transfers": osession.tail_transfers,
        "candidate_tail_transfers": csession.tail_transfers,
        "tail_sites": {
            "oracle": osession.tail_sites,
            "candidate": csession.tail_sites,
        },
        "environment_coverage": {
            "oracle": environment_parts(_lifted_map(osession)),
            "candidate": environment_parts(_lifted_map(csession)),
        },
        "block_compare": compared,
        "block_verdicts": verdicts,
        "oracle_ssa": ossa,
        "candidate_ssa": cssa,
    }
