"""Closed matched-loop induction over flat32 CFGs containing resolved calls.

Layer: dosunit relational loop proofs.
Responsibility: prove paired flat32 CFGs whose superblock transitions may end
in admitted direct or finite-target indirect calls. A call member is never an assumed boundary: the
caller's call-block continuation is composed with the callee's checked
complete body from ``flat32_call_execution`` and the callee return is proved
by the shared ``_prove_return_target`` back to the recorded fallthrough, so a
call transition is an honest SSA transfer over the full machine state. The
composed transitions are then discharged by the common matched-CFG induction
(``region_pairing.propose_paired_regions`` + ``flat32_region_attempts``),
which gives initiation, preservation over every reachable transition,
branch/successor agreement, every normal and early exit, full
register/flags/memory state, and divergence equivalence for the synchronized
paired graph. Cyclic/recursive or incomplete callees, unconstrained indirect calls,
unproved return targets, unmapped edges and exhausted budgets keep the
existing typed refusals; no premise is ever invented.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict
from typing import Any

from tools.comparator.services import proof_owners
from tools.dosunit.architectures.flat32 import X87_REGISTER_NAMES
from tools.dosunit.compare.flat32_call_composition import _normalization_assumptions
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionLimits,
    CallCompositionRefusal,
    _ComposeSession,
    _LiftedBlock,
    _normalize_function_map,
    _register_widths,
)
from tools.dosunit.compare.flat32_call_lowering import _lift_function
from tools.dosunit.compare.flat32_callee_frames import expand_frame_safe_callees
from tools.dosunit.compare.flat32_environment_coverage import environment_parts
from tools.dosunit.compare.flat32_identity_edges import contract_identity_edges
from tools.dosunit.compare.flat32_loop_graph_search import (
    search_loop_graphs,
)
from tools.dosunit.compare.flat32_loop_relations import compare_loop_relations
from tools.dosunit.compare.flat32_loop_transitions import Flat32LoopCallReason, _cutpoint_tokens, _lower_transitions
from tools.dosunit.compare.flat32_native_constants import (
    NativeConstantProof,
    native_constant_checker,
    prove_native_constants,
)
from tools.dosunit.compare.flat32_predecessor_edges import prune_predecessor_edges
from tools.dosunit.compare.flat32_region_attempts import (
    comparison_deadline,
)
from tools.dosunit.compare.paired_region_graph import (
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
    RegionNode,
)
from tools.dosunit.compare.region_pairing import PairedRegions, paired_control_tokens
from tools.dosunit.contracts.proof_scope import ProofScope


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


def _lifted_map(session: _ComposeSession) -> dict[int, _LiftedBlock]:
    """Flatten a session's per-function lifted blocks for coverage evidence."""
    return {
        address: block
        for blocks in session.blocks.values()
        for address, block in blocks.items()
    }


def _record_x87_premises(
    result: dict[str, Any], verdict: Any,  # noqa: ANN401
    olifted: Mapping[int, _LiftedBlock], clifted: Mapping[int, _LiftedBlock],
) -> None:
    """Publish declared x87 premises and downgrade assumed loop proofs.

    Checking x87 instructions only execute their modeled continuation when
    no unmasked exception is pending, and CPU-specific policies are declared
    contracts. A passed induction is published CONDITIONAL with the premise
    records; failed/refused verdicts are left untouched.
    """
    records: dict[str, dict[str, Any]] = {}
    for lifted in (olifted, clifted):
        for block in lifted.values():
            for premise in block.part.get("summary", {}).get("premises", ()):
                records.setdefault(json.dumps(premise, sort_keys=True), premise)
    obligations = [
        {"side": side, **obligation}
        for side, summary in (("oracle", result.get("oracle_ssa")), ("candidate", result.get("candidate_ssa")))
        for function in (summary or {}).get("functions", ())
        for obligation in function.get("obligations", ())
    ]
    if not records and not obligations:
        return
    assumption = {
        "kind": "declared_x87_premises",
        "premises": list(records.values()),
        "obligations": obligations,
    }
    result["x87_assumptions"] = assumption
    if result["status"] is verdict.Status.PASSED:
        result.update(status=verdict.Status.CONDITIONAL,
                      reason="declared_x87_premises", assumptions=assumption)


def _native_comparison_normalization(
    candidate_facts: NativeConstantProof | None,
    requested: Mapping[int, int] | None,
) -> Mapping[int, int] | None:
    """Admit relocated facts only in their independently certified exact domain."""
    if candidate_facts is None:
        return requested
    evidence = candidate_facts.evidence
    if evidence.get("scalar_domain") != "candidate_normalization":
        return None
    expected = {hex(key): hex(value) for key, value in sorted((requested or {}).items())}
    if not expected or evidence.get("candidate_normalization") != expected:
        raise CallCompositionRefusal(Flat32LoopCallReason.NATIVE_CONSTANT_DOMAIN_MISMATCH.value)
    return requested


def _compare_loop_graph(
    osession: _ComposeSession, csession: _ComposeSession,
    olifted: Mapping[int, _LiftedBlock], clifted: Mapping[int, _LiftedBlock],
    graph: PairedRegions, oracle_entry: int, candidate_entry: int,
    outputs: tuple[str, ...], deadline: float, name: str,
    candidate_normalization: Mapping[int, int] | None,
    native_constants: tuple[NativeConstantProof | None, NativeConstantProof | None] = (None, None),
) -> dict[str, Any]:
    """Discharge every transition of one untrusted complete graph proposal."""
    owners = proof_owners()
    adapter, verdict = owners.model, owners.verdict
    comparison_normalization = _native_comparison_normalization(
        native_constants[1], candidate_normalization)
    oregions = list(graph.oracle.regions)
    cregions = list(graph.candidate.regions)
    pairs = list(graph.pairs)
    pair_tokens = paired_control_tokens(pairs, oregions, cregions, allow_state_merges=graph.evidence.state_merges)
    o_tokens = _cutpoint_tokens(oregions, [left for left, _ in pairs], olifted, pair_tokens)
    c_tokens = _cutpoint_tokens(cregions, [right for _, right in pairs], clifted, pair_tokens)
    if candidate_normalization and set(candidate_normalization).intersection(c_tokens.values()):
        raise CallCompositionRefusal(Flat32LoopCallReason.NORMALIZATION_TOKEN_OVERLAP.value)
    full_state = (*tuple(name for name, _ in adapter.REG32.values()), *X87_REGISTER_NAMES)
    ossa = _lower_transitions(
        oregions, pairs, olifted, osession, o_tokens,
        function_entry=oracle_entry, module="oracle", outputs=outputs,
        full_state=full_state, left=True, native_constants=native_constants[0],
    )
    cssa = _lower_transitions(
        cregions, pairs, clifted, csession, c_tokens,
        function_entry=candidate_entry, module="candidate", outputs=outputs,
        full_state=full_state, left=False, native_constants=native_constants[1],
    )
    checked = compare_loop_relations(
        ossa, cssa,
        lambda relation: _lower_transitions(
            cregions, pairs, clifted, csession, c_tokens, function_entry=candidate_entry,
            module="candidate", outputs=outputs, full_state=full_state, left=False, relation=relation,
            native_constants=native_constants[1],
        ), deadline=deadline,
        candidate_normalization=comparison_normalization,
    )
    status, compared, verdicts = checked.status, checked.compared, checked.verdicts
    cssa, attempts = checked.candidate_ssa, checked.attempts
    if checked.projected_oracle is not None:
        ossa = checked.projected_oracle
    result = {
        "function": {"name": name},
        "graph_evidence": asdict(graph.evidence),
        "status": status,
        "reason": (
            Flat32LoopCallReason.INDUCTION.value
            if status in {verdict.Status.PASSED, verdict.Status.CONDITIONAL}
            else Flat32LoopCallReason.TRANSITIONS_UNPROVED.value
        ),
        "proof_scope": ProofScope.CUTPOINT_SIMULATION,
        "register_relation": [asdict(binding) for binding in checked.relation.bindings],
        "proposal_reason": checked.proposal_reason,
        "memory_relation": None,
        "native_constant_invariants": {side: facts.evidence for side, facts
                                       in zip(("oracle", "candidate"), native_constants, strict=True)
                                       if facts is not None},
        "constant_register_invariants": checked.constant_invariants,
        "frame_invariants": checked.frame_invariants,
        "dead_flag_projection": checked.dead_flags,
        "dead_register_projection": checked.dead_registers,
        "narrow_register_projection": checked.narrow_registers,
        "relation_attempts": attempts,
        "counters": attempts[-1]["counters"],
        "superblock_pairs": [
            {
                "pair": index,
                "oracle_head": hex(oregions[left].members[0]),
                "oracle_members": [hex(member) for member in oregions[left].members],
                "oracle_exits": [hex(target) for target in oregions[left].exits],
                "oracle_kind": oregions[left].kind.value,
                "candidate_head": hex(cregions[right].members[0]),
                "candidate_members": [hex(member) for member in cregions[right].members],
                "candidate_exits": [hex(target) for target in cregions[right].exits],
                "candidate_kind": cregions[right].kind.value,
            }
            for index, (left, right) in enumerate(pairs)
        ],
        "call_sites": {"oracle": osession.call_sites, "candidate": csession.call_sites},
        "oracle_inlined_calls": osession.inlined_calls,
        "candidate_inlined_calls": csession.inlined_calls,
        "oracle_blocks_lifted": osession.blocks_lifted,
        "candidate_blocks_lifted": csession.blocks_lifted,
        "block_lift_retries": {
            "oracle": [retry.to_document() for retry in osession.block_lift_retries],
            "candidate": [retry.to_document() for retry in csession.block_lift_retries],
        },
        "return_targets_proved": osession.return_targets_proved + csession.return_targets_proved,
        "oracle_tail_transfers": osession.tail_transfers,
        "candidate_tail_transfers": csession.tail_transfers,
        "tail_sites": {"oracle": osession.tail_sites, "candidate": csession.tail_sites},
        "environment_coverage": {
            "oracle": environment_parts(_lifted_map(osession)),
            "candidate": environment_parts(_lifted_map(csession)),
        },
        "block_compare": compared,
        "block_verdicts": verdicts,
        "oracle_ssa": ossa,
        "candidate_ssa": cssa,
    }
    _record_x87_premises(result, verdict, olifted, clifted)
    if any(native_constants):
        result["native_constant_comparison_coordinates"] = (
            "candidate_normalization" if comparison_normalization else "literal")
        result["requested_normalization_used"] = bool(comparison_normalization)
    if candidate_normalization:
        # Preserve the caller's declared premise in the public domain even
        # when a stronger literal attempt discharged the actual transitions.
        if status == verdict.Status.PASSED:
            result["status"] = verdict.Status.CONDITIONAL
        premise = _normalization_assumptions(candidate_normalization)
        result["normalization_assumptions"] = premise
        result["assumptions"] = premise
    return result


def _retry_callee_frames(
    sessions: tuple[_ComposeSession, _ComposeSession],
    lifted: tuple[Mapping[int, _LiftedBlock], Mapping[int, _LiftedBlock]],
    entries: tuple[int, int], outputs: tuple[str, ...], deadline: float,
    name: str, candidate_normalization: Mapping[int, int] | None,
    searched: dict[str, Any],
) -> dict[str, Any]:
    """Retry a nested cycle using independently proved native return frames."""
    osession, csession = sessions
    olifted, clifted = lifted
    oracle_entry, candidate_entry = entries
    if searched.get("reason") != "loop_requires_inductive_proof":
        return searched
    try:
        expanded_o, evidence_o = expand_frame_safe_callees(osession, dict(olifted))
        expanded_c, evidence_c = expand_frame_safe_callees(csession, dict(clifted))
        if not evidence_o and not evidence_c:
            return searched
        expanded = search_loop_graphs(
            _nodes(expanded_o), _nodes(expanded_c), oracle_entry, candidate_entry,
            lambda graph: _compare_loop_graph(
                osession, csession, expanded_o, expanded_c, graph, oracle_entry, candidate_entry,
                outputs, deadline, name, candidate_normalization,
            ), deadline=deadline, name=name,
        )
        expanded["callee_frame_expansion"] = {"oracle": evidence_o, "candidate": evidence_c}
        if "graph_evidence" not in expanded:
            # A failed structural proposal must not hide the native blocker
            # already reached by the original complete graph.
            searched["callee_frame_expansion_attempt"] = expanded
            return searched
        expanded["before_callee_expansion"] = searched
        return expanded
    except (CallCompositionRefusal, RegionGraphRefusal) as error:
        searched["callee_frame_expansion_refusal"] = str(error)
    return searched


def _search_native_graphs(
    sessions: tuple[_ComposeSession, _ComposeSession],
    lifted: tuple[Mapping[int, _LiftedBlock], Mapping[int, _LiftedBlock]],
    entries: tuple[int, int], outputs: tuple[str, ...], deadline: float,
    name: str, candidate_normalization: Mapping[int, int] | None,
) -> dict[str, Any]:
    """Give each complete native block map its own invariant-inference cache."""
    osession, csession = sessions
    olifted, clifted = lifted
    oracle_entry, candidate_entry = entries
    check = native_constant_checker(
        lambda graph, facts: _compare_loop_graph(
            osession, csession, olifted, clifted, graph, oracle_entry, candidate_entry,
            outputs, deadline, name, candidate_normalization, facts,
        ),
        lambda: (
            prove_native_constants(olifted, oracle_entry, osession, deadline=deadline),
            prove_native_constants(clifted, candidate_entry, csession, deadline=deadline,
                                   candidate_normalization=candidate_normalization),
        ), enabled=True, prefer_facts_first=bool(candidate_normalization),
    )
    return search_loop_graphs(_nodes(olifted), _nodes(clifted), oracle_entry, candidate_entry,
                             check, deadline=deadline, name=name)


def _retry_predecessor_edges(
    sessions: tuple[_ComposeSession, _ComposeSession],
    lifted: tuple[Mapping[int, _LiftedBlock], Mapping[int, _LiftedBlock]],
    entries: tuple[int, int], outputs: tuple[str, ...], deadline: float,
    name: str, candidate_normalization: Mapping[int, int] | None,
    searched: dict[str, Any],
) -> dict[str, Any]:
    """Retry structural refusal after independently certified oracle simplification.

    Literal oracle semantics do not undergo candidate relocation. Candidate
    pruning is intentionally absent until its implication can be certified in
    exactly the normalized domain consumed by the paired transition checker.
    """
    if searched.get("reason") not in {RegionGraphReason.SHAPE.value, RegionGraphReason.BIJECTION.value}:
        return searched
    result = prune_predecessor_edges(lifted[0], entries[0], sessions[0], deadline=deadline)
    if not result.proofs:
        return searched
    retried = _search_native_graphs(sessions, (result.blocks, lifted[1]), entries, outputs,
                                    deadline, name, candidate_normalization)
    retried["predecessor_edge_pruning"] = {
        "oracle": [proof.to_document() for proof in result.proofs], "candidate": [],
        "domain": "literal_oracle", "raw_fact_count": result.attempted,
        "normalized_fact_count": result.attempted, "classified_fact_count": len(result.proofs),
        "materialized_count": len(result.proofs), "failure_count": result.attempted - len(result.proofs),
    }
    retried["before_predecessor_edge_pruning"] = searched
    return retried


def _retry_identity_edges(
    sessions: tuple[_ComposeSession, _ComposeSession],
    lifted: tuple[Mapping[int, _LiftedBlock], Mapping[int, _LiftedBlock]],
    entries: tuple[int, int], outputs: tuple[str, ...], deadline: float,
    name: str, candidate_normalization: Mapping[int, int] | None,
    searched: dict[str, Any],
) -> dict[str, Any]:
    """Retry mismatched graph shape after certified literal identity removal."""
    if searched.get("reason") not in {RegionGraphReason.SHAPE.value, RegionGraphReason.BIJECTION.value}:
        return searched
    oracle = contract_identity_edges(lifted[0], entries[0], sessions[0], deadline=deadline)
    candidate = contract_identity_edges(lifted[1], entries[1], sessions[1], deadline=deadline)
    if not oracle.proofs and not candidate.proofs:
        return searched
    retried = _search_native_graphs(sessions, (oracle.blocks, candidate.blocks), entries,
                                    outputs, deadline, name, candidate_normalization)
    retried["identity_edge_contraction"] = {
        "oracle": [proof.to_document() for proof in oracle.proofs],
        "candidate": [proof.to_document() for proof in candidate.proofs],
        "domain": "literal_native_state_identity",
        "oracle_retained_cycles": [hex(a) for a in oracle.retained_cycles],
        "candidate_retained_cycles": [hex(a) for a in candidate.retained_cycles],
    }
    retried["before_identity_edge_contraction"] = searched
    return retried


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
    candidate_normalization: Mapping[int, int] | None = None,
) -> dict[str, Any]:
    """Prove a paired flat32 CFG with complete callees and full-state induction.

    Root inputs are arbitrary. Every paired transition, successor, normal and
    early return, preserved register and complete memory array must agree.
    Finite positive region progress preserves divergence. Unsupported calls,
    effects and exhausted budgets remain explicit refusals.

    Unrestricted graph comparisons run before optional physical-entry constant
    specialization. Its side invariants require independent initiation and all
    incoming-edge proofs; they never replace full relational obligations.
    Constant relocation is applied only after native routing/return checks and
    remains an explicit conditional premise, without native constant refinement.
    """
    deadline = comparison_deadline(timeout_ms, total_deadline)
    owners = proof_owners()
    adapter, verdict = owners.model, owners.verdict
    outputs = tuple(dict.fromkeys((*outputs, *adapter.OUTPUT_REGS[2:])))
    limits = limits or CallCompositionLimits()
    oracle_project, candidate_project = projects
    try:
        oracle_map = _normalize_function_map(
            oracle_functions if oracle_functions is not None else {oracle_range[0]: oracle_range[1]}
        )
        candidate_map = _normalize_function_map(
            candidate_functions if candidate_functions is not None else {candidate_range[0]: candidate_range[1]}
        )
        osession = _ComposeSession(
            project=oracle_project, functions=oracle_map,
            labels={address: str(label) for address, label in (oracle_labels or {}).items()},
            limits=limits, reg_widths=_register_widths(), compose_stats={"deadline": deadline},
            admit_indirect_calls=True,
        )
        csession = _ComposeSession(
            project=candidate_project, functions=candidate_map,
            labels={address: str(label) for address, label in (candidate_labels or {}).items()},
            limits=limits, reg_widths=_register_widths(), compose_stats={"deadline": deadline},
            admit_indirect_calls=True,
        )
        oracle_entry, _oracle_size = oracle_range
        candidate_entry, _candidate_size = candidate_range
        for entry, session in ((oracle_entry, osession), (candidate_entry, csession)):
            if entry not in session.functions:
                raise CallCompositionRefusal("entry_not_in_functions")
        olifted = _lift_function(osession, oracle_entry)
        clifted = _lift_function(csession, candidate_entry)
    except CallCompositionRefusal as error:
        report = {"function": {"name": name}, "status": verdict.Status.REFUSED, "reason": str(error)}
        if error.evidence is not None:
            report["return_proof_failure"] = error.evidence.to_document()
        if error.location is not None:
            report["refusal_location"] = error.location.to_document()
        return report
    except RegionGraphRefusal as error:
        return {"function": {"name": name}, "status": verdict.Status.REFUSED, "reason": error.reason.value}
    searched = _search_native_graphs((osession, csession), (olifted, clifted),
                                    (oracle_entry, candidate_entry), outputs, deadline,
                                    name, candidate_normalization)
    searched = _retry_identity_edges((osession, csession), (olifted, clifted),
                                    (oracle_entry, candidate_entry), outputs, deadline,
                                    name, candidate_normalization, searched)
    searched = _retry_predecessor_edges((osession, csession), (olifted, clifted),
                                       (oracle_entry, candidate_entry), outputs, deadline,
                                       name, candidate_normalization, searched)
    return _retry_callee_frames(
        (osession, csession), (olifted, clifted), (oracle_entry, candidate_entry),
        outputs, deadline, name, candidate_normalization, searched,
    )
