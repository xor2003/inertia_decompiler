"""Bounded complete-graph proposal search for native flat32 loop proofs.

Layer: dosunit relational loop proofs.
Responsibility: preserve ordered induction first, then discharge alternative
branch bijections without promoting structural matches or partial transitions.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from tools.comparator.verdict import Status
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.compare.paired_region_graph import RegionGraphRefusal, RegionNode
from tools.dosunit.compare.region_pairing import PairedRegions, propose_paired_regions, propose_region_pairings
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy


def _refused(error: CallCompositionRefusal | RegionGraphRefusal) -> dict[str, Any]:
    """Keep typed graph/native failure evidence without interpreting it as equality."""
    if isinstance(error, RegionGraphRefusal):
        return {"status": Status.REFUSED, "reason": error.reason.value}
    report: dict[str, Any] = {"status": Status.REFUSED, "reason": str(error)}
    if error.evidence is not None:
        report["return_proof_failure"] = error.evidence.to_document()
    if error.location is not None:
        report["refusal_location"] = error.location.to_document()
    return report


def _check_graph(
    graph: PairedRegions, check: Callable[[PairedRegions], dict[str, Any]],
) -> dict[str, Any]:
    """Check one complete candidate and preserve any native composition refusal."""
    try:
        return check(graph)
    except (CallCompositionRefusal, RegionGraphRefusal) as error:
        return {**_refused(error), "graph_evidence": asdict(graph.evidence)}


def _discharged(result: dict[str, Any]) -> bool:
    """Only the transition checker can discharge a proposal, with its premises."""
    return proof_status_from_legacy(result.get("status")) in {ProofStatus.PROVED, ProofStatus.CONDITIONAL}


def _attempt_record(result: dict[str, Any]) -> dict[str, Any]:
    """Retain verdicts and countermodels without duplicating large SSA documents."""
    return {key: value for key, value in result.items()
            if key not in {"oracle_ssa", "candidate_ssa", "block_compare", "environment_coverage"}}


def _diagnostic_stage(result: dict[str, Any]) -> int:
    """Prefer reached transition obligations over an earlier graph proposal failure.

    This ranks diagnostics only. A failed cutpoint obligation never establishes
    a reachable root counterexample, and only _discharged can establish proof.
    Equal-depth failures keep the first report; all attempts remain available.
    """
    if "block_verdicts" in result:
        return 2
    return int("graph_evidence" in result)


def _search_loop_graphs(
    oracle: dict[int, RegionNode], candidate: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int,
    check: Callable[[PairedRegions], dict[str, Any]], *, deadline: float, name: str,
    allow_state_merges: bool,
) -> dict[str, Any]:
    """Try ordered then bounded alternative pairings under one solver deadline.

    Every candidate is a complete partition or finite cover from the common
    graph owner. Search gets at most half a second of the remaining budget;
    the callback retains the original cumulative composition and solver limits.
    Failed proposals and raw cutpoint verdicts remain in the public report.
    """
    primary: PairedRegions | None = None
    try:
        primary = propose_paired_regions(oracle, candidate, oracle_entry, candidate_entry)
        result = _check_graph(primary, check)
    except RegionGraphRefusal as error:
        result = _refused(error)
    if _discharged(result):
        return result
    attempts = [_attempt_record(result)]
    best_result = result
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {**result, "function": {"name": name}, "graph_attempts": attempts}
    try:
        search = propose_region_pairings(
            oracle, candidate, oracle_entry, candidate_entry,
            deadline_seconds=min(remaining, 0.5), max_candidates=64,
            allow_terminal_merges=True, allow_state_merges=allow_state_merges,
        )
    except RegionGraphRefusal as error:
        return {**result, "function": {"name": name}, "graph_attempts": attempts,
                "graph_search_refusal": error.reason.value}
    for graph in search.candidates:
        if primary is not None and graph.pairs == primary.pairs and graph.evidence.formation == primary.evidence.formation:
            continue
        if time.monotonic() >= deadline:
            break
        result = _check_graph(graph, check)
        attempts.append(_attempt_record(result))
        best_result = max((best_result, result), key=_diagnostic_stage)
        if _discharged(result):
            break
    if not _discharged(result):
        result = best_result
    return {**result, "function": {"name": name}, "graph_search": asdict(search.evidence()),
            "graph_attempts": attempts}


def search_loop_graphs(
    oracle: dict[int, RegionNode], candidate: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int,
    check: Callable[[PairedRegions], dict[str, Any]], *, deadline: float, name: str,
) -> dict[str, Any]:
    """Keep established bijections first, then try closed shared-state relations.

    Exact graph proposals are checked only once under the same total deadline
    and composition budget. Reusing a failed result grants no proof; shared
    states still require every distinct transition obligation to discharge.
    """
    cache: dict[tuple[str, frozenset[tuple[int, int]]], dict[str, Any]] = {}

    def checked_once(graph: PairedRegions) -> dict[str, Any]:
        """Reuse complete results only for identical layouts and pair sets."""
        key = (graph.evidence.formation.value, frozenset(graph.pairs))
        if key not in cache:
            cache[key] = _check_graph(graph, check)
        return cache[key]

    strict = _search_loop_graphs(
        oracle, candidate, oracle_entry, candidate_entry, checked_once,
        deadline=deadline, name=name, allow_state_merges=False,
    )
    if _discharged(strict) or time.monotonic() >= deadline:
        return strict
    relaxed = _search_loop_graphs(
        oracle, candidate, oracle_entry, candidate_entry, checked_once,
        deadline=deadline, name=name, allow_state_merges=True,
    )
    selected = relaxed if _discharged(relaxed) else max((strict, relaxed), key=_diagnostic_stage)
    return {**selected, "strict_graph_search": _attempt_record(strict),
            "state_merge_graph_search": _attempt_record(relaxed)}
