"""Whole-function evidence admission for fresh real16 binary comparisons.

Layer: dosunit proof accounting.
Responsibility: translate complete leaf or closed-region evidence into typed
required-function obligations without promoting incomplete per-block results.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from tools.dosunit.callee_proof_scope import complete_leaf_block
from tools.dosunit.proof_contracts import (
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ProofStatus,
)

NON_PROVED_FAILURE: int = 1

def _catalog_key(entry: dict[str, Any]) -> str | None:
    """Return the catalog identity of a declared function without guessing."""
    function_id = entry.get("id")
    if isinstance(function_id, str) and function_id:
        return function_id
    names = entry.get("names")
    if isinstance(names, list) and names and isinstance(names[0], str) and names[0]:
        return names[0]
    return None


def _requested_obligations(
    oracle_catalog: dict[str, Any], selected: Sequence[str]
) -> tuple[list[Obligation], dict[str, dict[str, Any]]]:
    """Bind required obligations to oracle catalog ids; unknown selections stay required."""
    entries = [
        entry
        for entry in oracle_catalog.get("functions", []) or []
        if isinstance(entry, dict) and _catalog_key(entry) is not None
    ]
    by_token: dict[str, dict[str, Any]] = {}
    for entry in entries:
        key = _catalog_key(entry)
        names = entry.get("names")
        tokens = [key, *([str(name) for name in names] if isinstance(names, list) else [])]
        for token in tokens:
            if token:
                by_token.setdefault(token, entry)
    requested = [token.strip() for token in selected if token.strip()]
    if requested:
        keys = [str(_catalog_key(by_token[token])) if token in by_token else token for token in requested]
        resolved = {key: by_token[token] for token, key in zip(requested, keys, strict=True) if token in by_token}
        return [Obligation(ObligationId("function", key)) for key in keys], resolved
    return [Obligation(ObligationId("function", str(_catalog_key(entry)))) for entry in entries], {
        str(_catalog_key(entry)): entry for entry in entries
    }


def _group_parts(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Group lowered SSA parts by each declared function identity key."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for part in document.get("functions", []) or []:
        if not isinstance(part, dict):
            continue
        info = part["function"] if isinstance(part.get("function"), dict) else {}
        for key in (str(info.get("id") or ""), str(info.get("name") or "")):
            if key:
                groups.setdefault(key, []).append(part)
    return groups


def _parts_by_id(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index lowered SSA parts by their unique part document id."""
    return {
        str(part["id"]): part
        for part in document.get("functions", []) or []
        if isinstance(part, dict) and isinstance(part.get("id"), str)
    }


def _region_verdicts(compare: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index whole-region equality results by oracle function id and name."""
    region = compare.get("region_equality")
    rows = region.get("results") if isinstance(region, dict) else None
    verdicts: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        info = row["function"] if isinstance(row.get("function"), dict) else {}
        for key in (str(info.get("id") or ""), str(info.get("name") or "")):
            if key:
                verdicts.setdefault(key, row)
    return verdicts


def _pending_callee_functions(compare: dict[str, Any]) -> set[str]:
    """Collect functions whose callee proofs never settled in the fixpoint."""
    pending: set[str] = set()
    for row in compare.get("results", []) or []:
        if isinstance(row, dict) and row.get("reason") == "callee_not_proven":
            info = row["function"] if isinstance(row.get("function"), dict) else {}
            pending.update(str(info.get(field) or "") for field in ("id", "name"))
    return {key for key in pending if key}


def _candidate_only_functions(compare: dict[str, Any]) -> set[str]:
    """Collect candidate functions with reachable parts never covered by a proof."""
    gate = compare.get("candidate_only_parts")
    rows = gate.get("parts") if isinstance(gate, dict) else None
    functions: set[str] = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        info = row["function"] if isinstance(row.get("function"), dict) else {}
        functions.update(str(info.get(field) or "") for field in ("id", "name"))
    return {key for key in functions if key}


def _mapped_candidate_keys(key: str, oracle_entry: dict[str, Any], mapping: dict[str, Any] | None) -> set[str]:
    """Resolve the candidate identities a mapping proposes for one obligation."""
    if not isinstance(mapping, dict):
        return {key, str(oracle_entry.get("id") or key)}
    keys: set[str] = set()
    oracle_name = str(_catalog_key(oracle_entry) or key)
    for row in mapping.get("functions", []) or []:
        if not isinstance(row, dict):
            continue
        if key in {str(row.get("oracle_id") or ""), str(row.get("oracle_name") or "")} or oracle_name in {
            str(row.get("oracle_id") or ""),
            str(row.get("oracle_name") or ""),
        }:
            keys.update(str(row.get(field) or "") for field in ("candidate_id", "candidate_name"))
    return {item for item in keys if item}


def _part_results(compare: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index compare rows by the oracle SSA part id they resolved."""
    rows: dict[str, dict[str, Any]] = {}
    for row in compare.get("results", []) or []:
        if isinstance(row, dict) and isinstance(row.get("oracle_function"), str):
            rows.setdefault(str(row["oracle_function"]), row)
    return rows


def _row_assumptions(row: dict[str, Any]) -> tuple[str, ...]:
    """Expose backend assumption payloads as typed conditional markers."""
    if (row.get("assumptions") or row.get("paired_call_assumptions")
            or row.get("layout_normalization") or row.get("call_normalizations")
            or row.get("skipped_layout_outputs")):
        return ("backend_assumptions",)
    return ()


def _row_evidence(row: dict[str, Any], *, reason: str) -> tuple[ProofStatus, tuple[str, ...], str]:
    """Translate one backend row into a proof status without trusting its verdict."""
    status = {
        "passed": ProofStatus.PROVED,
        "failed": ProofStatus.COUNTEREXAMPLE,
        "conditional": ProofStatus.CONDITIONAL,
    }.get(str(row.get("status")), ProofStatus.UNKNOWN)
    return status, _row_assumptions(row), str(row.get("reason") or reason)


@dataclass(frozen=True)
class _CompareIndex:
    """Precomputed per-function evidence indexes over one compare document."""

    oracle_parts: dict[str, list[dict[str, Any]]]
    part_rows: dict[str, dict[str, Any]]
    region_rows: dict[str, dict[str, Any]]
    pending_callees: frozenset[str]
    candidate_only: frozenset[str]
    candidate_parts_by_id: dict[str, dict[str, Any]]
    refusals_by_function: dict[str, dict[str, Any]]


def _compare_index(compare: dict[str, Any], oracle_doc: dict[str, Any], candidate_doc: dict[str, Any]) -> _CompareIndex:
    """Build every per-function evidence lookup once for obligation evaluation."""
    refusals: dict[str, dict[str, Any]] = {}
    for row in oracle_doc.get("refusals", []) or []:
        if not isinstance(row, dict):
            continue
        detail = row.get("detail")
        if isinstance(detail, dict) and detail.get("function_id"):
            refusals[str(detail["function_id"])] = row
    return _CompareIndex(
        oracle_parts=_group_parts(oracle_doc),
        part_rows=_part_results(compare),
        region_rows=_region_verdicts(compare),
        pending_callees=frozenset(_pending_callee_functions(compare)),
        candidate_only=frozenset(_candidate_only_functions(compare)),
        candidate_parts_by_id=_parts_by_id(candidate_doc),
        refusals_by_function=refusals,
    )


def _function_evidence(
    obligation: Obligation,
    oracle_entry: dict[str, Any],
    contract: ContractIdentity,
    index: _CompareIndex,
    mapping: dict[str, Any] | None,
) -> ObligationEvidence:
    """Evaluate one function obligation from whole-scope backend evidence only."""
    key, function_id = obligation.id.key, str(oracle_entry.get("id") or "")

    def evidence(status: ProofStatus, reason: str, *, assumptions: tuple[str, ...] = ()) -> ObligationEvidence:
        return ObligationEvidence(
            id=obligation.id,
            contract=contract,
            status=status,
            reason=reason,
            method="ssa_z3_whole_scope",
            assumptions=assumptions,
            counters=FactCounters(1, 1, 1, 1, NON_PROVED_FAILURE if status is not ProofStatus.PROVED else 0),
        )

    refused = index.refusals_by_function.get(function_id)
    if refused is not None:
        return evidence(ProofStatus.UNKNOWN, f"lowering_refused:{refused.get('reason')}")
    parts = index.oracle_parts.get(key) or index.oracle_parts.get(function_id, [])
    if not parts:
        return evidence(ProofStatus.UNKNOWN, "no_lowered_parts")
    if key in index.pending_callees or function_id in index.pending_callees:
        return evidence(ProofStatus.UNKNOWN, "callee_not_proven")
    if _mapped_candidate_keys(key, oracle_entry, mapping) & index.candidate_only:
        return evidence(ProofStatus.UNKNOWN, "candidate_only_reachable")
    if len(parts) == 1 and complete_leaf_block(parts[0]):
        row = index.part_rows.get(str(parts[0].get("id") or ""))
        if row is None:
            return evidence(ProofStatus.UNKNOWN, "uncompared_leaf_part")
        candidate_part = index.candidate_parts_by_id.get(str(row.get("candidate_function") or ""))
        if candidate_part is None or not complete_leaf_block(candidate_part):
            return evidence(ProofStatus.UNKNOWN, "candidate_leaf_scope_incomplete")
        status, assumptions, reason = _row_evidence(row, reason="leaf_block")
        return evidence(status, reason, assumptions=assumptions)
    region = index.region_rows.get(key) or index.region_rows.get(function_id)
    if region is None:
        return evidence(ProofStatus.UNKNOWN, "whole_region_unproved")
    status, assumptions, reason = _row_evidence(region, reason="region_equality")
    return evidence(status, f"region:{reason}", assumptions=assumptions)

