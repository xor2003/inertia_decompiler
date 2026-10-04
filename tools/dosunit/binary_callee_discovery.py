"""Bounded binary callee discovery before public comparator provenance sealing.

Layer: dosunit binary evidence intake orchestration.
Responsibility: recover missing direct-call leaf or acyclic region bodies for requested callers,
retain every attempted receipt/refusal and shared evidence counter, and leave
equivalence and saved-return proofs to the existing whole-function comparator.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

import angr

from tools.dosunit.binary_callee_intake import (
    IntakeBudget,
    IntakeRefusalReason,
    IntakeRequest,
    IntakeStatus,
    intake_uncatalogued_leaf,
)
from tools.dosunit.binary_callee_region_contracts import RegionScanBudget, ScanWindow
from tools.dosunit.binary_callee_region_intake import intake_uncatalogued_region_candidate
from tools.dosunit.binary_callee_region_lowering import RegionLoweringStatus, lower_region_candidate
from tools.dosunit.proof_contracts import FactCounters
from tools.dosunit.real16_call_evidence import block_transfer, part_delta, part_entry_linear


class DiscoveryRefusal(StrEnum):
    """An intake request unavailable at the orchestration boundary."""

    TARGET_MISSING = "target_missing"
    REQUEST_LIMIT = "request_limit"
    DEADLINE = "deadline"


@dataclass(frozen=True)
class DiscoveryBudget:
    """Shared work limits; exhaustion supplies no callee proof."""

    max_requests: int = 16
    max_elapsed_ms: int = 60000


def _integer(value: object) -> int | None:
    """Read exact integer coordinates at the lowered JSON boundary."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def discovery_root_ids(document: dict[str, Any], proposed_keys: frozenset[str]) -> frozenset[str]:
    """Resolve proposed caller IDs/names to canonical freshly lowered identities.

    This selects intake work only. It provides no call target, body range or
    semantic equivalence evidence.
    """
    roots: set[str] = set()
    for part in document.get("functions", []):
        function = part.get("function")
        if not isinstance(function, dict):
            continue
        identifier, name = function.get("id"), function.get("name")
        if isinstance(identifier, str) and (
            identifier in proposed_keys or (isinstance(name, str) and name in proposed_keys)
        ):
            roots.add(identifier)
    return frozenset(roots)


def _request(
    project: angr.Project, document: dict[str, Any], part: dict[str, Any],
) -> IntakeRequest | None:
    """Require a source caller identity, block delta and full recorded target."""
    function = part.get("function")
    target = block_transfer(part).get("target")
    if not isinstance(function, dict) or not isinstance(target, dict):
        return None
    key = function.get("id")
    delta, linear = part_delta(part), _integer(target.get("raw"))
    if not isinstance(key, str) or delta is None or linear is None:
        return None
    return IntakeRequest(project, document, key, delta, linear)


def _publish(document: dict[str, Any], parts: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> None:
    """Attach admitted parts; their effects still require whole-caller proof."""
    document["functions"].extend(parts)
    counters = document.get("counters")
    if isinstance(counters, dict):
        for name in ("functions_seen", "functions_attempted", "functions_lowered"):
            counters[name] += 1
        counters["ssa_parts_lowered"] += len(parts)
        counters["assignments_emitted"] += sum(len(part.get("assignments", [])) for part in parts)


def _classify_request(
    request: IntakeRequest | None, attempted: int, budget: DiscoveryBudget, deadline: float,
) -> DiscoveryRefusal | None:
    """Classify missing coordinates or exhausted shared work before intake."""
    if request is None:
        return DiscoveryRefusal.TARGET_MISSING
    if attempted >= budget.max_requests:
        return DiscoveryRefusal.REQUEST_LIMIT
    if time.monotonic() >= deadline:
        return DiscoveryRefusal.DEADLINE
    return None


def _intake_attempt(
    document: dict[str, Any], request: IntakeRequest, budget: IntakeBudget,
) -> tuple[dict[str, Any], bool]:
    """Materialize admitted parts once and retain their receipt and identities."""
    result = intake_uncatalogued_leaf(request, budget=budget)
    entry = result.to_dict()
    entry.pop("parts")
    entry["part_ids"] = [part["id"] for part in result.parts]
    admitted = result.status is IntakeStatus.ADMITTED
    if admitted:
        if result.receipt is None or not result.parts:
            raise ValueError("admitted intake lacks receipt or materialized parts")
        _publish(document, result.parts)
    if not admitted and result.refusal is not None and result.refusal.reason in {
        IntakeRefusalReason.BODY_ALTERNATE_EXITS, IntakeRefusalReason.BODY_BRANCH,
    }:
        return _region_attempt(document, request, budget, entry)
    return entry, admitted


def _region_attempt(
    document: dict[str, Any], request: IntakeRequest, budget: IntakeBudget,
    leaf_attempt: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    """Try source-verified region intake, including discharged REP self-edges."""
    scan_budget = RegionScanBudget(budget.max_instructions, budget.max_instructions,
                                   budget.max_body_bytes, budget.max_body_bytes)
    candidate = intake_uncatalogued_region_candidate(
        request, window=ScanWindow(request.target_linear, request.target_linear + budget.max_body_bytes),
        budget=scan_budget, max_lift_block_ms=budget.max_lift_block_ms)
    result = lower_region_candidate(
        request, candidate, max_assignments=budget.max_assignments_per_function,
        max_lift_block_ms=budget.max_lift_block_ms)
    admitted = result.status is RegionLoweringStatus.LOWERED
    entry = result.to_dict()
    entry.pop("parts")
    entry["status"] = IntakeStatus.ADMITTED.value if admitted else IntakeStatus.REFUSED.value
    entry["intake_kind"] = "source_bound_region"
    entry["leaf_attempt"] = leaf_attempt
    entry["part_ids"] = [part["id"] for part in result.parts]
    if admitted:
        _publish(document, result.parts)
    return entry, admitted


def discover_uncatalogued_leaves(
    project: angr.Project,
    document: dict[str, Any],
    *,
    root_ids: frozenset[str],
    leaf_budget: IntakeBudget,
    budget: DiscoveryBudget | None = None,
) -> dict[str, Any]:
    """Recover omitted direct leaves or acyclic regions with explicit accounting.

    Raw target coordinates propose a request only. The intake owner must verify
    source CALL bytes, target domain, terminal body closure and full lowering.
    Each accepted body enters the document before provenance sealing. Refused
    requests remain absent, so existing dependency/return proofs fail closed.
    """
    budget = DiscoveryBudget() if budget is None else budget
    parts = document.get("functions")
    if not isinstance(parts, list):
        raise ValueError("leaf discovery requires a lowered functions list")
    known = {entry for part in parts if isinstance(part, dict)
             for entry in [part_entry_linear(part)] if entry is not None}
    # Catalogued call closure may contain another caller with an omitted leaf.
    pending = sorted(root_ids)
    visited: set[str] = set()
    requests: list[dict[str, Any]] = []
    failures = 0
    attempted = 0
    deadline = time.monotonic() + max(0, budget.max_elapsed_ms) / 1000
    while pending:
        caller = pending.pop()
        if caller in visited:
            continue
        visited.add(caller)
        caller_parts = [part for part in list(parts) if isinstance(part, dict)
                        and part.get("function", {}).get("id") == caller]
        for part in caller_parts:
            if block_transfer(part).get("kind") != "direct_call":
                continue
            request = _request(project, document, part)
            if request is not None and request.target_linear in known:
                pending.extend(str(item["function"]["id"]) for item in parts
                               if isinstance(item, dict) and part_entry_linear(item) == request.target_linear)
                continue
            reason = _classify_request(request, attempted, budget, deadline)
            if reason is not None:
                failures += 1
                requests.append({"status": IntakeStatus.REFUSED.value, "reason": reason.value,
                                 "caller": caller, "delta": part_delta(part)})
                continue
            if request is None:
                raise AssertionError("classified intake request disappeared")
            attempted += 1
            entry, admitted = _intake_attempt(document, request, leaf_budget)
            requests.append(entry)
            if admitted:
                known.add(request.target_linear)
            else:
                failures += 1
    count = len(requests)
    report = {"requests": requests, "attempted": attempted,
              "counters": asdict(FactCounters(count, count, count, count, failures))}
    document["binary_callee_intake"] = report
    return report
