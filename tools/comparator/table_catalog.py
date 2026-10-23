"""Layer: comparator partial-check orchestration.

Responsibility: attach source-bound per-function table evidence to MSC8 reports
without promoting partial checks into function proofs or changing coverage.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.comparator.table_checks import TableCheckStatus, check_target_tables, read_target_table
from tools.comparator.table_context_checks import check_rooted_targets, check_selected_slot_targets
from tools.comparator.table_dispatch_checks import check_dispatch_pair
from tools.comparator.table_function_proof import promote_table_function
from tools.comparator.table_prefix_checks import check_dispatch_prefix
from tools.comparator.table_root_checks import check_completed_switch
from tools.comparator.table_target_checks import check_returning_targets
from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain


@dataclass(frozen=True)
class TableCatalogEvidence:
    """Checks computed from immutable bytes, with independently verifiable inputs."""

    path: Path
    catalog_sha256: str
    image_sha256: dict[str, str]
    functions: dict[str, list[dict[str, object]]]


def _address(value: object) -> int:
    """Accept explicit hexadecimal/decimal strings or integer preferred-image VAs."""
    if isinstance(value, str):
        value = int(value, 0)
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("table catalog address must be a 32-bit integer")
    return value


def _target_map(value: object) -> dict[int, int]:
    """Validate correspondence without silently overwriting duplicate originals."""
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("target_pairs requires a list of at most 4096 pairs")
    pairs: dict[int, int] = {}
    for pair in value:
        if not isinstance(pair, dict) or set(pair) != {"original", "candidate"}:
            raise ValueError("target pair requires original and candidate")
        original, candidate = _address(pair["original"]), _address(pair["candidate"])
        if original in pairs:
            raise ValueError("duplicate original target")
        pairs[original] = candidate
    return pairs


def _retain_check(result: dict[str, object], name: str, check: dict[str, object]) -> None:
    """Keep every component while propagating mismatch before incomplete evidence."""
    result[name] = check
    if result["status"] != "mismatch" and check["status"] != "checked":
        result["status"] = check["status"]


def _check_item(
    item: object, original: bytes, candidate: bytes, entry_domain: Flat32ProofDomain | None,
    abi_observation: Flat32AbiObservation | None = None,
) -> dict[str, object]:
    """Validate and evaluate one declared table pair and optional dispatch pair."""
    required = {"original_table", "candidate_table", "original_count", "candidate_count", "target_pairs"}
    optional = {"original_dispatch", "candidate_dispatch", "check_returning_targets", "original_entry",
                "candidate_entry", "assume_initial_tables", "check_rooted_targets", "check_selected_slots"}
    if not isinstance(item, dict) or not required <= set(item) or set(item) - required - optional:
        raise ValueError("table entry has missing or unknown fields")
    if ("original_dispatch" in item) != ("candidate_dispatch" in item):
        raise ValueError("both dispatch sites must be supplied")
    left = read_target_table(original, _address(item["original_table"]), item["original_count"])
    right = read_target_table(candidate, _address(item["candidate_table"]), item["candidate_count"])
    result = check_target_tables(left, right, _target_map(item["target_pairs"]))
    assumed = item.get("assume_initial_tables", False)
    if type(assumed) is not bool:
        raise ValueError("assume_initial_tables must be boolean")
    result["initial_tables_assumed"] = assumed
    if "original_entry" in item or "candidate_entry" in item:
        if not {"original_entry", "candidate_entry", "original_dispatch", "candidate_dispatch"} <= set(item):
            raise ValueError("prefix checks require both entries and both dispatch sites")
        prefix = check_dispatch_prefix(original, candidate, _address(item["original_entry"]),
                                        _address(item["candidate_entry"]), _address(item["original_dispatch"]),
                                        _address(item["candidate_dispatch"]),
                                        original_count=item["original_count"], candidate_count=item["candidate_count"],
                                        check_defaults=item.get("check_returning_targets") is True,
                                        entry_domain=entry_domain)
        _retain_check(result, "prefix_check", prefix)
    target_checks = item.get("check_returning_targets", False)
    if type(target_checks) is not bool:
        raise ValueError("check_returning_targets must be boolean")
    if target_checks:
        used = set(left.targets) - {0}
        pairs = {key: value for key, value in _target_map(item["target_pairs"]).items() if key in used}
        targets = check_returning_targets(original, candidate, pairs)
        _retain_check(result, "target_block_checks", targets)
    _attach_context_check(result, item, original, candidate, entry_domain)
    if "original_dispatch" in item:
        dispatch = check_dispatch_pair(original, candidate, left, right,
                                       _address(item["original_dispatch"]), _address(item["candidate_dispatch"]))
        _retain_check(result, "dispatch_check", dispatch)
    if abi_observation is not None and "prefix_check" in result:
        fields = ("original_entry", "candidate_entry", "original_dispatch", "candidate_dispatch")
        result["root_path_checks"] = check_completed_switch(
            original, candidate, _target_map(item["target_pairs"]), left, right,
            *(_address(item[field]) for field in fields),
            abi_observation=abi_observation, entry_domain=entry_domain)
    return result


def _attach_context_check(
    result: dict[str, object], item: dict[str, Any], original: bytes, candidate: bytes,
    entry_domain: Flat32ProofDomain | None,
) -> None:
    """Retain explicit diagnostics; gate automatic slot retries on their prerequisites."""
    enabled = item.get("check_rooted_targets", False)
    if type(enabled) is not bool:
        raise ValueError("check_rooted_targets must be boolean")
    selected_only = item.get("check_selected_slots", False)
    if type(selected_only) is not bool:
        raise ValueError("check_selected_slots must be boolean")
    if not enabled and not selected_only:
        return
    fields = ("original_entry", "candidate_entry", "original_dispatch", "candidate_dispatch")
    if not set(fields) <= set(item):
        raise ValueError("rooted target checks require both root entries and dispatch sites")
    if not enabled and not _automatic_slot_candidate(result):
        result["slot_target_checks"] = {"status": TableCheckStatus.INCOMPLETE,
                                       "scope": "selected_slot_root_paths",
                                       "pending": "prefix unproved or strict targets already checked"}
        return
    used = set(read_target_table(original, _address(item["original_table"]), item["original_count"]).targets) - {0}
    pairs = {key: value for key, value in _target_map(item["target_pairs"]).items() if key in used}
    if enabled:
        result["rooted_target_checks"] = check_rooted_targets(
            original, candidate, pairs, *(_address(item[field]) for field in fields), entry_domain=entry_domain)
    result["slot_target_checks"] = check_selected_slot_targets(
        original, candidate, pairs,
        read_target_table(original, _address(item["original_table"]), item["original_count"]),
        read_target_table(candidate, _address(item["candidate_table"]), item["candidate_count"]),
        *(_address(item[field]) for field in fields), entry_domain=entry_domain)


def _automatic_slot_candidate(result: dict[str, object]) -> bool:
    """Retry only when a checked prefix can lead to additional whole-root evidence."""
    prefix, targets = result.get("prefix_check"), result.get("target_block_checks")
    return (isinstance(prefix, dict) and prefix.get("status") == TableCheckStatus.CHECKED
            and isinstance(targets, dict) and targets.get("status") != TableCheckStatus.CHECKED)


def prepare_table_catalog(
    path: Path | None, oracle_path: Path, candidate_path: Path, original_names: list[str],
    *, entry_domain: Flat32ProofDomain | None = None,
    abi_contracts: dict[str, Flat32AbiObservation] | None = None,
) -> TableCatalogEvidence | None:
    """Check an optional bounded catalog against exactly the supplied binary bytes."""
    if path is None:
        return None
    raw = path.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict) or set(document) != {"schema", "functions"}:
        raise ValueError("table catalog requires schema and functions")
    functions = document["functions"]
    if document["schema"] != "comparator.target_table_catalog.v1" or not isinstance(functions, dict):
        raise ValueError("unsupported table catalog schema")
    if functions.keys() - set(original_names):
        raise ValueError("table catalog names absent from original function manifest")
    original, candidate = oracle_path.read_bytes(), candidate_path.read_bytes()
    results: dict[str, list[dict[str, object]]] = {}
    for name, items in functions.items():
        if not isinstance(items, list) or not 1 <= len(items) <= 32:
            raise ValueError("each function requires 1..32 table checks")
        results[name] = [_check_item(item, original, candidate, entry_domain, (abi_contracts or {}).get(name)) for item in items]
    return TableCatalogEvidence(path.resolve(), hashlib.sha256(raw).hexdigest(),
                                {"oracle": hashlib.sha256(original).hexdigest(),
                                 "candidate": hashlib.sha256(candidate).hexdigest()}, results)


def attach_table_catalog(report: dict[str, Any], evidence: TableCatalogEvidence | None) -> None:
    """Retain independent partial evidence while preserving all function verdicts."""
    if evidence is None:
        return
    if hashlib.sha256(evidence.path.read_bytes()).hexdigest() != evidence.catalog_sha256:
        raise RuntimeError("table catalog changed during comparison")
    for side, digest in evidence.image_sha256.items():
        if report["inputs"][side]["sha256"] != digest:
            raise RuntimeError("table checks and function proof used different images")
    selected: set[str] = set()
    for row in report["results"]:
        name = row["function"]["name"]
        if name in evidence.functions:
            for check in evidence.functions[name]:
                _bind_root_entries(check, name, report.get("function_ranges", {}))
            row["partial_table_checks"] = evidence.functions[name]
            promote_table_function(row, evidence.functions[name])
            selected.add(name)
    counts = Counter(str(check["status"]) for checks in evidence.functions.values() for check in checks)
    report["partial_table_checks"] = {
        "schema": "comparator.partial_table_checks.v1",
        "catalog": {"path": str(evidence.path), "sha256": evidence.catalog_sha256},
        "image_sha256": evidence.image_sha256,
        "counts": {status: counts[status] for status in ("checked", "mismatch", "incomplete")},
        "functions": evidence.functions,
        "functions_outside_proof_selection": sorted(evidence.functions.keys() - selected),
        "contributes_to_function_proof_coverage": False,
    }


def _bind_root_entries(check: dict[str, object], name: str, ranges: dict[str, Any]) -> None:
    """Bind declared prefix entries to the actual selected original/candidate pair."""
    prefix = check.get("prefix_check")
    if not isinstance(prefix, dict):
        return
    sides: dict[str, dict[str, object]] = {}
    for label, side in (("original", "oracle"), ("candidate", "candidate")):
        selected = ranges.get(side, {}).get(name)
        declared = int(prefix[label]["entry"], 0)
        if selected is None:
            sides[label] = {"status": "incomplete", "declared_entry": hex(declared)}
        else:
            sides[label] = {"status": "checked" if selected[0] == declared else "mismatch",
                            "declared_entry": hex(declared), "selected_entry": hex(selected[0])}
    statuses = [item["status"] for item in sides.values()]
    status = "mismatch" if "mismatch" in statuses else "incomplete" if "incomplete" in statuses else "checked"
    _retain_check(check, "root_entry_check", {"status": status, "scope": "selected_function_entries", **sides})
    if status == "checked":
        prefix["pending_conditions"] = [condition for condition in prefix["pending_conditions"]
                                         if condition != "declared entries are the intended root function entries"]
        contextual = check.get("rooted_target_checks")
        if isinstance(contextual, dict):
            contextual["pending_conditions"] = [condition for condition in contextual["pending_conditions"]
                                                 if condition != "declared root entries match selected functions"]
