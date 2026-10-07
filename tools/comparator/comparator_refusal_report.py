"""Report structured blocker evidence from saved comparator documents.

Layer: comparator reporting.
Responsibility: account for requested roots and retry lanes without changing proof verdicts.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Direct script invocation needs the checkout package, just as module invocation does.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy


class Lane(StrEnum):
    """Known report positions; unfamiliar retry names remain in lane_name."""

    TOP = "top"
    CALLS = "calls"
    CALL_LOOP = "call_loop"
    MACRO_STEP = "macro_step"
    REBLOCKED_CFG = "reblocked_cfg"
    UNKNOWN = "unknown"


class RequestAccounting(StrEnum):
    """Separate verified requested identities from legacy reported rows only."""

    EXPLICIT = "explicit_requested_roots"
    UNAVAILABLE = "requested_roots_unavailable"


@dataclass(frozen=True)
class BlockerEvidence:
    """Only explicit, structured source fields, never parsed exception prose."""

    side: str | None = None
    root: str | None = None
    blocking_callee: str | None = None
    source_address: int | str | None = None
    exhausted_limit: int | str | None = None


@dataclass(frozen=True)
class Attempt:
    """One unmodified legacy verdict with a typed interpretation and evidence."""

    lane: Lane
    lane_name: str
    raw_status: str
    status: ProofStatus | None
    reason: str
    blocker: BlockerEvidence


@dataclass
class Bucket:
    """Count records separately from qualified unique roots in a report position."""

    histogram: Counter[str] = field(default_factory=Counter)
    roots: set[tuple[str, str]] = field(default_factory=set)

    def add(self, target: str, root: str, reason: str) -> None:
        """Record a reason and one qualified function identity."""
        self.histogram[reason] += 1
        self.roots.add((target, root))

    def document(self) -> dict[str, Any]:
        """Publish stable counts without summing overlapping retry lanes."""
        return {"records": self.histogram.total(), "unique_functions": len(self.roots),
                "histogram": dict(sorted(self.histogram.items()))}


class ReportShapeError(ValueError):
    """A requested function or retry cannot be accounted for faithfully."""


def _object(value: object, location: str) -> dict[str, Any]:
    """Require a JSON object at an accounting boundary."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ReportShapeError(f"{location}: expected string-keyed object")
    return value


def _name(value: object, location: str) -> str:
    """Reject missing and empty identities rather than inventing a root."""
    if not isinstance(value, str) or not value:
        raise ReportShapeError(f"{location}: expected nonempty string")
    return value


def _lane(name: str) -> Lane:
    """Preserve unrecognized retry positions with an explicit unknown category."""
    try:
        return Lane(name)
    except ValueError:
        return Lane.UNKNOWN


def _merge_evidence(evidence: dict[str, Any], part: Mapping[str, Any]) -> None:
    """Copy only declared structured evidence fields."""
    for key in ("side", "root", "blocking_callee", "source_address", "exhausted_limit"):
        if key in part:
            evidence[key] = part[key]


def _return_proof_evidence(attempt: Mapping[str, Any]) -> dict[str, Any]:
    """Consume the call producer's serialized ReturnTargetProofFailure fields.

    The decoded callsite is the instruction address, unlike call_block (which
    may include argument setup). An empty callee label is unavailable evidence.
    Keep the original complete failure document in the retained source row.
    """
    if "return_proof_failure" not in attempt:
        return {}
    proof = _object(attempt["return_proof_failure"], "return_proof_failure")
    evidence: dict[str, Any] = {}
    for source, target in (("side", "side"), ("callsite", "source_address")):
        if source in proof:
            evidence[target] = proof[source]
    callee = proof.get("callee")
    if callee is not None and callee != "":
        evidence["blocking_callee"] = callee
    return evidence


def _blocker(attempt: Mapping[str, Any], root: str) -> BlockerEvidence:
    """Read named evidence only from this attempt's structured detail."""
    evidence: dict[str, Any] = {"root": root, **_return_proof_evidence(attempt)}
    _merge_evidence(evidence, attempt)
    detail = attempt.get("detail")
    if detail is not None:
        detail_obj = _object(detail, "detail")
        _merge_evidence(evidence, detail_obj)
        if "blocker" in detail_obj:
            _merge_evidence(evidence, _object(detail_obj["blocker"], "detail.blocker"))
    for key in ("side", "root", "blocking_callee"):
        if key in evidence and evidence[key] is not None:
            _name(evidence[key], f"blocker.{key}")
    for key in ("source_address", "exhausted_limit"):
        value = evidence.get(key)
        if value is not None and (type(value) not in (int, str) or value == ""):
            raise ReportShapeError(f"blocker.{key}: expected integer, string, or null")
    return BlockerEvidence(**evidence)


def _attempt(value: object, root: str, name: str, location: str) -> Attempt:
    """Decode one verdict at the legacy serialization boundary."""
    item = _object(value, location)
    raw_status = _name(item.get("status"), f"{location}.status")
    reason = _name(item.get("reason"), f"{location}.reason")
    return Attempt(_lane(name), name, raw_status, proof_status_from_legacy(raw_status),
                   reason, _blocker(item, root))


def build_report(paths: Sequence[Path]) -> dict[str, Any]:
    """Aggregate validated saved reports by resolved target path and root name."""
    if not paths:
        raise ReportShapeError("at least one compare.json path is required")
    aggregate_top = Bucket()
    aggregate_lanes: dict[str, Bucket] = {}
    aggregate_status: Counter[str] = Counter()
    targets: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    for path in paths:
        target = str(path.resolve())
        if target in seen_targets:
            raise ReportShapeError(f"{target}: repeated input target")
        seen_targets.add(target)
        document = _object(json.loads(path.read_text(encoding="utf-8")), target)
        requested = document.get("requested_functions")
        rows = document.get("results")
        if not isinstance(rows, list) or ("requested_functions" in document and not isinstance(requested, list)):
            raise ReportShapeError(f"{target}: requested_functions and results must be lists when present")
        accounting = RequestAccounting.EXPLICIT if isinstance(requested, list) else RequestAccounting.UNAVAILABLE
        names = [_name(name, f"{target}.requested_functions[{i}]")
                 for i, name in enumerate(requested or [])]
        if len(set(names)) != len(names):
            raise ReportShapeError(f"{target}: duplicate requested root")
        requested_names = set(names)
        local_top = Bucket()
        local_lanes: dict[str, Bucket] = {}
        local_status: Counter[str] = Counter()
        reported: set[str] = set()
        entries: list[dict[str, Any]] = []
        for i, raw in enumerate(rows):
            location = f"{target}.results[{i}]"
            row = _object(raw, location)
            function = _object(row.get("function"), f"{location}.function")
            root = _name(function.get("name"), f"{location}.function.name")
            if root in reported or (accounting is RequestAccounting.EXPLICIT and root not in requested_names):
                raise ReportShapeError(f"{location}: duplicate or unrequested root {root}")
            reported.add(root)
            top = _attempt(row, root, Lane.TOP.value, location)
            retries = row.get("additional_proof_attempts", {})
            attempts = _object(retries, f"{location}.additional_proof_attempts")
            typed_retries = {name: _attempt(attempt, root, name, f"{location}.{name}")
                             for name, attempt in attempts.items()}
            local_status[top.raw_status] += 1
            aggregate_status[top.raw_status] += 1
            local_top.add(target, root, top.reason)
            aggregate_top.add(target, root, top.reason)
            for name, attempt in typed_retries.items():
                local_lanes.setdefault(name, Bucket()).add(target, root, attempt.reason)
                aggregate_lanes.setdefault(name, Bucket()).add(target, root, attempt.reason)
            entries.append({"root": root, "top": asdict(top),
                            "attempts": {name: asdict(attempt) for name, attempt in typed_retries.items()},
                            "source": row})
        if accounting is RequestAccounting.EXPLICIT and reported != requested_names:
            raise ReportShapeError(f"{target}: missing requested roots: {sorted(set(names) - reported)}")
        targets.append({"target": target, "requested": len(names) if accounting is RequestAccounting.EXPLICIT else None,
                        "request_accounting": accounting, "reported_functions": len(reported),
                        "status": dict(sorted(local_status.items())),
                        "top": local_top.document(),
                        "lanes": {name: bucket.document() for name, bucket in sorted(local_lanes.items())},
                        "functions": entries})
    requested_count = sum(t["requested"] for t in targets) if all(t["requested"] is not None for t in targets) else None
    return {"schema": "comparator.refusal_report.v1", "requested": requested_count,
            "reported_functions": sum(t["reported_functions"] for t in targets),
            "status": dict(sorted(aggregate_status.items())), "top": aggregate_top.document(),
            "lanes": {name: bucket.document() for name, bucket in sorted(aggregate_lanes.items())},
            "targets": targets}


def main(argv: Sequence[str] | None = None) -> int:
    """Write one atomic accounting report, failing visibly on malformed input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="saved compare.json documents")
    parser.add_argument("--output", required=True, type=Path, help="report JSON path")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.inputs)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"comparator refusal report: {exc}\n")
    output: Path = args.output
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
