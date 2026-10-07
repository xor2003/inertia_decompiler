"""Audit the finite compiler coverage matrix without executing its cases.

Layer: Tooling/gates.
Responsibility: validate planning identities and reject earned coverage states
without existing round-trip receipts and hash-pinned observed mechanisms.

An evidence row names ``profile`` and ``receipt`` (coverage-result.json).
Verified emission additionally names ``observed_mechanism``,
``mechanism_artifact`` and ``mechanism_sha256``. These observations are reviewed
evidence, not an automatic proof that the requested mechanism is present.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

from tools.compiler_toolchain.compiler_coverage_result import (
    CoverageOutcome,
    classify_roundtrip_report,
)
from tools.compiler_toolchain.compiler_profile import CompilerToolchain, resolve_case_toolchain

ROOT: Path = Path(__file__).resolve().parents[2]


class MatrixIssueKind(StrEnum):
    """Distinguish malformed plans, identity drift and unearned evidence."""

    CONTRACT = "contract"
    IDENTITY = "identity"
    EVIDENCE = "evidence"


@dataclass(frozen=True)
class MatrixIssue:
    """One actionable consistency or evidence refusal."""

    kind: MatrixIssueKind
    location: str
    reason: str


@dataclass(frozen=True)
class MatrixAudit:
    """Consistency findings; passing this audit does not accept round trips."""

    issues: tuple[MatrixIssue, ...]
    counts: dict[str, int]

    @property
    def passed(self) -> bool:
        """Whether all audited contracts have compatible evidence."""
        return not self.issues


def _object(value: object) -> dict[str, object]:
    """Check the JSON object boundary before using owned fields."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("expected JSON object")
    return cast(dict[str, object], value)


def _rows(value: object) -> list[dict[str, object]]:
    """Require a list of JSON objects."""
    if not isinstance(value, list):
        raise ValueError("expected object list")
    return [_object(item) for item in value]


def _strings(value: object) -> list[str]:
    """Require explicit nonempty string identities."""
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError("expected nonempty string identities")
    identities = cast(list[str], value)
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate string identity")
    return identities


def _text(value: object) -> str:
    """Require one nonempty JSON string."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected nonempty string")
    return value


def _path(root: Path, value: object) -> Path:
    """Constrain matrix-owned inputs and receipts to the checkout."""
    relative = Path(_text(value))
    target = (root / relative).resolve()
    if relative.is_absolute() or not target.is_relative_to(root.resolve()):
        raise ValueError("path must remain relative to the checkout")
    return target


def _digest(path: Path) -> str:
    """Hash the current bytes of one explicitly named evidence artifact."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _index(rows: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """Reject duplicate IDs before references can hide overwritten rows."""
    result: dict[str, dict[str, object]] = {}
    for row in rows:
        identifier = _text(row["id"])
        if identifier in result:
            raise ValueError(f"duplicate ID {identifier}")
        result[identifier] = row
    return result


def _source_file(source: dict[str, object], root: Path) -> tuple[Path, str]:
    """Resolve ordinary or retained generated source identity."""
    if source["state"] == "generated_retained":
        generated = _object(source["generated"])
        return _path(root, generated["retained_copy"]), _text(generated["source_sha256"])
    return _path(root, source["path"]), _text(source["sha256"])


def _source_contract(source: dict[str, object], root: Path, profiles: set[str]) -> None:
    """Permit planned absence while requiring current bytes for implemented sources."""
    if not set(_strings(source["profiles"])) <= profiles:
        raise ValueError("unknown source profile")
    CoverageOutcome(_text(source["roundtrip"]))
    if source["state"] == "planned_not_implemented":
        if _path(root, source["path"]).exists():
            raise ValueError("planned source exists; update its state and hash")
        if source["roundtrip"] != CoverageOutcome.NOT_ATTEMPTED.value:
            raise ValueError("missing planned source cannot have execution status")
        return
    if source["state"] not in ("existing", "generated_retained"):
        raise ValueError("unknown source state")
    path, expected = _source_file(source, root)
    if _digest(path) != expected:
        raise ValueError("source hash drift")


def _receipt(
    evidence: dict[str, object], source: dict[str, object], root: Path,
    outcome: CoverageOutcome, toolchain: CompilerToolchain,
) -> None:
    """Recheck an existing runner receipt rather than trusting a matrix verdict."""
    if source["kind"] == "compile_probe":
        raise ValueError("compile-probe evidence requires its own contract; round-trip receipts are insufficient")
    receipt = _object(json.loads(_path(root, evidence["receipt"]).read_text(encoding="utf-8")))
    if receipt["outcome"] != outcome.value:
        raise ValueError("receipt outcome differs from matrix status")
    profile = _object(receipt["compiler_profile"])
    if profile != toolchain.to_dict() or profile["profile_id"] != evidence["profile"]:
        raise ValueError("receipt compiler profile differs")
    inputs = _object(receipt["inputs"])
    source_identity = _object(inputs["source"])
    source_path, expected = _source_file(source, root)
    if receipt["schema"] != 1 or receipt["case"] != source_path.stem:
        raise ValueError("receipt schema or case identity differs")
    if Path(_text(source_identity["path"])).resolve() != source_path:
        raise ValueError("receipt source path differs")
    if source_identity["sha256"] != expected:
        raise ValueError("receipt source hash differs")
    if outcome is CoverageOutcome.PASSED:
        _passing_report(receipt, root)


def _passing_report(receipt: dict[str, object], root: Path) -> None:
    """Reclassify actual stage and observation evidence for a passing receipt."""
    if receipt["implementation_unchanged"] is not True or receipt["environment_unchanged"] is not True:
        raise ValueError("passing receipt has unstable inputs")
    report_path = Path(_text(receipt["report"]))
    if not report_path.is_absolute():
        report_path = root / report_path
    if not report_path.resolve().is_relative_to(root.resolve()):
        raise ValueError("receipt report escapes checkout")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    returncode = receipt["returncode"]
    if type(returncode) is not int:
        raise ValueError("receipt lacks integer returncode")
    if classify_roundtrip_report(report, _text(receipt["case"]), returncode) is not CoverageOutcome.PASSED:
        raise ValueError("referenced round-trip report does not pass")


def _earned_evidence(
    row: dict[str, object], sources: dict[str, dict[str, object]],
    profiles: dict[str, dict[str, object]], root: Path, *, cell: bool,
) -> None:
    """Require explicit evidence per selected profile for earned status."""
    outcome = CoverageOutcome(_text(row["roundtrip"]))
    emitted = row.get("emitted_evidence", "unverified")
    if emitted not in ("verified", "unverified"):
        raise ValueError("unknown emitted evidence state")
    if outcome is not CoverageOutcome.PASSED and emitted != "verified":
        return
    if cell and row["scope"] != "admitted":
        raise ValueError("only admitted cells can earn coverage")
    if cell and outcome is CoverageOutcome.PASSED and emitted != "verified":
        raise ValueError("passed cell lacks verified emitted mechanism")
    evidence_rows, evidence_profiles = _selected_evidence(row)
    source = sources[_text(row["witness"])] if cell else row
    if not set(evidence_profiles) <= set(_strings(source["profiles"])):
        raise ValueError("earned evidence profile is not selected for its source witness")
    for evidence in evidence_rows:
        profile = profiles[_text(evidence["profile"])]
        toolchain = _configuration(profile, root)
        _receipt(evidence, source, root, outcome, toolchain)
        if emitted == "verified":
            _mechanism(evidence, root)


def _selected_evidence(row: dict[str, object]) -> tuple[list[dict[str, object]], list[str]]:
    """Reject empty or duplicate profile evidence instead of vacuous acceptance."""
    rows = _rows(row.get("evidence", []))
    profiles = [_text(item["profile"]) for item in rows]
    selected = _strings(row["profiles"])
    if not selected or not rows or len(set(profiles)) != len(profiles):
        raise ValueError("earned status requires nonempty distinct profile evidence")
    if set(profiles) != set(selected):
        raise ValueError("earned status requires evidence for every selected profile")
    return rows, profiles


def _configuration(profile: dict[str, object], root: Path) -> CompilerToolchain:
    """Consume the existing verified registry and tool identities."""
    if profile["config_evidence"] != "verified":
        raise ValueError("earned status requires verified compiler configuration")
    toolchain = resolve_case_toolchain(_text(profile["id"]), evidence_path=_path(root, profile["receipt"]))
    if profile.get("memory_model", toolchain.memory_model.value) != toolchain.memory_model.value:
        raise ValueError("matrix memory model differs from verified configuration")
    return toolchain


def _mechanism(evidence: dict[str, object], root: Path) -> None:
    """Require a recorded observation and the artifact actually reviewed."""
    _text(evidence["observed_mechanism"])
    if _digest(_path(root, evidence["mechanism_artifact"])) != evidence["mechanism_sha256"]:
        raise ValueError("observed mechanism artifact hash differs")


def _partition(matrix: dict[str, object], cells: list[dict[str, object]]) -> set[str]:
    """Ensure each obligation occupies exactly one declared partition."""
    deferred = _object(matrix["deferred"])
    identities = [item for cell in cells for item in _strings(cell["covers"])]
    identities += _strings(deferred["later"])
    identities += [_text(row["id"]) for key in ("excluded", "undecided") for row in _rows(deferred[key])]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate or overlapping obligation partition")
    return set(identities)


def _counts(matrix: dict[str, object], sources: list[dict[str, object]], cells: list[dict[str, object]],
            profiles: dict[str, dict[str, object]]) -> dict[str, int]:
    """Derive planning denominators; none of these counts establishes acceptance."""
    states = Counter(_text(source["state"]) for source in sources)
    runtime = [source for source in sources if source["kind"] != "compile_probe"]
    probes = [source for source in sources if source["kind"] == "compile_probe"]
    first = _object(matrix["first_batch"])
    batch = _strings(first["sources"])
    first_profiles = _strings(first["profiles"])
    roles = ("baseline_sources", "directed_sources", "csmith_sources")
    role_ids = [item for role in roles for item in _strings(first[role])]
    if sorted(role_ids) != sorted(batch) or len(set(batch)) != len(batch):
        raise ValueError("first batch role partition differs")
    subtotals = _object(first["subtotals"])
    for role, subtotal in zip(roles, ("baseline_existing", "directed_additions", "csmith"), strict=True):
        if subtotals[subtotal] != len(_strings(first[role])) * len(first_profiles):
            raise ValueError(f"first batch subtotal {subtotal} differs")
    for identifier in batch:
        source = next(source for source in sources if source["id"] == identifier)
        if not set(first_profiles) <= set(_strings(source["profiles"])):
            raise ValueError("first batch source lacks selected profiles")
    return {
        "sources_total": len(sources), "sources_existing": states["existing"],
        "sources_planned_not_implemented": states["planned_not_implemented"],
        "sources_generated_retained": states["generated_retained"],
        "runtime_sources": len(runtime), "compile_probes": len(probes),
        "first_batch_cases": len(batch) * len(first_profiles),
        "ms_borland_case_pairs": _pairs(runtime, {"msc51", "bc31"}, profiles),
        "watcom_case_pairs_not_started": _pairs(sources, {"wtc11"}, profiles),
        "cells": len(cells), "admitted_cells": sum(cell["scope"] == "admitted" for cell in cells),
        "undecided_cells": sum(cell["scope"] == "undecided" for cell in cells),
    }


def _pairs(sources: list[dict[str, object]], compilers: set[str],
           profiles: dict[str, dict[str, object]]) -> int:
    """Count selected source/compiler configurations from the declared profiles."""
    return sum(
        profiles[profile]["compiler"] in compilers
        for source in sources for profile in _strings(source["profiles"])
    )


def _cell_contract(cell: dict[str, object], sources: dict[str, dict[str, object]],
                   profiles: dict[str, dict[str, object]], root: Path) -> None:
    """Validate a cell's references before interpreting its earned state."""
    if cell["scope"] not in ("admitted", "later", "excluded", "undecided"):
        raise ValueError("unknown cell scope")
    witnesses = [_text(cell["witness"]), *_strings(cell.get("secondary_witnesses", []))]
    if not set(witnesses) <= set(sources):
        raise ValueError("unknown cell witness")
    if not set(_strings(cell["profiles"])) <= set(profiles):
        raise ValueError("unknown cell profile")
    _earned_evidence(cell, sources, profiles, root, cell=True)


def _summary_issues(matrix: dict[str, object], counts: dict[str, int]) -> list[MatrixIssue]:
    """Keep denominator drift separate from per-row evidence refusals."""
    issues: list[MatrixIssue] = []
    summary = _object(matrix["summary"])
    for key, expected in counts.items():
        if type(summary.get(key)) is not int or summary[key] != expected:
            issues.append(MatrixIssue(MatrixIssueKind.CONTRACT, f"summary.{key}", f"expected {expected}"))
    if _object(matrix["first_batch"])["denominator"] != counts["first_batch_cases"]:
        issues.append(MatrixIssue(MatrixIssueKind.CONTRACT, "first_batch", "denominator differs"))
    return issues


def audit_matrix(path: Path, *, root: Path = ROOT) -> MatrixAudit:
    """Audit frozen planning data and explicit earned evidence without running DOS."""
    issues: list[MatrixIssue] = []
    counts: dict[str, int] = {}
    try:
        matrix = _object(json.loads(path.read_text(encoding="utf-8")))
        if matrix["schema"] != "coverage-matrix-1":
            raise ValueError("unsupported matrix schema")
        sources, cells = _rows(matrix["sources"]), _rows(matrix["cells"])
        source_index, cell_index = _index(sources), _index(cells)
        profiles = _index(_rows(matrix["profiles"]))
        obligations = _partition(matrix, cells)
        for source in sources:
            identifier = _text(source["id"])
            try:
                _source_contract(source, root, set(profiles))
                if not set(_strings(source["source_features"])) <= obligations:
                    raise ValueError("source feature outside obligation partition")
                _earned_evidence(source, source_index, profiles, root, cell=False)
            except (ValueError, KeyError, OSError) as error:
                issues.append(MatrixIssue(MatrixIssueKind.IDENTITY, identifier, str(error)))
        for identifier, cell in cell_index.items():
            try:
                _cell_contract(cell, source_index, profiles, root)
            except (ValueError, KeyError, OSError) as error:
                issues.append(MatrixIssue(MatrixIssueKind.EVIDENCE, identifier, str(error)))
        counts = _counts(matrix, sources, cells, profiles)
        issues.extend(_summary_issues(matrix, counts))
    except (ValueError, KeyError, OSError, StopIteration) as error:
        issues.append(MatrixIssue(MatrixIssueKind.CONTRACT, str(path), str(error)))
    return MatrixAudit(tuple(issues), counts)


def main() -> int:
    """Expose consistency findings separately from semantic acceptance."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=ROOT / "examples/compiler_coverage/coverage-matrix.json")
    args = parser.parse_args()
    audit = audit_matrix(args.matrix)
    for issue in audit.issues:
        print(f"{issue.kind.value}: {issue.location}: {issue.reason}")
    print(f"matrix consistency: {'passed' if audit.passed else 'failed'}; no new semantic acceptance")
    return 0 if audit.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
