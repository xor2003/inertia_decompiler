"""Load the explicit compiler coverage scope and candidate witnesses.

Layer: Test infrastructure.
Responsibility: reject ambiguous scope, duplicate IDs and invalid references.
Admission is an obligation, never proof that a witness exercises the mechanism.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ScopeStatus(StrEnum):
    """Distinguish required obligations from deferred and undecided scope."""

    ADMITTED = "admitted"
    LATER = "later"
    EXCLUDED = "excluded"
    UNDECIDED = "undecided"


@dataclass(frozen=True)
class CoverageFeature:
    """One enumerated coverage obligation, not a passing test result."""

    identifier: str
    status: ScopeStatus


@dataclass(frozen=True)
class CoverageCase:
    """An existing fixture nominated to witness named obligations."""

    identifier: str
    construct: str
    obligations: tuple[str, ...]


@dataclass(frozen=True)
class CoverageManifest:
    """Versioned pilot selection and explicitly qualified compiler profile."""

    profile: str
    compiler: str
    compiler_flags: tuple[str, ...]
    memory_model: str | None
    features: tuple[CoverageFeature, ...]
    cases: tuple[CoverageCase, ...]

    def select(self, case: str | None = None, obligation: str | None = None) -> tuple[CoverageCase, ...]:
        """Select witnesses by exact IDs, rejecting empty or unknown selections."""
        selected = tuple(item for item in self.cases
                         if (case is None or item.identifier == case)
                         and (obligation is None or obligation in item.obligations))
        if not selected:
            raise ValueError(f"No admitted cases match case={case!r}, obligation={obligation!r}")
        return selected


def _record(value: object, fields: set[str], label: str) -> dict[str, object]:
    """Require an exact object schema so misspelled settings cannot disappear."""
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label}: expected fields {sorted(fields)}")
    return value


def _text(value: object, label: str) -> str:
    """Require a nonempty string identifier or setting."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}: expected a nonempty string")
    return value


def _sequence(value: object, label: str) -> tuple[str, ...]:
    """Preserve ordered settings, including repetitions and empty defaults."""
    if not isinstance(value, list):
        raise ValueError(f"{label}: expected a list")
    return tuple(_text(item, label) for item in value)


def _strings(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    """Read unique identifiers without coercing or discarding invalid values."""
    result = _sequence(value, label)
    if not result and not allow_empty:
        raise ValueError(f"{label}: expected a nonempty list")
    if len(set(result)) != len(result):
        raise ValueError(f"{label}: duplicate values")
    return result


def _features(value: object) -> tuple[CoverageFeature, ...]:
    """Validate explicitly enumerated features grouped by admission status."""
    groups = _record(value, {status.value for status in ScopeStatus}, "scope")
    result = tuple(CoverageFeature(identifier, ScopeStatus(status))
                   for status, identifiers in groups.items()
                   for identifier in _strings(identifiers, f"scope.{status}", allow_empty=True))
    if len({item.identifier for item in result}) != len(result):
        raise ValueError("scope: a feature cannot have multiple statuses")
    return result


def _cases(value: object, features: tuple[CoverageFeature, ...]) -> tuple[CoverageCase, ...]:
    """Require unique cases referencing admitted obligations only."""
    if not isinstance(value, list) or not value:
        raise ValueError("cases: expected a nonempty list")
    admitted = {item.identifier for item in features if item.status is ScopeStatus.ADMITTED}
    cases: list[CoverageCase] = []
    for raw in value:
        row = _record(raw, {"id", "construct", "obligations"}, "case")
        identifier, construct = _text(row["id"], "case.id"), _text(row["construct"], "case.construct")
        obligations = _strings(row["obligations"], "case.obligations")
        if not construct.isidentifier() or not set(obligations) <= admitted:
            raise ValueError(f"case {identifier}: invalid construct or non-admitted obligation")
        cases.append(CoverageCase(identifier, construct, obligations))
    if len({item.identifier for item in cases}) != len(cases):
        raise ValueError("cases: duplicate IDs")
    if set().union(*(set(item.obligations) for item in cases)) != admitted:
        raise ValueError("scope: every admitted obligation requires a candidate witness")
    return tuple(cases)


def load_manifest(path: Path) -> CoverageManifest:
    """Read a version-one scope without interpreting planned features as covered."""
    payload = _record(json.loads(path.read_text(encoding="utf-8")),
                      {"schema", "profile", "scope", "cases"}, "manifest")
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        raise ValueError("manifest: unsupported schema version")
    profile = _record(payload["profile"], {"id", "compiler", "flags", "memory_model"}, "profile")
    model = profile["memory_model"]
    if model is not None:
        model = _text(model, "profile.memory_model")
    features = _features(payload["scope"])
    return CoverageManifest(
        _text(profile["id"], "profile.id"), _text(profile["compiler"], "profile.compiler"),
        _sequence(profile["flags"], "profile.flags"), model, features, _cases(payload["cases"], features),
    )
