"""Load the explicit compiler coverage scope and candidate witnesses.

Layer: Tooling/gates.
Responsibility: reject ambiguous scope, duplicate IDs and invalid references.
Admission is an obligation, never proof that a witness exercises the mechanism.
Schema 1 covers the single-profile pilot selection; schema 2 is the frozen
first-batch form, where every row pins its own compiler profile, source bytes,
runtime inputs, catalogues, expected observations, and bounded budgets.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOS_83_NAME = re.compile(r"^[A-Za-z0-9_.$-]{1,8}\.[A-Za-z0-9_.$-]{1,3}$")
MAX_CASE_BUDGET_SECONDS: int = 600
MAX_STAGE_BUDGET_SECONDS: int = 120


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
class PinnedInput:
    """A repo-relative input pinned by SHA-256; staged under ``name``."""

    path: str
    sha256: str
    name: str
    provenance: str | None = None


@dataclass(frozen=True)
class CaseSource:
    """The exact source file one frozen row feeds through the runner."""

    identifier: str
    path: str
    sha256: str


@dataclass(frozen=True)
class GeneratedProvenance:
    """Pinned generation recipe for a retained generated source."""

    seed: int
    generator_revision: str
    generator_sha256: str
    generator_branch: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class CoverageCase:
    """An existing fixture nominated to witness named obligations.

    Schema-1 rows carry only ``identifier``/``construct``/``obligations``.
    Schema-2 (frozen batch) rows additionally pin their compiler profile,
    source bytes, expected observations, runtime inputs, signature catalogues,
    and generation provenance; every pinned field stays explicit.
    """

    identifier: str
    construct: str
    obligations: tuple[str, ...]
    compiler_profile: str | None = None
    source: CaseSource | None = None
    expected_exit_code: int = 255
    expected_stdout_contains: str | None = None
    runtime_headers: tuple[PinnedInput, ...] = ()
    runtime_sources: tuple[PinnedInput, ...] = ()
    signature_catalogs: tuple[PinnedInput, ...] = ()
    generated: GeneratedProvenance | None = None


@dataclass(frozen=True)
class CoverageManifest:
    """Versioned pilot selection and explicitly qualified compiler profile.

    ``schema`` selects the record contract; schema-2 manifests pin per-case
    profiles and bounded budgets instead of a manifest-wide compiler.
    """

    profile: str
    compiler: str
    compiler_flags: tuple[str, ...]
    memory_model: str | None
    features: tuple[CoverageFeature, ...]
    cases: tuple[CoverageCase, ...]
    schema: int = 1
    manifest_id: str | None = None
    batch: str | None = None
    case_budget_seconds: int | None = None
    stage_budget_seconds: int | None = None

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
    """Require unique schema-1 cases referencing admitted obligations only."""
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


def _pinned_sha256(value: object, label: str) -> str:
    """Require a lowercase SHA-256 pin; a missing or fuzzy digest is invalid."""
    digest = _text(value, label)
    if not _SHA256.fullmatch(digest):
        raise ValueError(f"{label}: expected a 64-digit lowercase SHA-256 pin")
    return digest


def _dos_staged_name(value: object, label: str) -> str:
    """Require a plain DOS 8.3 staging name; ambiguous names refuse."""
    name = _text(value, label)
    if Path(name).name != name or not _DOS_83_NAME.fullmatch(name):
        raise ValueError(f"{label}: expected a plain DOS 8.3 filename, got {name!r}")
    return name


def _repo_relative_path(value: object, label: str) -> str:
    """Require a canonical POSIX path inside the checkout, never an external pin."""
    path = _text(value, label)
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or "\\" in path
        or ":" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
        or parsed.as_posix() != path
    ):
        raise ValueError(f"{label}: expected a canonical repo-relative POSIX path")
    return path


def _pinned_input(value: object, label: str, *, suffix: str, fields: set[str]) -> PinnedInput:
    """Read one pinned input record with an exact field set."""
    row = _record(value, fields, label)
    name = _dos_staged_name(row["name"], f"{label}.name")
    if not name.upper().endswith(suffix):
        raise ValueError(f"{label}.name: expected a {suffix} filename, got {name!r}")
    provenance = row.get("provenance")
    return PinnedInput(
        path=_repo_relative_path(row["path"], f"{label}.path"),
        sha256=_pinned_sha256(row["sha256"], f"{label}.sha256"),
        name=name,
        provenance=_text(provenance, f"{label}.provenance") if provenance is not None else None,
    )


def _pinned_inputs(value: object, label: str, *, suffix: str, fields: set[str]) -> tuple[PinnedInput, ...]:
    """Read pinned input lists; staged names must not collide under DOS folding."""
    if not isinstance(value, list):
        raise ValueError(f"{label}: expected a list")
    result = tuple(_pinned_input(item, label, suffix=suffix, fields=fields) for item in value)
    if len({item.name.casefold() for item in result}) != len(result):
        raise ValueError(f"{label}: staged names collide under DOS case folding")
    return result


def _frozen_source(value: object, label: str) -> CaseSource:
    """Read the pinned source record a frozen row feeds to the runner."""
    row = _record(value, {"id", "path", "sha256"}, label)
    path = _repo_relative_path(row["path"], f"{label}.path")
    if Path(path).suffix != ".c" or not Path(path).stem.isidentifier():
        raise ValueError(f"{label}.path: expected a .c file with an identifier stem: {path!r}")
    identifier = _text(row["id"], f"{label}.id")
    if not identifier.isidentifier():
        raise ValueError(f"{label}.id: expected an identifier")
    return CaseSource(
        identifier=identifier,
        path=path,
        sha256=_pinned_sha256(row["sha256"], f"{label}.sha256"),
    )


def _expected_observation(value: object, label: str) -> tuple[int, str | None]:
    """Read the declared original-program exit code and stdout requirement."""
    row = _record(value, {"exit_code", "stdout_contains"}, label)
    exit_code = row["exit_code"]
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        raise ValueError(f"{label}.exit_code: expected a DOS exit status integer")
    stdout = row["stdout_contains"]
    if stdout is not None:
        stdout = _text(stdout, f"{label}.stdout_contains")
    return exit_code, stdout


def _generated_provenance(value: object, label: str) -> GeneratedProvenance | None:
    """Read the pinned generator recipe for a retained generated source."""
    if value is None:
        return None
    row = _record(value, {"seed", "generator_revision", "generator_sha256", "generator_branch", "options"}, label)
    seed = row["seed"]
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError(f"{label}.seed: expected an unsigned 32-bit integer")
    return GeneratedProvenance(
        seed=seed,
        generator_revision=_text(row["generator_revision"], f"{label}.generator_revision"),
        generator_sha256=_pinned_sha256(row["generator_sha256"], f"{label}.generator_sha256"),
        generator_branch=_text(row["generator_branch"], f"{label}.generator_branch"),
        options=_sequence(row["options"], f"{label}.options"),
    )


_FROZEN_CASE_FIELDS = {
    "id", "construct", "compiler_profile", "obligations", "source", "expected",
    "runtime_headers", "runtime_sources", "signature_catalogs", "generated",
}
_HEADER_FIELDS = {"name", "path", "sha256"}
_CATALOG_FIELDS = {"path", "sha256", "name", "provenance"}


def _frozen_cases(value: object, features: tuple[CoverageFeature, ...]) -> tuple[CoverageCase, ...]:
    """Require unique frozen rows with complete pinned inputs and observations."""
    if not isinstance(value, list) or not value:
        raise ValueError("cases: expected a nonempty list")
    admitted = {item.identifier for item in features if item.status is ScopeStatus.ADMITTED}
    cases: list[CoverageCase] = []
    for raw in value:
        row = _record(raw, _FROZEN_CASE_FIELDS, "case")
        identifier = _text(row["id"], "case.id")
        construct = _text(row["construct"], "case.construct")
        profile_id = _text(row["compiler_profile"], "case.compiler_profile")
        obligations = _strings(row["obligations"], "case.obligations")
        exit_code, stdout = _expected_observation(row["expected"], "case.expected")
        source = _frozen_source(row["source"], "case.source")
        if not construct.isidentifier() or not set(obligations) <= admitted:
            raise ValueError(f"case {identifier}: invalid construct or non-admitted obligation")
        if Path(source.path).stem != construct:
            raise ValueError(f"case {identifier}: construct {construct!r} must equal the source stem")
        cases.append(CoverageCase(
            identifier, construct, obligations,
            compiler_profile=profile_id,
            source=source,
            expected_exit_code=exit_code,
            expected_stdout_contains=stdout,
            runtime_headers=_pinned_inputs(
                row["runtime_headers"], "case.runtime_headers", suffix=".H", fields=_HEADER_FIELDS),
            runtime_sources=_pinned_inputs(
                row["runtime_sources"], "case.runtime_sources", suffix=".C", fields=_HEADER_FIELDS),
            signature_catalogs=_pinned_inputs(
                row["signature_catalogs"], "case.signature_catalogs", suffix=".PAT",
                fields=_CATALOG_FIELDS),
            generated=_generated_provenance(row["generated"], "case.generated"),
        ))
    if len({item.identifier for item in cases}) != len(cases):
        raise ValueError("cases: duplicate IDs")
    if set().union(*(set(item.obligations) for item in cases)) != admitted:
        raise ValueError("scope: every admitted obligation requires a candidate witness")
    return tuple(cases)


def _budgets(value: object, label: str) -> tuple[int, int]:
    """Require bounded case/stage budgets inside the frozen plan limits."""
    row = _record(value, {"case_seconds", "stage_seconds"}, label)
    case_seconds = row["case_seconds"]
    stage_seconds = row["stage_seconds"]
    if type(case_seconds) is not int or not 0 < case_seconds <= MAX_CASE_BUDGET_SECONDS:
        raise ValueError(f"{label}.case_seconds: expected 1..{MAX_CASE_BUDGET_SECONDS}")
    if type(stage_seconds) is not int or not 0 < stage_seconds <= MAX_STAGE_BUDGET_SECONDS:
        raise ValueError(f"{label}.stage_seconds: expected 1..{MAX_STAGE_BUDGET_SECONDS}")
    return case_seconds, stage_seconds


def load_manifest(path: Path) -> CoverageManifest:
    """Read a versioned scope without interpreting planned features as covered."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or type(payload.get("schema")) is not int:
        raise ValueError("manifest: unsupported schema version")
    if payload["schema"] == 1:
        return _load_v1(payload)
    if payload["schema"] == 2:
        return _load_v2(payload)
    raise ValueError("manifest: unsupported schema version")


def _load_v1(payload: dict[str, object]) -> CoverageManifest:
    """Read the single-profile pilot selection contract."""
    payload = _record(payload, {"schema", "profile", "scope", "cases"}, "manifest")
    profile = _record(payload["profile"], {"id", "compiler", "flags", "memory_model"}, "profile")
    model = profile["memory_model"]
    if model is not None:
        model = _text(model, "profile.memory_model")
    features = _features(payload["scope"])
    return CoverageManifest(
        _text(profile["id"], "profile.id"), _text(profile["compiler"], "profile.compiler"),
        _sequence(profile["flags"], "profile.flags"), model, features, _cases(payload["cases"], features),
    )


def _load_v2(payload: dict[str, object]) -> CoverageManifest:
    """Read the frozen-batch selection with per-row profiles and budgets."""
    payload = _record(payload, {"schema", "id", "batch", "budgets", "scope", "cases"}, "manifest")
    features = _features(payload["scope"])
    case_seconds, stage_seconds = _budgets(payload["budgets"], "budgets")
    return CoverageManifest(
        profile="", compiler="", compiler_flags=(), memory_model=None,
        features=features, cases=_frozen_cases(payload["cases"], features),
        schema=2,
        manifest_id=_text(payload["id"], "manifest.id"),
        batch=_text(payload["batch"], "manifest.batch"),
        case_budget_seconds=case_seconds,
        stage_budget_seconds=stage_seconds,
    )
