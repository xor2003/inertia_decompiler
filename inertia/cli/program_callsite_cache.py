# cython: language_level=3, infer_types=True
"""Persist complete direct-caller and typed callsite-summary evidence.

Layer: CLI/fallback/reporting.
Responsibility: key, encode, restore, and attach one already-classified program
callsite artifact without rebuilding Frontend ranges or Lowering summaries.
This module never discovers calls or derives argument, type, or return facts.
"""

from __future__ import annotations
import typing
import cython

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

import angr

from inertia.lowering.callee_callsite_codec import (
    callee_callsite_census_map_from_record_8616,
    callee_callsite_census_map_record_8616,
)
from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)
from inertia.semantics.callsite_summary_program import (
    ProgramCallsiteSummaryEvidence8616,
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_8616,
)
from inertia.semantics.callsite_summary_program_codec import (
    program_callsite_summary_evidence_from_record_8616,
    program_callsite_summary_evidence_record_8616,
)

from .cache import _load_cache_json, _recovery_cache_key, _store_cache_json
from .cache_source_manifest import RecoveryCacheSourceScope8616
from .cli_function_discovery import _display_catalog_cache_policy_8616
import dataclasses
import operator

PROGRAM_CALLSITE_CACHE_NAMESPACE_8616: str = "program_callsite_evidence"
_PROGRAM_CALLSITE_CACHE_SCHEMA_8616: cython.longlong = 3

log: logging.Logger = logging.getLogger(__name__)


class _CallerRangeSurface8616(Protocol):
    """Project-owned complete caller-range evidence used by callsite scans."""

    _inertia_caller_function_ranges_8616: object


def _validate_caller_ranges_8616(
    ranges: object,
) -> None:
    """Reject empty, malformed, or noncanonical caller-range coverage."""
    if not ranges:
        raise ValueError("program callsite caller-range coverage is empty")
    if any(start < 0 or end <= start for start, end in iter(ranges)):
        raise ValueError("program callsite caller ranges are invalid")
    if operator.ne(ranges, tuple(sorted(tuple(set(ranges))))):
        raise ValueError("program callsite caller ranges are not canonical")


def _caller_ranges_8616(project: object) -> object:
    """Return canonical caller ranges when the project owns that evidence."""
    try:
        ranges = cast(
            _CallerRangeSurface8616,
            project,
        )._inertia_caller_function_ranges_8616
    except AttributeError:
        return None
    if not isinstance(ranges, tuple) or any(
        not isinstance(item, tuple)
        or len(item) != 2
        or not all(isinstance(value, int) for value in iter(item))
        for item in iter(ranges)
    ):
        raise TypeError("program callsite caller ranges must be integer pairs")
    _validate_caller_ranges_8616(ranges)
    return ranges


def _caller_ranges_from_record_8616(
    value: object,
) -> object:
    """Decode the persisted caller-range coverage witness."""
    item: object
    if not isinstance(value, list):
        raise ValueError("program callsite caller ranges are not a list")
    ranges: list[tuple[cython.longlong, cython.longlong]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(part, int) for part in iter(item))
        ):
            raise ValueError("program callsite caller range is malformed")
        ranges.append((item[0], item[1]))
    result = tuple(ranges)
    _validate_caller_ranges_8616(result)
    return result


def attach_program_callsite_caller_ranges_8616(
    destination: object,
    *sources: object,
) -> cython.bint:
    """Attach the first available complete caller-range coverage witness."""
    ranges: object
    source: object
    for source in sources:
        ranges = _caller_ranges_8616(source)
        if ranges is None:
            continue
        cast(
            _CallerRangeSurface8616,
            destination,
        )._inertia_caller_function_ranges_8616 = ranges
        return True
    return False


@dataclasses.dataclass(frozen=True, )
class PersistedProgramCallsiteEvidence8616:
    """Closed callsite censuses and their coherent caller-indexed projection."""

    caller_ranges: object
    censuses_by_target: Mapping[cython.longlong, CalleeCallsiteCensus8616]
    summaries: ProgramCallsiteSummaryEvidence8616

    def validate(self) -> None:
        """Reject open censuses or disagreement between owned projections."""
        previous: object
        census: object
        fact: object
        target_addr: object
        _validate_caller_ranges_8616(self.caller_ranges)
        projected: dict[tuple[int | None, cython.longlong], dict[str, object] | None] = {}
        for target_addr, census in self.censuses_by_target.items():
            if operator.ne(target_addr, census.target_addr):
                raise ValueError("program callsite census key disagrees with target")
            census.validate()
            for fact in census.facts:
                key = (fact.caller_addr, fact.callsite_addr)
                summary_record = (
                    None if fact.summary is None else fact.summary.to_dict()
                )
                previous = projected.get(key)
                if key in projected and operator.ne(previous, summary_record):
                    raise ValueError("program callsite census summaries conflict")
                projected[key] = summary_record
        self.summaries.validate()
        summary_projection = {
            (fact.caller_addr, fact.callsite_addr): (
                None if fact.summary is None else fact.summary.to_dict()
            )
            for fact in iter(self.summaries.facts)
        }
        if projected != summary_projection:
            raise ValueError("program callsite summary projection is incoherent")

    @property
    def closed(self) -> cython.bint:
        """Return whether all counters and typed projections validate."""
        try:
            self.validate()
        except ValueError:
            return False
        return True


@cython.ccall
def program_callsite_cache_key_8616(
    source_project: object,
    binary_path: Path | None,
) -> object:
    """Return semantic identity for one complete program callsite artifact."""
    policy = _display_catalog_cache_policy_8616(cast(angr.Project, source_project))
    cache_key: object = _recovery_cache_key(
        binary_path=binary_path,
        kind=PROGRAM_CALLSITE_CACHE_NAMESPACE_8616,
        source_scope=RecoveryCacheSourceScope8616.PROGRAM_CALLSITE,
        extra={
            "artifact_schema": _PROGRAM_CALLSITE_CACHE_SCHEMA_8616,
            "ignore_local_sidecar_hints": policy.ignore_local_sidecar_hints,
            "include_library_functions": policy.include_library_functions,
            "function_discovery_backend": policy.function_discovery_backend,
            "pat_backend": policy.pat_backend,
            "auto_rizin_policy": policy.auto_rizin_policy,
            "signature_catalog_path": policy.signature_catalog_path,
            "signature_catalog_size": policy.signature_catalog_size,
            "signature_catalog_mtime_ns": policy.signature_catalog_mtime_ns,
        },
    )
    return cache_key


@cython.ccall
def program_callsite_evidence_from_project_8616(
    project: object,
) -> PersistedProgramCallsiteEvidence8616:
    """Snapshot one already-derived authoritative project artifact."""
    caller_ranges: object
    summaries: object
    summaries = program_callsite_summary_evidence_8616(project)
    if summaries is None:
        raise ValueError("project has no complete program callsite summaries")
    caller_ranges = _caller_ranges_8616(project)
    if caller_ranges is None:
        raise ValueError("project has no complete caller-range evidence")
    evidence = PersistedProgramCallsiteEvidence8616(
        caller_ranges,
        MappingProxyType(dict(callee_callsite_censuses_by_addr_8616(project))),
        summaries,
    )
    evidence.validate()
    return evidence


@cython.ccall
def attach_program_callsite_evidence_8616(
    project: object,
    evidence: PersistedProgramCallsiteEvidence8616,
) -> None:
    """Attach both coherent projections to one active project atomically."""
    active_ranges: object
    evidence.validate()
    active_ranges = _caller_ranges_8616(project)
    if active_ranges is not None and operator.ne(active_ranges, evidence.caller_ranges):
        raise ValueError("program callsite caller-range coverage changed")
    cast(
        _CallerRangeSurface8616,
        project,
    )._inertia_caller_function_ranges_8616 = evidence.caller_ranges
    attach_callee_callsite_censuses_8616(
        project,
        dict(evidence.censuses_by_target),
    )
    attach_program_callsite_summary_evidence_8616(project, evidence.summaries)


@cython.ccall
def attach_available_program_callsite_evidence_8616(
    project: object,
    cache_key: object,
) -> cython.bint:
    """Attach cached evidence unless a coherent artifact is already present."""
    persisted: object
    try:
        program_callsite_evidence_from_project_8616(project)
    except ValueError:
        pass
    else:
        return True
    if cache_key is None:
        return False
    persisted = load_program_callsite_cache_8616(cache_key, project)
    if persisted is None:
        return False
    attach_program_callsite_evidence_8616(project, persisted)
    return True


@cython.ccall
def load_program_callsite_cache_8616(
    cache_key: object,
    project: object,
) -> PersistedProgramCallsiteEvidence8616 | None:
    """Restore one closed artifact and rebind facts to the active project."""
    record: object
    record = _load_cache_json(PROGRAM_CALLSITE_CACHE_NAMESPACE_8616, cache_key)
    if record is None:
        return None
    try:
        if (
            not isinstance(record, dict)
            or operator.ne(record.get("schema"), _PROGRAM_CALLSITE_CACHE_SCHEMA_8616)
            or set(record)
            != {"schema", "caller_ranges", "censuses", "summaries"}
        ):
            raise ValueError("program callsite cache has an unsupported schema")
        evidence = PersistedProgramCallsiteEvidence8616(
            _caller_ranges_from_record_8616(record["caller_ranges"]),
            MappingProxyType(
                callee_callsite_census_map_from_record_8616(
                    project,
                    record["censuses"],
                )
            ),
            program_callsite_summary_evidence_from_record_8616(
                record["summaries"]
            ),
        )
        evidence.validate()
        return evidence
    except ValueError as exc:
        log.warning("persisted program callsite artifact refused: %s", exc)
        return None


@cython.ccall
def store_program_callsite_cache_8616(
    cache_key: object,
    project: object,
    evidence: PersistedProgramCallsiteEvidence8616,
) -> None:
    """Persist one already-classified closed program callsite artifact."""
    evidence.validate()
    if operator.ne(dict(callee_callsite_censuses_by_addr_8616(project)), dict(
        evidence.censuses_by_target
    )):
        raise ValueError("program callsite cache source registry changed")
    _store_cache_json(
        PROGRAM_CALLSITE_CACHE_NAMESPACE_8616,
        cache_key,
        {
            "schema": _PROGRAM_CALLSITE_CACHE_SCHEMA_8616,
            "caller_ranges": [list(item) for item in iter(evidence.caller_ranges)],
            "censuses": callee_callsite_census_map_record_8616(project),
            "summaries": program_callsite_summary_evidence_record_8616(
                evidence.summaries
            ),
        },
    )


__all__ = [
    "PROGRAM_CALLSITE_CACHE_NAMESPACE_8616",
    "PersistedProgramCallsiteEvidence8616",
    "attach_available_program_callsite_evidence_8616",
    "attach_program_callsite_caller_ranges_8616",
    "attach_program_callsite_evidence_8616",
    "load_program_callsite_cache_8616",
    "program_callsite_cache_key_8616",
    "program_callsite_evidence_from_project_8616",
    "store_program_callsite_cache_8616",
]
