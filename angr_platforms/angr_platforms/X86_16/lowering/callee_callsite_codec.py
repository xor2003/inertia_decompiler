"""Transport exact callee callsite censuses across JSON boundaries.

Layer: Types/Lowering.
Responsibility: encode and rebind already-derived direct-caller facts while
preserving target, caller, callsite, summary, and project-owner identities.
This module does not discover calls or derive arity, width, or value classes.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from ..callsite_summary_codec import (
    callsite_summary_from_record_8616,
    callsite_summary_record_8616,
)
from ..frontend_boundary_transport import (
    function_boundary_from_record_8616,
    function_boundary_record_8616,
)
from .callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    callee_callsite_censuses_by_addr_8616,
)

__all__ = [
    "callee_callsite_census_map_from_record_8616",
    "callee_callsite_census_map_record_8616",
]


class _OriginalProjectSurface8616(Protocol):
    """Dynamic project relation needed to preserve an original evidence owner."""

    _inertia_original_project: object


def _record_8616(value: object, label: str) -> dict[str, object]:
    """Return one string-keyed record or reject malformed JSON data."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return value


def _int_8616(value: object, label: str) -> int:
    """Return one exact nonnegative integer."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _optional_int_8616(value: object, label: str) -> int | None:
    """Return one optional nonnegative integer."""
    return None if value is None else _int_8616(value, label)


def _original_project_8616(project: object) -> object | None:
    """Return the explicit original project at the third-party boundary."""
    try:
        return cast(_OriginalProjectSurface8616, project)._inertia_original_project
    except AttributeError:
        return None


def _owner_kind_8616(project: object, evidence_project: object) -> str:
    """Encode one evidence owner using only an explicit project relation."""
    if evidence_project is project:
        return "active"
    if evidence_project is _original_project_8616(project):
        return "original"
    raise ValueError("callee callsite fact has an untransportable evidence owner")


def _owner_from_kind_8616(project: object, kind: object) -> object:
    """Rebind one encoded evidence owner to the freshly loaded project."""
    if kind == "active":
        return project
    if kind == "original":
        original = _original_project_8616(project)
        if original is None:
            raise ValueError("callee callsite original owner is unavailable")
        return original
    raise ValueError("callee callsite evidence owner kind is invalid")


def _fact_record_8616(
    project: object,
    fact: CalleeCallsiteFact8616,
) -> dict[str, object]:
    """Encode one exact fact without serializing third-party objects."""
    return {
        "owner": _owner_kind_8616(project, fact.evidence_project),
        "evidence_target_addr": fact.evidence_target_addr,
        "caller_addr": fact.caller_addr,
        "caller_boundary": function_boundary_record_8616(
            fact.evidence_project, fact.caller_function,
            required_entry=fact.caller_addr, required_instruction=fact.callsite_addr,
        ),
        "callsite_addr": fact.callsite_addr,
        "summary": (
            None
            if fact.summary is None
            else callsite_summary_record_8616(fact.summary)
        ),
    }


def _fact_from_record_8616(
    project: object,
    value: object,
) -> CalleeCallsiteFact8616:
    """Decode one fact and bind it to the fresh evidence project."""
    record = _record_8616(value, "callee callsite fact")
    if set(record) != {
        "owner",
        "evidence_target_addr",
        "caller_addr",
        "caller_boundary",
        "callsite_addr",
        "summary",
    }:
        raise ValueError("callee callsite fact has an incompatible field set")
    raw_summary = record["summary"]
    summary = (
        None
        if raw_summary is None
        else callsite_summary_from_record_8616(raw_summary)
    )
    callsite_addr = _int_8616(record["callsite_addr"], "callee callsite address")
    if summary is not None and summary.callsite_addr != callsite_addr:
        raise ValueError("callee callsite summary address disagrees with its fact")
    owner = _owner_from_kind_8616(project, record["owner"])
    caller_addr = _optional_int_8616(record["caller_addr"], "callee callsite caller address")
    boundary = function_boundary_from_record_8616(owner, record["caller_boundary"])
    boundary_disagrees = boundary is not None and (
        boundary.addr != caller_addr or callsite_addr not in boundary.reachable_instruction_addrs
    )
    if boundary_disagrees:
        raise ValueError(
            f"callee callsite {callsite_addr:#x}, caller {caller_addr!r}: "
            "identity disagrees with its caller boundary"
        )
    return CalleeCallsiteFact8616(
        evidence_project=owner,
        caller_function=boundary,
        evidence_target_addr=_int_8616(
            record["evidence_target_addr"],
            "callee callsite evidence target",
        ),
        caller_addr=caller_addr,
        callsite_addr=callsite_addr,
        summary=summary,
    )


def callee_callsite_census_map_record_8616(
    project: object,
) -> list[dict[str, object]]:
    """Encode the authoritative project census registry deterministically."""
    return [
        {
            "target_addr": target_addr,
            "facts": [_fact_record_8616(project, fact) for fact in census.facts],
            "raw_fact_count": census.raw_fact_count,
            "normalized_fact_count": census.normalized_fact_count,
            "failure_count": census.failure_count,
        }
        for target_addr, census in sorted(
            callee_callsite_censuses_by_addr_8616(project).items()
        )
    ]


def callee_callsite_census_map_from_record_8616(
    project: object,
    value: object,
) -> dict[int, CalleeCallsiteCensus8616]:
    """Decode and validate one complete project census registry."""
    if not isinstance(value, list):
        raise ValueError("callee callsite census transport must be an array")
    result: dict[int, CalleeCallsiteCensus8616] = {}
    for item in value:
        record = _record_8616(item, "callee callsite census")
        if set(record) != {
            "target_addr",
            "facts",
            "raw_fact_count",
            "normalized_fact_count",
            "failure_count",
        }:
            raise ValueError("callee callsite census has an incompatible field set")
        target_addr = _int_8616(record["target_addr"], "callee census target")
        if target_addr in result:
            raise ValueError("callee callsite transport contains duplicate targets")
        raw_facts = record["facts"]
        if not isinstance(raw_facts, list):
            raise ValueError("callee callsite census facts must be an array")
        census = CalleeCallsiteCensus8616(
            target_addr=target_addr,
            facts=tuple(_fact_from_record_8616(project, fact) for fact in raw_facts),
            raw_fact_count=_int_8616(record["raw_fact_count"], "callee census raw count"),
            normalized_fact_count=_int_8616(
                record["normalized_fact_count"],
                "callee census normalized count",
            ),
            failure_count=_int_8616(
                record["failure_count"],
                "callee census failure count",
            ),
        )
        census.validate()
        result[target_addr] = census
    return result
