# cython: language_level=3, infer_types=True
"""Typed persistence contract for CLI-owned function-discovery evidence.

Layer: CLI/fallback/reporting.
Responsibility: serialize and validate discovered addresses and typed evidence without inference.
Forbidden: discovering functions or deriving call/return semantics from cached text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass

from inertia.semantics.caller_return_use_contracts import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
)
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
import dataclasses
import operator

DISPLAY_CATALOG_CACHE_PAYLOAD_SCHEMA_8616: cython.longlong = 3


@cython.ccall
def _nonnegative_int_8616(value: object) -> cython.longlong:
    """Return a validated nonnegative integer that is not a boolean."""
    if type(value) is not int or value < 0:
        raise ValueError("evidence count or address must be a nonnegative integer")
    return value


def _nonnegative_int_tuple_8616(value: object, *, field_name: object) -> object:
    """Return a validated JSON integer list as an immutable tuple."""
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    items = tuple(_nonnegative_int_8616(item) for item in iter(value))
    if operator.ne(len(items), len(set(items))):
        raise ValueError(f"{field_name} must not contain duplicates")
    return items


@dataclasses.dataclass(frozen=True, )
class SourceRegionCatalogEvidence8616:
    """Closed evidence counts for a startup-bounded application catalog."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    failed_addrs: object

    @property
    def complete(self) -> cython.bint:
        """Return whether every classified source entry was materialized."""
        return (
            self.classified_fact_count > 0
            and operator.eq(self.materialized_count, self.classified_fact_count)
            and self.failure_count == 0
        )


def source_region_catalog_evidence_comment_8616(
    evidence: SourceRegionCatalogEvidence8616,
) -> str:
    """Render the stable C-comment diagnostic for one discovery evidence loop."""
    failed_addrs = ",".join(hex(addr) for addr in iter(evidence.failed_addrs)) or "none"
    return (
        "/* source-region discovery evidence: "
        f"raw_fact_count={evidence.raw_fact_count} "
        f"normalized_fact_count={evidence.normalized_fact_count} "
        f"classified_fact_count={evidence.classified_fact_count} "
        f"materialized_count={evidence.materialized_count} "
        f"failure_count={evidence.failure_count} failed_addrs={failed_addrs} */"
    )


@dataclasses.dataclass(frozen=True, )
class DisplayCatalogCachePayload8616:
    """Validated display catalog and the exact evidence available when it was built."""

    addrs: object
    caller_return_use: object
    source_region: SourceRegionCatalogEvidence8616 | None

    def caller_return_use_by_addr(self) -> dict[cython.longlong, CallerReturnUseEvidence8616]:
        """Return caller-return evidence keyed by its project carrier address."""
        return dict(self.caller_return_use)


@cython.ccall
def _caller_return_use_fact_record_8616(fact: CallerReturnUseFact8616) -> dict[str, object]:
    """Serialize one exact caller-return fact without discarding its witness."""
    return {
        "caller_addr": fact.caller_addr,
        "callsite_addr": fact.callsite_addr,
        "verdict": fact.verdict.value,
        "kind": None if fact.kind is None else fact.kind.value,
        "witness_instruction_addr": fact.witness_instruction_addr,
        "excluded_recursive_passthrough": fact.excluded_recursive_passthrough,
        "byte_extension": (
            None if fact.byte_extension is None else fact.byte_extension.value
        ),
        "byte_extension_instruction_addr": fact.byte_extension_instruction_addr,
        "observed_value_view": (
            None if fact.observed_value_view is None else fact.observed_value_view.value
        ),
    }


@cython.ccall
def _caller_return_use_fact_from_record_8616(record: object) -> CallerReturnUseFact8616:
    """Validate and restore one exact caller-return fact."""
    excluded: object
    raw_extension: object
    raw_extension_addr: object
    raw_kind: object
    raw_verdict: object
    raw_view: object
    raw_witness: object
    if not isinstance(record, dict):
        raise ValueError("caller-return fact must be an object")
    try:
        raw_verdict = record.get("verdict")
        if raw_verdict is None:
            raise ValueError("caller-return fact is missing verdict")
        verdict = CallerReturnUseVerdict8616(raw_verdict)
        raw_kind = record.get("kind")
        kind = None if raw_kind is None else CallsiteReturnUseKind8616(raw_kind)
        raw_extension = record.get("byte_extension")
        byte_extension = (
            None
            if raw_extension is None
            else ByteReturnExtensionKind8616(raw_extension)
        )
        raw_view = record.get("observed_value_view")
        observed_value_view = (
            None if raw_view is None else AxValueView8616(raw_view)
        )
    except (TypeError, ValueError) as ex:
        raise ValueError("caller-return fact has an invalid typed classification") from ex
    raw_witness = record.get("witness_instruction_addr")
    witness = None if raw_witness is None else _nonnegative_int_8616(raw_witness)
    raw_extension_addr = record.get("byte_extension_instruction_addr")
    extension_addr = (
        None
        if raw_extension_addr is None
        else _nonnegative_int_8616(raw_extension_addr)
    )
    excluded = record.get("excluded_recursive_passthrough")
    if type(excluded) is not bool:
        raise ValueError("caller-return recursive exclusion must be boolean")
    fact = CallerReturnUseFact8616(
        caller_addr=_nonnegative_int_8616(record.get("caller_addr")),
        callsite_addr=_nonnegative_int_8616(record.get("callsite_addr")),
        verdict=verdict,
        kind=kind,
        witness_instruction_addr=witness,
        excluded_recursive_passthrough=excluded,
        byte_extension=byte_extension,
        byte_extension_instruction_addr=extension_addr,
        observed_value_view=observed_value_view,
    )
    if not fact.extension_complete:
        raise ValueError("caller-return byte extension is incomplete")
    return fact


@cython.ccall
def caller_return_use_evidence_record_8616(
    evidence: CallerReturnUseEvidence8616,
) -> dict[str, object]:
    """Serialize one owned caller-return evidence contract without inference."""
    if evidence.raw_fact_count and not evidence.fact_census_complete:
        raise ValueError("caller-return retained facts do not close their counters")
    return {
        "target_addr": evidence.target_addr,
        "verdict": evidence.verdict.value,
        "raw_fact_count": evidence.raw_fact_count,
        "normalized_fact_count": evidence.normalized_fact_count,
        "classified_fact_count": evidence.classified_fact_count,
        "materialized_count": evidence.materialized_count,
        "failure_count": evidence.failure_count,
        "used_callsite_count": evidence.used_callsite_count,
        "unused_callsite_count": evidence.unused_callsite_count,
        "excluded_callsite_count": evidence.excluded_callsite_count,
        "callsite_addrs": list(evidence.callsite_addrs),
        "facts": [_caller_return_use_fact_record_8616(fact) for fact in iter(evidence.facts)],
    }


@cython.ccall
def _assert_unused_verdict_closed_8616(counts: object) -> None:
    """An unused verdict requires every classified fact accounted for."""
    if (
        counts["used_callsite_count"] != 0
        or counts["raw_fact_count"] == 0
        or operator.ne(counts["normalized_fact_count"], counts["raw_fact_count"])
        or counts["classified_fact_count"] == 0
        or operator.ne(counts["classified_fact_count"] + counts["excluded_callsite_count"], counts["normalized_fact_count"])
    ):
        raise ValueError("unused caller-return verdict is not fully classified")


@cython.ccall
def _assert_caller_return_count_closure_8616(
    counts: object,
    callsite_addrs: object,
    verdict: CallerReturnUseVerdict8616,
) -> None:
    """Enforce the closed-loop counter invariants for caller-return evidence."""
    if counts["normalized_fact_count"] > counts["raw_fact_count"]:
        raise ValueError("caller-return normalized facts exceed raw facts")
    if counts["classified_fact_count"] > counts["normalized_fact_count"]:
        raise ValueError("caller-return classified facts exceed normalized facts")
    if operator.ne(counts["materialized_count"], counts["classified_fact_count"]):
        raise ValueError("caller-return materialized facts do not close classified facts")
    if operator.ne(counts["used_callsite_count"] + counts["unused_callsite_count"], counts["classified_fact_count"]):
        raise ValueError("caller-return callsite classifications do not close")
    if operator.ne(len(callsite_addrs), counts["raw_fact_count"]):
        raise ValueError("caller-return callsite addresses do not match raw facts")
    if verdict is CallerReturnUseVerdict8616.USED and counts["used_callsite_count"] == 0:
        raise ValueError("used caller-return verdict has no used callsite")
    if verdict is CallerReturnUseVerdict8616.UNUSED:
        _assert_unused_verdict_closed_8616(counts)


def caller_return_use_evidence_from_record_8616(record: object) -> CallerReturnUseEvidence8616:
    """Validate and deserialize one caller-return evidence record."""
    raw_facts: object
    raw_verdict: object
    if not isinstance(record, dict):
        raise ValueError("caller-return evidence entry must be an object")
    target_addr = _nonnegative_int_8616(record.get("target_addr"))
    try:
        raw_verdict = record.get("verdict")
        if raw_verdict is None:
            raise ValueError("caller-return evidence is missing verdict")
        verdict = CallerReturnUseVerdict8616(raw_verdict)
    except (TypeError, ValueError) as ex:
        raise ValueError("caller-return evidence has an invalid verdict") from ex
    count_names = (
        "raw_fact_count",
        "normalized_fact_count",
        "classified_fact_count",
        "materialized_count",
        "failure_count",
        "used_callsite_count",
        "unused_callsite_count",
    )
    counts = {name: _nonnegative_int_8616(record.get(name)) for name in iter(count_names)}
    counts["excluded_callsite_count"] = _nonnegative_int_8616(
        record.get("excluded_callsite_count", 0)
    )
    callsite_addrs = _nonnegative_int_tuple_8616(record.get("callsite_addrs"), field_name="callsite_addrs")
    raw_facts = record.get("facts")
    if not isinstance(raw_facts, list):
        raise ValueError("caller-return facts must be a list")
    facts = tuple(_caller_return_use_fact_from_record_8616(item) for item in iter(raw_facts))
    _assert_caller_return_count_closure_8616(counts, callsite_addrs, verdict)
    evidence = CallerReturnUseEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        raw_fact_count=counts["raw_fact_count"],
        normalized_fact_count=counts["normalized_fact_count"],
        classified_fact_count=counts["classified_fact_count"],
        materialized_count=counts["materialized_count"],
        failure_count=counts["failure_count"],
        used_callsite_count=counts["used_callsite_count"],
        unused_callsite_count=counts["unused_callsite_count"],
        callsite_addrs=callsite_addrs,
        excluded_callsite_count=counts["excluded_callsite_count"],
        facts=facts,
    )
    if counts["raw_fact_count"] and not evidence.fact_census_complete:
        raise ValueError("caller-return retained facts do not close their counters")
    if operator.ne(tuple(fact.callsite_addr for fact in iter(facts)), callsite_addrs):
        raise ValueError("caller-return fact addresses do not match the census")
    return evidence


@cython.ccall
def _source_region_record_8616(evidence: SourceRegionCatalogEvidence8616) -> dict[str, object]:
    """Serialize one closed source-region catalog evidence loop."""
    return {
        "raw_fact_count": evidence.raw_fact_count,
        "normalized_fact_count": evidence.normalized_fact_count,
        "classified_fact_count": evidence.classified_fact_count,
        "materialized_count": evidence.materialized_count,
        "failure_count": evidence.failure_count,
        "failed_addrs": list(evidence.failed_addrs),
    }


@cython.ccall
def _source_region_from_record_8616(record: object) -> SourceRegionCatalogEvidence8616:
    """Validate one cached source-region catalog evidence loop."""
    if not isinstance(record, dict):
        raise ValueError("source-region evidence must be an object")
    raw_count = _nonnegative_int_8616(record.get("raw_fact_count"))
    normalized_count = _nonnegative_int_8616(record.get("normalized_fact_count"))
    classified_count = _nonnegative_int_8616(record.get("classified_fact_count"))
    materialized_count = _nonnegative_int_8616(record.get("materialized_count"))
    failure_count = _nonnegative_int_8616(record.get("failure_count"))
    failed_addrs = _nonnegative_int_tuple_8616(record.get("failed_addrs"), field_name="failed_addrs")
    if normalized_count > raw_count or classified_count > normalized_count:
        raise ValueError("source-region evidence counts are not monotonic")
    if materialized_count > classified_count or operator.ne(failure_count, classified_count - materialized_count):
        raise ValueError("source-region materialization evidence does not close")
    if operator.ne(failure_count, len(failed_addrs)):
        raise ValueError("source-region failed addresses do not match failure count")
    evidence = SourceRegionCatalogEvidence8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        failed_addrs=failed_addrs,
    )
    if not evidence.complete:
        raise ValueError("cached source-region catalog evidence is incomplete")
    return evidence


def display_catalog_cache_record_8616(
    addrs: object,
    caller_return_use_by_addr: Mapping[cython.longlong, CallerReturnUseEvidence8616],
    source_region: object,
) -> dict[str, object]:
    """Build a versioned JSON record preserving the complete discovery evidence state."""
    evidence: object
    function_addr: object
    normalized_addrs = tuple(_nonnegative_int_8616(addr) for addr in iter(addrs))
    if not normalized_addrs or operator.ne(len(normalized_addrs), len(set(normalized_addrs))):
        raise ValueError("display catalog addresses must be nonempty and unique")
    if source_region is not None and not source_region.complete:
        raise ValueError("refusing to cache an incomplete source-region catalog")
    caller_records: list[dict[str, object]] = []
    for function_addr, evidence in sorted(tuple(caller_return_use_by_addr.items())):
        validated_addr = _nonnegative_int_8616(function_addr)
        if operator.ne(validated_addr, evidence.target_addr):
            raise ValueError("caller-return cache key and evidence target differ")
        evidence_record = caller_return_use_evidence_record_8616(evidence)
        caller_return_use_evidence_from_record_8616(evidence_record)
        caller_records.append(
            {
                "function_addr": validated_addr,
                "evidence": evidence_record,
            }
        )
    return {
        "schema": DISPLAY_CATALOG_CACHE_PAYLOAD_SCHEMA_8616,
        "addrs": list(normalized_addrs),
        "caller_return_use": caller_records,
        "source_region": None if source_region is None else _source_region_record_8616(source_region),
    }


@cython.ccall
def display_catalog_cache_payload_from_record_8616(record: object) -> DisplayCatalogCachePayload8616:
    """Validate and deserialize a display-catalog cache record."""
    raw_caller_records: object
    raw_source_region: object
    raw_record: object
    if not isinstance(record, dict) or operator.ne(record.get("schema"), DISPLAY_CATALOG_CACHE_PAYLOAD_SCHEMA_8616):
        raise ValueError("display catalog cache has an unsupported schema")
    addrs = _nonnegative_int_tuple_8616(record.get("addrs"), field_name="display catalog addresses")
    if not addrs:
        raise ValueError("display catalog cache has no addresses")
    raw_caller_records = record.get("caller_return_use")
    if not isinstance(raw_caller_records, list):
        raise ValueError("display catalog caller-return evidence must be a list")
    caller_return_use: list[tuple[cython.longlong, CallerReturnUseEvidence8616]] = []
    seen_function_addrs: set[cython.longlong] = set()
    for raw_record in raw_caller_records:
        if not isinstance(raw_record, dict):
            raise ValueError("display catalog caller-return entry must be an object")
        function_addr = _nonnegative_int_8616(raw_record.get("function_addr"))
        evidence = caller_return_use_evidence_from_record_8616(raw_record.get("evidence"))
        if function_addr in seen_function_addrs:
            raise ValueError("display catalog caller-return evidence contains duplicate addresses")
        if operator.ne(function_addr, evidence.target_addr):
            raise ValueError("display catalog caller-return key and target differ")
        seen_function_addrs.add(function_addr)
        caller_return_use.append((function_addr, evidence))
    raw_source_region = record.get("source_region")
    source_region = None if raw_source_region is None else _source_region_from_record_8616(raw_source_region)
    return DisplayCatalogCachePayload8616(
        addrs=addrs,
        caller_return_use=tuple(caller_return_use),
        source_region=source_region,
    )
