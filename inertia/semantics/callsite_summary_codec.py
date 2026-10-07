"""Encode complete typed callsite summaries for process transport.

Layer: Recovery metadata.
Responsibility: losslessly encode and decode the owned ``CallsiteSummary8616``
contract, including Alias-owned predecessor and partial-register evidence.
This module transports existing facts; it does not discover or classify calls.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import fields

from inertia.alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsitePushTrace8616,
    CallsiteRegisterJoin8616,
    CallsiteRegisterJoinTrace8616,
)
from inertia.alias.partial_register_address_break import (
    PartialRegisterAddressBreakEvidence8616,
)

from .caller_return_use_contracts import CallsiteReturnUseKind8616
from .callsite_summary import CallsiteArgumentClass8616, CallsiteSummary8616

__all__ = [
    "callsite_summary_from_record_8616",
    "callsite_summary_record_8616",
]


def _record_8616(value: object, label: str) -> dict[str, object]:
    """Return one string-keyed record or reject malformed transport data."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return value


def _int_8616(value: object, label: str) -> int:
    """Return one exact integer, excluding JSON booleans."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _optional_int_8616(value: object, label: str) -> int | None:
    """Return one optional exact integer."""
    return None if value is None else _int_8616(value, label)


def _optional_str_8616(value: object, label: str) -> str | None:
    """Return one optional string."""
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} must be a string or null")
    return value


def _tuple_value_from_record_8616(value: object, label: str) -> object:
    """Restore nested tuple facts while refusing foreign object shapes."""
    if isinstance(value, list | tuple):
        return tuple(
            _tuple_value_from_record_8616(item, f"{label}[]") for item in value
        )
    if value is None or isinstance(value, bool | int | str):
        return value
    raise ValueError(f"{label} contains a non-transportable value")


def _int_tuple_8616(value: object, label: str) -> tuple[int, ...]:
    """Decode one integer tuple."""
    restored = _tuple_value_from_record_8616(value, label)
    if not isinstance(restored, tuple) or any(
        not isinstance(item, int) or isinstance(item, bool) for item in restored
    ):
        raise ValueError(f"{label} must contain only integers")
    return restored


def _source_tuple_8616(value: object, label: str) -> tuple[object, ...] | None:
    """Decode one optional nested callsite source tuple."""
    if value is None:
        return None
    restored = _tuple_value_from_record_8616(value, label)
    if not isinstance(restored, tuple):
        raise ValueError(f"{label} must be an array or null")
    return restored


def _push_trace_from_record_8616(value: object) -> CallsitePushTrace8616:
    """Decode one predecessor push trace."""
    record = _record_8616(value, "callsite push trace")
    sources_raw = record.get("sources")
    if not isinstance(sources_raw, list | tuple):
        raise ValueError("callsite push trace sources must be an array")
    return CallsitePushTrace8616(
        widths=_int_tuple_8616(record.get("widths"), "callsite push trace widths"),
        sources=tuple(
            _source_tuple_8616(source, "callsite push trace source")
            for source in sources_raw
        ),
        instruction_addrs=_int_tuple_8616(
            record.get("instruction_addrs"),
            "callsite push trace instruction addresses",
        ),
        predecessor_addr=_optional_int_8616(
            record.get("predecessor_addr"),
            "callsite push trace predecessor address",
        ),
    )


def _register_join_from_record_8616(value: object) -> CallsiteRegisterJoin8616 | None:
    """Decode one optional predecessor register join."""
    if value is None:
        return None
    record = _record_8616(value, "callsite register join")
    traces_raw = record.get("traces")
    if not isinstance(traces_raw, list | tuple):
        raise ValueError("callsite register join traces must be an array")
    traces = tuple(
        CallsiteRegisterJoinTrace8616(
            predecessor_addr=_int_8616(
                trace.get("predecessor_addr"),
                "callsite register join predecessor address",
            ),
            register=str(trace.get("register")),
            source=_source_tuple_8616(
                trace.get("source"),
                "callsite register join source",
            ),
        )
        for item in traces_raw
        for trace in (_record_8616(item, "callsite register join trace"),)
        if isinstance(trace.get("register"), str)
    )
    if len(traces) != len(traces_raw):
        raise ValueError("callsite register join trace register must be a string")
    return CallsiteRegisterJoin8616(
        register=str(record.get("register")),
        push_instruction_addr=_int_8616(
            record.get("push_instruction_addr"),
            "callsite register join push address",
        ),
        traces=traces,
        raw_fact_count=_int_8616(record.get("raw_fact_count"), "register join raw count"),
        normalized_fact_count=_int_8616(
            record.get("normalized_fact_count"), "register join normalized count"
        ),
        classified_fact_count=_int_8616(
            record.get("classified_fact_count"), "register join classified count"
        ),
        materialized_count=_int_8616(
            record.get("materialized_count"), "register join materialized count"
        ),
        failure_count=_int_8616(
            record.get("failure_count"), "register join failure count"
        ),
    )


def _predecessor_merge_from_record_8616(
    value: object,
) -> CallsitePredecessorStackMerge8616 | None:
    """Decode one optional closed predecessor stack merge."""
    if value is None:
        return None
    record = _record_8616(value, "callsite predecessor merge")
    sources_raw = record.get("sources")
    alternatives_raw = record.get("alternative_instruction_addrs")
    traces_raw = record.get("traces")
    if not isinstance(sources_raw, list | tuple):
        raise ValueError("callsite predecessor sources must be an array")
    if not isinstance(alternatives_raw, list | tuple):
        raise ValueError("callsite predecessor alternatives must be an array")
    if not isinstance(traces_raw, list | tuple):
        raise ValueError("callsite predecessor traces must be an array")
    return CallsitePredecessorStackMerge8616(
        widths=_int_tuple_8616(record.get("widths"), "predecessor widths"),
        sources=tuple(
            _source_tuple_8616(source, "predecessor source")
            for source in sources_raw
        ),
        representative_instruction_addrs=_int_tuple_8616(
            record.get("representative_instruction_addrs"),
            "predecessor representative addresses",
        ),
        alternative_instruction_addrs=tuple(
            _int_tuple_8616(addresses, "predecessor alternative addresses")
            for addresses in alternatives_raw
        ),
        raw_fact_count=_int_8616(record.get("raw_fact_count"), "predecessor raw count"),
        normalized_fact_count=_int_8616(
            record.get("normalized_fact_count"), "predecessor normalized count"
        ),
        classified_fact_count=_int_8616(
            record.get("classified_fact_count"), "predecessor classified count"
        ),
        materialized_count=_int_8616(
            record.get("materialized_count"), "predecessor materialized count"
        ),
        failure_count=_int_8616(
            record.get("failure_count"), "predecessor failure count"
        ),
        register_join=_register_join_from_record_8616(record.get("register_join")),
        traces=tuple(_push_trace_from_record_8616(trace) for trace in traces_raw),
    )


def _address_break_from_record_8616(
    value: object,
) -> PartialRegisterAddressBreakEvidence8616 | None:
    """Decode one optional partial-register provenance break."""
    if value is None:
        return None
    record = _record_8616(value, "partial-register address break")
    carrier = record.get("carrier_register")
    written = record.get("written_register")
    if not isinstance(carrier, str) or not isinstance(written, str):
        raise ValueError("partial-register address break registers must be strings")
    evidence = PartialRegisterAddressBreakEvidence8616(
        push_instruction_addr=_int_8616(record.get("push_instruction_addr"), "break push address"),
        definition_instruction_addr=_int_8616(
            record.get("definition_instruction_addr"), "break definition address"
        ),
        carrier_register=carrier,
        written_register=written,
        immediate=_int_8616(record.get("immediate"), "break immediate"),
    )
    if not evidence.complete:
        raise ValueError("partial-register address break is incomplete")
    return evidence


def callsite_summary_record_8616(summary: CallsiteSummary8616) -> dict[str, object]:
    """Return a complete JSON-friendly record for one callsite summary."""
    if not isinstance(summary, CallsiteSummary8616):
        raise TypeError("callsite summary transport requires CallsiteSummary8616")
    return summary.to_dict()


def callsite_summary_from_record_8616(value: object) -> CallsiteSummary8616:
    """Decode one complete callsite summary without semantic reconstruction."""
    record = _record_8616(value, "callsite summary")
    expected_keys = {item.name for item in fields(CallsiteSummary8616)}
    if set(record) != expected_keys:
        raise ValueError("callsite summary record has an incompatible field set")
    sources_raw = record["push_arg_sources"]
    classes_raw = record["logical_arg_classes"]
    breaks_raw = record["push_arg_address_break_evidence"]
    destination_raw = record["return_store_destination"]
    if not isinstance(sources_raw, list | tuple):
        raise ValueError("callsite push sources must be an array")
    if not isinstance(classes_raw, list | tuple):
        raise ValueError("callsite logical argument classes must be an array")
    if not isinstance(breaks_raw, list | tuple):
        raise ValueError("callsite address-break evidence must be an array")
    destination: tuple[str, int] | None = None
    if destination_raw is not None:
        restored_destination = _tuple_value_from_record_8616(
            destination_raw, "callsite return-store destination"
        )
        if (
            not isinstance(restored_destination, tuple)
            or len(restored_destination) != 2
            or not isinstance(restored_destination[0], str)
            or not isinstance(restored_destination[1], int)
            or isinstance(restored_destination[1], bool)
        ):
            raise ValueError("callsite return-store destination is malformed")
        destination = (restored_destination[0], restored_destination[1])
    return_use_raw = record["return_use_kind"]
    return_use = (
        None
        if return_use_raw is None
        else CallsiteReturnUseKind8616(str(return_use_raw))
    )
    return CallsiteSummary8616(
        callsite_addr=_int_8616(record["callsite_addr"], "callsite address"),
        target_addr=_optional_int_8616(record["target_addr"], "callsite target"),
        return_addr=_optional_int_8616(record["return_addr"], "callsite return address"),
        kind=_optional_str_8616(record["kind"], "callsite kind"),
        arg_count=_optional_int_8616(record["arg_count"], "callsite argument count"),
        arg_widths=_int_tuple_8616(record["arg_widths"], "callsite argument widths"),
        stack_cleanup=_optional_int_8616(record["stack_cleanup"], "callsite cleanup"),
        return_register=_optional_str_8616(record["return_register"], "return register"),
        return_used=(
            None
            if record["return_used"] is None
            else record["return_used"]
            if isinstance(record["return_used"], bool)
            else _raise_bool_8616("callsite return-used")
        ),
        stack_probe_helper=(
            record["stack_probe_helper"]
            if isinstance(record["stack_probe_helper"], bool)
            else _raise_bool_8616("callsite stack-probe flag")
        ),
        stack_probe_allocation_size=_optional_int_8616(
            record["stack_probe_allocation_size"], "stack-probe allocation"
        ),
        helper_return_state=str(record["helper_return_state"]),
        helper_return_space=_optional_str_8616(record["helper_return_space"], "helper return space"),
        helper_return_width=_optional_int_8616(record["helper_return_width"], "helper return width"),
        helper_return_address_kind=str(record["helper_return_address_kind"]),
        return_shape=_optional_str_8616(record["return_shape"], "return shape"),
        push_arg_sources=tuple(
            _source_tuple_8616(source, "callsite push source") for source in sources_raw
        ),
        push_arg_instruction_addrs=_int_tuple_8616(
            record["push_arg_instruction_addrs"], "push instruction addresses"
        ),
        return_store_destination=destination,
        return_store_width=_optional_int_8616(record["return_store_width"], "return-store width"),
        target_source=_source_tuple_8616(record["target_source"], "callsite target source"),
        return_use_kind=return_use,
        logical_arg_widths=_int_tuple_8616(record["logical_arg_widths"], "logical argument widths"),
        logical_arg_classes=tuple(CallsiteArgumentClass8616(str(item)) for item in classes_raw),
        stack_cleanup_instruction_addr=_optional_int_8616(
            record["stack_cleanup_instruction_addr"], "cleanup instruction address"
        ),
        predecessor_stack_merge=_predecessor_merge_from_record_8616(
            record["predecessor_stack_merge"]
        ),
        return_store_instruction_addr=_optional_int_8616(
            record["return_store_instruction_addr"], "return-store instruction address"
        ),
        push_arg_address_break_evidence=tuple(
            _address_break_from_record_8616(item) for item in breaks_raw
        ),
    )


def _raise_bool_8616(label: str) -> bool:
    """Raise a consistent malformed-boolean error in expression contexts."""
    raise ValueError(f"{label} must be a boolean or null")
