from __future__ import annotations

import json

import pytest
from inertia.semantics.caller_return_use_contracts import (
    CallsiteReturnUseKind8616,
)
from inertia.semantics.callsite_summary import (
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
)
from inertia.semantics.callsite_summary_codec import (
    callsite_summary_from_record_8616,
    callsite_summary_record_8616,
)

from inertia.alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsitePushTrace8616,
    CallsiteRegisterJoin8616,
    CallsiteRegisterJoinTrace8616,
)
from inertia.alias.partial_register_address_break import (
    PartialRegisterAddressBreakEvidence8616,
)


def _complete_summary() -> CallsiteSummary8616:
    register_trace = CallsiteRegisterJoinTrace8616(0x1100, "ax", ("imm", 7))
    register_join = CallsiteRegisterJoin8616(
        register="ax",
        push_instruction_addr=0x1110,
        traces=(register_trace,),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
    push_trace = CallsitePushTrace8616(
        widths=(2,),
        sources=(("expr", ("bp", 4, 2), (("add", 1),)),),
        instruction_addrs=(0x1110,),
        predecessor_addr=0x1100,
    )
    predecessor = CallsitePredecessorStackMerge8616(
        widths=(2,),
        sources=(("expr", ("bp", 4, 2), (("add", 1),)),),
        representative_instruction_addrs=(0x1110,),
        alternative_instruction_addrs=((0x1110, 0x1120),),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        register_join=register_join,
        traces=(push_trace,),
    )
    address_break = PartialRegisterAddressBreakEvidence8616(
        push_instruction_addr=0x1110,
        definition_instruction_addr=0x110F,
        carrier_register="ax",
        written_register="al",
        immediate=0x12,
    )
    return CallsiteSummary8616(
        callsite_addr=0x1130,
        target_addr=0x2200,
        return_addr=0x1133,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        stack_probe_helper=False,
        stack_probe_allocation_size=None,
        helper_return_state="value",
        helper_return_space="near",
        helper_return_width=2,
        helper_return_address_kind="offset",
        return_shape="ax",
        push_arg_sources=(("expr", ("bp", 4, 2), (("add", 1),)),),
        push_arg_instruction_addrs=(0x1110,),
        return_store_destination=("ss", 8),
        return_store_width=2,
        target_source=("imm", 0x2200),
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
        logical_arg_widths=(2,),
        logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
        stack_cleanup_instruction_addr=0x1133,
        predecessor_stack_merge=predecessor,
        return_store_instruction_addr=0x1135,
        push_arg_address_break_evidence=(address_break,),
    )


def test_callsite_summary_codec_round_trips_every_owned_field_through_json() -> None:
    summary = _complete_summary()
    record = callsite_summary_record_8616(summary)
    decoded_json = json.loads(json.dumps(record, sort_keys=True))

    restored = callsite_summary_from_record_8616(decoded_json)

    assert callsite_summary_record_8616(restored) == record


def test_callsite_summary_codec_rejects_incompatible_field_set() -> None:
    record = callsite_summary_record_8616(_complete_summary())
    del record["arg_widths"]

    with pytest.raises(ValueError, match="field set"):
        callsite_summary_from_record_8616(record)


def test_callsite_summary_codec_rejects_incomplete_partial_register_evidence() -> None:
    record = callsite_summary_record_8616(_complete_summary())
    breaks = record["push_arg_address_break_evidence"]
    assert isinstance(breaks, tuple)
    broken = dict(breaks[0])
    broken["definition_instruction_addr"] = 0x1110
    record["push_arg_address_break_evidence"] = (broken,)

    with pytest.raises(ValueError, match="incomplete"):
        callsite_summary_from_record_8616(record)
