from __future__ import annotations

from inertia.alias.callsite_stack_merge import (
    CallsitePushTrace8616,
    CallsiteRegisterJoinTrace8616,
    merge_callsite_predecessor_stack_traces_8616,
    merge_callsite_register_join_traces_8616,
)


def test_callsite_stack_merge_keeps_common_width_and_source() -> None:
    traces = (
        CallsitePushTrace8616((2,), (("imm", 5),), (0x101E,), predecessor_addr=0x1000),
        CallsitePushTrace8616((2,), (("imm", 5),), (0x1027,), predecessor_addr=0x1020),
    )
    result = merge_callsite_predecessor_stack_traces_8616(traces)

    assert result is not None
    assert result.widths == (2,)
    assert result.sources == (("imm", 5),)
    assert result.representative_instruction_addrs == (0x101E,)
    assert result.alternative_instruction_addrs == ((0x101E, 0x1027),)
    assert result.traces == traces
    assert result.materialized_count == 1


def test_callsite_stack_merge_keeps_differing_values_unknown() -> None:
    result = merge_callsite_predecessor_stack_traces_8616(
        (
            CallsitePushTrace8616((2,), (("imm", 1),), (0x2000,)),
            CallsitePushTrace8616((2,), (("imm", 2),), (0x2010,)),
        )
    )

    assert result is not None
    assert result.widths == (2,)
    assert result.sources == (None,)


def test_callsite_stack_merge_refuses_different_physical_widths() -> None:
    result = merge_callsite_predecessor_stack_traces_8616(
        (
            CallsitePushTrace8616((2,), (("imm", 1),), (0x2000,)),
            CallsitePushTrace8616((4,), (("imm", 1),), (0x2010,)),
        )
    )

    assert result is None


def test_callsite_register_join_keeps_path_indexed_sources() -> None:
    result = merge_callsite_register_join_traces_8616(
        (
            CallsiteRegisterJoinTrace8616(0x101B, "ax", ("imm", 0x7002)),
            CallsiteRegisterJoinTrace8616(0x1024, "ax", ("imm", 0x7004)),
        ),
        push_instruction_addr=0x102B,
    )

    assert result is not None
    assert result.register == "ax"
    assert result.push_instruction_addr == 0x102B
    assert tuple(trace.source for trace in result.traces) == (("imm", 0x7002), ("imm", 0x7004))
    assert result.classified_fact_count == result.materialized_count == 1


def test_callsite_register_join_refuses_missing_predecessor_source() -> None:
    result = merge_callsite_register_join_traces_8616(
        (
            CallsiteRegisterJoinTrace8616(0x101B, "ax", ("imm", 1)),
            CallsiteRegisterJoinTrace8616(0x1024, "ax", None),
        ),
        push_instruction_addr=0x102B,
    )

    assert result is None
