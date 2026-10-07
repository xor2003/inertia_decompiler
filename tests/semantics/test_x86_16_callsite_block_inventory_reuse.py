"""Regression tests for Frontend-owned callsite block reuse."""

from types import SimpleNamespace

import pytest
import inertia.semantics.callsite_summary as callsite_summary

from inertia.semantics.callsite_summary_request import (
    CallsiteSummaryRequestCache8616,
)


def _instruction(address: int, mnemonic: str) -> SimpleNamespace:
    return SimpleNamespace(
        address=address,
        size=1,
        mnemonic=mnemonic,
        op_str="",
        operands=(),
    )


def test_callsite_lookup_reuses_one_exact_cfg_block() -> None:
    calls: list[int] = []
    instructions = (
        _instruction(0x1000, "nop"),
        _instruction(0x1001, "call"),
        _instruction(0x1002, "nop"),
        _instruction(0x1003, "call"),
    )

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> SimpleNamespace:
        del opt_level, num_inst
        calls.append(address)
        return SimpleNamespace(capstone=SimpleNamespace(insns=instructions))

    project = SimpleNamespace(
        factory=SimpleNamespace(block=decode_block),
        loader=SimpleNamespace(),
    )
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        project=project,
    )

    first = callsite_summary._block_insns_for_callsite(function, 0x1001)
    second = callsite_summary._block_insns_for_callsite(function, 0x1003)

    assert first == second == instructions
    assert calls == [0x1000]


def test_next_block_lookup_reuses_one_exact_cfg_block() -> None:
    calls: list[int] = []
    instructions = (_instruction(0x1010, "nop"),)

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> SimpleNamespace:
        del opt_level, num_inst
        calls.append(address)
        return SimpleNamespace(capstone=SimpleNamespace(insns=instructions))

    project = SimpleNamespace(
        factory=SimpleNamespace(block=decode_block),
        loader=SimpleNamespace(),
    )
    function = SimpleNamespace(
        block_addrs_set={0x1000, 0x1010},
        project=project,
    )

    first = callsite_summary._next_linear_block_insns(function, 0x1001)
    second = callsite_summary._next_linear_block_insns(function, 0x1002)

    assert first == second == instructions
    assert calls == [0x1010]


def test_direct_jump_follow_scan_reuses_one_exact_target_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    jump = _instruction(0x1000, "jmp")
    target_instructions = (_instruction(0x1010, "nop"),)

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> SimpleNamespace:
        del opt_level, num_inst
        calls.append(address)
        return SimpleNamespace(capstone=SimpleNamespace(insns=target_instructions))

    project = SimpleNamespace(
        factory=SimpleNamespace(block=decode_block),
        loader=SimpleNamespace(),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        callsite_summary,
        "_direct_jump_target_8616",
        lambda _instruction: 0x1010,
    )

    first = callsite_summary._extend_follow_insns_through_direct_jumps_8616(
        function,
        [jump],
    )
    second = callsite_summary._extend_follow_insns_through_direct_jumps_8616(
        function,
        [jump],
    )

    assert first == second == [jump, *target_instructions]
    assert calls == [0x1010]


def test_request_cache_reuses_callee_saved_frame_pushes_by_function_identity() -> None:
    calls = 0
    function = SimpleNamespace(addr=0x1000)
    cache = CallsiteSummaryRequestCache8616()

    def collect() -> frozenset[int]:
        nonlocal calls
        calls += 1
        return frozenset({0x1000, 0x1001})

    first = cache.callee_saved_frame_pushes(function, collect)
    second = cache.callee_saved_frame_pushes(function, collect)

    assert first is second
    assert calls == 1
    stats = cache.stats()
    assert stats.raw_fact_count == stats.materialized_count == 2
    assert stats.build_count == stats.reuse_count == 1


def test_frame_push_filter_uses_request_local_semantic_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    function = SimpleNamespace(addr=0x1000)
    cache = CallsiteSummaryRequestCache8616()

    def collect(_function: object) -> frozenset[int]:
        nonlocal calls
        calls += 1
        return frozenset({0x1000})

    monkeypatch.setattr(
        callsite_summary,
        "_callee_saved_frame_push_addresses_8616",
        collect,
    )

    first = callsite_summary._filter_callee_saved_frame_pushes_8616(
        function,
        callsite_addr=0x1004,
        widths=(2, 2),
        sources=(("reg", "bp"), ("imm", 7)),
        instruction_addrs=(0x1000, 0x1002),
        request_cache=cache,
    )
    second = callsite_summary._filter_callee_saved_frame_pushes_8616(
        function,
        callsite_addr=0x1004,
        widths=(2, 2),
        sources=(("reg", "bp"), ("imm", 7)),
        instruction_addrs=(0x1000, 0x1002),
        request_cache=cache,
    )

    assert first == second == ((2,), (("imm", 7),), (0x1002,))
    assert calls == 1
