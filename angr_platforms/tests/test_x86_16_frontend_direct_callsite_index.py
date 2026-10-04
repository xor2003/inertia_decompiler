"""Tests for the request-owned decoded direct-call index."""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedFarCallTarget8616,
    build_decoded_direct_callsite_index_8616,
)


@dataclass(frozen=True, slots=True)
class _Instruction:
    target: int | None
    address: int | None


def test_direct_callsite_index_scans_once_and_normalizes_16_bit_targets() -> None:
    resolver_calls: list[_Instruction] = []
    address_calls: list[_Instruction] = []
    first = _Instruction(0x12345, 0x1010)
    invalid = _Instruction(0x2345, None)
    non_call = _Instruction(None, 0x1012)
    second = _Instruction(0x2345, 0x2010)
    decoded_ranges = {
        (0x2000, 0x2020): (second,),
        (0x1000, 0x1020): (first, invalid, non_call),
    }

    def resolve_target(instruction: object) -> int | None:
        typed = instruction
        assert isinstance(typed, _Instruction)
        resolver_calls.append(typed)
        return typed.target

    def resolve_address(instruction: object) -> int | None:
        typed = instruction
        assert isinstance(typed, _Instruction)
        address_calls.append(typed)
        return typed.address

    index = build_decoded_direct_callsite_index_8616(
        decoded_ranges,
        direct_target_resolver=resolve_target,
        instruction_address_resolver=resolve_address,
    )

    assert resolver_calls == [first, invalid, non_call, second]
    assert address_calls == [first, invalid, second]
    assert index.for_target(0x2345) == index.for_target(0x12345)
    assert tuple(callsite.callsite_addr for callsite in index.for_target(0x2345)) == (
        0x1010,
        0x2010,
    )
    assert index.stats.raw_fact_count == 3
    assert index.stats.normalized_fact_count == 3
    assert index.stats.classified_fact_count == 2
    assert index.stats.materialized_count == 2
    assert index.stats.failure_count == 1
    assert index.stats.closed is True


def test_direct_callsite_index_returns_empty_for_unknown_target() -> None:
    index = build_decoded_direct_callsite_index_8616(
        {},
        direct_target_resolver=lambda _instruction: None,
        instruction_address_resolver=lambda _instruction: None,
    )

    assert index.for_target(0xBEEF) == ()
    assert index.stats.closed is True


@pytest.mark.parametrize("corruption", (None, "missing_block", "duplicate_block", "missing_instruction", "unknown_address"))
def test_boundary_index_requires_the_exact_reachable_census(corruption: str | None) -> None:
    """Boundary indexing cannot silently become a linear-range instruction scan."""
    from angr_platforms.X86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
    from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

    first = _Instruction(0x2000, 0x1000)
    second = _Instruction(None, 0x1003)
    block = SimpleNamespace(addr=0x1000, capstone=SimpleNamespace(insns=(first, second)))
    boundary = ExactFunctionRangeBoundary8616(object(), 0x1000, 4,
        frozenset({0x1000}), frozenset({0x1000, 0x1003}), (), (block,))
    if corruption == "missing_block":
        boundary = replace(boundary, blocks=())
    elif corruption == "duplicate_block":
        boundary = replace(boundary, blocks=(block, block))
    elif corruption == "missing_instruction":
        block.capstone.insns = (first,)
    elif corruption == "unknown_address":
        block.capstone.insns = (first, replace(second, address=None))
    if corruption is not None:
        with pytest.raises(ValueError, match="boundary"):
            build_boundary_direct_callsite_index_8616(boundary,
                direct_target_resolver=lambda instruction: instruction.target)
    else:
        index = build_boundary_direct_callsite_index_8616(boundary,
            direct_target_resolver=lambda instruction: instruction.target)
        entry, = index.for_target(0x2000)
        assert entry.callsite_addr == 0x1000 and entry.caller_start == boundary.addr
        assert entry.instructions == (first, second)
        assert index.stats.closed and index.stats.failure_count == 0


def test_far_callsite_targets_do_not_alias_on_low_sixteen_bits() -> None:
    first = _Instruction(0x11013, 0x1010)
    second = _Instruction(0x21013, 0x2010)
    index = build_decoded_direct_callsite_index_8616(
        {(0x1000, 0x1020): (first,), (0x2000, 0x2020): (second,)},
        direct_target_resolver=lambda instruction: DecodedFarCallTarget8616(instruction.target),
        instruction_address_resolver=lambda instruction: instruction.address,
    )

    assert tuple(item.callsite_addr for item in index.for_target(0x11013)) == (0x1010,)
    assert tuple(item.callsite_addr for item in index.for_target(0x21013)) == (0x2010,)
    assert index.for_target(0x1013) == ()
    assert index.stats.closed


def test_near_low_word_call_does_not_pollute_exact_far_target() -> None:
    near = _Instruction(0x1013, 0x3010)
    far = _Instruction(0x11013, 0x4010)
    index = build_decoded_direct_callsite_index_8616(
        {(0x3000, 0x3020): (near,), (0x4000, 0x4020): (far,)},
        direct_target_resolver=lambda instruction: (
            DecodedFarCallTarget8616(instruction.target)
            if instruction is far else instruction.target
        ),
        instruction_address_resolver=lambda instruction: instruction.address,
    )

    assert tuple(item.callsite_addr for item in index.for_target(0x11013)) == (0x4010,)
    assert tuple(item.callsite_addr for item in index.for_target(0x1013)) == (0x3010,)
    assert index.target_identity(0x11013) == 0x11013
    assert index.stats.closed
