"""Decoded complements preserve argument-value provenance and push accounting."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import callsite_summary as summaries
from angr_platforms.X86_16.analysis_helpers import CallTargetSeed
from capstone import CS_ARCH_X86, CS_MODE_16, Cs


def _instructions(code):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    return tuple(decoder.disasm(bytes.fromhex(code), 0x1000))


@pytest.mark.parametrize(("code", "register", "mask"), [
    ("b8 34 12 f7 d0 50", "ax", 0xffff),
    ("66 b8 34 12 00 00 66 f7 d0 66 50", "eax", 0xffffffff),
])
def test_register_complement_source(code, register, mask):
    instructions = _instructions(code)
    assert summaries._register_source_from_context_8616(instructions, len(instructions) - 1, register) == (
        "expr", ("imm", 0x1234), (("xor", mask),),
    )


def test_complement_does_not_hide_earlier_push(monkeypatch):
    instructions = _instructions("6a 01 b8 34 12 f7 d0 50 e8 00 00 83 c4 04")
    call = instructions[-2]
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    function = SimpleNamespace(project=SimpleNamespace(
        arch=SimpleNamespace(name="86_16"), factory=SimpleNamespace(block=lambda *args, **kwargs: block),
    ))
    monkeypatch.setattr(summaries, "collect_neighbor_call_targets", lambda function: [
        CallTargetSeed(call.address, 0x2000, call.address + call.size, "direct_near"),
    ])
    summary = summaries.summarize_x86_16_callsite(function, call.address)
    assert summary.arg_count == 2
    assert summary.push_arg_sources == (
        ("imm", 1), ("expr", ("imm", 0x1234), (("xor", 0xffff),)),
    )


@pytest.mark.parametrize("code", ["f7 d4", "f7 d5", "f7 16 00 20"])
def test_stack_frame_or_memory_complement_is_not_transparent(code):
    assert not summaries._transparent_between_push_args_8616(_instructions(code)[0])
