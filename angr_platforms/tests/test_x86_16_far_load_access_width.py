"""Require decoded far-load access widths to include the segment word."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.calling_convention_compat import collect_bp_word_stack_access_offsets_8616
from angr_platforms.X86_16.widening.widening_rules import (
    collect_bp_stack_access_widths_from_instructions_8616,
)
from capstone import CS_ARCH_X86, CS_MODE_16, Cs


@pytest.mark.parametrize("opcode", ["c4", "c5", "0f b2", "0f b4", "0f b5"])
@pytest.mark.parametrize("prefix, expected_width", [("", 4), ("66", 6)])
@pytest.mark.parametrize("route", ["summary", "fallback"])
def test_far_load_stack_access_includes_segment(opcode, prefix, expected_width, route):
    code = bytes.fromhex(f"{prefix} {opcode} 46 04")
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(decoder.disasm(code, 0x4010))))
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=None),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda addr, size: code[:size] if route == "summary" else b"")),
        factory=SimpleNamespace(block=lambda addr, opt_level: block),
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010, size=len(code), name="load"))

    assert collect_bp_stack_access_widths_from_instructions_8616(project, codegen) == {4: expected_width}


@pytest.mark.parametrize("raw", ["26 c4 46 04", "3e c4 46 04", "c4 42 04", "c4 43 04"])
def test_abi_far_load_refuses_nonstack_or_indexed_storage(raw):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instructions = tuple(decoder.disasm(bytes.fromhex(raw), 0x4010))
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda addr, opt_level: block))
    function = SimpleNamespace(block_addrs_set={0x4010})
    assert collect_bp_word_stack_access_offsets_8616(project, function) == ()
