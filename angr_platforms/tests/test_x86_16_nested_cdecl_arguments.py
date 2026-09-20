"""Caller cleanup of an inner call must not hide surviving outer arguments."""

from types import SimpleNamespace

import capstone
import pytest
from angr_platforms.X86_16 import callsite_summary as summary


@pytest.mark.parametrize("callee_cleanup,expected", [(0, (2, 2, 2)), (None, (2,)), (2, (2,))])
def test_nested_cdecl_cleanup_preserves_only_proven_outer_pushes(monkeypatch, callee_cleanup, expected):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    # Two outer arguments, one inner argument, inner call+cleanup, result push, outer call.
    instructions = tuple(decoder.disasm(bytes.fromhex("6a036a026a01e8000083c40250e8000083c406"), 0x1000))
    function = SimpleNamespace()
    monkeypatch.setattr(summary, "_callee_stack_cleanup_bytes_8616", lambda *_args: callee_cleanup)
    widths = summary._collect_push_args_before_call(function, instructions, 6, 6)
    addresses = summary._collect_push_arg_instruction_addrs_before_call(function, instructions, 6, 6)
    sources = summary._collect_push_arg_sources_before_call(function, instructions, 6, 6)
    assert widths == expected
    assert len(sources) == len(addresses) == len(expected)
    if len(expected) == 3:
        assert addresses == (0x1000, 0x1002, 0x100c)
        assert sources[:2] == (("imm", 3), ("imm", 2))
