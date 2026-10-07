"""Regression coverage for Structuring-owned switch loop-exit evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.loop_body_repair import (
    recover_switch_loop_exit_return_evidence_8616,
)


@pytest.mark.parametrize(("function_size", "expected_count"), ((15, 1), (8, 0)))
def test_switch_exit_evidence_reads_shared_epilogue_but_keeps_targets_in_function(
    function_size: int,
    expected_count: int,
) -> None:
    """Allow a tail RET read without accepting case targets past the function."""
    base_addr = 0x4010
    code = bytes.fromhex("2d1b007503eb029090eb0390909090c3")
    memory = SimpleNamespace(
        load=lambda addr, size: code[addr - base_addr : addr - base_addr + size],
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=memory),
    )
    function = SimpleNamespace(addr=base_addr, size=function_size)

    evidence = recover_switch_loop_exit_return_evidence_8616(project, function)

    assert len(evidence) == expected_count
    if evidence:
        assert evidence[0].case_value == 27
        assert evidence[0].case_target == 0x4019
        assert evidence[0].exit_target == 0x401E
