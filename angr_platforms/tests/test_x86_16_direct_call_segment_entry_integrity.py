"""Refuse segment-entry candidates with stale or conflicting IR effects."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import (
    build_x86_16_segment_stack_restore_artifact,
)
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    build_decoded_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.direct_call_segment_entry import (
    DirectCallSegmentEntryCandidate8616,
    DirectCallSegmentEntryVerdict8616,
    prove_x86_16_direct_call_segment_entry_8616,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

from inertia_decompiler.project_loading import _build_project_from_bytes


@pytest.mark.parametrize("fault", ["none", "missing-restore-write", "second-restore-write"])
def test_alias_restore_requires_one_matching_live_ir_write(fault: str) -> None:
    """A prior Alias relation cannot hide a missing or later DS destination."""
    # PUSH SS; POP DS; near CALL; RET. The final RET is the called body.
    project = _build_project_from_bytes(
        bytes.fromhex("16 1f e8 02 00 c3 90 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    caller = exact_function_range_boundary_8616(project, 0x1000, 0x1006)
    callee = exact_function_range_boundary_8616(project, 0x1007, 0x1008)
    assert caller is not None and callee is not None
    artifact = build_x86_16_ir_function_artifact(project, caller)
    alias = build_x86_16_segment_stack_restore_artifact(artifact)
    assert len(alias.restore_sources) == 1
    index = build_decoded_direct_callsite_index_8616(
        {(caller.addr, caller.addr + caller.size): tuple(
            instruction
            for block in caller.blocks
            for instruction in cast(Any, block).capstone.insns
        )},
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(
            project, instruction,
        ),
        instruction_address_resolver=lambda instruction: cast(Any, instruction).address,
    )
    first_block = artifact.blocks[0]
    instructions = list(first_block.instrs)
    restored_write = next(
        position for position, instruction in enumerate(instructions)
        if isinstance(instruction.dst, IRValue)
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name == "ds"
        and instruction.addr == 0x1001
    )
    if fault == "missing-restore-write":
        del instructions[restored_write]
    elif fault == "second-restore-write":
        instructions.insert(restored_write + 1, IRInstr(
            "MOV", IRValue(MemSpace.REG, name="ds", size=2),
            (IRValue(MemSpace.CONST, const=7, size=2),), addr=0x1001,
        ))
    altered = replace(
        artifact,
        blocks=(replace(first_block, instrs=tuple(instructions)), *artifact.blocks[1:]),
    )
    if fault == "none":
        # The accepted path binds the proved artifact and its Alias evidence
        # to the project's registered raw IR by object identity; the stale
        # evidence cases below still refuse before that gate.
        assert publish_function_ir_artifact_8616(project, altered).artifact is altered
        alias = build_x86_16_segment_stack_restore_artifact(altered)

    result = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(0x1000, 0x1002, 0x1007),
        caller_boundary=caller,
        callee_boundary=callee,
        artifact=altered,
        callsite_index=index,
        restore_sources=alias.restore_sources,
    )

    expected = (
        DirectCallSegmentEntryVerdict8616.PROVEN if fault == "none"
        else DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    )
    assert result.verdict is expected
    assert result.stats.closed
    if fault != "none":
        assert result.refusal is not None
        assert result.stats.classified_fact_count == result.stats.materialized_count == 0
        assert result.stats.failure_count == 1


@pytest.mark.parametrize("field", ["caller_start", "callsite_addr", "callee_addr"])
def test_boolean_is_not_an_exact_code_address(field: str) -> None:
    """Boolean values are not integer machine-code identities."""
    arguments = {"caller_start": 0x1000, "callsite_addr": 0x1002, "callee_addr": 0x1007}
    arguments[field] = True
    with pytest.raises(ValueError):
        DirectCallSegmentEntryCandidate8616(**arguments)
