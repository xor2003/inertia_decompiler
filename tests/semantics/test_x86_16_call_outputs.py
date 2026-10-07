"""Tests for exact Semantics-owned CALL output definitions."""

from __future__ import annotations

from dataclasses import replace

import inertia.semantics.caller_return_use_contracts as caller_return_use_contracts
import inertia.semantics.callsite_summary as callsite_summary
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir import (
    IRAddress,
    IRBlock,
    IRCallOutputProvenance8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
    empty_ir_logical_memory_artifact_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa

from inertia.semantics.call_output_contracts import (
    CallOutputFailure8616,
    CallOutputShape8616,
)
from inertia.semantics.call_outputs import materialize_call_outputs_8616


def test_callsite_summary_exports_authoritative_return_use_kind() -> None:
    """Keep compatibility imports bound to the owned caller-use enum."""
    assert "CallsiteReturnUseKind8616" in callsite_summary.__all__
    assert callsite_summary.CallsiteReturnUseKind8616 is caller_return_use_contracts.CallsiteReturnUseKind8616


def _artifact(*, extra_predecessor: bool = False) -> IRFunctionArtifact:
    blocks = [
        IRBlock(
            0x1000,
            (
                IRInstr(
                    "CALL",
                    None,
                    (IRValue(MemSpace.CONST, const=0x2000, size=2),),
                    addr=0x1003,
                ),
            ),
            successor_addrs=(0x1006,),
        ),
        IRBlock(
            0x1006,
            (
                IRInstr(
                    "MOV",
                    IRValue(MemSpace.TMP, name="t0", size=2, source_tmp=0),
                    (IRValue(MemSpace.REG, name="ax", size=2),),
                    size=2,
                    addr=0x1006,
                ),
            ),
        ),
    ]
    if extra_predecessor:
        blocks.append(IRBlock(0x1010, successor_addrs=(0x1006,)))
    return IRFunctionArtifact(0x1000, tuple(blocks))


def _summary(*, used: bool | None = True, shape: str | None = "dx_ax") -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1003,
        target_addr=0x2000,
        return_addr=0x1006,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=used,
        return_shape=shape,
    )


def test_dx_ax_call_outputs_are_definitions_on_exact_return_edge() -> None:
    result = materialize_call_outputs_8616(_artifact(), {0x1003: _summary()})

    assert result.complete is True
    assert result.facts[0].shape is CallOutputShape8616.DX_AX
    return_block = next(block for block in result.function.blocks if block.addr == 0x1006)
    assert [(instruction.op, instruction.dst.name) for instruction in return_block.instrs[:2]] == [
        ("CALL_OUTPUT", "ax"),
        ("CALL_OUTPUT", "dx"),
    ]
    ssa = build_x86_16_function_ssa(result.function)
    ssa_return = next(block for block in ssa.blocks if block.addr == 0x1006)
    assert [(binding.target.name, binding.version) for binding in ssa_return.bindings[:2]] == [
        ("ax", 0),
        ("dx", 0),
    ]
    mov_source = ssa_return.instrs[2].args[0]
    assert isinstance(mov_source, IRValue)
    assert mov_source.version == 0
    expected_provenance = IRCallOutputProvenance8616(
        callsite_addr=0x1003,
        target_addr=0x2000,
        shape=CallOutputShape8616.DX_AX,
    )
    assert all(
        instruction.dst is not None and instruction.dst.call_output == expected_provenance
        for instruction in ssa_return.instrs[:2]
    )
    assert mov_source.call_output == expected_provenance


def test_call_output_projection_preserves_logical_memory_artifact() -> None:
    marker = empty_ir_logical_memory_artifact_8616(0x1000)
    evidence = object()
    source = replace(_artifact(), logical_memory=marker, summary={"prior_evidence": evidence})

    result = materialize_call_outputs_8616(source, {0x1003: _summary()})

    assert result.function.logical_memory is marker
    assert source.summary == {"prior_evidence": evidence}
    assert result.function.summary == {
        "prior_evidence": evidence,
        "call_output_raw_fact_count": 1,
        "call_output_normalized_fact_count": 1,
        "call_output_classified_fact_count": 1,
        "call_output_materialized_count": 1,
        "call_output_failure_count": 0,
    }


def test_call_output_projection_rebases_logical_memory_execution_slice() -> None:
    address = IRAddress(MemSpace.SS, base=("bp",), offset=4, size=1)
    source = _artifact()
    return_block = next(block for block in source.blocks if block.addr == 0x1006)
    load = IRInstr(
        "LOAD",
        IRValue(MemSpace.TMP, name="t0", size=1, source_tmp=0),
        (address,),
        size=1,
        addr=0x1006,
    )
    source = replace(
        source,
        blocks=tuple(
            replace(block, instrs=(load, *block.instrs))
            if block is return_block
            else block
            for block in source.blocks
        ),
        logical_memory=replace(
            empty_ir_logical_memory_artifact_8616(0x1000),
            accesses=(
                IRLogicalMemoryAccess8616(
                    IRLogicalMemoryAccessKey8616(0x1000, 0x1006, 0x1006, 0),
                    IRMemoryAccessKind8616.READ,
                    address,
                    16,
                    (IRMemoryExecutionSlice8616(0x1006, 0, 0x1006, 0, address),),
                ),
            ),
            stats=IRLogicalMemoryStats8616(1, 1, 1, 1, 0),
        ),
    )

    result = materialize_call_outputs_8616(source, {0x1003: _summary()})

    logical_memory = result.function.logical_memory
    assert logical_memory is not None and logical_memory.closed
    assert logical_memory.accesses[0].execution_slices[0].instr_index == 2
    return_block = next(block for block in result.function.blocks if block.addr == 0x1006)
    assert return_block.instrs[2] is load


def test_call_output_refuses_return_block_with_bypass_predecessor() -> None:
    result = materialize_call_outputs_8616(
        _artifact(extra_predecessor=True),
        {0x1003: _summary()},
    )

    assert result.complete is False
    assert result.facts[0].failure is CallOutputFailure8616.RETURN_BLOCK_HAS_OTHER_PREDECESSOR
    return_block = next(block for block in result.function.blocks if block.addr == 0x1006)
    assert all(instruction.op != "CALL_OUTPUT" for instruction in return_block.instrs)


def test_known_unused_call_has_no_output_definitions() -> None:
    result = materialize_call_outputs_8616(
        _artifact(),
        {0x1003: _summary(used=False, shape=None)},
    )

    assert result.complete is True
    assert result.facts[0].outputs == ()
    assert all(
        instruction.op != "CALL_OUTPUT"
        for block in result.function.blocks
        for instruction in block.instrs
    )
