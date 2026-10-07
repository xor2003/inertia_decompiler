from __future__ import annotations

from dataclasses import replace

import pytest
from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    ScalarAffineFailure8616,
    SegmentOrigin,
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
    trace_scalar_affine_expression_8616,
)
from inertia.ir.scalar_affine_contracts import ScalarAffineEntryRegister8616
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact


def _artifact(operation: str = "Iop_Add16") -> SSAFunctionArtifact:
    source = IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    loaded = IRValue(MemSpace.TMP, name="loaded", size=2)
    shifted = IRValue(MemSpace.TMP, name="shifted", size=2)
    result = IRValue(MemSpace.TMP, name="result", size=2)
    return build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    (
                        IRInstr("LOAD", loaded, (source,), 2, 0x1000),
                        IRInstr(
                            "Iop_Shl16",
                            shifted,
                            (loaded, IRValue(MemSpace.CONST, const=1, size=2)),
                            2,
                            0x1002,
                        ),
                        IRInstr(
                            operation,
                            result,
                            (shifted, IRValue(MemSpace.CONST, const=0x0B4C, size=2)),
                            2,
                            0x1004,
                        ),
                    ),
                ),
            ),
        )
    )


def test_affine_trace_retains_stack_term_scale_constant_and_path() -> None:
    artifact = _artifact()
    block = artifact.blocks[0]
    root = block.instrs[-1].dst
    assert root is not None

    trace = trace_scalar_affine_expression_8616(
        artifact,
        root,
        block_addr=block.addr,
        before_index=len(block.instrs),
    )

    assert trace.complete
    assert trace.failure is None
    expression = trace.expression
    assert expression is not None
    assert expression.constant == 0x0B4C
    assert len(expression.terms) == 1
    assert expression.terms[0].source.offset == -2
    assert expression.terms[0].coefficient == 2
    assert tuple(site.op for site in expression.definition_path) == (
        "Iop_Add16",
        "Iop_Shl16",
        "LOAD",
    )


def test_non_affine_operation_refuses_without_partial_expression() -> None:
    artifact = _artifact("Iop_Xor16")
    block = artifact.blocks[0]
    root = block.instrs[-1].dst
    assert root is not None

    trace = trace_scalar_affine_expression_8616(
        artifact,
        root,
        block_addr=block.addr,
        before_index=len(block.instrs),
    )

    assert not trace.complete
    assert trace.expression is None
    assert trace.failure is ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED


@pytest.mark.parametrize("name", ["sp", "bp"])
def test_entry_register_root_requires_explicit_opt_in(name):
    artifact = _artifact()
    root = IRValue(MemSpace.REG, name=name, size=2, version=0)
    kwargs = {"block_addr": artifact.function_addr, "before_index": 0}
    assert not trace_scalar_affine_expression_8616(artifact, root, **kwargs).complete
    trace = trace_scalar_affine_expression_8616(artifact, root, **kwargs, allow_entry_registers=True)
    assert trace.complete
    assert trace.expression.terms[0].source == ScalarAffineEntryRegister8616(0x1000, name, 2)


@pytest.mark.parametrize("changes", [
    {"name": "ax"}, {"version": 1}, {"offset": 2}, {"source_tmp": 123},
    {"size": 4}, {"space": MemSpace.TMP}, {"index": "ax"},
])
def test_entry_register_refuses_inexact_roots(changes):
    root = replace(IRValue(MemSpace.REG, name="sp", size=2, version=0), **changes)
    trace = trace_scalar_affine_expression_8616(
        _artifact(), root, block_addr=0x1000, before_index=0, allow_entry_registers=True,
    )
    assert not trace.complete
    assert trace.expression is None


@pytest.mark.parametrize("block_addr,predecessors", [(0x1002, {}), (0x1000, {0x1000: (0x1002,)})])
def test_block_local_live_in_is_not_necessarily_function_entry(block_addr, predecessors):
    artifact = replace(_artifact(), predecessor_map=predecessors)
    trace = trace_scalar_affine_expression_8616(
        artifact, IRValue(MemSpace.REG, name="sp", size=2, version=0),
        block_addr=block_addr, before_index=0, allow_entry_registers=True,
    )
    assert not trace.complete


def test_machine_frame_value_retains_entry_sp_and_modular_displacement():
    artifact = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex("5589e583ec028d46fec3")))
    block = artifact.blocks[0]
    index, instruction = next(
        (index, instruction) for index, instruction in enumerate(block.instrs)
        if instruction.dst is not None and instruction.dst.name == "ax"
    )
    trace = trace_scalar_affine_expression_8616(
        artifact, instruction.dst, block_addr=block.addr, before_index=index + 1, allow_entry_registers=True,
    )
    assert trace.complete
    expression = trace.expression
    assert expression.constant == 0xfffc
    assert len(expression.terms) == 1
    term = expression.terms[0]
    assert term.source == ScalarAffineEntryRegister8616(artifact.function_addr, "sp", 2)
    assert term.coefficient == 1
    for entry_sp in (0, 1, 0x1000, 0xffff):
        assert (entry_sp * term.coefficient + expression.constant) & 0xffff == (entry_sp - 4) & 0xffff
