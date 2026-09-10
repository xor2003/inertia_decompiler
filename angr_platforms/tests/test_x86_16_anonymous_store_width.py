"""Do not materialize each byte projection as an entire machine word store."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CFunctionCall, CStatements, CUnaryOp
from angr.sim_type import SimTypeChar
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    DirectSegmentedGlobalStoreEvidence8616,
    SegmentedGlobalLoadStats8616,
    materialize_direct_global_symbol_stores_from_evidence_8616,
)
from test_x86_16_segmented_global_loads import _const, _deref, _DummyCodegen

BYTE_BITS = 8

@pytest.mark.parametrize("value", [0, 0xFF, 0xFF00, 0xFFFF])
@pytest.mark.parametrize("complete_pair", [False, True])
def test_byte_projection_cannot_independently_materialize_word(value: int, complete_pair: bool) -> None:
    codegen = _DummyCodegen()
    project = SimpleNamespace(arch=Arch86_16())
    instruction = 0x1020
    low = CAssignment(_deref(_const(0x417, codegen), codegen), _const(value & 0xFF, codegen),
                      codegen=codegen, tags={"ins_addr": instruction})
    high = CAssignment(_deref(_const(0x418, codegen), codegen), _const(value >> 8, codegen),
                       codegen=codegen, tags={"ins_addr": instruction})
    low.lhs._type = high.lhs._type = SimTypeChar(False).with_arch(project.arch)
    root = CStatements([low, high] if complete_pair else [low], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    evidence = DirectSegmentedGlobalStoreEvidence8616(0x417, 2, MemSpace.ES, instruction, value, 0)
    stats = SegmentedGlobalLoadStats8616()
    materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen, (), anonymous_direct_stores=(evidence,), project=project, stats=stats,
    )
    assert len(root.statements) == 1
    assignment = root.statements[0]
    if complete_pair:
        assert isinstance(assignment.lhs, CFunctionCall)
        assert assignment.lhs.callee_target == "SEG_U16"
        assert assignment.rhs.value == value
        assert stats.anonymous_direct_store_materialized_count == 1
    else:
        assert assignment is low
        assert isinstance(assignment.lhs, CUnaryOp)
        assert assignment.lhs.type.size == BYTE_BITS
        assert assignment.rhs.value == value & 0xFF
        assert stats.anonymous_direct_store_materialized_count == 0
