"""Runtime register projections retain instruction provenance and update timing."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_expr_8616
from angr_platforms.X86_16.structuring.condition_lowering import materialize_same_block_register_projection_8616
from test_x86_16_structuring_condition_materialization import _Codegen

WORD_MASK = 0xFFFF

@pytest.mark.parametrize("tag_type", [dict, Tags])
@pytest.mark.parametrize("invalid_evidence", [None, "ordinary_memory", "different_block", "later_write"])
def test_runtime_counter_condition_reads_stored_value(tag_type, invalid_evidence):
    """Read the updated low word once, with genuine tags and owned storage only."""
    codegen = _Codegen()
    destination = runtime_gp_state_expr_8616("ecx", codegen=codegen, function_addr=0x1000)
    if invalid_evidence == "ordinary_memory":
        destination.variable.category = None
    update = CAssignment(
        destination,
        CBinaryOp("Sub", destination, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
        tags=tag_type({
            "ins_addr": 0x100D if invalid_evidence == "later_write" else 0x100B,
            "vex_block_addr": 0x1003 if invalid_evidence == "different_block" else 0x1008,
        }),
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=CStatements([update], codegen=codegen))
    operand = IRValue(MemSpace.REG, name="cx", offset=4, size=2)
    condition = ConditionIR(
        op="nonzero", lhs=operand, rhs=None, width_bits=16,
        source=("test", "jne"), src_insn=0x100C, block_addr=0x1008,
        producer_insn=0x100B, operand_bind_insn=0x100C,
        taken_target=0x1003, fallthrough_target=0x100E,
        producer_semantics=("dec_reg16", "cx", 1),
    )
    result = materialize_same_block_register_projection_8616(operand, condition, codegen.project, codegen)
    if invalid_evidence is not None:
        assert result.expression is None
        return
    expression = result.expression
    assert isinstance(expression, CBinaryOp)
    assert expression.op == "And"
    assert expression.lhs is destination
    assert expression.lhs is not update.rhs
    assert expression.rhs.value == WORD_MASK
    assert result.stats.materialized_count == 1
