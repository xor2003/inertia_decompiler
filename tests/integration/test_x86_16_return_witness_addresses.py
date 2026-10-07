"""Exact instruction-address requirements at the return materialization boundary."""

from dataclasses import replace

import pytest
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.ir import IRInstr, IRValue, MemSpace
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.interprocedural_storage_return_trial_materialization import (
    _witness_use_8616,
    return_output_storages_8616,
)
from inertia.lowering.interprocedural_storage_return_types import (
    classify_return_storage_type_8616,
)

from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616


@pytest.mark.parametrize(
    ("witness", "addresses", "accepted", "conflict"),
    [
        (None, (None,), False, False),
        (None, (0x1003,), False, False),
        (0x1003, (None,), False, False),
        (0x1003, (None, 0x1003), True, False),
        (0, (0,), True, False),
        (0x1003, (0x1003, 0x1003), False, True),
    ],
)
def test_scalar_witness_requires_unique_concrete_instruction_address(
    witness: int | None,
    addresses: tuple[int | None, ...],
    accepted: bool,
    conflict: bool,
) -> None:
    fact = CallerReturnUseFact8616(
        caller_addr=0x1000,
        callsite_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.CONDITION,
        witness_instruction_addr=0x1003,
    )
    value = IRValue(space=MemSpace.REG, name="ax", size=2, version=1)
    condition = ConditionIR(
        op="slt", lhs=value,
        rhs=IRValue(space=MemSpace.CONST, const=0, size=2),
        width_bits=16, src_insn=0x1006, producer_insn=0x1003,
    )
    storages = return_output_storages_8616(TerminalReturnStorage8616.AX)
    classification = classify_return_storage_type_8616(fact, storages, (condition,))
    assert classification.complete
    artifact = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(SSABlock(
            addr=0x1000, bindings=(),
            instrs=tuple(IRInstr(op="CMP", dst=None, args=(value,), size=2, addr=addr) for addr in addresses),
        ),),
    )

    uses, conflicting = _witness_use_8616(
        artifact, replace(fact, witness_instruction_addr=witness), classification, storages,
    )

    assert conflicting is conflict
    assert (uses is not None) is accepted
    if uses is not None:
        assert len(uses) == 1
        assert uses[0].is_complete
        assert uses[0].instr_addr == witness
        assert uses[0].instr_index == addresses.index(witness)
