"""Keep register displacement in the value, not in the SSA storage key."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa import build_x86_16_block_local_ssa
from angr_platforms.X86_16.ir.ssa_function import _value_key


@pytest.mark.parametrize("name", ["sp", "bp", "bx"])
@pytest.mark.parametrize("offset", [-4, 2])
@pytest.mark.parametrize("captured", [False, True])
def test_displaced_register_uses_its_actual_definition(name: str, offset: int, captured: bool) -> None:
    register = IRValue(MemSpace.REG, name=name, size=2)
    constant = IRValue(MemSpace.CONST, const=12, size=2)
    temporary = IRValue(MemSpace.TMP, name="t7", size=2, source_tmp=7)
    displaced = replace(register, offset=offset, expr=("Iop_Add16",), source_tmp=7 if captured else None)
    block = IRBlock(0x1000, instrs=(
        IRInstr("MOV", temporary, (register,)),
        IRInstr("MOV", register, (constant,)),
        IRInstr("MOV", temporary, (register,)),
        IRInstr("MOV", register, (constant,)),
        IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (displaced,)),
    ))
    result = build_x86_16_block_local_ssa(block)
    source = result.instrs[-1].args[0]
    expected_definition = result.instrs[1 if captured else 3].dst
    assert isinstance(source, IRValue)
    assert expected_definition is not None
    assert source.version == expected_definition.version
    assert source.offset == offset
    assert source.expr == displaced.expr
    assert source.source_tmp == displaced.source_tmp
    assert _value_key(source) == _value_key(expected_definition)


@pytest.mark.parametrize("space,name", [(MemSpace.SS, "bp"), (MemSpace.DS, None), (MemSpace.REG, None)])
def test_storage_offsets_without_named_register_identity_remain_distinct(space: MemSpace, name: str | None) -> None:
    first = IRValue(space, name=name, offset=0, size=2)
    second = replace(first, offset=2)
    assert _value_key(first) != _value_key(second)
