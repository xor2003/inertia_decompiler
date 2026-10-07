"""Keep address bases tied to the register read used by their VEX expression."""

import pytest
from inertia.ir.core import IRAddress, MemSpace
from inertia.ir.ssa_function import build_x86_16_function_ssa
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact


@pytest.mark.parametrize(("code", "expected"), [
    ("55c3", [(0x1000, 0, -2), (0x1000, 0, -1)]),
    ("54c3", [(0x1000, 0, -2), (0x1000, 0, -1)]),
    ("5550c3", [(0x1000, 0, -2), (0x1000, 0, -1), (0x1001, 1, -2), (0x1001, 1, -1)]),
    ("c8020002c3", [(0x1000, 0, offset) for offset in (-2, -1, -4, -3, -6, -5)]),
])
def test_stack_store_base_uses_captured_sp_not_post_decrement_sp(code, expected):
    artifact = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex(code)))
    actual = []
    for block in artifact.blocks:
        for instruction in block.instrs:
            if instruction.op != "STORE":
                continue
            address = instruction.args[0]
            assert isinstance(address, IRAddress) and address.space is MemSpace.SS
            assert len(address.base_values) == 1
            base = address.base_values[0]
            assert base.name == "sp" and base.offset == 0
            actual.append((instruction.addr, base.version, address.offset))
    assert actual == expected
