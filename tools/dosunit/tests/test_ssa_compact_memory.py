"""Compact stack projection preserves holes, wrapping bytes and public effects."""

import pytest
import z3

from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation, _observe
from tools.dosunit.ssa.z3_ops import _z3_store

pytestmark = pytest.mark.ssa_z3


@pytest.mark.parametrize("base", [0x70000, 0xFFFFFFF0])
@pytest.mark.parametrize("byte", [0, 173])
@pytest.mark.parametrize("little", [True, False])
def test_long_constant_fill_matches_every_byte(base, byte, little):
    memory = z3.Array("memory", z3.BitVecSort(32), z3.BitVecSort(8))
    address = z3.BitVecVal(base, 32)
    value = z3.BitVecVal(int.from_bytes(bytes([byte]) * 36, "little"), 288)
    compact = _z3_store(memory, address, value, little_endian=little, z3=z3)
    explicit = memory
    for offset in range(36):
        explicit = z3.Store(explicit, address + offset, z3.BitVecVal(byte, 8))
    witness = z3.BitVec("witness", 32)
    solver = z3.Solver()
    solver.set(timeout=4000)
    solver.add(z3.simplify(compact[witness] != explicit[witness], blast_select_store=True))
    assert solver.check() == z3.unsat
    # Both boundary neighbours remain observable, including address wraparound.
    for offset in (-1, 36):
        solver = z3.Solver()
        changed = z3.Store(compact, address + offset, memory[address + offset] ^ 1)
        solver.add(changed[witness] != compact[witness])
        assert solver.check() == z3.sat


def test_stack_projection_coalesces_only_exact_excluded_offsets():
    function = {"inputs": [], "assignments": [], "outputs": {}}
    observed = _observe(function, Flat32AbiObservation(32, private_stack_bytes=36),
                        (-36, -35, -34, -2, -1))
    stores = [item for item in observed["assignments"] if item["op"] == "storele"]
    assert [item["args"][2]["width"] for item in stores] == [24, 16]
    addresses = [item for item in observed["assignments"] if item["op"] == "add"]
    assert [int(item["args"][1]["value"], 16) for item in addresses] == [(-36) & 0xFFFFFFFF, (-2) & 0xFFFFFFFF]
