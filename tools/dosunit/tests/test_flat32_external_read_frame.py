"""Explicit external read footprints retain all other observable dependencies."""
from dataclasses import replace

import pytest
import z3

from tools.dosunit.compare.flat32_external_call import external_call_state
from tools.dosunit.tests.test_flat32_external_call import CONTRACT, different, state, translate

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]


def constant(value, width=32):
    return {"op": "const", "width": width, "value": hex(value)}


def test_read_exclusion_masks_dependencies_but_not_actual_memory():
    contract = replace(CONTRACT, read_excluded_memory_ranges=((0x1000, 0x1fff),),
                       preserved_memory_ranges=((0x1000, 0x1fff),))
    before = state()
    before["esp"] = constant(0x8000)
    changed = dict(before)
    changed["memory"] = {"op": "storele", "width": 0,
                         "args": [before["memory"], constant(0x1000), constant(42, 8)]}
    left, right = external_call_state(contract, before), external_call_state(contract, changed)
    values = translate({"left": left["eax"], "right": right["eax"],
                        "memory": right["memory"], "io_left": left["io"], "io_right": right["io"]})
    for a, b in (("left", "right"), ("io_left", "io_right")):
        solver = z3.Solver()
        solver.set(timeout=5000)
        solver.add(values[a] != values[b])
        assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(z3.Select(values["memory"], z3.BitVecVal(0x1000, 32)) != 42)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("address", [0xfff, 0x2000, 0x8004])
def test_other_memory_and_arguments_remain_observable(address):
    contract = replace(CONTRACT, read_excluded_memory_ranges=((0x1000, 0x1fff),))
    before = state()
    before["esp"] = constant(0x8000)
    changed = dict(before)
    changed["memory"] = {"op": "storele", "width": 0,
                         "args": [before["memory"], constant(address), constant(42, 8)]}
    values = translate({"left": external_call_state(contract, before)["eax"],
                        "right": external_call_state(contract, changed)["eax"]})
    assert different(values["left"], values["right"])


@pytest.mark.parametrize("ranges", [((2, 1),), ((0, 2), (2, 3)), ((-1, 3),), ((0, 2**32),)])
def test_invalid_read_ranges_rejected(ranges):
    with pytest.raises(ValueError):
        replace(CONTRACT, read_excluded_memory_ranges=ranges)



def test_excluded_argument_slots_still_supply_actual_arguments():
    contract = replace(CONTRACT, read_excluded_memory_ranges=((0x8004, 0x8007),))
    before = state()
    before["esp"] = constant(0x8000)
    changed = dict(before)
    changed["memory"] = {"op": "storele", "width": 0,
                         "args": [before["memory"], constant(0x8004), constant(42)]}
    values = translate({"left": external_call_state(contract, before)["eax"],
                        "right": external_call_state(contract, changed)["eax"]})
    assert different(values["left"], values["right"])


def test_read_exclusion_does_not_imply_write_preservation():
    contract = replace(CONTRACT, read_excluded_memory_ranges=((0x1000, 0x1007),))
    before = state()
    before["esp"] = constant(0x8000)
    values = translate({"before": before["memory"], "after": external_call_state(contract, before)["memory"]})
    address = z3.BitVecVal(0x1000, 32)
    assert different(z3.Select(values["before"], address), z3.Select(values["after"], address))


def test_catalog_roundtrip_publishes_read_and_write_premises():
    from tools.comparator.external_catalog import _contracts
    item = {"dll": "kernel32.dll", "name": "Example", "argument_count": 3,
            "cleanup": "callee", "read_excluded_memory_ranges": [[0x1000, 0x1007]],
            "preserved_memory_ranges": [[0x2000, 0x2007]]}
    contract, = _contracts([item])
    fields = contract.declared_fields()
    assert fields["read_excluded_memory_ranges"] == item["read_excluded_memory_ranges"]
    assert fields["preserved_memory_ranges"] == item["preserved_memory_ranges"]
    assert "memory_except_explicit_read_exclusions" in fields["dependencies"]
