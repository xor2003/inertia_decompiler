"""Interior byte references retain their offset without deleting sibling uses."""

import angr
import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.code_location import CodeLocation
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16 import variable_recovery_compat
from angr_platforms.X86_16.alias.stack_reference_offsets import (
    StackReferenceInvariantError8616,
    stack_reference_displacement_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.variable_recovery_compat import apply_stack_reference_compatibility_8616


@pytest.mark.parametrize("arch", [Arch86_16(), "x86"])
def test_registration_retains_interior_offset_and_sibling_accesses(arch):
    project = angr.load_shellcode(b"\xc3", arch=arch, load_address=0x1000)
    manager = project.kb.variables[0x1000]
    variable = SimStackVariable(2, 2, base="bp", ident="arg", region=0x1000)
    location = CodeLocation(0x1000, 0, ins_addr=0x1000)
    low = VirtualVariable(1, 1, 8, VirtualVariableCategory.STACK, oident=2)
    high = VirtualVariable(2, 2, 8, VirtualVariableCategory.STACK, oident=3)
    apply_stack_reference_compatibility_8616()
    manager.record_variable(location, variable, None, atom=low)
    manager.record_variable(location, variable, None, atom=high)
    expected_high = 1 if project.arch.name == "86_16" else None
    assert manager.find_variables_by_atom(0x1000, 0, low) == {(variable, None)}
    assert manager.find_variables_by_atom(0x1000, 0, high) == {(variable, expected_high)}
    manager.reference_at(variable, None, location, atom=high)
    assert {access.offset for access in manager.get_variable_accesses(variable)} == {expected_high}


@pytest.mark.parametrize("stack_offset,bits", [(1, 8), (4, 8), (3, 16)])
def test_noncontained_range_retains_existing_offset(stack_offset, bits):
    variable = SimStackVariable(2, 2, base="bp")
    atom = VirtualVariable(1, 1, bits, VirtualVariableCategory.STACK, oident=stack_offset)
    existing_offset = 7
    assert stack_reference_displacement_8616(atom, variable, existing_offset) == existing_offset


@pytest.mark.parametrize("base", [-32768, -4, 0, 4, 32767, 65535])
@pytest.mark.parametrize("owner_size", [1, 2, 4, 8])
def test_storage_subrange_invariants(base, owner_size):
    variable = SimStackVariable(base, owner_size, base="bp")
    unchanged = 99
    for width in (1, 2, 4):
        for delta in range(-1, owner_size + 1):
            atom = VirtualVariable(1, 1, width * 8, VirtualVariableCategory.STACK, oident=base + delta)
            actual = stack_reference_displacement_8616(atom, variable, unchanged)
            if delta >= 0 and delta + width <= owner_size:
                assert base + (actual or 0) == atom.stack_offset
                assert (actual or 0) + atom.size <= variable.size
            else:
                assert actual == unchanged


def test_other_storage_and_unproven_wrap_keep_their_association():
    atom = VirtualVariable(1, 1, 8, VirtualVariableCategory.STACK, oident=0)
    unchanged = 9
    for variable in (SimMemoryVariable(0, 2), SimStackVariable(0, 2, base="sp"),
                     SimStackVariable(65535, 2, base="bp")):
        assert stack_reference_displacement_8616(atom, variable, unchanged) == unchanged


@pytest.mark.parametrize("publication", ["index", "reference"])
def test_corrupted_projection_fails_before_any_variable_publication(monkeypatch, publication):
    project = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    manager = project.kb.variables[0x1000]
    variable = SimStackVariable(2, 2, base="bp", ident="arg", region=0x1000)
    location = CodeLocation(0x1000, 0, ins_addr=0x1000)
    atom = VirtualVariable(1, 1, 8, VirtualVariableCategory.STACK, oident=3)
    monkeypatch.setattr(variable_recovery_compat, "stack_reference_displacement_8616", lambda *_args: None)
    with pytest.raises(StackReferenceInvariantError8616) as caught:
        if publication == "index":
            manager.record_variable(location, variable, None, atom=atom)
        else:
            manager.reference_at(variable, None, location, atom=atom)
    assert caught.value.requested_range == (3, 1)
    assert caught.value.owner_range == (2, 2)
    assert caught.value.displacement is None
    assert "function=4096" in caught.value.__notes__[0]
    assert not manager.find_variables_by_atom(0x1000, 0, atom)
    assert not manager.get_variable_accesses(variable)
