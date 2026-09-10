"""Machine-BP names must not confuse published entry-SP argument coordinates."""

from types import SimpleNamespace

import pytest
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.machine_stack_names import machine_bp_stack_object_name_8616
from angr_platforms.X86_16.lowering.real_mode_linear import _preferred_stack_object_name_8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


@pytest.mark.parametrize("delta", [-2, -4])
@pytest.mark.parametrize("offset,expected", [(6, "arg_6"), (4, "local_4"), (-6, "local_6")])
def test_argument_names_use_machine_coordinates_not_raw_offsets(delta, offset, expected):
    variable = SimStackVariable(6 + delta, 2, base="bp", name="parameter", region=0x1000)
    arg = SimpleNamespace(variable=variable)
    codegen = SimpleNamespace(
        project=SimpleNamespace(),
        cfunc=SimpleNamespace(addr=0x1000, arg_list=[arg], variables_in_use={}),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=variable, cvar=arg, bp_offset=6,
        entry_sp_offset=6 + delta, size=2,
    )
    assert _preferred_stack_object_name_8616(offset, codegen=codegen, byte_size=2) == expected


@pytest.mark.parametrize(
    "offset,expected",
    [(0x7FFF, "local_7fff"), (0x8000, "local_8000"), (0xFFFF, "local_1"),
     (-1, "local_1"), (0x10000, "local_10000")],
)
def test_machine_bp_names_preserve_signed_offset_boundaries(offset, expected):
    assert machine_bp_stack_object_name_8616(offset) == expected
