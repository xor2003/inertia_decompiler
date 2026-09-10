"""Exact byte writes to Alias-owned word storage, including uninitialized words."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CIndexedVariable, CVariable
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from angr_platforms.X86_16.lowering.stack_value_projection import (
    StackValueProjectionStatus8616,
    project_stack_value_range_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


def _word_owner(*, pointer=False, signed=False):
    arch = Arch86_16()
    codegen = SimpleNamespace(
        cstyle_null_cmp=False, display_vvar_ids=False, const_formats={},
        next_ident=lambda name: name, next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    storage = SimStackVariable(-2, 2, base="bp", name="word")
    scalar_type = SimTypeShort(signed)
    type_ = SimTypePointer(scalar_type) if pointer else scalar_type
    value = CVariable(storage, variable_type=type_.with_arch(arch), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000, arg_list=[], variables_in_use={storage: value}, unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=storage, cvar=value, bp_offset=-2, entry_sp_offset=-4, size=2,
    )
    return codegen


@pytest.mark.parametrize("offset,initial,expected", [(0, "0x1234", 0x12AB), (1, "0x1234", 0xAB34), (None, None, 0xCDAB)])
@pytest.mark.parametrize("signed", [False, True])
def test_stack_byte_write_compiles_without_reading_other_bytes(tmp_path, offset, initial, expected, signed):
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for generated-C byte-write verification"
    codegen = _word_owner(signed=signed)
    writes = []
    for lane, byte in ([(0, 0xAB), (1, 0xCD)] if offset is None else [(offset, 0xAB)]):
        target = stack_cvar_for_stable_ss_linear_access_8616(
            codegen, RealModeLinearStackAccess8616(-2 + lane, 1), require_lvalue=True,
        )
        assert isinstance(target, CIndexedVariable)
        rendered = "".join(text for text, _node in target.c_repr_chunks())
        writes.append(f"{rendered} = {byte};")
    name = next(iter(codegen.cfunc.variables_in_use.values())).name
    type_name = "short" if signed else "unsigned short"
    declaration = f"{type_name} {name}" + (f" = {initial}" if initial else "") + ";"
    source = "int main(void) { " + declaration + " ".join(writes) + f" return (unsigned short){name} != {expected}; }}"
    executable = tmp_path / "write"
    compiled = subprocess.run(
        [compiler, "-std=c99", "-Wall", "-Werror", "-O2", "-x", "c", "-", "-o", str(executable)],
        input=source, text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + source
    assert subprocess.run([str(executable)], check=False).returncode == 0


def test_partial_stack_pointer_write_does_not_mutate_host_pointer_bytes():
    codegen = _word_owner(pointer=True)
    target = stack_cvar_for_stable_ss_linear_access_8616(
        codegen, RealModeLinearStackAccess8616(-1, 1), require_lvalue=True,
    )
    assert target is None


@pytest.mark.parametrize("offset,size", [(-3, 1), (0, 1), (-1, 2)])
def test_stack_write_outside_owner_refuses_without_an_expression(offset, size):
    result = project_stack_value_range_8616(
        _word_owner(), bp_offset=offset, size=size, require_lvalue=True,
    )
    assert result.status is StackValueProjectionStatus8616.NO_OWNER
    assert not result.materialized
    assert result.expression is None
