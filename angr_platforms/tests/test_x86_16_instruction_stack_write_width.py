"""Logical storage ownership must not widen an exact execution-byte write."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CIndexedVariable, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.stack_memory_ssa_contracts import StackMemoryAliasFactKind8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.instruction_bp_stack_access import (
    InstructionBpStackAccess8616,
    InstructionBpStackAccessEvidence8616,
    select_instruction_bp_stack_access_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


@pytest.mark.parametrize("lane,expected", [(0, 0x12AB), (1, 0xAB34)])
def test_logical_word_owner_keeps_exact_byte_write(tmp_path, lane, expected):
    kind = StackMemoryAliasFactKind8616.STORE
    byte = InstructionBpStackAccess8616(
        -2 + lane, 1, kind, InstructionBpStackAccessEvidence8616.EXECUTION_SLICE,
    )
    word = InstructionBpStackAccess8616(
        -2, 2, kind, InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS,
    )
    index = SimpleNamespace(by_instruction_addr={0x1000: (byte, word)})
    selected = select_instruction_bp_stack_access_8616(
        index, frozenset({0x1000}), displacement=-2 + lane, size=1, kind=kind,
    )
    assert selected == byte

    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch), cstyle_null_cmp=False,
        display_vvar_ids=False, const_formats={}, next_ident=lambda name: name,
        next_node_idx=lambda: 0,
    )
    variable = SimStackVariable(-4, 2, base="bp", name="word")
    cvar = CVariable(variable, variable_type=SimTypeShort(False).with_arch(arch), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000, arg_list=[], variables_in_use={variable: cvar}, unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=variable, cvar=cvar, bp_offset=-2, entry_sp_offset=-4, size=2,
    )
    target = stack_cvar_for_stable_ss_linear_access_8616(
        codegen, RealModeLinearStackAccess8616(selected.displacement, selected.size),
        instruction_access=selected, require_lvalue=True,
    )
    assert isinstance(target, CIndexedVariable)
    rendered = "".join(text for text, _node in target.c_repr_chunks())
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for execution-byte write verification"
    source = (
        f"int main(void) {{ unsigned short {cvar.name} = 0x1234; "
        f"{rendered} = 0xAB; return {cvar.name} != {expected}; }}"
    )
    executable = tmp_path / "write"
    result = subprocess.run(
        [compiler, "-std=c99", "-Wall", "-Werror", "-O2", "-x", "c", "-", "-o", str(executable)],
        input=source, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr + source
    assert subprocess.run([str(executable)], check=False).returncode == 0
