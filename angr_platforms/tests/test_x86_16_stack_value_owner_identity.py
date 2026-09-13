"""Argument wrapper clones must retain their proven stack-storage owner."""

import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CReturn, CStatements, CVariable
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_value_projection import (
    StackValueProjectionStatus8616,
    project_stack_value_range_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.lowering.wide_stack_argument_views import (
    WideStackArgumentOwner8616,
    materialize_wide_stack_argument_subviews_8616,
)
from angr_platforms.X86_16.validation_stack_projection import validated_stack_projection_fact_8616

_BYTE_BITS = 8


def _surface(mode):
    arch = Arch86_16()
    cg = SimpleNamespace(
        cstyle_null_cmp=False, display_vvar_ids=False, const_formats={},
        next_ident=lambda name: name, next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=arch),
    )
    storage = SimStackVariable(2, 2, base="bp", name="value")
    recorded = CVariable(storage, variable_type=SimTypeShort(False).with_arch(arch), codegen=cg)
    current_storage = (
        SimStackVariable(2, 2, base="bp", name="value") if mode == "unrelated" else storage
    )
    current_type = SimTypeChar(False) if mode == "narrowed" else SimTypeShort(False)
    current = CVariable(current_storage, variable_type=current_type.with_arch(arch), codegen=cg)
    arguments = [recorded] if mode == "same" else [current]
    if mode == "ambiguous":
        arguments.append(recorded)
    cg.cfunc = SimpleNamespace(addr=0x1000, arg_list=arguments)
    fragment_storage = SimStackVariable(3, 1, base="bp", name="fragment")
    fragment = CVariable(fragment_storage, variable_type=SimTypeChar(False).with_arch(arch), codegen=cg)
    for variable, cvar, bp, sp, size in (
        (storage, recorded, 4, 2, 2), (fragment_storage, fragment, 5, 3, 1),
    ):
        record_stack_variable_coordinate_projection_8616(
            cg, variable=variable, cvar=cvar, bp_offset=bp, entry_sp_offset=sp, size=size,
        )
    return cg, arguments[0]


@pytest.mark.parametrize(
    ("mode", "status"),
    [
        ("same", StackValueProjectionStatus8616.CONTAINED_VALUE),
        ("clone", StackValueProjectionStatus8616.CONTAINED_VALUE),
        ("unrelated", StackValueProjectionStatus8616.AMBIGUOUS_OWNER),
        ("ambiguous", StackValueProjectionStatus8616.AMBIGUOUS_OWNER),
        ("narrowed", StackValueProjectionStatus8616.OUTSIDE_VALUE),
    ],
)
def test_argument_owner_uses_recorded_storage_identity(mode, status):
    codegen, current = _surface(mode)

    result = project_stack_value_range_8616(codegen, 5, 1)

    assert result.status is status
    if result.materialized:
        assert result.owner.cvar is current
        assert result.expression.expr.lhs is current
        assert result.expression.expr.rhs.value == _BYTE_BITS


def test_word_argument_high_byte_is_materialized_and_executable(tmp_path):
    """Exercise every word value, including the rotate's previously untested high bit."""
    codegen, current = _surface("clone")
    fragment = stack_variable_coordinate_registry_8616(codegen).projections[1].cvar
    ret = CReturn(fragment, codegen=codegen)
    codegen.cfunc.statements = CStatements([ret], codegen=codegen)

    result = materialize_wide_stack_argument_subviews_8616(
        codegen, (WideStackArgumentOwner8616(4, 2, current),),
    )

    assert result.changed
    assert result.failure_count == 0
    assert not result.retained_variables
    owner_read = ret.retval.lhs.lhs
    owner_fact = validated_stack_projection_fact_8616(owner_read)
    assert owner_fact is None or (owner_fact.view_offset, owner_fact.view_size) == (4, 2)
    expression = "".join(text for text, _node in ret.retval.c_repr_chunks())
    source = (
        f"unsigned short rotate(unsigned short value) {{ return (({expression}) >> 7) | (value << 1); }}\n"
        "int main(void) { unsigned value; for (value = 0; value < 65536U; ++value) "
        "if (rotate(value) != (unsigned short)((value << 1) | (value >> 15))) return 1; return 0; }"
    )
    executable = tmp_path / "rotate"
    compiled = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Werror", "-x", "c", "-", "-o", str(executable)],
        input=source, text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + source
    assert subprocess.run([str(executable)], check=False).returncode == 0


def test_terminal_byte_read_consumes_contained_argument_projection():
    """ABI word slots must not turn a terminal byte load into new word storage."""
    from angr_platforms.X86_16.decompiler_postprocess_stage import _terminal_stack_arg_expr_8616

    codegen, current = _surface("clone")
    codegen.cfunc.variables_in_use = {current.variable: current}
    before = dict(codegen.cfunc.variables_in_use)

    expression = _terminal_stack_arg_expr_8616(codegen.project, codegen, 5, 1)

    assert expression.type.size == _BYTE_BITS
    assert expression.expr.lhs is current
    assert expression.expr.rhs.value == _BYTE_BITS
    assert codegen.cfunc.variables_in_use == before


def test_terminal_word_read_retains_the_existing_argument_surface():
    """Exact loads retain their interface binding rather than adding a new cast."""
    from angr_platforms.X86_16.decompiler_postprocess_stage import _terminal_stack_arg_expr_8616

    codegen, current = _surface("clone")
    expression = _terminal_stack_arg_expr_8616(codegen.project, codegen, 4, 2)

    assert isinstance(expression, CVariable)
    assert expression.variable is current.variable
    assert expression.variable_type is current.variable_type


@pytest.mark.parametrize("mode", ["unrelated", "ambiguous", "narrowed"])
def test_terminal_byte_read_refuses_conflicting_or_padding_storage(mode):
    """A failed typed projection must not fall back to invented stack storage."""
    from angr_platforms.X86_16.decompiler_postprocess_stage import _terminal_stack_arg_expr_8616

    codegen, current = _surface(mode)
    codegen.cfunc.variables_in_use = {current.variable: current}
    before = dict(codegen.cfunc.variables_in_use)

    assert _terminal_stack_arg_expr_8616(codegen.project, codegen, 5, 1) is None
    assert codegen.cfunc.variables_in_use == before


@pytest.mark.parametrize("owner_type", [SimTypeChar(False), SimTypePointer(SimTypeChar(False))])
def test_word_subview_pass_refuses_padding_and_pointer_owners(owner_type):
    """Integer subview recovery cannot reinterpret ABI padding or pointer storage."""
    codegen, current = _surface("clone")
    current.variable_type = owner_type.with_arch(codegen.project.arch)
    fragment = stack_variable_coordinate_registry_8616(codegen).projections[1].cvar
    ret = CReturn(fragment, codegen=codegen)
    codegen.cfunc.statements = CStatements([ret], codegen=codegen)

    result = materialize_wide_stack_argument_subviews_8616(
        codegen, (WideStackArgumentOwner8616(4, 2, current),),
    )

    assert not result.changed
    assert result.failure_count > 0
    assert ret.retval is fragment
    assert fragment.variable in result.retained_variables
