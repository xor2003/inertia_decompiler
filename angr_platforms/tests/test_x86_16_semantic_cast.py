"""Tests for required Lowering-owned C casts."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.lowering import real_mode_linear
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    materialize_runtime_helper_segment_carriers_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import (
    CSemanticCast8616,
    RequiredAssignmentCastReconcileStatus8616,
    reconcile_required_assignment_cast_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering import (
    _canonicalize_stack_cvar_expr,
)
from archinfo import ArchX86


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=ArchX86()),
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)


@pytest.mark.parametrize("signed", [False, True], ids=["unsigned-byte", "signed-byte"])
@pytest.mark.parametrize("char_default", ["-fsigned-char", "-funsigned-char"])
def test_semantic_byte_cast_preserves_all_values_independent_of_plain_char(tmp_path, signed, char_default):
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for semantic byte-cast execution"
    codegen = _codegen()
    codegen.display_vvar_ids = False
    codegen.show_casts = False
    source = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="value"),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    expression = CSemanticCast8616(
        SimTypeShort(False), SimTypeChar(signed), source, codegen=codegen,
    )
    rendered = "".join(text for text, _node in expression.c_repr_chunks())
    value_name = source.name
    expected = f"({value_name} >= 128 ? (int){value_name} - 256 : (int){value_name})" if signed else value_name
    program = (
        f"int main(void) {{ unsigned short {value_name};"
        f" for ({value_name}=0; {value_name}<256; ++{value_name}) {{"
        f" int actual = {rendered}; if (actual != {expected}) return 1; }} return 0; }}"
    )
    executable = tmp_path / "semantic-byte-cast"
    compiled = subprocess.run(
        [compiler, "-std=c99", "-Wall", "-Werror", "-O2", char_default, "-x", "c", "-", "-o", str(executable)],
        input=program, text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + program
    assert subprocess.run([str(executable)], check=False).returncode == 0, program


def test_semantic_cast_renders_when_cosmetic_casts_are_hidden() -> None:
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=ArchX86()),
        show_casts=False,
        display_vvar_ids=False,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    source = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="local_8"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(True),
        source,
        codegen=codegen,
    )

    rendered = "".join(text for text, _node in expression.c_repr_chunks())

    assert rendered == "(signed char)local_8"


def test_semantic_cast_remains_traversable_as_structured_c() -> None:
    codegen = _codegen()
    call = structured_c.CFunctionCall("rand", None, [], codegen=codegen)
    expression = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeShort(True),
        call,
        codegen=codegen,
    )

    assert tuple(_iter_c_nodes_deep_8616(expression)) == (expression, call)


def test_stack_canonicalization_preserves_semantic_cast() -> None:
    codegen = _codegen()
    call = structured_c.CFunctionCall("clock", None, [], codegen=codegen)
    expression = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeShort(True),
        call,
        codegen=codegen,
    )

    canonical = _canonicalize_stack_cvar_expr(
        expression,
        codegen,
        unwrap_c_casts=lambda node: node.expr
        if isinstance(node, structured_c.CTypeCast)
        else node,
        resolve_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
    )

    assert canonical is expression


def test_reconciles_required_cast_onto_unique_stale_assignment() -> None:
    codegen = _codegen()
    source = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="local_8"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    destination = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_6"),
        variable_type=SimTypeChar(True),
        codegen=codegen,
    )
    stale = structured_c.CAssignment(destination, source, codegen=codegen)
    required_cast = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(True),
        source,
        codegen=codegen,
    )
    expected = structured_c.CAssignment(destination, required_cast, codegen=codegen)
    root = structured_c.CStatements([stale], codegen=codegen)

    result = reconcile_required_assignment_cast_8616(
        root,
        expected,
        same_destination=lambda actual, wanted: actual is wanted,
        same_source=lambda actual, wanted: actual is wanted,
    )
    assert result.status is RequiredAssignmentCastReconcileStatus8616.APPLIED
    assert result.candidate_count == 1
    assert stale.rhs is required_cast
    repeated = reconcile_required_assignment_cast_8616(
        root,
        expected,
        same_destination=lambda actual, wanted: actual is wanted,
        same_source=lambda actual, wanted: actual is wanted,
    )
    assert (
        repeated.status
        is RequiredAssignmentCastReconcileStatus8616.ALREADY_PRESENT
    )


def test_refuses_to_reconcile_ambiguous_required_cast() -> None:
    codegen = _codegen()
    source = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="local_8"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    destination = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_6"),
        variable_type=SimTypeChar(True),
        codegen=codegen,
    )
    stale_assignments = [
        structured_c.CAssignment(destination, source, codegen=codegen),
        structured_c.CAssignment(destination, source, codegen=codegen),
    ]
    required_cast = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(True),
        source,
        codegen=codegen,
    )
    expected = structured_c.CAssignment(destination, required_cast, codegen=codegen)
    root = structured_c.CStatements(stale_assignments, codegen=codegen)

    result = reconcile_required_assignment_cast_8616(
        root,
        expected,
        same_destination=lambda actual, wanted: actual is wanted,
        same_source=lambda actual, wanted: actual is wanted,
    )
    assert result.status is RequiredAssignmentCastReconcileStatus8616.AMBIGUOUS
    assert result.candidate_count == 2
    assert all(assignment.rhs is source for assignment in stale_assignments)


def test_reconciles_narrow_cast_source_with_proven_wide_stack_storage() -> None:
    codegen = _codegen()
    wide_source = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="local_8"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    narrow_source = structured_c.CVariable(
        SimStackVariable(-8, 1, base="bp", name="local_8"),
        variable_type=SimTypeChar(True),
        codegen=codegen,
    )
    destination = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale = structured_c.CAssignment(destination, wide_source, codegen=codegen)
    required_cast = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(True),
        narrow_source,
        codegen=codegen,
    )
    expected = structured_c.CAssignment(destination, required_cast, codegen=codegen)
    root = structured_c.CStatements([stale], codegen=codegen)

    result = reconcile_required_assignment_cast_8616(
        root,
        expected,
        same_destination=real_mode_linear._same_stack_cvar_8616,
        same_source=lambda actual, wanted: (
            real_mode_linear._same_stack_move_rhs_8616(actual, wanted)
            or real_mode_linear._same_stack_low_half_cvar_8616(wanted, actual)
        ),
    )
    assert result.status is RequiredAssignmentCastReconcileStatus8616.APPLIED
    assert result.candidate_count == 1
    assert stale.rhs is required_cast


def test_runtime_segment_carrier_pass_preserves_unrelated_semantic_cast() -> None:
    codegen = _codegen()
    source = structured_c.CVariable(
        SimStackVariable(-8, 2, base="bp", name="local_8"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    destination = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_6"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    required_cast = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(True),
        source,
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        destination,
        required_cast,
        codegen=codegen,
    )
    root = structured_c.CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root)
    codegen._func = None

    assert not materialize_runtime_helper_segment_carriers_8616(codegen)
    assert assignment.rhs is required_cast
