"""Indexed stack addresses must consume, not duplicate, their proven frame."""

import subprocess

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CTypeCast, CUnaryOp, CVariable
from angr.sim_type import SimTypeFixedSizeArray, SimTypeShort
from inertia.lowering.real_mode_linear import (
    lower_stable_ss_linear_stack_dereferences_8616,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from tests.lowering.test_x86_16_segmented_stack_alias import (
    _codegen,
    _const,
    _indexed_bp_function,
    _reg,
    _stack,
    _stack_offsets_in_expr,
)


@pytest.mark.parametrize("segment,frame_proven", [("ss", True), ("ds", True), ("ss", False)])
def test_indexed_linear_address_consumes_only_proven_ss_frame(segment, frame_proven):
    project, codegen = _codegen([], standard_bp_coordinate=frame_proven)
    codegen._inertia_current_function_8616 = _indexed_bp_function(-90)
    segment_term = CBinaryOp("Shl", _reg(project, segment, codegen), _const(4, codegen), codegen=codegen)
    anchor = CUnaryOp("Reference", _stack(-2, codegen, name="anchor"), codegen=codegen)
    index = _reg(project, "si", codegen)
    address = CBinaryOp("Add", segment_term, anchor, codegen=codegen)
    address = CBinaryOp("Add", address, _const(0xFFA6, codegen), codegen=codegen)
    address = CBinaryOp("Add", address, index, codegen=codegen)
    original = CUnaryOp("Dereference", address, codegen=codegen)
    statement = CAssignment(original, _const(1, codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(statement)

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    if segment == "ss" and frame_proven:
        assert changed
        assert -92 in _stack_offsets_in_expr(statement.lhs)
        assert -2 not in _stack_offsets_in_expr(statement.lhs)
    else:
        assert not changed
        assert statement.lhs is original


def test_repeated_indexed_loads_never_take_address_of_value_cast():
    """Reusing a coordinate owner must keep the pointer base addressable."""
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_current_function_8616 = _indexed_bp_function(-90, size=1)
    for lane in (0, 1):
        address = CBinaryOp("Add", _const(0xFFA6, codegen), _reg(project, "si", codegen), codegen=codegen)
        address = CBinaryOp("Add", address, _const(lane, codegen), codegen=codegen)
        load = CUnaryOp("Dereference", address, codegen=codegen)
        codegen.cfunc.statements.statements.append(CAssignment(_reg(project, "al", codegen), load, codegen=codegen))

    assert lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)
    references = [
        node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements)
        if isinstance(node, CUnaryOp) and node.op == "Reference"
    ]
    assert len(references) == 2
    assert all(isinstance(node.operand, CVariable) for node in references)
    assert not any(isinstance(node.operand, CTypeCast) for node in references)
    assert references[0].operand.variable is references[1].operand.variable


@pytest.mark.parametrize("byte_value", [0x56, 0x80, 0xFF])
def test_indexed_byte_address_keeps_byte_stride_when_array_type_is_replayed(tmp_path, byte_value):
    """Hidden cosmetic casts must not turn a byte offset into a word index."""
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen.show_casts = False
    codegen.display_vvar_ids = False
    codegen._inertia_current_function_8616 = _indexed_bp_function(-90, size=1)
    address = CBinaryOp("Add", _const(0xFFA6, codegen), _reg(project, "si", codegen), codegen=codegen)
    statement = CAssignment(_reg(project, "al", codegen), CUnaryOp("Dereference", address, codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(statement)
    assert lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)
    reference = next(node for node in _iter_c_nodes_deep_8616(statement.rhs)
                     if isinstance(node, CUnaryOp) and node.op == "Reference")
    reference.operand.variable_type = SimTypeFixedSizeArray(SimTypeShort(False), 4).with_arch(project.arch)
    name = reference.operand.variable.name
    expression = "".join(text for text, _node in statement.rhs.c_repr_chunks())
    source = (
        f"int main(void) {{ unsigned short {name}[4] = {{0}}; unsigned short si = 2; "
        f"((unsigned char *){name})[2] = {byte_value}; return ({expression}) != {byte_value}; }}"
    )
    executable = tmp_path / "byte-stride"
    compiled = subprocess.run(["gcc", "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), "-"],
                              input=source, text=True, capture_output=True, check=False)
    assert compiled.returncode == 0, compiled.stderr + "\n" + source
    assert subprocess.run([str(executable)], check=False).returncode == 0, source
