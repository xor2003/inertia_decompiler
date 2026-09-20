"""Exact IR address origins must survive copied selector expressions."""

import shutil
import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import SEGMENTED_LOAD_ADDRESS_TAG_8616, AddressStatus
from angr_platforms.X86_16.ir.function_ir_registry import FunctionIRArtifactVerdict8616
from angr_platforms.X86_16.lowering import segmented_load_origins as owner
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616
from angr_platforms.X86_16.widening.segmented_load_identity import segmented_load_identity_8616
from angr_platforms.X86_16.widening.segmented_load_widening import apply_segmented_load_widening_8616
from test_x86_16_ir_segmented_load_carriers import _Codegen
from test_x86_16_segment_stack_restore import _lift_function


def _fixture(monkeypatch):
    artifact = _lift_function(bytes.fromhex("8e c2 26 8b 07 c3"))
    block = artifact.blocks[0]
    definitions = {item.dst.source_tmp: item for item in block.instrs if item.dst is not None}
    load = next(item for item in block.instrs if item.op == "LOAD" and item.addr == 0x1002)
    root = definitions[load.origin.address_tmp]
    scale = definitions[root.args[0].source_tmp]
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()), stmt_comments={}, expr_comments={},
                       const_formats={}, display_vvar_ids=False)
    selector = structured_c.CVariable(SimRegisterVariable(8, 2, name="saved_selector"),
                                     variable_type=SimTypeShort(False), codegen=codegen)
    offset = structured_c.CVariable(SimRegisterVariable(12, 2, name="saved_offset"),
                                   variable_type=SimTypeShort(False), codegen=codegen)

    def tags(instruction):
        return {"ins_addr": instruction.addr, "vex_block_addr": instruction.origin.block_addr,
                "vex_stmt_idx": instruction.origin.statement_index}

    shifted = structured_c.CBinaryOp("Shl", selector,
                                    structured_c.CConstant(4, SimTypeInt(False), codegen=codegen),
                                    codegen=codegen, tags=tags(scale))
    address = structured_c.CBinaryOp("Add", shifted, offset, codegen=codegen, tags=tags(root))
    dereference = structured_c.CUnaryOp("Dereference", address, codegen=codegen)
    dereference.set_type(SimTypeChar(False))
    assignment = structured_c.CAssignment(offset, dereference, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=artifact.function_addr,
                                   statements=structured_c.CStatements([assignment], codegen=codegen))
    resolution = SimpleNamespace(verdict=FunctionIRArtifactVerdict8616.PROVEN, artifact=artifact)
    monkeypatch.setattr(owner, "registered_function_ir_artifact_8616", lambda *_args: resolution)
    return codegen, assignment, selector, offset, (load.dst.source_tmp, load.addr)


def test_copied_selector_uses_retained_ast_values(monkeypatch):
    codegen, assignment, selector, offset, key = _fixture(monkeypatch)
    assert owner.materialize_segmented_load_origins_8616(codegen, frozenset({key})) == frozenset({key})
    helper = assignment.rhs
    assert isinstance(helper, structured_c.CFunctionCall)
    assert helper.callee_target == "SEG_U8"
    assert helper.args[0] is selector
    assert helper.args[1] is offset
    assert helper.tags["inertia_source_instruction_addrs"] == (0x1002,)


@pytest.mark.parametrize("corruption", ["root_origin", "scale_origin", "block", "instruction", "shift", "operator", "load_key"])
def test_incomplete_or_changed_provenance_refuses(monkeypatch, corruption):
    codegen, assignment, _, _, key = _fixture(monkeypatch)
    original = assignment.rhs
    address = original.operand
    keys = frozenset({key})
    if corruption == "root_origin":
        address.tags = {}
    elif corruption == "scale_origin":
        address.lhs.tags = {}
    elif corruption == "block":
        address.tags["vex_block_addr"] = 0x2000
    elif corruption == "instruction":
        address.tags["ins_addr"] = 0x1000
    elif corruption == "shift":
        address.lhs.rhs.value = 5
    elif corruption == "operator":
        address.op = "Sub"
    else:
        keys = frozenset()
    assert owner.materialize_segmented_load_origins_8616(codegen, keys) == frozenset()
    assert assignment.rhs is original


def test_nonbyte_read_is_not_replaced(monkeypatch):
    codegen, assignment, _, _, key = _fixture(monkeypatch)
    original = assignment.rhs
    original.set_type(SimTypeShort(False))
    assert owner.materialize_segmented_load_origins_8616(codegen, frozenset({key})) == frozenset()
    assert assignment.rhs is original


def test_register_based_address_is_not_an_absolute_storage_identity(monkeypatch):
    codegen, assignment, _, _, key = _fixture(monkeypatch)
    owner.materialize_segmented_load_origins_8616(codegen, frozenset({key}))
    assert segmented_load_identity_8616(assignment.rhs) is None


@pytest.mark.parametrize("context", ["write", "reference"])
def test_address_reuse_does_not_authorize_a_read_replacement(monkeypatch, context):
    codegen, assignment, _, _, key = _fixture(monkeypatch)
    dereference = assignment.rhs
    if context == "write":
        assignment.lhs = dereference
        assignment.rhs = structured_c.CConstant(0, SimTypeInt(False), codegen=codegen)
    else:
        assignment.rhs = structured_c.CUnaryOp("Reference", dereference, codegen=codegen)
    assert owner.materialize_segmented_load_origins_8616(codegen, frozenset({key})) == frozenset()
    assert (assignment.lhs if context == "write" else assignment.rhs.operand) is dereference


@pytest.mark.parametrize("corruption", ["unproven_address", "duplicate_temporary", "missing_origin", "wide_offset", "wrong_segment"])
def test_ir_proof_gaps_leave_the_dereference_unchanged(monkeypatch, corruption):
    codegen, assignment, _, _, key = _fixture(monkeypatch)
    resolution = owner.registered_function_ir_artifact_8616(codegen.project, codegen.cfunc.addr)
    artifact = resolution.artifact
    block = artifact.blocks[0]
    definitions = {item.dst.source_tmp: item for item in block.instrs if item.dst is not None}
    load = definitions[key[0]]
    root = definitions[load.origin.address_tmp]
    scale = definitions[root.args[0].source_tmp]
    original, replacement = root, root
    if corruption == "unproven_address":
        original, replacement = load, replace(load, args=(replace(load.args[0], status=AddressStatus.UNKNOWN),))
    elif corruption == "missing_origin":
        replacement = replace(root, origin=None)
    elif corruption == "wide_offset":
        replacement = replace(root, args=(root.args[0], replace(root.args[1], expr=())))
    elif corruption == "wrong_segment":
        original, replacement = scale, replace(scale, args=(replace(scale.args[0], name="ds"), scale.args[1]))
    instructions = tuple(replacement if item is original else item for item in block.instrs)
    if corruption == "duplicate_temporary":
        instructions = (*instructions, root)
    resolution.artifact = replace(artifact, blocks=(replace(block, instrs=instructions), *artifact.blocks[1:]))
    before = assignment.rhs
    assert owner.materialize_segmented_load_origins_8616(codegen, frozenset({key})) == frozenset()
    assert assignment.rhs is before


def test_widening_preserves_bytewise_reads_when_offset_can_wrap(monkeypatch, tmp_path):
    codegen, assignment, selector, offset, key = _fixture(monkeypatch)
    owner.materialize_segmented_load_origins_8616(codegen, frozenset({key}))
    low = assignment.rhs
    tags = dict(low.tags)
    tags[SEGMENTED_LOAD_ADDRESS_TAG_8616] = replace(tags[SEGMENTED_LOAD_ADDRESS_TAG_8616], offset=1)
    one = structured_c.CConstant(1, SimTypeInt(False), codegen=codegen)
    high_offset = structured_c.CBinaryOp("Add", offset, one, codegen=codegen)
    high = structured_c.CFunctionCall("SEG_U8", None, [selector, high_offset], codegen=codegen, tags=tags)
    shifted = structured_c.CBinaryOp("Shl", high, structured_c.CConstant(8, SimTypeInt(False), codegen=codegen),
                                    codegen=codegen)
    combined = structured_c.CBinaryOp("Or", low, shifted, codegen=codegen)
    assignment.rhs = combined
    assert apply_segmented_load_widening_8616(codegen) is False
    assert assignment.rhs is combined
    compiler = shutil.which("gcc")
    assert compiler is not None, "segmented-wrap behavioral gate requires gcc"
    for name, expression, expected in (("bytewise", combined.c_repr(), 0),
                                       ("wrong_contiguous", "SEG_U16(saved_selector, saved_offset)", 1)):
        source = tmp_path / f"{name}.c"
        binary = tmp_path / name
        source.write_text(render_c_runtime_header_8616("portable-flat") + f"""
uint8_t inertia_memory[0x20000];
int main(void) {{
    uint16_t saved_selector = 0x100, saved_offset = 0xffff;
    inertia_memory[0x10fff] = 0x34;
    inertia_memory[0x1000] = 0x12;
    inertia_memory[0x11000] = 0x99;
    return ({expression}) != 0x1234;
}}
""", encoding="utf-8")
        compiled = subprocess.run([compiler, "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror",
                                   str(source), "-o", str(binary)], capture_output=True, text=True,
                                  check=False, timeout=30)
        assert compiled.returncode == 0, compiled.stderr
        execution = subprocess.run([str(binary)], capture_output=True, text=True, check=False, timeout=10)
        assert execution.returncode == expected, execution.stderr
