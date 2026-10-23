"""Execute and independently validate real source-bound call SP contexts."""
import shutil
import subprocess
from dataclasses import replace
from itertools import count
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.knowledge_plugins.functions.function import Function
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeNum, SimTypeShort

from inertia.lowering.call_stack_input_contracts import (
    CALL_STACK_INPUT_BINDING_TAG_8616,
    call_stack_context_layout_8616,
)
from inertia.lowering.call_stack_inputs import lower_call_stack_inputs_8616
from inertia.lowering.entry_stack_pointer_capture import observe_entry_stack_pointer_capture_8616
from inertia.lowering.gp_register_state import runtime_gp_state_expr_8616
from inertia.pipeline.call_stack_input_outcome import CallStackInputFailure8616, CallStackInputStatus8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from inertia.validation.validation_call_stack_inputs import validate_call_stack_inputs_8616
from tests.semantics.test_call_stack_coordinates import _world


def _fixture(*, returns_call_value: bool = True):
    after_call = "83c001" if returns_call_value else "b80700"
    project, function, source, summary = _world(bytes.fromhex(f"e80500 {after_call} c3 90 89e0c3"), 0x1000)
    source = materialize_call_stack_effects_8616(source, {0x1000: summary}, project=project).function
    indices = count()
    codegen = SimpleNamespace(project=project, next_node_idx=lambda: next(indices),
        next_ident=lambda name: name, display_vvar_ids=False, cstyle_null_cmp=False,
        stmt_comments={}, expr_comments={}, display_block_addrs=False,
        use_compound_assignments=False, prettify_thiscall=False, show_casts=True,
        const_formats={}, max_str_len=2048, kb=project.kb, _func=function,
        default_simtype_from_bits=lambda bits, signed=False: SimTypeNum(bits, signed).with_arch(project.arch))
    root = c.CStatements([], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, variables_in_use={},
        variable_manager=project.kb.variables[0x1000], refresh=lambda: None)
    codegen._variables_in_use = codegen.cfunc.variables_in_use
    codegen._inertia_vex_ir_artifact = source
    # This frontend may retain a conditional call target outside CFG discovery.
    # Keep native project identity without changing the CFG's function census.
    target = Function(project.kb.functions, 0x1008, name="callee")
    target.prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(project.arch)
    invoked = c.CFunctionCall("callee", target, [], tags={"ins_addr": 0x1000}, codegen=codegen)
    root.statements = [c.CReturn(c.CBinaryOp("Add", invoked,
        c.CConstant(1, SimTypeInt(False), codegen=codegen), codegen=codegen), codegen=codegen)]
    if not returns_call_value:
        root.statements = [c.CExpressionStatement(invoked, codegen=codegen), c.CReturn(c.CConstant(7, SimTypeShort(False).with_arch(project.arch),
                                                        codegen=codegen), codegen=codegen)]
    return codegen, invoked


def _wrapper(codegen):
    return codegen.cfunc.statements.statements[-1].retval.lhs


@pytest.mark.parametrize("entry", [0x8000, 0x12348000, 0x12349000, 0x12340000])
def test_generated_call_receives_machine_entry_word(tmp_path: Path, entry: int):
    """The original C call runs once with SP-2, preserving arbitrary upper ESP."""
    codegen, _ = _fixture()
    before = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert before.materialized_count == 0 and before.issues
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.status is CallStackInputStatus8616.MATERIALIZED
    report = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert report.materialized_count == 1 and not report.issues
    assert report.root is not codegen.cfunc.statements
    assert call_stack_context_layout_8616(_wrapper(codegen)) is not None
    declarations = '\n'.join(f'{value.type.c_repr()} {value.c_repr()};'
                             for value in codegen.cfunc.variables_in_use.values())
    text = f'''#include <stdint.h>
#include <stdio.h>
uint32_t inertia_esp={entry};
unsigned calls=0;
unsigned short callee(void) {{ ++calls; return inertia_esp & 0xffff; }}
unsigned short caller(void) {{ {declarations}
{codegen.cfunc.statements.c_repr()}
}}
int main(void) {{ unsigned value=caller(); printf("%u %u %u\\n",value,calls,inertia_esp >> 16); }}
'''
    path = tmp_path / 'bound.c'
    path.write_text(text)
    compiler = shutil.which('gcc')
    assert compiler is not None
    compiled = subprocess.run([compiler, '-std=c11', str(path), '-o', str(tmp_path / 'bound')], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr + text
    executed = subprocess.run([str(tmp_path / 'bound')], capture_output=True, text=True, check=True)
    assert tuple(map(int, executed.stdout.split())) == ((entry - 1) & 0xffff, 1, entry >> 16)
    repeated = lower_call_stack_inputs_8616(codegen)
    assert repeated is not None and not repeated.changed
    assert len(codegen.cfunc.variables_in_use) == 2


@pytest.mark.parametrize('mutation', ['position', 'pre_value', 'post_value', 'upper_bits', 'order', 'result', 'capture', 'signed_cast'])
def test_binding_tampering_is_not_normalized(mutation):
    """A correct marker never authorizes a wrong source input or C state write."""
    codegen, _ = _fixture()
    lower_call_stack_inputs_8616(codegen)
    wrapper = _wrapper(codegen)
    layout = call_stack_context_layout_8616(wrapper)
    assert layout is not None
    if mutation == 'position':
        marker = layout.marker
        wrapper.tags[CALL_STACK_INPUT_BINDING_TAG_8616] = replace(marker,
            authority=replace(marker.authority, callee_entry_offset=0))
    elif mutation in {'pre_value', 'post_value'}:
        assignment = layout.pre_write if mutation == 'pre_value' else layout.post_write
        assignment.rhs = c.CConstant(0, SimTypeInt(False), codegen=codegen)
    elif mutation == 'upper_bits':
        capture = observe_entry_stack_pointer_capture_8616(codegen, codegen._inertia_vex_ir_artifact)
        assert capture is not None
        layout.post_write.rhs = capture.value
    elif mutation == 'order':
        wrapper.stmts.statements[0], wrapper.stmts.statements[-1] = wrapper.stmts.statements[-1], wrapper.stmts.statements[0]
    elif mutation == 'result':
        wrapper.expr = c.CConstant(1, SimTypeInt(False), codegen=codegen)
    elif mutation == 'capture':
        codegen.cfunc.statements.statements[0].rhs = c.CConstant(0x8000, SimTypeInt(False), codegen=codegen)
    else:
        capture = observe_entry_stack_pointer_capture_8616(codegen, codegen._inertia_vex_ir_artifact)
        assert capture is not None
        word = c.CTypeCast(capture.value.type, SimTypeShort(True), capture.value, codegen=codegen)
        parent = runtime_gp_state_expr_8616('esp', codegen=codegen, function_addr=0x1000)
        high = c.CBinaryOp('And', parent, c.CConstant(0xffff0000, SimTypeInt(False), codegen=codegen), codegen=codegen)
        layout.post_write.rhs = c.CBinaryOp('Or', high, word, codegen=codegen)
    report = validate_call_stack_inputs_8616(codegen, codegen.cfunc.statements)
    assert report.issues
    assert report.materialized_count == 0


def test_unknown_call_position_keeps_original_tree():
    """A source CALL without frame/body proof never gets a guessed two-byte input."""
    codegen, call = _fixture()
    source = codegen._inertia_vex_ir_artifact
    codegen._inertia_vex_ir_artifact = replace(source, blocks=tuple(replace(block, instrs=tuple(
        replace(instruction, call_stack_effect=None) if instruction.op == 'CALL' else instruction
        for instruction in block.instrs)) for block in source.blocks))
    original = codegen.cfunc.statements
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.failure is CallStackInputFailure8616.POSITION_UNPROVEN
    assert not result.changed and not codegen.cfunc.variables_in_use
    assert codegen.cfunc.statements is original and call.args == []
    assert validate_call_stack_inputs_8616(codegen, original).issues


def test_unowned_retained_sp_read_refuses_atomic_lowering():
    """Introducing call writes cannot silently retime an unproved SP live-in."""
    codegen, _ = _fixture()
    original = codegen.cfunc.statements
    returned = original.statements[-1]
    returned.retval.rhs = runtime_gp_state_expr_8616('sp', codegen=codegen, function_addr=0x1000)
    result = lower_call_stack_inputs_8616(codegen)
    assert result is not None and result.failure is CallStackInputFailure8616.UNOWNED_SP_USE
    assert not result.changed and not codegen.cfunc.variables_in_use
    assert codegen.cfunc.statements is original


@pytest.mark.parametrize('scope', ['project', 'root', 'declaration'])
def test_context_cannot_borrow_a_different_scope_or_declaration(scope):
    """A semantic view cannot trust foreign roots, projects or changed local types."""
    codegen, _ = _fixture()
    lower_call_stack_inputs_8616(codegen)
    root = codegen.cfunc.statements
    if scope == 'project':
        codegen.project = object()
    elif scope == 'root':
        root = c.CStatements(list(root.statements), codegen=codegen)
    else:
        manager = codegen.cfunc.variable_manager
        codegen.cfunc.variable_manager = SimpleNamespace(set_variable_type=manager.set_variable_type,
            get_variable_type=lambda _variable: SimTypeInt(False).with_arch(codegen.project.arch))
    report = validate_call_stack_inputs_8616(codegen, root)
    assert report.issues and report.materialized_count == 0


def test_binding_metadata_is_part_of_actual_output_snapshot():
    """Source context changes remain visible even when the rendered C is unchanged."""
    from inertia.pipeline.structured_ast_output import observe_structured_ast_output_8616
    from tests.pipeline.test_structured_ast_output import _actual_ast

    codegen, _ = _fixture()
    lower_call_stack_inputs_8616(codegen)
    marker = _wrapper(codegen).tags[CALL_STACK_INPUT_BINDING_TAG_8616]
    actual, constant = _actual_ast()
    constant.tags['binding'] = marker
    first = observe_structured_ast_output_8616(actual)
    assert first.complete and first.snapshot is not None
    constant.tags['binding'] = replace(marker, authority=replace(marker.authority, callee_entry_offset=-4))
    second = observe_structured_ast_output_8616(actual)
    assert second.complete and second.snapshot is not None
    assert first.snapshot.digest != second.snapshot.digest
