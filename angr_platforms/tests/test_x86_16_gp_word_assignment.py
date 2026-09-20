"""Check word rendering against its canonical register effect and mutations."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeFloat, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimTemporaryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_assignment_8616
from angr_platforms.X86_16.lowering.gp_word_assignment import CGPWordAssignment8616
from angr_platforms.X86_16.lowering.gp_word_runtime import (
    GPRegisterRuntimeABI8616 as ABI,
)
from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    select_gp_runtime_abi_8616,
)
from angr_platforms.X86_16.lowering.terminal_return_expressions import _safe_scalar_expression_8616
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint, _location_fingerprint
from test_x86_16_gp_stack_restore import _Codegen

from inertia_decompiler.cli_c_text_postprocess import (
    _collect_declared_identifiers_8616,
    _materialize_missing_synthetic_global_declarations_text,
    _prune_unused_local_declarations_text,
)
from inertia_decompiler.cli_decompilation import _materialize_codegen_global_externs_text_8616


def _assignment(register="si", abi=ABI.COHERENT_WORD_VIEWS):
    codegen = _Codegen(
        project=SimpleNamespace(arch=Arch86_16()), use_compound_assignments=False,
        const_formats={}, display_vvar_ids=False, show_casts=True,
    )
    select_gp_runtime_abi_8616(codegen, abi)
    value = c.CConstant(123, SimTypeShort(False), codegen=codegen)
    assignment = runtime_gp_state_assignment_8616(register, value, codegen=codegen, function_addr=0x1000)
    assert assignment is not None
    return assignment


def _render(assignment, **kwargs):
    return "".join(chunk for chunk, _ in assignment.c_repr_chunks(**kwargs))


@pytest.mark.parametrize("register", ["ax", "bx", "cx", "dx", "si", "di", "sp", "bp"])
def test_word_statement_uses_shared_lvalue_without_mutating_full_effect(register):
    assignment = _assignment(register)
    assert isinstance(assignment, CGPWordAssignment8616)
    original_rhs = assignment.rhs
    assert _render(assignment).strip() == f"inertia_{register} = 123;"
    assert assignment.rhs is original_rhs
    assert assignment.rhs.lhs.rhs.value == 0xffff0000
    assert assignment.rhs.rhs.rhs.value == 0xffff
    assert assignment.rhs.rhs.lhs in tuple(_iter_c_nodes_deep_8616(assignment))
    clone = _clone_c_ast_tree_8616(assignment)
    assert _render(clone) == _render(assignment)


@pytest.mark.parametrize("mutation", ["mask", "parent", "call", "narrow_parent"])
def test_mutated_proof_never_uses_stale_word_projection(mutation):
    assignment = _assignment()
    if mutation == "mask":
        assignment.rhs.lhs.rhs.value = 0xffffff00
    elif mutation == "parent":
        assignment.rhs.lhs.lhs = _assignment("di").lhs
    elif mutation == "narrow_parent":
        parent = assignment.rhs.lhs.lhs
        assignment.rhs.lhs.lhs = c.CTypeCast(
            parent.type, SimTypeShort(False), parent, codegen=assignment.codegen,
        )
    else:
        assignment.rhs.rhs.lhs = c.CFunctionCall("mutate_register", None, [], codegen=assignment.codegen)
    assert _render(assignment).startswith("inertia_esi = ")


def test_assignment_expression_and_legacy_abi_retain_full_value():
    assignment = _assignment()
    assert _render(assignment, asexpr=True).startswith("inertia_esi = ")
    select_gp_runtime_abi_8616(assignment.codegen, ABI.SCALAR)
    assert _render(assignment).startswith("inertia_esi = ")
    assert not isinstance(_assignment(abi=ABI.SCALAR), CGPWordAssignment8616)


def test_byte_write_is_not_projected_as_whole_word():
    assert not isinstance(_assignment("al"), CGPWordAssignment8616)


def test_word_write_can_read_a_typed_scalar_temporary_without_resolving_its_definition():
    assignment = _assignment()
    temporary = c.CVariable(SimTemporaryVariable(0, 2), variable_type=SimTypeShort(False), codegen=assignment.codegen)
    assignment.rhs.rhs.lhs = temporary
    assert _render(assignment).strip() == "inertia_si = tmp_0;"
    assert assignment.rhs.rhs.lhs is temporary
    assert not _safe_scalar_expression_8616(temporary)


@pytest.mark.parametrize("value_type", [SimTypeFloat(), SimTypePointer(SimTypeShort(False))])
def test_noninteger_temporary_is_not_projected(value_type):
    assignment = _assignment()
    assignment.rhs.rhs.lhs = c.CVariable(
        SimTemporaryVariable(0, 4), variable_type=value_type, codegen=assignment.codegen,
    )
    assert _render(assignment).startswith("inertia_esi = ")


def test_macro_before_aggregate_is_not_a_function_body():
    source = """#define get_state (storage.full)
typedef struct item {
    char field_0;
    char field_1;
} item;
void update(item *value)
{
    value->field_0 = 1;
}
"""
    assert _prune_unused_local_declarations_text(source) == source


def test_runtime_full_view_macro_never_gets_a_synthetic_extern():
    from angr_platforms.X86_16.lowering.gp_word_runtime import coherent_gp_runtime_header_8616

    source = coherent_gp_runtime_header_8616() + "unsigned long read_lane(void)\n{\n    return inertia_esi;\n}\n"
    assert "extern unsigned short inertia_esi;" not in _materialize_missing_synthetic_global_declarations_text(source)


def test_macro_lvalues_are_already_declared_identifiers():
    assert "inertia_esi" in _collect_declared_identifiers_8616([
        "#define inertia_esi (inertia_gp_esi.full)",
    ])


def test_runtime_header_does_not_move_globals_before_existing_typedef():
    codegen = _assignment().codegen
    definition = "typedef struct entry {\n    char field;\n} entry;"
    codegen._inertia_named_type_definitions_8616 = (definition,)
    codegen._inertia_global_declaration_specs_8616 = (("entry", "g_1234", None),)
    source = "void helper(void);\n" + definition + "\nvoid update(void)\n{\n    g_1234.field = 1;\n}\n"
    exported = _materialize_codegen_global_externs_text_8616(source, codegen)
    assert exported.index(definition) < exported.index("extern entry g_1234;")


def test_word_projection_regressions_run_in_default_pipeline():
    """Make's focused list alone does not enroll tests in the curated pipeline."""
    from scripts.test_pipeline import FOCUSED_PYTEST_TARGETS

    assert "angr_platforms/tests/test_x86_16_gp_word_runtime.py" in FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_gp_word_assignment.py" in FOCUSED_PYTEST_TARGETS


def test_canonical_validation_fingerprints_survive_word_rendering():
    assignment = _assignment()
    project = assignment.codegen.project
    before = (_location_fingerprint(assignment.lhs, project), _expr_fingerprint(assignment.rhs, project))
    assert "inertia_si = " in _render(assignment)
    after = (_location_fingerprint(assignment.lhs, project), _expr_fingerprint(assignment.rhs, project))
    assert before == after
    assert before[0] == "reg:esi"


@pytest.mark.parametrize("legacy_extern", ["", "extern unsigned short inertia_esi;\n"])
@pytest.mark.parametrize("temporary_value", [False, True])
def test_actual_lowering_and_declaration_output_compile_and_preserve_upper_word(tmp_path, legacy_extern, temporary_value):
    """Compile the renderer's actual output, not a hand-written word assignment."""
    compiler = shutil.which("gcc")
    assert compiler is not None, "GCC is required for the GP word projection gate"
    assignment = _assignment()
    local = ""
    if temporary_value:
        assignment.rhs.rhs.lhs = c.CVariable(
            SimTemporaryVariable(0, 4), variable_type=SimTypeLong(False), codegen=assignment.codegen,
        )
        local = "unsigned long tmp_0 = 0x1234007bUL;\n"
    body = legacy_extern + "void update(void) {\n" + local + _render(assignment) + "}\n"
    exported = _materialize_codegen_global_externs_text_8616(body, assignment.codegen)
    exported = _materialize_missing_synthetic_global_declarations_text(exported)
    assert "extern unsigned long inertia_esi;" not in exported
    assert _materialize_codegen_global_externs_text_8616(exported, assignment.codegen) == exported
    source = exported + coherent_gp_runtime_definitions_8616() + """
int main(void) {
    inertia_esi = 0xabcdffffUL;
    update();
    return inertia_esi != 0xabcd007bUL;
}
"""
    executable = tmp_path / "word_projection"
    compiled = subprocess.run(
        [compiler, "-std=c89", "-pedantic-errors", "-Wall", "-Wextra", "-Werror",
         "-O2", "-fstrict-aliasing", "-x", "c", "-", "-o", str(executable)],
        input=source, capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    run = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=10)
    assert run.returncode == 0, run.stderr
