"""Binary-only far-load recovery must preserve the low stack argument word."""

import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.stack_memory_ssa_contracts import StackMemoryAliasFactKind8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import AddressStatus, MemSpace
from angr_platforms.X86_16.ir.logical_memory_contracts import IRMemoryAccessKind8616
from angr_platforms.X86_16.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthEvidence8616,
    CalleeArgumentWidthVerdict8616,
)
from angr_platforms.X86_16.lowering.live_stack_word_inputs import _entry_word_evidence
from angr_platforms.X86_16.lowering.positive_bp_argument_plan import (
    PositiveBpArgumentPlanDecision8616,
    PositiveBpArgumentPlanEntry8616,
    complete_positive_bp_argument_plan_8616,
)
from angr_platforms.X86_16.lowering.positive_bp_arguments import _argument_type_for_proven_stack_width_8616
from angr_platforms.X86_16.lowering.stack_function_coordinates import final_c_function_machine_bp_offset_8616
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.lowering.wide_stack_argument_views import (
    WideStackArgumentOwner8616,
    materialize_wide_stack_argument_subviews_8616,
)
from angr_platforms.X86_16.tail_validation import refresh_x86_16_final_semantic_validation_8616
from test_x86_16_cod_samples import _decompile_blob, _project_from_bytes
from test_x86_16_positive_bp_argument_plan import _closed_three_word_evidence


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("55 8b ec 8b 46 04 5d c3", id="mov-word-control"),
        pytest.param("55 8b ec 06 c4 7e 04 8b c7 07 5d c3", id="les-saved-es"),
    ],
)
def test_stack_word_return_compiles_and_preserves_both_bytes(tmp_path, body):
    """LES with restored ES must return the same low word as MOV AX,[BP+4]."""
    recovered = _decompile_blob(bytes.fromhex(body))
    source = """
#include <stdint.h>
uint32_t inertia_ebp;
uint16_t inertia_ss;
uint16_t inertia_es;
#define _start recovered_word
""" + recovered + """
#undef _start
int main(void) {
    if (recovered_word(0x1234) != 0x1234) return 1;
    if (recovered_word(0x80ff) != 0x80ff) return 2;
    if (recovered_word(0xff00) != 0xff00) return 3;
    inertia_ss = 0x1234;
    if (recovered_word(0x1234) != 0x1234) return 4;
    return 0;
}
"""
    executable = tmp_path / "stack_word"
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-pedantic-errors", "-o", str(executable), "-"],
        input=source, capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + "\n" + recovered
    executed = subprocess.run([str(executable)], check=False)
    assert executed.returncode == 0, recovered


def test_live_les_segment_return_has_defined_input_bytes(tmp_path):
    """Returning the loaded segment requires its input even when ES is restored."""
    project = _project_from_bytes(bytes.fromhex("55 8b ec 06 c4 7e 04 8c c0 07 5d c3"))
    cfg = project.analyses.CFGFast(normalize=True)
    decompiled = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert decompiled.codegen is not None
    report = refresh_x86_16_final_semantic_validation_8616(
        project, decompiled.codegen, persist_failures=False,
    )
    assert report.def_use.passed, report.def_use.issue_tokens()
    assert report.passed, report
    recovered = decompiled.codegen.text
    source = "unsigned short inertia_es;\n#define _start recovered_segment\n" + recovered + """
int main(void) {
    inertia_es = 0xa731;
    if (recovered_segment(0x1234, 0x80ff) != 0x80ff) return 1;
    if (recovered_segment(0xffff, 0x1234) != 0x1234) return 2;
    if (recovered_segment(0, 0xff00) != 0xff00) return 3;
    if (inertia_es != 0xa731) return 4;
    return 0;
}
"""
    executable = tmp_path / "live_segment"
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-pedantic-errors", "-o", str(executable), "-"],
        input=source, capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + recovered
    assert subprocess.run([str(executable)], check=False).returncode == 0, recovered


@pytest.mark.parametrize(
    ("has_owner", "kind", "version", "expected"),
    [
        (True, IRMemoryAccessKind8616.READ, 0, {6}),
        (False, IRMemoryAccessKind8616.READ, 0, set()),
        (True, IRMemoryAccessKind8616.WRITE, 0, set()),
        (True, IRMemoryAccessKind8616.READ, 1, set()),
        (True, IRMemoryAccessKind8616.READ, None, set()),
    ],
)
def test_live_word_requires_logical_entry_owner(has_owner, kind, version, expected):
    """Adjacent incoming bytes alone must not invent a logical word parameter."""
    def address(offset, size, version):
        return SimpleNamespace(
            space=MemSpace.SS, base=("bp",), status=AddressStatus.STABLE,
            offset=offset, size=size, version=version,
        )

    facts = tuple(
        SimpleNamespace(kind=StackMemoryAliasFactKind8616.LOAD, address=address(offset, 1, 0))
        for offset in (6, 7)
    )
    owner = SimpleNamespace(
        source=SimpleNamespace(kind=kind), address=address(6, 2, None),
        slices=tuple(
            SimpleNamespace(raw_slice=SimpleNamespace(address=address(offset, 1, version)))
            for offset in (6, 7)
        ),
    )
    candidates, incoming, written = _entry_word_evidence(SimpleNamespace(
        facts=facts, logical_accesses=(owner,) if has_owner else (),
    ))
    assert candidates == expected
    assert incoming == {6, 7}
    assert not written


@pytest.mark.parametrize(
    ("physical", "logical", "accepted"),
    [
        ((2, 2, 2, 2), (), True),
        ((2, 2, 2), (), False),
        ((2, 4, 2), (), False),
        ((4, 2, 2), (), False),
        ((2, 2, 4), (), True),
        ((2, 2, 2, 2), (2, 2, 4), False),
    ],
)
def test_proven_body_grouping_requires_complete_physical_boundaries(physical, logical, accepted):
    """Body grouping may join PUSH slots, but never split one or override a proven grouping."""
    count = _closed_three_word_evidence(complete_sources=False)
    summary = replace(
        count.callsite_summaries[0], arg_count=len(physical), arg_widths=physical,
        logical_arg_widths=logical,
    )
    count = replace(count, callsite_summaries=(summary,))
    evidence = CalleeArgumentWidthEvidence8616(
        target_addr=count.target_addr, verdict=CalleeArgumentWidthVerdict8616.UNKNOWN,
        raw_fact_count=1, count_evidence=count,
    )
    body = tuple(
        PositiveBpArgumentPlanEntry8616(offset, width, f"arg_{offset}", SimTypeShort(False))
        for offset, width in ((4, 4), (8, 2), (10, 2))
    )
    plan = complete_positive_bp_argument_plan_8616(body, evidence, default_argument_type=SimTypeShort(False))
    expected = (
        PositiveBpArgumentPlanDecision8616.BODY_CALLER_PHYSICAL
        if accepted else PositiveBpArgumentPlanDecision8616.REFUSE
    )
    assert plan.decision is expected


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize(("width", "bits"), [(None, 8), (2, 16), (4, 32)])
def test_proven_argument_width_promotes_byte_value_not_only_slot(signed, width, bits):
    """A byte view must supply the entire proven value without changing signedness."""
    project = SimpleNamespace(arch=Arch86_16())
    original = SimTypeChar(signed=signed).with_arch(project.arch)
    recovered = _argument_type_for_proven_stack_width_8616(project, original, proven_width=width)
    assert recovered.size == bits
    assert recovered.signed is signed


def _wide_argument_view(offset, size):
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), next_node_idx=lambda: 0,
        next_ident=lambda name: f"{name}_0", display_vvar_ids=False, cstyle_null_cmp=False,
        stmt_comments={}, expr_comments={}, const_formats={},
    )
    owner = CVariable(
        SimStackVariable(4, 4, base="bp", name="wide"),
        variable_type=SimTypeLong(False), codegen=codegen,
    )
    view = CVariable(
        SimStackVariable(offset, size, base="bp", name="unbound"),
        variable_type=SimTypeChar(signed=False) if size == 1 else SimTypeShort(False), codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([CReturn(view, codegen=codegen)], codegen=codegen))
    return codegen, owner, view


@pytest.mark.parametrize("offset", [4, 8])
def test_registered_argument_coordinate_precedes_interface_delta(offset):
    codegen, owner, _view = _wide_argument_view(offset, 1)
    owner.variable.offset = offset
    codegen.cfunc.arg_list = [owner]
    codegen.cfunc.functy = SimTypeFunction([SimTypeLong()], SimTypeLong()).with_arch(codegen.project.arch)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=owner.variable, cvar=owner,
        bp_offset=offset, entry_sp_offset=offset - 2, size=4,
    )
    assert final_c_function_machine_bp_offset_8616(codegen, owner.variable) == offset
    unified = SimStackVariable(offset, 4, base="bp", name="unrelated_spelling")
    owner.unified_variable = unified
    assert final_c_function_machine_bp_offset_8616(codegen, unified) == offset
    replacement = CVariable(
        SimStackVariable(offset, 4, base="bp"),
        unified_variable=SimStackVariable(offset, 4, base="bp"),
        variable_type=SimTypeLong(), codegen=codegen,
    )
    codegen.cfunc.arg_list = [replacement]
    assert final_c_function_machine_bp_offset_8616(codegen, replacement.unified_variable) == offset


@pytest.mark.parametrize("offset", [4, 8])
def test_byte_materialization_does_not_rebind_wide_argument(offset):
    """Raw BP offsets must not impersonate registered entry-SP coordinates."""
    codegen, owner, _view = _wide_argument_view(offset, 1)
    owner.variable.offset = offset
    codegen.cfunc.arg_list = [owner]
    codegen.cfunc.variables_in_use = {owner.variable: owner}
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=owner.variable, cvar=owner,
        bp_offset=offset, entry_sp_offset=offset - 2, size=4,
    )
    byte = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen, offset, size=1, machine_bp_offset=offset + 2,
    )
    assert byte is not owner
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(owner.variable)
    assert (projection.bp_offset, projection.entry_sp_offset, projection.size) == (offset, offset - 2, 4)


def test_long_sum_saved_registers_keep_argument_coordinates():
    """Additional native restore definitions cannot move the final argument reads."""
    project = _project_from_bytes(bytes.fromhex(
        "55 8b ec 57 56 8b 46 08 8b 56 0a 03 46 04 13 56 06 "
        "5e 5f 8b e5 5d c3"
    ))
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[0x1000]
    function.prototype = SimTypeFunction(
        [SimTypeLong(), SimTypeLong()], SimTypeLong(),
    ).with_arch(project.arch)
    codegen = project.analyses.Decompiler(function, cfg=cfg).codegen
    report = refresh_x86_16_final_semantic_validation_8616(project, codegen, persist_failures=False)
    assert report.def_use.passed, report.def_use.issue_tokens()
    assert report.passed, report


@pytest.mark.parametrize("offset", [4, 5, 6, 7])
def test_wide_argument_byte_views_compile_and_return_exact_byte(tmp_path, offset):
    codegen, owner, _view = _wide_argument_view(offset, 1)
    result = materialize_wide_stack_argument_subviews_8616(codegen, (WideStackArgumentOwner8616(4, 4, owner),))
    assert result.materialized_count == 1
    assert result.failure_count == 0
    expression = codegen.cfunc.statements.statements[0].retval.c_repr()
    source = f"""
unsigned f(unsigned long wide) {{ return {expression}; }}
int main(void) {{ return f(0x80ff1234UL) != {(0x80ff1234 >> ((offset - 4) * 8)) & 0xff}; }}
"""
    executable = tmp_path / "byte_view"
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), "-"],
        input=source, capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    assert subprocess.run([str(executable)], check=False).returncode == 0


@pytest.mark.parametrize("mode", ["write", "reference", "ambiguous"])
def test_wide_argument_word_view_refuses_nonvalue_or_ambiguous_use(mode):
    codegen, owner, view = _wide_argument_view(6, 2)
    owners = (WideStackArgumentOwner8616(4, 4, owner),)
    if mode == "write":
        node = CAssignment(view, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    elif mode == "reference":
        node = CUnaryOp("Reference", view, codegen=codegen)
    else:
        node = view
        owners = (*owners, owners[0])
    codegen.cfunc.statements = CStatements([node], codegen=codegen)
    result = materialize_wide_stack_argument_subviews_8616(codegen, owners)
    assert result.materialized_count == 0
    assert view.variable in result.retained_variables
