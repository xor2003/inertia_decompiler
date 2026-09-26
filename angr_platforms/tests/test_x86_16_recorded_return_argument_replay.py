"""Recorded return replay must not consume an unrelated following argument."""

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _materialize_callsite_stack_arguments_8616,
)
from test_x86_16_decompiler_postprocess_calls import _empty_codegen, _project


def test_recorded_ax_return_keeps_following_immediate_argument():
    project = _project()
    codegen = _empty_codegen(project)
    producer = CFunctionCall(
        "sub_2000",
        SimpleNamespace(addr=0x2000, name="sub_2000", block_addrs_set={0x2000}),
        [CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    consumer = CFunctionCall(
        "sub_3000",
        SimpleNamespace(addr=0x3000, name="sub_3000", block_addrs_set={0x3000}),
        [],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CExpressionStatement(consumer, codegen=codegen)], addr=0x4010, codegen=codegen
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_callsite_return_exprs_8616 = {0x1001: producer}
    codegen._inertia_callsite_summaries = {
        id(consumer): CallsiteSummary8616(
            callsite_addr=0x1008,
            target_addr=0x3000,
            return_addr=0x100B,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register="ax",
            return_used=False,
            push_arg_sources=(("imm", 7), ("ret_reg", 0x1001, "ax")),
        )
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen)
    assert len(consumer.args) == 2
    assert isinstance(consumer.args[0], CFunctionCall)
    assert consumer.args[0].callee_target == "sub_2000"
    assert isinstance(consumer.args[1], CConstant)
    assert consumer.args[1].value == 7


@pytest.mark.parametrize("base, actual_offset, expected_clear", [
    ("bp", -4, True), ("bp", -6, False), ("sp", -4, False),
])
def test_exact_stack_argument_sanitizer_preserves_unproven_identity(base, actual_offset, expected_clear):
    from angr.analyses.decompiler import structured_codegen
    from angr.sim_variable import SimStackVariable

    # Exercise the nested compatibility guard without exporting it as a public API.
    source = Path(inspect.getfile(_materialize_callsite_stack_arguments_8616)).read_text()
    node = next(
        node for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef)
        and node.name == "_sanitize_exact_negative_bp_call_arg_cvar_8616"
    )
    module = ast.Module(body=[node], type_ignores=[])
    namespace = {
        "StructuredAstValue": object,
        "structured_c": structured_codegen.c,
        "SimStackVariable": SimStackVariable,
        "codegen": None,
        "call_argument_stack_variable_offset_8616": lambda _codegen, _expr: actual_offset,
    }
    exec(compile(module, "<stack-argument-guard>", "exec"), namespace)
    codegen = _empty_codegen(_project())
    variable = SimStackVariable(actual_offset, 2, base=base)
    unified = SimStackVariable(4, 2, base="bp")
    expr = structured_codegen.c.CVariable(
        variable, unified_variable=unified, variable_type=SimTypeShort(False), codegen=codegen,
    )

    sanitizer_self = SimpleNamespace(codegen=codegen)
    assert namespace[node.name](sanitizer_self, expr, -4) is expr
    assert expr.unified_variable is (None if expected_clear else unified)
