"""Regress ownership of void-return normalization.

Layer: postprocess orchestration
Responsibility: keep return-shape normalization before validation baseline capture.
"""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16 import decompiler_postprocess as postprocess
from angr_platforms.X86_16 import decompiler_postprocess_stage as post_stage
from angr_platforms.X86_16.arch_86_16 import Arch86_16


def test_void_return_pruning_runs_only_during_prevalidation_priming(monkeypatch) -> None:
    """Do not repeat a baseline-defining mutation inside validated cleanup passes."""
    calls: list[str] = []
    monkeypatch.setattr(
        post_stage._post,
        "_classify_return_shape_8616",
        lambda _project, _codegen: calls.append("classify") or False,
    )
    monkeypatch.setattr(
        post_stage._post,
        "_prune_void_function_return_values_8616",
        lambda _project, _codegen: calls.append("prune") or True,
    )
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = post_stage._prime_return_shape_before_validation_baseline_8616(SimpleNamespace(), codegen)

    assert changed is True
    assert calls == ["classify", "prune"]
    assert "_prune_void_function_return_values_8616" not in {
        spec.name for spec in post_stage.DECOMPILER_POSTPROCESS_PASSES
    }


@pytest.mark.parametrize("nested_definition", [False, True])
def test_void_return_normalization_preserves_live_call_definition(monkeypatch, nested_definition):
    """A void caller still needs results used outside the defining statement list."""
    codegen = SimpleNamespace(
        next_ident=lambda name: name, next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
    )
    variable = SimRegisterVariable(0, 2, ident="ir_8", name="v14", region=0x1000)
    carrier = structured_c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    call = structured_c.CFunctionCall("callee", None, [], codegen=codegen)
    assignment = structured_c.CAssignment(carrier, call, codegen=codegen)
    condition = structured_c.CBinaryOp(
        "CmpEQ", carrier, structured_c.CConstant(27, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    branch = structured_c.CIfElse(
        [(condition, structured_c.CStatements([structured_c.CReturn(None, codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    definition_scope = structured_c.CStatements([assignment], codegen=codegen)
    root = structured_c.CStatements(
        [definition_scope, branch] if nested_definition else [assignment, branch], codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, variables_in_use={variable: carrier})
    monkeypatch.setattr(postprocess, "_codegen_has_void_return_evidence_8616", lambda *_args: True)

    changed = postprocess._prune_void_function_return_values_8616(SimpleNamespace(), codegen)

    assert changed is False
    actual_scope = definition_scope if nested_definition else root
    assert actual_scope.statements[0] is assignment
    assert assignment.rhs is call
    assert branch.condition_and_nodes[0][0].lhs is carrier
    assert codegen.cfunc.variables_in_use[variable] is carrier
