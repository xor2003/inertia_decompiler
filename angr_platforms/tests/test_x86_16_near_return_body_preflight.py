"""Binary-backed body census and stale-plan controls for near-return lowering."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.lowering.gp_word_assignment import CGPWordAssignment8616
from angr_platforms.X86_16.lowering.near_return_body_preflight import (
    NearReturnBodyFailure8616,
    preflight_near_return_body_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from test_x86_16_near_return_expression import _build, _congruence, _selector


def _body():
    codegen, congruence, variables = _congruence()
    candidate = _build(codegen, congruence)
    returned = structured_c.CReturn(congruence.expression, codegen=codegen)
    return codegen, candidate, variables, returned


def test_retained_body_plan_is_nonpublishing_and_replayable():
    codegen, candidate, _, returned = _body()
    prefix = structured_c.CFunctionCall("other", None, [_selector(codegen, 7)], codegen=codegen)
    root = structured_c.CStatements([prefix, returned], codegen=codegen)
    result = preflight_near_return_body_8616(root, candidate)
    assert result.complete and result.return_node is returned
    assert root.statements == [prefix, returned]
    assert returned.retval is candidate.congruence.expression
    assert (result.raw_fact_count, result.normalized_fact_count, result.classified_fact_count,
            result.materialized_count, result.failure_count) == (1, 1, 1, 1, 0)
    assert not replace(result, raw_fact_count=True).complete
    assert not replace(result, return_node=structured_c.CReturn(returned.retval, codegen=codegen)).complete
    root.statements.append(structured_c.CReturn(_selector(codegen, 0), codegen=codegen))
    assert not result.complete


@pytest.mark.parametrize("mode", ("arithmetic", "call", "assignment", "reference"))
def test_every_base_use_outside_return_blocks_retyping(mode):
    codegen, candidate, variables, returned = _body()
    base = variables["base"]
    other = {
        "arithmetic": structured_c.CBinaryOp("Add", base, _selector(codegen, 1), codegen=codegen),
        "call": structured_c.CFunctionCall("other", None, [base], codegen=codegen),
        "assignment": structured_c.CAssignment(variables["index"], base, codegen=codegen),
        "reference": structured_c.CUnaryOp("Reference", base, codegen=codegen),
    }[mode]
    root = structured_c.CStatements([other, returned], codegen=codegen)
    result = preflight_near_return_body_8616(root, candidate)
    assert not result.complete and result.failure is NearReturnBodyFailure8616.BASE_USE_OUTSIDE_RETURN
    assert result.classified_fact_count == result.materialized_count == 0
    assert result.failure_count == 1


def test_scalar_index_uses_and_unrelated_calls_survive():
    codegen, candidate, variables, returned = _body()
    call = structured_c.CFunctionCall("other", None, [variables["index"]], codegen=codegen)
    root = structured_c.CStatements([call, returned], codegen=codegen)
    assert preflight_near_return_body_8616(root, candidate).complete
    assert root.statements[0] is call


@pytest.mark.parametrize("base_use", (False, True))
def test_owned_register_assignment_and_semantic_cast_are_censused(base_use):
    codegen, candidate, variables, returned = _body()
    value = variables["base"] if base_use else variables["index"]
    converted = CSemanticCast8616(value.variable_type, value.variable_type, value, codegen=codegen)
    saved = CGPWordAssignment8616(variables["index"], converted, codegen=codegen)
    root = structured_c.CStatements([saved, returned], codegen=codegen)
    result = preflight_near_return_body_8616(root, candidate)
    if base_use:
        assert result.failure is NearReturnBodyFailure8616.BASE_USE_OUTSIDE_RETURN
    else:
        assert result.complete
    assert root.statements[0] is saved and saved.rhs is converted


def test_owned_assignment_subclass_still_refuses_unregistered_fields():
    codegen, candidate, variables, returned = _body()
    class ExtendedAssignment(CGPWordAssignment8616):
        pass
    saved = ExtendedAssignment(variables["index"], variables["index"], codegen=codegen)
    result = preflight_near_return_body_8616(structured_c.CStatements([saved, returned], codegen=codegen), candidate)
    assert result.failure is NearReturnBodyFailure8616.BODY_CENSUS_UNPROVEN


def test_distinct_cvariable_for_the_same_argument_cannot_hide_an_extra_use():
    codegen, candidate, variables, returned = _body()
    base = variables["base"]
    alias = structured_c.CVariable(base.variable, variable_type=base.variable_type, codegen=codegen)
    root = structured_c.CStatements([alias, returned], codegen=codegen)
    assert preflight_near_return_body_8616(root, candidate).failure is NearReturnBodyFailure8616.BASE_USE_OUTSIDE_RETURN


@pytest.mark.parametrize("mode", ("unknown", "cycle", "subclass", "reference_substitution"))
def test_incomplete_body_census_refuses_without_deleting_code(mode):
    codegen, candidate, variables, returned = _body()
    root = structured_c.CStatements([returned], codegen=codegen)
    if mode == "unknown":
        root.statements.append(object())
    elif mode == "cycle":
        root.statements.append(root)
    elif mode == "subclass":
        class ExtendedReturn(structured_c.CReturn):
            pass
        root.statements.append(ExtendedReturn(_selector(codegen, 0), codegen=codegen))
    else:
        literal = _selector(codegen, 0)
        literal.reference_values = {0: variables["base"]}
        root.statements.append(literal)
    result = preflight_near_return_body_8616(root, candidate)
    assert not result.complete and result.failure is NearReturnBodyFailure8616.BODY_CENSUS_UNPROVEN
    assert root.statements[0] is returned


def test_volatile_argument_and_detached_return_refuse():
    codegen, candidate, variables, returned = _body()
    returned.retval = _selector(codegen, 0)
    assert preflight_near_return_body_8616(returned, candidate).failure is NearReturnBodyFailure8616.RETURN_UNBOUND
    returned.retval = candidate.congruence.expression
    variables["base"].variable_type = SimTypeShort(False, qualifier=["volatile"]).with_arch(codegen.project.arch)
    assert preflight_near_return_body_8616(returned, candidate).failure is NearReturnBodyFailure8616.VOLATILE_OPERAND
