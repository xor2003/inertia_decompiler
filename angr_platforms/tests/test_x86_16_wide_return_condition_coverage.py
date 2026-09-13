"""Whole wide predicates retain every consumed branch's shared provenance."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.structuring.condition_chain_provenance import (
    CONDITION_CHAIN_PROVENANCE_TAG_8616,
    condition_chain_provenance_8616,
)
from angr_platforms.X86_16.structuring.condition_evidence_closure import classify_condition_evidence_closure_8616
from angr_platforms.X86_16.structuring.wide_stack_return_predicates import (
    WideStackReturnPredicateStatus8616,
    materialize_wide_stack_return_predicate_8616,
)
from test_x86_16_wide_stack_condition_chains import _adjacent, _Codegen, _condition


def _fixture():
    codegen = _Codegen()
    root = CStatements([], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    facts = (
        _condition("slt", 10, 6, 0x1000, 0x1030, 0x1010),
        _condition("eq", 10, 6, 0x1010, 0x1020, 0x1040),
        _condition("ult", 8, 4, 0x1020, 0x1030, 0x1040),
    )
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)

    def materialize(conditions):
        return materialize_wide_stack_return_predicate_8616(
            codegen, conditions, {}, _adjacent,
            lambda target: {0x1030: zero, 0x1040: one}.get(target),
            lambda lhs, rhs: lhs.value == rhs.value,
            lambda _: CBinaryOp("CmpLT", zero, one, codegen=codegen),
            effects_are_safe=True,
        )

    return codegen, facts, root, materialize


def test_wide_predicate_publishes_complete_condition_coverage():
    codegen, facts, _, materialize = _fixture()
    result = materialize(facts)
    assert result.status is WideStackReturnPredicateStatus8616.MATERIALIZED
    root = codegen.cfunc.statements
    predicate = root.statements[0].condition_and_nodes[0][0]
    provenance = condition_chain_provenance_8616(predicate)
    assert provenance is not None
    assert provenance.jcc_addrs == tuple(fact.src_insn for fact in facts)
    assert classify_condition_evidence_closure_8616(root, facts, {}).complete
    predicate.tags.pop(CONDITION_CHAIN_PROVENANCE_TAG_8616)
    assert not classify_condition_evidence_closure_8616(root, facts, {}).complete


@pytest.mark.parametrize("corruption", ["missing", "duplicate"])
def test_wide_predicate_refuses_incomplete_identity_before_replacing_body(corruption):
    codegen, facts, root, materialize = _fixture()
    first = replace(facts[0], src_insn=None if corruption == "missing" else facts[1].src_insn)
    result = materialize((first, *facts[1:]))
    assert result.status is WideStackReturnPredicateStatus8616.EXPRESSION_MATERIALIZATION_FAILED
    assert result.stats.classified_fact_count == len(facts)
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
    assert codegen.cfunc.statements is root
