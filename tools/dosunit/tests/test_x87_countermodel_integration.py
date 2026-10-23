"""Real numeric SSA operators must distinguish abstraction from exact witnesses."""
import pytest

from tools.dosunit.compare import straightline_ssa as S


def constant(value,width=80):
    return {"op": "const","width": width,"value": hex(value)}


def document(value=0x3fff8000000000000000):
    return {"outputs": {"x87_st0":{"ref":"sin"}},"inputs": [],"assignments": [
        {"id": "sin","op": "x87fp_sin","width": 80,"args": [constant(0x37f,16),constant(value)]}]}


@pytest.mark.parametrize("case",["abstract","same","edge","exact_other","abstract_domain"])
def test_actual_x87_comparator_countermodel_policy(case):
    left=document(0 if case=="edge" else 0x3fff8000000000000000)
    right={"outputs": {"x87_st0":constant(1 if case=="edge" else 0)},"inputs": [],"assignments": []}
    if case=="same":
        right=document()
    if case in {"exact_other","abstract_domain"}:
        left["outputs"]["eax"]=constant(0,32)
        right["outputs"]["eax"]=constant(1,32)
    if case=="abstract_domain":
        left["obligations"]=[{"kind": "checking_guard","predicate": {"op": "eq","width": 1,
            "args": [{"ref": "sin"},constant(0)]}}]
    result=S._compare_functions(left,right,timeout_ms=3000)
    expected={"abstract":"refused","same":"passed","edge":"failed", "exact_other":"failed","abstract_domain":"refused"}
    assert result["status"]==expected[case],result
    if case in {"abstract","abstract_domain"}:
        assert result["reason"]=="x87_transcendental_counterexample_unvalidated",result
    if case=="exact_other":
        assert [row["reg"] for row in result["mismatches"]]==["eax"]
