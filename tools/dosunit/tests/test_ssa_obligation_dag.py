"""Bound work by DAG nodes, and preserve inline-obligation semantics."""
from typing import Any

import z3

from tools.dosunit.compare import straightline_ssa as S


class BudgetDict(dict[str, Any]):
    """Fail deterministically on an exponentially repeated node traversal."""
    accesses=0

    def get(self, key: str, default: Any = None) -> Any:
        """Count accesses and stop before an exponential regression hangs."""
        type(self).accesses += 1
        assert type(self).accesses <= 2000, "shared DAG expanded as a tree"
        return super().get(key,default)


def dag(depth: int) -> BudgetDict:
    """Build repeated additions with two edges to each shared child."""
    BudgetDict.accesses=0
    term=BudgetDict(op="input",name="value",width=64)
    for _ in range(depth):
        term=BudgetDict(op="add",width=64,args=[term,term])
    return term


def test_input_collection_is_linear_for_shared_nodes() -> None:
    term=dag(70)
    memory=BudgetDict(op="mem_input",name="mem",addr_width=32,value_width=8)
    root=BudgetDict(op="synthetic_container",args=[term,term,memory])
    assert S._term_named_inputs(root)=={"value","mem"}


def test_flatten_preserves_shared_arithmetic() -> None:
    term=dag(24)
    value=z3.BitVec("value",64)
    actual=S._z3_obligation_term(term,document={},inputs={"value":(value,64)},z3=z3)
    solver=z3.Solver()
    solver.add(actual != value*(1<<24))
    assert solver.check()==z3.unsat


def test_existing_assignment_name_is_not_overwritten() -> None:
    document={"assignments":[{"id":"__x87_obligation_0","op":"add","width":32,
        "args":[{"op": "const","width": 32,"value": "0x3"},{"op": "const","width": 32,"value": "0x4"}]}]}
    term={"op": "add","width": 32,"args": [{"ref":"__x87_obligation_0"},
                                      {"op": "const","width": 32,"value": "0x5"}]}
    actual=S._z3_obligation_term(term,document=document,inputs={},z3=z3)
    assert z3.simplify(actual).as_long()==12


def test_input_collection_terminates_on_cycle() -> None:
    term={"op": "container"}
    term["args"]=[term,{"op": "input","name": "eax","width": 32}]
    assert S._term_named_inputs(term)=={"eax"}
