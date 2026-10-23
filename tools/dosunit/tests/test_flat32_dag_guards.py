"""Exact branch reconvergence without expanding shared path histories."""

import pytest
import z3

from tools.dosunit.compare.flat32_dag_composition import _guard


def _input(name):
    return {"op": "input", "width": 1, "name": name}


def _not(value):
    return {"op": "not", "width": 1, "args": [value]}


def _term(op, left, right):
    return {"op": op, "width": 1, "args": [left, right]}


def _z3(term):
    if term["op"] == "input":
        return z3.BitVec(term["name"], term["width"])
    if term["op"] == "const":
        return z3.BitVecVal(int(term["value"], 0), term["width"])
    args = [_z3(arg) for arg in term["args"]]
    if term["op"] == "not":
        return ~args[0]
    return args[0] & args[1] if term["op"] == "and" else args[0] | args[1]


@pytest.mark.parametrize("outer,inner", [("or", "and"), ("and", "or")])
@pytest.mark.parametrize("reverse_left", [False, True])
@pytest.mark.parametrize("reverse_right", [False, True])
def test_reconverged_guards_keep_only_common_reachability(outer, inner, reverse_left, reverse_right):
    reach, branch = _input("reach"), _input("branch")
    left = [reach, branch]
    right = [reach, _not(branch)]
    if reverse_left:
        left.reverse()
    if reverse_right:
        right.reverse()
    original = _term(outer, _term(inner, *left), _term(inner, *right))
    reduced = _guard(outer, *original["args"])
    solver = z3.Solver()
    solver.add(_z3(original) != _z3(reduced))
    assert solver.check() == z3.unsat
    assert reduced is reach


def test_sequential_diamonds_do_not_accumulate_path_history():
    entry = _input("incoming_root_guard")
    reach = entry
    for index in range(128):
        branch = _input(f"branch_{index}")
        reach = _guard("or", _guard("and", reach, branch), _guard("and", reach, _not(branch)))
        assert reach is entry


@pytest.mark.parametrize("outer,inner", [("or", "and"), ("and", "or")])
def test_different_branch_or_incoming_guard_is_not_cancelled(outer, inner):
    reach, other, branch, different = (_input(name) for name in ("reach", "other", "c", "d"))
    for right in (_term(inner, other, _not(branch)), _term(inner, reach, _not(different))):
        left = _term(inner, reach, branch)
        reduced = _guard(outer, left, right)
        solver = z3.Solver()
        solver.add(_z3(reduced) != _z3(_term(outer, left, right)))
        assert solver.check() == z3.unsat
        solver = z3.Solver()
        solver.add(_z3(reduced) != _z3(reach))
        assert solver.check() == z3.sat


@pytest.mark.parametrize("op", ["and", "or"])
@pytest.mark.parametrize("value", [0, 1])
@pytest.mark.parametrize("reverse", [False, True])
def test_guard_constants_use_exact_one_bit_identities(op, value, reverse):
    live = _input("live")
    constant = {"op": "const", "width": 1, "value": hex(value)}
    args = [live, constant]
    if reverse:
        args.reverse()
    reduced = _guard(op, *args)
    solver = z3.Solver()
    solver.add(_z3(reduced) != _z3(_term(op, *args)))
    assert solver.check() == z3.unsat
    expected = live if (op == "and") == bool(value) else constant
    assert reduced is expected


def test_guard_reduction_does_not_treat_word_complements_as_boolean():
    value = {"op": "input", "width": 32, "name": "word"}
    negated = {"op": "not", "width": 32, "args": [value]}
    result = _guard("or", value, negated)
    assert result["op"] == "or"
    assert result["args"] == [value, negated]
