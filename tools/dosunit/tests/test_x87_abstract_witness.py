"""An arbitrary transcendental model must not become a hardware counterexample."""

import z3

from tools.dosunit.ssa.x87_abstract_witness import counterexample_scope


def test_nonconcrete_output_does_not_hide_a_concrete_register_mismatch():
    from tools.dosunit.compare.straightline_ssa import _z3_mismatch_list

    solver = z3.Solver()
    assert solver.check() == z3.sat
    payload = z3.BitVec("unavailable_output", 32)

    class PartialModel:
        """Reproduce the symbolic BitVecRef returned by the native failing run."""

        def eval(self, expression, model_completion):
            if z3.eq(expression, payload):
                return payload
            return solver.model().eval(expression, model_completion=model_completion)

    result = _z3_mismatch_list(
        [("x87_payload", payload, z3.BitVecVal(0, 32)),
         ("eax", z3.BitVecVal(3, 32), z3.BitVecVal(4, 32))],
        model=PartialModel(), counterexample={}, z3=z3)
    assert [item["reg"] for item in result] == ["eax"]


def test_missing_numeric_witness_is_not_published_as_a_failure(monkeypatch):
    from tools.dosunit.compare import straightline_ssa as ssa

    def unavailable(pairs, *, model, counterexample, z3, non_concrete_outputs):
        non_concrete_outputs.append("eax")
        return []

    monkeypatch.setattr(ssa, "_z3_mismatch_list", unavailable)
    left = {"outputs": {"eax": {"op": "const", "width": 32, "value": "0x0"}}}
    right = {"outputs": {"eax": {"op": "const", "width": 32, "value": "0x1"}}}
    result = ssa._compare_functions(left, right, timeout_ms=1000)
    assert result["status"] == "refused", result
    assert result["reason"] == "counterexample_outputs_not_concrete"
    assert result["non_concrete_model_outputs"] == ["eax"]


def terms():
    x = z3.BitVec("x", 80)
    approximation = z3.Function("x87_trans_sin", z3.BitVecSort(80), z3.BitVecSort(80))(x)
    return x, approximation


def test_opaque_result_requires_validation():
    _, approximation = terms()
    scope = counterexample_scope([("st0", approximation, z3.BitVecVal(0, 80))], [])
    assert scope.abstract_outputs == ("st0",)
    assert not scope.exact_outputs


def test_exact_register_difference_is_separate_evidence():
    _, approximation = terms()
    scope = counterexample_scope([("st0", approximation, z3.BitVecVal(0, 80)),
                                  ("eax", z3.BitVecVal(0, 32), z3.BitVecVal(1, 32))], [])
    assert scope.exact_outputs == {"eax"}
    assert not scope.abstract_domain


def test_domain_dependency_cannot_be_ignored():
    _, approximation = terms()
    scope = counterexample_scope([("eax", z3.BitVecVal(0, 32), z3.BitVecVal(1, 32))],
                                 [approximation == z3.BitVecVal(7, 80)])
    assert scope.abstract_domain


def test_exact_constant_edge_eliminates_unselected_approximation():
    _, approximation = terms()
    edge = z3.If(z3.BoolVal(False), approximation, z3.BitVecVal(0, 80))
    scope = counterexample_scope([("st0", edge, z3.BitVecVal(1, 80))], [])
    assert scope.exact_outputs == {"st0"}
    assert not scope.abstract_outputs


def test_array_and_quantifier_bodies_are_scanned():
    _, approximation = terms()
    address = z3.BitVec("address", 32)
    memory = z3.Array("memory", z3.BitVecSort(32), z3.BitVecSort(80))
    scope = counterexample_scope([("memory", z3.Lambda(address, approximation), memory)], [])
    assert scope.abstract_outputs == ("memory",)
