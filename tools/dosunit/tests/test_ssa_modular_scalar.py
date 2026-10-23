"""Exact modular scalar proofs preserve carries, truncations and all outputs."""
from __future__ import annotations

import time

import pytest
import z3

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.ssa.ssa_modular_scalar import prove_modular_identity
from tools.dosunit.ssa.ssa_output_lemmas import prove_output_equalities
from tools.dosunit.ssa.ssa_shared_subterms import _shared, prove_shared_scalar


@pytest.mark.parametrize("width", [8, 16, 32])
@pytest.mark.parametrize("delta", [0, 1])
def test_modular_polynomial_and_corrupted_coefficient(width: int, delta: int) -> None:
    a, b = z3.BitVecs("mod_a mod_b", width)
    left = (a * 60 + b) * 100
    right = (a * 4 + a * 8) * 500 + b * (100 + delta)
    assert prove_modular_identity(left, right, deadline=time.monotonic() + 3) is (delta == 0)


def test_narrow_add_carry_cannot_escape_its_width() -> None:
    a, b = z3.BitVecs("carry_a carry_b", 8)
    left = z3.Concat(z3.BitVecVal(0, 8), a + b)
    right = z3.Concat(z3.BitVecVal(0, 8), a) + z3.Concat(z3.BitVecVal(0, 8), b)
    assert not prove_modular_identity(left, right, deadline=time.monotonic() + 3)
    solver = z3.Solver()
    solver.add(a == 255, b == 1, left != right)
    assert solver.check() == z3.sat


def test_concat_preserves_order_and_truncation() -> None:
    a, b = z3.BitVecs("concat_a concat_b", 8)
    extended = z3.Concat(z3.BitVecVal(0, 8), a)
    correct = extended * 256 + z3.Concat(z3.BitVecVal(0, 8), b)
    assert prove_modular_identity(z3.Concat(a, b), correct, deadline=time.monotonic() + 3)
    assert not prove_modular_identity(z3.Concat(b, a), correct, deadline=time.monotonic() + 3)


def test_distinct_loads_remain_independent() -> None:
    memory = z3.Array("mod_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    a, b = z3.BitVecs("address_a address_b", 32)
    left, right = z3.Select(memory, a), z3.Select(memory, b)
    assert not prove_modular_identity(left, right, deadline=time.monotonic() + 3)


def test_shared_division_arithmetic_proves_without_division_premise() -> None:
    a, b = z3.BitVecs("div_a div_b", 32)
    value = z3.UDiv(a, b)
    left, right = value * 60, (value << 2) * 15
    assert prove_shared_scalar(left, right, z3.Solver(), deadline=time.monotonic() + 3)
    assert not prove_shared_scalar(left, right + 1, z3.Solver(), deadline=time.monotonic() + 3)


def test_abstract_failure_falls_back_to_actual_correlated_terms() -> None:
    a, b = z3.BitVecs("correlated_a correlated_b", 8)
    left = z3.ZeroExt(8, a + b)
    right = (z3.ZeroExt(8, a) + z3.ZeroExt(8, b)) & 255
    assert not prove_modular_identity(left, right, deadline=time.monotonic() + 3)
    result = prove_output_equalities([("eax", left, right)], z3.Solver(), deadline=time.monotonic() + 3)
    assert result.status is ProofStatus.PROVED


def test_scalar_proof_does_not_hide_changed_flags() -> None:
    a, b, flags = z3.BitVecs("output_a output_b output_flags", 32)
    value = z3.UDiv(a, b)
    result = prove_output_equalities([("eax", value * 60, (value << 2) * 15),
                                     ("flags", flags, flags ^ 1)],
                                    z3.Solver(), deadline=time.monotonic() + 3)
    assert result.status is ProofStatus.COUNTEREXAMPLE
    assert result.model is not None
    assert z3.is_true(result.model.eval(flags != flags ^ 1))


def test_expired_deadline_never_proves_identity() -> None:
    a = z3.BitVec("expired_modular", 32)
    assert not prove_modular_identity(a, a, deadline=time.monotonic() - 1)


def test_lambda_bound_values_are_not_global_shared_atoms() -> None:
    """External effects can consume arrays whose lambda body contains bound BV."""
    index = z3.BitVec("lambda_index", 8)
    array = z3.Lambda(index, index + 1)
    first = z3.Function("first_array_effect", array.sort(), z3.BitVecSort(32))
    second = z3.Function("second_array_effect", array.sort(), z3.BitVecSort(32))
    assert _shared(first(array), second(array)) == []
    result = prove_output_equalities([("eax", first(array), second(array))],
                                    z3.Solver(), deadline=time.monotonic() + 3)
    # Z3 can refuse a model for UF applications to lambda arrays. Preserve
    # that inconclusive result; neither unrelated effect becomes a proof.
    assert result.status in {ProofStatus.COUNTEREXAMPLE, ProofStatus.UNKNOWN}
    assert not result.lemmas


def test_closed_scalar_over_lambda_can_still_be_abstracted() -> None:
    """The whole closed result is safe even though its array argument is bound."""
    index = z3.BitVec("closed_index", 8)
    array = z3.Lambda(index, index + 1)
    effect = z3.Function("closed_array_effect", array.sort(), z3.BitVecSort(32))
    value = effect(array)
    assert prove_shared_scalar(value * 60, (value << 2) * 15,
                               z3.Solver(), deadline=time.monotonic() + 3)
