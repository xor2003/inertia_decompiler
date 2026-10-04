"""Complete SSA output refinement uses only independently proved array equalities."""
from __future__ import annotations

import time
from typing import Any

import pytest
import z3

from tools.dosunit import ssa_output_lemmas as L
from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.real16_call_contracts import materialize_function


def _pairs() -> list[L.OutputPair]:
    memory = z3.Array("memory", z3.BitVecSort(32), z3.BitVecSort(8))
    a, b, observed = z3.BitVecs("a b observed", 32)
    swapped = z3.Store(z3.Store(memory, a, z3.Select(memory, b)), b, z3.Select(memory, a))
    restored = z3.Store(z3.Store(swapped, a, z3.Select(swapped, b)), b, z3.Select(swapped, a))
    return [("memory", memory, restored), ("loaded", z3.Select(memory, observed), z3.Select(restored, observed))]


def test_restored_array_and_loaded_output_prove() -> None:
    result = L.prove_output_equalities(_pairs(), z3.Solver(), deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.PROVED
    assert len(result.lemmas) == 1
    assert result.lemmas[0].status is ProofStatus.PROVED


def test_changed_scalar_retains_countermodel() -> None:
    pairs = _pairs()
    name, left, right = pairs[-1]
    pairs[-1] = (name, left, right + 1)
    result = L.prove_output_equalities(pairs, z3.Solver(), deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.COUNTEREXAMPLE
    assert result.model is not None


def test_changed_array_retains_countermodel() -> None:
    _, memory, _ = _pairs()[0]
    changed = z3.Store(memory, z3.BitVecVal(5, 32), z3.BitVecVal(6, 8))
    result = L.prove_output_equalities([("memory", memory, changed)], z3.Solver(), deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.COUNTEREXAMPLE
    assert result.model is not None
    assert z3.is_true(result.model.eval(memory != changed, model_completion=True))


def test_expired_deadline_never_proves() -> None:
    result = L.prove_output_equalities(_pairs(), z3.Solver(), deadline=time.monotonic() - 1)
    assert result.status is ProofStatus.UNKNOWN
    assert result.model is None


def test_unknown_array_lemma_is_not_assumed(monkeypatch: pytest.MonkeyPatch) -> None:
    def unknown(name: str, _left: z3.ExprRef, _right: z3.ExprRef, _solver: z3.Solver,
                _timeout_ms: int) -> tuple[L.OutputLemma, None]:
        return L.OutputLemma(name, ProofStatus.UNKNOWN, L.OutputLemmaReason.UNKNOWN, 0, "controlled timeout"), None
    monkeypatch.setattr(L, "_array_lemma", unknown)
    _, memory, _ = _pairs()[0]
    changed = z3.Store(memory, z3.BitVecVal(5, 32), z3.BitVecVal(6, 8))
    result = L.prove_output_equalities([("memory", memory, changed)], z3.Solver(), deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.COUNTEREXAMPLE
    assert result.lemmas[0].status is ProofStatus.UNKNOWN


def _input(name: str, width: int) -> dict[str, Any]:
    return {"op": "input", "name": name, "width": width}


def _states() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    a, b, observed = (_input(name, 32) for name in ("a", "b", "observed"))
    def swap(array: dict[str, Any]) -> dict[str, Any]:
        left = {"op": "loadle", "width": 8, "args": [array, a]}
        right = {"op": "loadle", "width": 8, "args": [array, b]}
        return {"op": "storele", "width": 0, "args": [
            {"op": "storele", "width": 0, "args": [array, a, right]}, b, left]}
    restored = swap(swap(memory))
    oracle = {"memory": memory, "eax": {"op": "loadle", "width": 32, "args": [memory, observed]},
              "flags": _input("flags", 16)}
    candidate = {**oracle, "memory": restored,
                 "eax": {"op": "loadle", "width": 32, "args": [restored, observed]}}
    return oracle, candidate


@pytest.mark.parametrize("mutation", [None, "scalar", "memory", "flags"])
def test_ssa_comparison_retains_all_outputs(mutation: str | None) -> None:
    oracle, candidate = _states()
    if mutation in {"scalar", "flags"}:
        name = "eax" if mutation == "scalar" else "flags"
        width = 32 if name == "eax" else 16
        candidate[name] = {"op": "add", "width": width,
                           "args": [candidate[name], {"op": "const", "width": width, "value": "0x1"}]}
    if mutation == "memory":
        candidate["memory"] = {"op": "storele", "width": 0, "args": [candidate["memory"],
            {"op": "const", "width": 32, "value": "0x100"}, {"op": "const", "width": 8, "value": "0x5a"}]}
    result = S._compare_functions(materialize_function("oracle", oracle),
                                  materialize_function("candidate", candidate), timeout_ms=5000)
    assert (proof_status_from_legacy(result["status"]) is ProofStatus.PROVED) is (mutation is None), result
    assert not result["skipped_layout_outputs"]
    assert result["output_lemmas"]


@pytest.mark.parametrize("manifest", [[], [("", z3.BitVecVal(0, 8), z3.BitVecVal(0, 8))],
                                        [("a", z3.BitVecVal(0, 8), z3.BitVecVal(0, 8))] * 2])
def test_missing_or_ambiguous_manifest_refuses(manifest: list[L.OutputPair]) -> None:
    assert L.prove_output_equalities(manifest, z3.Solver(), deadline=time.monotonic() + 1).status is ProofStatus.UNKNOWN


def test_exact_read_over_write_preserves_alias_countermodel() -> None:
    """Expanding memory reads must keep writes that can alias a saved return."""
    memory = z3.Array("return_mem", z3.BitVecSort(32), z3.BitVecSort(8))
    stack, other = z3.BitVecs("return_stack return_other", 32)
    original = z3.Select(z3.Store(z3.Store(memory, stack, z3.BitVecVal(7, 8)),
        other, z3.BitVecVal(9, 8)), stack)
    pairs = [("return", original, z3.BitVecVal(7, 8))]
    inequalities = L._refined_inequalities(pairs, [], L.ScalarPreprocessing.READ_OVER_WRITE)
    solver = z3.Solver()
    solver.add(z3.Or(*inequalities))
    assert solver.check() == z3.sat
    model = solver.model()
    assert model.eval(original).as_long() != model.eval(pairs[0][2]).as_long()
    solver.add(stack != other)
    assert solver.check() == z3.unsat


def test_flat32_return_check_selects_exact_memory_preprocessing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The actual call-return proof selects the exact expansion under its budget."""
    from tools.dosunit import flat32_call_execution as execution
    from tools.dosunit import straightline_ssa as ssa
    original = ssa._compare_functions
    seen = []
    def compare(oracle, candidate, **options):
        seen.append(options)
        return original(oracle, candidate, **options)
    monkeypatch.setattr(ssa, "_compare_functions", compare)
    execution._prove_return_target({"op": "const", "width": 32, "value": "0x100"},
        0x100, timeout_ms=1000, callsite=0, call_block=0, target=0, callee="")
    assert seen[0]["scalar_preprocessing"] is L.ScalarPreprocessing.READ_OVER_WRITE
    assert seen[0]["timeout_ms"] == 1000


def test_read_over_write_cannot_extend_expired_budget() -> None:
    """Exact preprocessing must refuse when the caller deadline has expired."""
    value = z3.BitVec("expired_return", 32)
    result = L.prove_output_equalities([("return", value, value)], z3.Solver(),
        deadline=time.monotonic() - 1, scalar_preprocessing=L.ScalarPreprocessing.READ_OVER_WRITE)
    assert result.status is ProofStatus.UNKNOWN
