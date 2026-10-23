"""Complete SSA output refinement uses only independently proved array equalities."""
from __future__ import annotations

import time
from typing import Any

import pytest
import z3

import tools.dosunit.compare.straightline_ssa as S
import tools.dosunit.ssa.ssa_output_lemmas as L
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy


def _pairs() -> list[L.OutputPair]:
    memory = z3.Array("memory", z3.BitVecSort(32), z3.BitVecSort(8))
    a, b, observed = z3.BitVecs("a b observed", 32)
    swapped = z3.Store(z3.Store(memory, a, z3.Select(memory, b)), b, z3.Select(memory, a))
    restored = z3.Store(z3.Store(swapped, a, z3.Select(swapped, b)), b, z3.Select(swapped, a))
    return [("memory", memory, restored), ("loaded", z3.Select(memory, observed), z3.Select(restored, observed))]


def test_restored_array_and_loaded_output_prove() -> None:
    result = L.prove_output_equalities(_pairs(), z3.Solver(), deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.PROVED
    assert {lemma.output for lemma in result.lemmas} == {"memory", "loaded"}
    assert all(lemma.status is ProofStatus.PROVED for lemma in result.lemmas)


def test_identical_scalar_outputs_do_not_spend_solver_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unchanged observations need exact simplification, not repeated SMT searches."""
    solver = z3.Solver()
    value = z3.BitVec("unchanged_output", 32)
    solver.add(value >= 0)
    pairs = [(f"output_{index}", value + index, value + index) for index in range(32)]

    def unexpected_check(self: z3.Solver, *assumptions: z3.BoolRef) -> z3.CheckSatResult:
        raise AssertionError("identical outputs must not consume solver queries")

    monkeypatch.setattr(z3.Solver, "check", unexpected_check)
    result = L.prove_output_equalities(pairs, solver, deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.PROVED
    assert len(solver.assertions()) == 1


@pytest.mark.parametrize("constrained", [False, True])
def test_changed_output_after_identical_outputs_preserves_domain(constrained: bool) -> None:
    """Eliminating tautologies must retain the last observation and caller domain."""
    solver = z3.Solver()
    value = z3.BitVec("observed_output", 32)
    if constrained:
        solver.add(value == 0)
    pairs = [(f"unchanged_{index}", value, value) for index in range(32)]
    pairs.append(("changed", value, z3.BitVecVal(0, 32)))
    result = L.prove_output_equalities(pairs, solver, deadline=time.monotonic() + 5)
    assert result.status is (ProofStatus.PROVED if constrained else ProofStatus.COUNTEREXAMPLE)
    if not constrained:
        assert result.model is not None
        assert result.model.eval(value).as_long() != 0


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
    import tools.dosunit.compare.flat32_call_execution as execution
    import tools.dosunit.compare.straightline_ssa as ssa
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


@pytest.mark.parametrize("mutation", ["scalar", "memory", "ninth", "none"])
def test_scalar_probes_preserve_complete_query(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    """Timeout recovery respects inputs and never drops unproved outputs."""
    def unknown(name, _left, _right, _solver, _timeout_ms):
        return L.OutputLemma(name, ProofStatus.UNKNOWN, L.OutputLemmaReason.UNKNOWN, 0), None
    monkeypatch.setattr(L, "_array_lemma", unknown)
    memory = z3.Array("probe_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    x = z3.BitVec("probe_x", 32)
    solver = z3.Solver()
    solver.add(x == 0)
    pairs = [(f"scalar{i}", x, z3.BitVecVal(0, 32)) for i in range(9)]
    if mutation == "scalar":
        pairs[0] = ("scalar0", x, x + 1)
    if mutation == "ninth":
        pairs[8] = ("scalar8", x, x + 1)
    changed = z3.Store(memory, x, z3.BitVecVal(7, 8)) if mutation == "memory" else memory
    pairs.append(("memory", memory, changed))
    result = L.prove_output_equalities(pairs, solver, deadline=time.monotonic() + 5)
    if mutation == "none":
        assert result.status is ProofStatus.PROVED
    else:
        assert result.status is ProofStatus.COUNTEREXAMPLE
        assert result.model is not None
        assert z3.is_true(result.model.eval(x == 0))
        assert any(z3.is_true(result.model.eval(left != right, model_completion=True))
                   for _, left, right in pairs)
    assert any(lemma.reason is L.OutputLemmaReason.SCALAR_COUNTEREXAMPLE
               for lemma in result.lemmas) is (mutation == "scalar")
    if mutation == "scalar":
        assert len(solver.assertions()) == 1


@pytest.mark.parametrize("branched", [False, True])
def test_finite_store_query_equals_full_array_disequality(branched: bool) -> None:
    """All aliases and both branch arms remain represented by the smaller query."""
    memory = z3.Array("finite_mem", z3.BitVecSort(32), z3.BitVecSort(8))
    a, b = z3.BitVecs("finite_a finite_b", 32)
    x, y = z3.BitVecs("finite_x finite_y", 8)
    left = z3.Store(z3.Store(memory, a, x), b, y)
    right = z3.Store(z3.Store(memory, b, y), a, x)
    if branched:
        right = z3.If(z3.Bool("finite_condition"), right, memory)
    reduced = L._finite_store_inequality(left, right)
    assert reduced is not None
    solver = z3.Solver()
    solver.add(z3.Xor(left != right, reduced[0]))
    assert solver.check() == z3.unsat


def test_finite_store_differing_bases_keep_extensional_check() -> None:
    """Matching writes cannot hide a difference at an unwritten address."""
    a = z3.Array("base_a", z3.BitVecSort(32), z3.BitVecSort(8))
    b = z3.Array("base_b", z3.BitVecSort(32), z3.BitVecSort(8))
    left, right = z3.Store(a, 0, 1), z3.Store(b, 0, 1)
    assert L._finite_store_inequality(left, right) is None
    result = L.prove_output_equalities([("memory", left, right)], z3.Solver(),
                                      deadline=time.monotonic() + 5)
    assert result.status is ProofStatus.COUNTEREXAMPLE


def test_finite_store_budget_falls_back_without_dropping_writes() -> None:
    memory = z3.Array("bounded_mem", z3.BitVecSort(32), z3.BitVecSort(8))
    changed = memory
    for index in range(130):
        changed = z3.Store(changed, index, 1)
    assert L._finite_store_inequality(memory, changed) is None


@pytest.mark.parametrize("bounded,corrupt", [(True, False), (False, False), (True, True)])
def test_saved_register_read_lemma_retains_address_constraints(bounded: bool, corrupt: bool) -> None:
    """Restoring a saved byte is equal only if later writes cannot alias it."""
    memory = z3.Array("restore_mem", z3.BitVecSort(32), z3.BitVecSort(8))
    esp = z3.BitVec("restore_esp", 32)
    saved = z3.BitVec("restore_saved", 8)
    changed = z3.Store(memory, esp - 4, saved)
    for address in range(0x100, 0x120):
        changed = z3.Store(changed, address, z3.BitVecVal(7, 8))
    left = z3.Select(changed, esp - 4)
    right = saved + 1 if corrupt else saved
    solver = z3.Solver()
    if bounded:
        solver.add(z3.UGE(esp, 0x70000), z3.ULE(esp, 0x80000))
    result = L.prove_output_equalities([("ebp", left, right)], solver, deadline=time.monotonic() + 5)
    expected = ProofStatus.PROVED if bounded and not corrupt else ProofStatus.COUNTEREXAMPLE
    assert result.status is expected
    proved = [lemma for lemma in result.lemmas if lemma.output == "ebp" and lemma.status is ProofStatus.PROVED]
    assert bool(proved) == (expected is ProofStatus.PROVED)


@pytest.mark.parametrize("mutated", [False, True])
def test_lambda_region_equality_observes_every_address(mutated: bool) -> None:
    memory = z3.Array("region_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    index, start, size = z3.BitVecs("region_index region_start region_size", 32)
    inside = z3.ULT(index - start, size)
    left = z3.Lambda(index, z3.If(inside, z3.BitVecVal(7, 8), memory[index]))
    right = z3.Lambda(index, z3.If(z3.Not(inside), memory[index], z3.BitVecVal(7, 8)))
    if mutated:
        right = z3.Store(right, start + size - 1, z3.BitVecVal(8, 8))
    solver = z3.Solver()
    solver.add(size == 4096)
    result = L.prove_output_equalities([("memory", left, right)], solver, deadline=time.monotonic() + 5)
    assert result.status is (ProofStatus.COUNTEREXAMPLE if mutated else ProofStatus.PROVED)


@pytest.mark.parametrize("changed", [False, True])
def test_final_array_query_is_extensional_after_unknown_lemma(monkeypatch, changed):
    first = z3.Array("first", z3.BitVecSort(32), z3.BitVecSort(8))
    second = z3.Array("second", z3.BitVecSort(32), z3.BitVecSort(8))
    address = z3.BitVec("cell", 32)
    inside = z3.And(z3.UGE(address, 0x1000), z3.ULE(address, 0x1007))
    left = z3.Lambda(address, z3.If(inside, first[address], second[address]))
    right = z3.Lambda(address, z3.If(inside, first[address], second[address]))
    if changed:
        right = z3.Lambda(address, z3.If(address == 0x1007, second[address], left[address]))

    def unknown(name, *args):
        return L.OutputLemma(name, ProofStatus.UNKNOWN, L.OutputLemmaReason.UNKNOWN, 0), None

    monkeypatch.setattr(L, "_array_lemma", unknown)
    result = L.prove_output_equalities([("memory", left, right)], z3.Solver(), deadline=time.monotonic() + 2)
    assert result.status is (ProofStatus.COUNTEREXAMPLE if changed else ProofStatus.PROVED)


@pytest.mark.parametrize("constrain,corrupt", [(True, False), (True, True), (False, False)])
def test_split_outputs_preserve_domain_and_check_all_outputs(constrain, corrupt):
    value = z3.BitVec("value", 32)
    memory = z3.Array("memory", z3.BitVecSort(32), z3.BitVecSort(8))
    solver = z3.Solver()
    if constrain:
        solver.add(value == 0)
    byte_change = z3.BitVecVal(1, 8) if corrupt else z3.Extract(7, 0, value)
    changed = z3.Store(memory, z3.BitVecVal(0x1000, 32), memory[0x1000] ^ byte_change)
    pairs = [("eax", value, z3.BitVecVal(0, 32)), ("memory", memory, changed)]
    result = L._compare_refined(pairs, [], solver, time.monotonic() + 2, (),
                               L.ScalarPreprocessing.STANDARD)
    expected = ProofStatus.PROVED if constrain and not corrupt else ProofStatus.COUNTEREXAMPLE
    assert result.status is expected
