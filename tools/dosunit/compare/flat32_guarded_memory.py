"""Layer: validation guarded memory observations.

Responsibility: prove a byte region unchanged under an explicit SSA path guard,
without treating that guard as an unconditional input fact or proving its reachability.
"""
from __future__ import annotations

import time
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.ssa_output_lemmas import ScalarPreprocessing


def check_guarded_region_preservation(
    before: dict[str, Any], after: dict[str, Any], guard: dict[str, Any],
    address: int, size: int, *, timeout_ms: int = 1000,
    input_constraints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Prove guard implies equal bytes, observing every byte of a bounded region.

    The returned certificate is a conditional lemma, never a root-function
    verdict. Callers must establish the exact path guard and its input domain
    before consuming it. In particular, no initialization, fresh allocation,
    callback value, guard feasibility or API behavior follows from this check.
    """
    if type(address) is not int or type(size) is not int or not 1 <= size <= 64:
        raise ValueError("guarded region requires an integer VA and 1..64 bytes")
    if not 0 <= address < address + size <= 2**32 or guard.get("width") != 1:
        raise ValueError("guarded region requires nonwrapping extent and one-bit guard")
    if type(timeout_ms) is not int or timeout_ms <= 0:
        raise ValueError("guarded region requires a positive solver budget")
    pointer = {"op": "const", "width": 32, "value": hex(address)}
    original = {"op": "loadle", "width": size * 8, "args": [before, pointer]}
    changed = {"op": "loadle", "width": size * 8, "args": [after, pointer]}
    observation = {"op": "ite", "width": size * 8, "args": [guard, changed, original]}
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    terms = {name: materialize_term(term, assignments=assignments, memo=memo)
             for name, term in (("before", original), ("after", observation), ("guard", guard), ("changed", changed))}
    common = {"assignments": assignments, "inputs": input_items(terms.values(), assignments)}
    left = {**common, "outputs": {"region": terms["before"]}}
    right = {**common, "outputs": {"region": terms["after"]}}
    rewrite = _literal_guard_projection(guard, terms, assignments, size * 8)
    if rewrite is not None:
        left, right = rewrite
    result = S._compare_functions(
        left, right,
        timeout_ms=timeout_ms, input_constraints=input_constraints,
        scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE,
    )
    return {"schema": "dosunit.guarded_region_preservation.v1",
            "status": {"passed": "checked", "failed": "mismatch"}.get(result["status"], "incomplete"),
            "scope": "guard_implies_equal_region_bytes", "address": hex(address), "size": size,
            "guard_feasibility_proved": False, "function_equivalence_proved": False,
            "input_constraints": input_constraints or [], "solver_result": result,
            "ssa_witness": {**common, "outputs": terms},
            "preprocessing": "literal_equality_under_guard" if rewrite is not None else "none",
            "solver_witness": {"before": left, "after": right}}


def check_region_preservation_via_guard(
    before: dict[str, Any], after: dict[str, Any], path_guard: dict[str, Any],
    sufficient_guard: dict[str, Any], address: int, size: int, *, timeout_ms: int = 1000,
    input_constraints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Factor path preservation into two proved implications under one deadline.

    A proposed sufficient guard is not an assumption: path => sufficient and
    sufficient => unchanged bytes must both prove. Failed proposals do not
    establish a counterexample to the original path property.
    """
    if path_guard.get("width") != 1:
        raise ValueError("path guard must be one bit")
    deadline = time.monotonic() + timeout_ms / 1000
    region = check_guarded_region_preservation(before, after, sufficient_guard, address, size,
                 timeout_ms=timeout_ms, input_constraints=input_constraints)
    result: dict[str, Any] = {"schema": "dosunit.factored_region_preservation.v1",
        "status": "incomplete", "scope": "path_guard_implies_equal_region_bytes",
        "method": "two_checked_implications", "region_lemma": region,
        "function_equivalence_proved": False, "guard_feasibility_proved": False,
        "timeout_ms": timeout_ms, "input_constraints": input_constraints or []}
    if region["status"] != "checked":
        result["reason"] = "sufficient_guard_does_not_prove_preservation"
        return result
    one = {"op": "const", "width": 1, "value": "0x1"}
    implication = {"op": "ite", "width": 1, "args": [path_guard, sufficient_guard, one]}
    assignments: list[dict[str, Any]] = []
    term = materialize_term(implication, assignments=assignments, memo={})
    document = {"outputs": {"implication": term}, "assignments": assignments,
                "inputs": input_items([term], assignments)}
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        result["reason"] = "guarded_preservation_deadline"
        return result
    proof = S._compare_functions(document, {"outputs": {"implication": one}, "assignments": [], "inputs": []},
        timeout_ms=remaining, input_constraints=input_constraints,
        scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE)
    result.update(path_implication=proof, path_implication_witness=document)
    if time.monotonic() >= deadline:
        result["reason"] = "guarded_preservation_deadline"
    elif proof["status"] == "passed":
        result["status"] = "checked"
    else:
        result["reason"] = "path_does_not_prove_sufficient_guard"
    return result


def _literal_guard_projection(
    guard: dict[str, Any], terms: dict[str, dict[str, Any]],
    assignments: list[dict[str, Any]], width: int,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Instantiate g:(t=c) only inside g, retaining the original g outside.

    Compact assignment identities provide exact structural matching. No
    instruction meaning, address normalization or sampled solver value is used.
    Equal widths are mandatory; arbitrary logical guards retain the general path.
    """
    definitions = {item["id"]: item for item in assignments}
    condition = definitions.get(terms["guard"].get("ref"), terms["guard"])
    args = condition.get("args", [])
    if condition.get("op") != "eq" or len(args) != 2 or len(assignments) > 4096:
        return None
    constant: dict[str, Any]
    target: dict[str, Any]
    constant, target = args if args[0].get("op") == "const" else list(reversed(args))
    resolved = definitions.get(target.get("ref"), target)
    if constant.get("op") != "const" or resolved.get("op") == "const":
        return None
    if constant.get("width") != resolved.get("width") or not constant.get("width", 0):
        return None
    cache: dict[str, dict[str, Any]] = {}

    def expand(term: dict[str, Any]) -> dict[str, Any]:
        """Expand each canonical assignment once while substituting its exact atom."""
        if term == target:
            return constant
        if "ref" not in term:
            return term
        key = term["ref"]
        if key not in cache:
            item = definitions[key]
            cache[key] = {name: value for name, value in item.items() if name not in {"id", "args"}}
            cache[key]["args"] = [expand(arg) for arg in item.get("args", [])]
        return cache[key]

    projected_assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    zero = {"op": "const", "width": width, "value": "0x0"}
    outputs = {name: materialize_term({"op": "ite", "width": width,
               "args": [guard, expand(terms[name]), zero]}, assignments=projected_assignments, memo=memo)
               for name in ("before", "changed")}
    common = {"assignments": projected_assignments, "inputs": input_items(outputs.values(), projected_assignments)}
    return ({**common, "outputs": {"region": outputs["before"]}},
            {**common, "outputs": {"region": outputs["changed"]}})
