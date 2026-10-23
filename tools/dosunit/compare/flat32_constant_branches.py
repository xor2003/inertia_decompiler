"""Layer: validation flat32 branch simplification.

Responsibility: certify constant guards and call destinations using exact SSA-to-Z3
simplification, retaining all aliases and declining symbolic or oversized terms.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

import z3

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.ssa.composition import _abi_terms_equal
from tools.dosunit.ssa.materialization import input_items, materialize_term
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector
from tools.dosunit.ssa.ssa_output_lemmas import ScalarPreprocessing
from tools.dosunit.ssa.x86_flag_dependencies import project_flag_dependencies


class BranchValue(StrEnum):
    """Only TRUE/FALSE authorize removal of a native control edge."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ConstantBranchProof:
    """Exact simplification result; UNKNOWN supplies no reachability premise."""

    value: BranchValue
    nodes: int
    detail: str
    ssa_guard: dict[str, Any] | None = None
    path_conditioned: bool = False
    input_constraints: tuple[dict[str, Any], ...] = ()

    def to_document(self) -> dict[str, object]:
        """Serialize the check without presenting a symbolic guard as constant."""
        return {**asdict(self), "method": ("exact_ssa_path_implication" if self.path_conditioned
                                         else "exact_literal_ssa_simplification"),
                "flag_dependencies": "x86_flag_dependencies.flag_argument_demands"}


def _bounded_nodes(term: dict[str, Any], limit: int = 256) -> int | None:
    """Bound native backend work before materialization; preserve shared DAGs."""
    stack = [(term, 0)]
    seen: set[int] = set()
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            return None
        if id(item) in seen:
            continue
        seen.add(id(item))
        if len(seen) > limit:
            return None
        stack.extend((child, depth + 1) for child in item.get("args", []))
    return len(seen)


def constant_branch(
    guard: dict[str, Any], *, cache: dict[str, ConstantBranchProof] | None = None,
) -> ConstantBranchProof:
    """Prove a one-bit guard constant for all input registers and memory.

    No input premise, constant relocation, solver sampling or model value is
    used. Simplification preserves load/store aliasing and instruction effects.
    A symbolic expression, unsupported operator or work limit leaves both arms.
    """
    nodes = _bounded_nodes(guard)
    if nodes is None:
        return ConstantBranchProof(BranchValue.UNKNOWN, 0, "term_work_limit")
    if guard.get("width") != 1:
        return ConstantBranchProof(BranchValue.UNKNOWN, nodes, "guard_must_be_one_bit")
    projected = _fold_literal_arithmetic(_project_flag_dependencies(guard, {}), {})
    if _bounded_nodes(projected, 32) is None:
        return ConstantBranchProof(BranchValue.UNKNOWN, nodes, "simplification_work_limit")
    assignments: list[dict[str, Any]] = []
    term = materialize_term(projected, assignments=assignments, memo={})
    document = {"outputs": {"guard": term}, "assignments": assignments,
                "inputs": input_items([term], assignments)}
    key = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if cache is not None and key in cache:
        return cache[key]
    proof = _simplified_value(document, term, nodes)
    if cache is not None and len(cache) < 256:
        cache[key] = proof
    return proof


def _fold_literal_arithmetic(
    term: dict[str, Any], memo: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    """Fold bounded scalar literal arithmetic, preserving modular widths and DAG sharing.

    The caller has already bounded depth and node count. Memory and symbolic
    operands remain untouched; this introduces no input or table assumptions.
    """
    key = id(term)
    if key in memo:
        return memo[key]
    args = term.get("args")
    result = ({**term, "args": [_fold_literal_arithmetic(arg, memo) for arg in args]}
              if isinstance(args, list) else term)
    width = result.get("width")
    if (result.get("op") in {"add", "sub", "trunc", "zext", "sext"}
            and type(width) is int and 0 < width <= 64):
        value = constant_bitvector(result)
        if value is not None:
            result = {"op": "const", "width": value[1], "value": hex(value[0])}
    memo[key] = result
    return result


def _path_literal(condition: dict[str, Any], path: dict[str, Any]) -> BranchValue:
    """Recognize a condition or its complement among exact one-bit conjuncts."""
    pending = [path]
    seen: set[int] = set()
    while pending:
        fact = pending.pop()
        if id(fact) in seen:
            continue
        seen.add(id(fact))
        if _abi_terms_equal(fact, condition, {}):
            return BranchValue.TRUE
        args = fact.get("args", [])
        if fact.get("width") != 1:
            continue
        if fact.get("op") == "not" and len(args) == 1 and _abi_terms_equal(args[0], condition, {}):
            return BranchValue.FALSE
        if fact.get("op") == "and" and len(args) == 2:
            pending.extend(args)
    return BranchValue.UNKNOWN


def _path_literal_proof(
    condition: dict[str, Any], path: dict[str, Any], nodes: int,
) -> ConstantBranchProof | None:
    """Retain a serialized implication witness for a syntactically known fact."""
    value = _path_literal(condition, path)
    if value is BranchValue.UNKNOWN:
        return None
    opposite = {"op": "not", "width": 1, "args": [condition]} if value is BranchValue.TRUE else condition
    assignments: list[dict[str, Any]] = []
    term = materialize_term({"op": "and", "width": 1, "args": [path, opposite]},
                            assignments=assignments, memo={})
    document = {"outputs": {"impossible": term}, "assignments": assignments,
                "inputs": input_items([term], assignments)}
    return ConstantBranchProof(value, nodes, "exact_path_conjunct_identity", document, path_conditioned=True)


def branch_under_path(
    condition: dict[str, Any], path: dict[str, Any] | None, *,
    timeout_ms: int = 0, input_constraints: list[dict[str, Any]] | None = None,
) -> ConstantBranchProof | None:
    """Prove an edge unreachable under its exact accumulated native guard.

    Exact simplification of path AND NOT condition to zero selects the true
    arm; path AND condition selects false. Unknown results retain both arms.
    The optional bounded solver uses only the explicitly supplied input domain,
    never a sampled model. The serialized
    witness is the impossible conjunction, not a claim that the branch is
    globally constant. Existing materialization/work bounds remain in force.
    """
    if path is None or path.get("width") != 1 or condition.get("width") != 1:
        return None
    nodes = _bounded_nodes({"op": "and", "width": 1, "args": [path, condition]})
    if nodes is None:
        return None
    literal = _path_literal_proof(condition, path, nodes)
    if literal is not None:
        return literal
    negative = {"op": "not", "width": 1, "args": [condition]}
    for impossible, selected in ((negative, BranchValue.TRUE), (condition, BranchValue.FALSE)):
        conjunction = {"op": "and", "width": 1, "args": [path, impossible]}
        proof = constant_branch(conjunction)
        if proof.value is BranchValue.FALSE:
            return ConstantBranchProof(selected, proof.nodes, "opposite_edge_impossible_under_path",
                                       proof.ssa_guard, path_conditioned=True)
    if timeout_ms > 0:
        return _solver_path_proof(condition, path, nodes, timeout_ms, input_constraints or [])
    return None


def _solver_path_proof(
    condition: dict[str, Any], path: dict[str, Any], nodes: int,
    timeout_ms: int, input_constraints: list[dict[str, Any]],
) -> ConstantBranchProof | None:
    """Discharge a bounded path implication while retaining its exact input domain.

    SAT and UNKNOWN authorize no pruning. Both polarities share one deadline;
    the root entry-domain premise is serialized alongside the SSA witness.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    outputs = {name: materialize_term(term, assignments=assignments, memo=memo)
               for name, term in (("path", path), ("condition", condition))}
    document = {"outputs": outputs, "assignments": assignments,
                "inputs": input_items(outputs.values(), assignments)}
    inputs = S._z3_inputs(document, document, z3)
    try:
        terms = {name: z3.simplify(S._z3_term(term, document=document, inputs=inputs, z3=z3) == 1, blast_select_store=True)
                 for name, term in outputs.items()}
    except DosUnitError:
        return None
    equalities = _literal_path_equalities(terms["path"])
    if equalities:
        terms = {name: z3.simplify(z3.substitute(term, *equalities), blast_select_store=True) for name, term in terms.items()}
    solver = z3.Solver()
    solver.add(terms["path"])
    S._add_z3_input_constraints(solver, inputs, input_constraints, z3)
    for opposite, selected in ((z3.Not(terms["condition"]), BranchValue.TRUE),
                               (terms["condition"], BranchValue.FALSE)):
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            return None
        solver.set(timeout=remaining)
        solver.push()
        solver.add(opposite)
        verdict = solver.check()
        solver.pop()
        if time.monotonic() >= deadline:
            return None
        if verdict == z3.unsat:
            return ConstantBranchProof(selected, nodes, "unsat_opposite_edge_under_entry_domain",
                                       document, path_conditioned=True,
                                       input_constraints=tuple(input_constraints))
    return None



def _literal_path_equalities(path: z3.BoolRef) -> list[tuple[z3.ExprRef, z3.ExprRef]]:
    """Extract only positive equalities forced by every execution of this path.

    Exact substitution of a scalar literal is valid inside this path only.
    Negative disjunctions are conjunctions of negative operands; a positive
    disjunction yields no individual fact. Original SSA remains in the witness.
    """
    pending = [(path, True)]
    result: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    while pending:
        term, positive = pending.pop()
        if z3.is_not(term):
            pending.append((term.arg(0), not positive))
        elif (positive and z3.is_and(term)) or (not positive and z3.is_or(term)):
            pending.extend((child, positive) for child in term.children())
        elif positive and z3.is_eq(term):
            left, right = term.children()
            if z3.is_bv_value(left):
                left, right = right, left
            if z3.is_bv_value(right) and not z3.is_bv_value(left):
                result.append((left, right))
    return result


def _simplified_value(document: dict[str, Any], term: dict[str, Any], nodes: int) -> ConstantBranchProof:
    """Interpret the complete literal guard; only exact constants discharge an edge."""
    inputs = S._z3_inputs(document, document, z3)
    try:
        expression = z3.simplify(S._z3_term(term, document=document, inputs=inputs, z3=z3))
    except DosUnitError as error:
        return ConstantBranchProof(BranchValue.UNKNOWN, nodes, str(error))
    if isinstance(expression, z3.BitVecNumRef) and expression.size() == 1:
        value = BranchValue.TRUE if expression.as_long() == 1 else BranchValue.FALSE
        return ConstantBranchProof(value, nodes, "constant_for_all_inputs", document)
    return ConstantBranchProof(BranchValue.UNKNOWN, nodes, "symbolic_guard")


def _project_flag_dependencies(
    term: dict[str, Any], memo: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    """Use the shared exact native flag projection for bounded constant guards."""
    return project_flag_dependencies(term, memo)


def constant_call_target(term: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    """Recover only universally constant 32-bit destinations, retaining evidence.

    Exact bit-vector/array simplification includes read-over-write aliases.
    No model sampling, PE initial bytes, input premise or target allowlist is
    used. Bounded symbolic expressions keep their existing refusal behavior.
    """
    if term.get("width") != 32 or _bounded_nodes(term, 128) is None:
        return None
    assignments: list[dict[str, Any]] = []
    root = materialize_term(term, assignments=assignments, memo={})
    document = {"outputs": {"target": root}, "assignments": assignments,
                "inputs": input_items([root], assignments)}
    inputs = S._z3_inputs(document, document, z3)
    try:
        expression = z3.simplify(S._z3_term(root, document=document, inputs=inputs, z3=z3))
    except DosUnitError:
        return None
    if not isinstance(expression, z3.BitVecNumRef) or expression.size() != 32:
        return None
    target = expression.as_long()
    return target, {"method": "exact_literal_ssa_simplification",
                    "target": hex(target), "ssa_witness": document,
                    "input_premises": []}


def finite_call_selector(
    term: dict[str, Any], entries: set[int], *, max_targets: int, timeout_ms: int,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Prove an exhaustive selector from literal candidate entries in live SSA.

    Candidates are proposals only: universal equality of the original term
    and the synthesized selector must prove before any call can use it.
    The final default target is justified by that proof, not an allowlist.
    Root input restrictions and PE initial bytes are never assumed.
    """
    if term.get("width") != 32 or _bounded_nodes(term, 128) is None:
        return None
    assignments: list[dict[str, Any]] = []
    root = materialize_term(term, assignments=assignments, memo={})
    document = {"outputs": {"target": root}, "assignments": assignments,
                "inputs": input_items([root], assignments)}
    literals = [root, *(arg for item in assignments for arg in item.get("args", []))]
    targets = sorted({int(item["value"], 0) for item in literals
                      if item.get("op") == "const" and item.get("width") == 32
                      and isinstance(item.get("value"), str)} & entries)
    if not 2 <= len(targets) <= min(max_targets, 16):
        return None
    selector: dict[str, Any] = {"op": "const", "width": 32, "value": hex(targets[-1])}
    for target in reversed(targets[:-1]):
        literal = {"op": "const", "width": 32, "value": hex(target)}
        guard = {"op": "eq", "width": 1, "args": [term, literal]}
        selector = {"op": "ite", "width": 32, "args": [guard, literal, selector]}
    proposed_assignments: list[dict[str, Any]] = []
    proposed = materialize_term(selector, assignments=proposed_assignments, memo={})
    proposal = {"outputs": {"target": proposed}, "assignments": proposed_assignments,
                "inputs": input_items([proposed], proposed_assignments)}
    result = S._compare_functions(
        document, proposal, timeout_ms=timeout_ms,
        scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE,
    )
    if result["status"] != "passed":
        return None
    return selector, {"method": "proved_exhaustive_target_selector",
                      "targets": [hex(target) for target in targets],
                      "ssa_witness": document, "selector_witness": proposal,
                      "proof": result, "input_premises": []}
