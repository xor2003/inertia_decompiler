"""Discharged array and scalar equalities refine complete SSA comparisons.

Layer: dosunit SMT equivalence.
Responsibility: prove bounded full-array output equalities before scalar
simplification, substitute only proved equal terms, and compare every output.
An inconclusive lemma is retained and never assumed. All checks share the
caller input constraints and deadline; countermodels remain in original terms.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

import z3

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.ssa.ssa_shared_subterms import prove_shared_scalar

type OutputPair = tuple[str, z3.ExprRef, z3.ExprRef]
"""Named opaque Z3 expressions at the external SMT-library boundary."""


class ScalarPreprocessing(StrEnum):
    """Exact scalar simplification policy; neither policy adds assumptions."""

    STANDARD = "standard"
    READ_OVER_WRITE = "read_over_write"


class OutputLemmaReason(StrEnum):
    """Exact proof or non-result of an attempted output equality."""

    PROVED = 'output_array_equality_proved'
    SHARED_SCALAR = 'output_scalar_shared_subterms_proved'
    READ_SCALAR = 'output_scalar_read_over_write_proved'
    SYNTACTIC = 'output_array_terms_identical'
    COUNTEREXAMPLE = 'output_array_equality_counterexample'
    UNKNOWN = 'output_array_equality_unknown'
    SCALAR_COUNTEREXAMPLE = 'output_scalar_counterexample'
    BUDGET = 'output_comparison_budget_exhausted'
    OUTPUTS = 'output_comparison_manifest_missing_or_ambiguous'


@dataclass(frozen=True, slots=True)
class OutputLemma:
    """One checked equality and its retained resource/refusal evidence."""

    output: str
    status: ProofStatus
    reason: OutputLemmaReason
    elapsed_ms: int
    detail: str = ''


@dataclass(frozen=True, slots=True)
class OutputEqualityResult:
    """Complete equality verdict; a SAT model is an external Z3 object."""

    status: ProofStatus
    lemmas: tuple[OutputLemma, ...]
    detail: str = ''
    model: z3.ModelRef | None = None


def _remaining_ms(deadline: float) -> int:
    """Keep every SMT call inside the original comparison's total budget."""
    return max(0, int((deadline - time.monotonic()) * 1000))


def _finite_store_inequality(left: z3.ExprRef, right: z3.ExprRef) -> tuple[z3.BoolRef, int] | None:
    """Replace array disequality by all possible writes over one identical base.

    Store addresses may alias and branch conditions remain symbolic. Every
    address from every arm is observed. Other array producers are opaque bases;
    differing bases or exhausted traversal budgets keep full array comparison.
    """
    pending = [left, right]
    seen: set[int] = set()
    addresses: dict[int, z3.ExprRef] = {}
    base: z3.ExprRef | None = None
    while pending:
        term = pending.pop()
        ident = term.get_id()
        if ident in seen:
            continue
        seen.add(ident)
        if len(seen) > 1024 or len(addresses) > 128:
            return None
        if z3.is_store(term):
            if term.num_args() != 3:
                return None
            address = term.arg(1)
            addresses[address.get_id()] = address
            pending.append(term.arg(0))
        elif z3.is_app(term) and term.decl().kind() == z3.Z3_OP_ITE:
            pending.extend((term.arg(1), term.arg(2)))
        elif base is None:
            base = term
        elif not base.eq(term):
            return None
    if not addresses or len(addresses) > 128:
        return None
    changed = z3.Or(*(z3.Select(left, address) != z3.Select(right, address)
                      for address in addresses.values()))
    return _boolean_expression(changed), len(addresses)


def _boolean_expression(expression: object) -> z3.BoolRef:
    """Authenticate the opaque solver's Boolean result before publishing it."""
    if not isinstance(expression, z3.BoolRef):
        raise TypeError('Z3 output inequality must be a Boolean expression')
    return expression


def _is_array_value(term: z3.ExprRef) -> bool:
    """Recognize array-valued lambdas as well as ordinary ArrayRef expressions."""
    return bool(term.sort().kind() == z3.Z3_ARRAY_SORT)


def _array_difference(left: z3.ExprRef, right: z3.ExprRef) -> tuple[z3.BoolRef, str]:
    """Encode exact extensional disequality for both lemma and final queries.

    A fresh unconstrained index witnesses any differing cell, including cells
    outside syntactic stores. No address is sampled or assumed reachable.
    """
    footprint = _finite_store_inequality(left, right)
    if footprint is not None:
        changed = footprint[0]
        description = f"complete finite-store comparison at {footprint[1]} addresses"
    else:
        array_sort = left.sort()
        if not isinstance(array_sort, z3.ArraySortRef):
            raise TypeError('Z3 extensional output comparison requires an array sort')
        index = z3.FreshConst(array_sort.domain(), prefix="array_difference")
        changed = z3.Select(left, index) != z3.Select(right, index)
        description = "complete extensional comparison at an unconstrained fresh index"
    return _boolean_expression(z3.simplify(changed, blast_select_store=True)), description


def _array_lemma(
    name: str, left: z3.ExprRef, right: z3.ExprRef, solver: z3.Solver, timeout_ms: int,
) -> tuple[OutputLemma, z3.ModelRef | None]:
    """Query one array equality at the opaque third-party solver boundary."""
    if left.eq(right):
        return OutputLemma(name, ProofStatus.PROVED, OutputLemmaReason.SYNTACTIC, 0), None
    solver.push()
    solver.set(timeout=timeout_ms)
    changed, description = _array_difference(left, right)
    solver.add(changed)
    started = time.monotonic()
    outcome = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    detail = solver.reason_unknown() if outcome == z3.unknown else description
    model = solver.model() if outcome == z3.sat else None
    solver.pop()
    if outcome == z3.unsat:
        return OutputLemma(name, ProofStatus.PROVED, OutputLemmaReason.PROVED, elapsed, detail), None
    if outcome == z3.sat:
        return OutputLemma(name, ProofStatus.COUNTEREXAMPLE, OutputLemmaReason.COUNTEREXAMPLE, elapsed), model
    return OutputLemma(name, ProofStatus.UNKNOWN, OutputLemmaReason.UNKNOWN, elapsed, detail), None


def _refined_inequalities(
    pairs: list[OutputPair], replacements: list[tuple[z3.ExprRef, z3.ExprRef]],
    preprocessing: ScalarPreprocessing = ScalarPreprocessing.STANDARD,
) -> list[z3.BoolRef]:
    """Apply discharged equalities before simplifying memory-dependent reads."""
    inequalities: list[z3.BoolRef] = []
    for _, left, right in pairs:
        if replacements:
            left = z3.substitute(left, *replacements)
            right = z3.substitute(right, *replacements)
        # Z3's exact read-over-write expansion preserves every possible alias.
        # Opt-in return checks benefit when array theory otherwise times out.
        expand = preprocessing is ScalarPreprocessing.READ_OVER_WRITE
        if _is_array_value(left) and _is_array_value(right):
            changed, _ = _array_difference(left, right)
        else:
            changed = z3.Not(z3.simplify(left, blast_select_store=expand)
                             == z3.simplify(right, blast_select_store=expand))
        inequalities.append(_boolean_expression(changed))
    return inequalities


def _scalar_counterexample(
    pairs: list[OutputPair], replacements: list[tuple[z3.ExprRef, z3.ExprRef]],
    solver: z3.Solver, deadline: float, preprocessing: ScalarPreprocessing,
) -> tuple[OutputLemma, z3.ModelRef] | None:
    """Find exact scalar witnesses; unsuccessful probes establish nothing."""
    budget = min(4000, _remaining_ms(deadline) // 4)
    probe_deadline = min(deadline, time.monotonic() + budget / 1000)
    attempted = 0
    for pair in pairs:
        name, left, right = pair
        if _is_array_value(left) or _is_array_value(right) or left.eq(right):
            continue
        if attempted >= 8 or not _remaining_ms(probe_deadline):
            break
        attempted += 1
        started = time.monotonic()
        inequalities = _refined_inequalities([pair], replacements, preprocessing)
        remaining = min(500, _remaining_ms(probe_deadline))
        if not remaining:
            break
        solver.push()
        try:
            solver.set(timeout=remaining)
            solver.add(z3.Or(*inequalities))
            if solver.check() == z3.sat:
                model = solver.model()
                elapsed = int((time.monotonic() - started) * 1000)
                lemma = OutputLemma(name, ProofStatus.COUNTEREXAMPLE,
                                    OutputLemmaReason.SCALAR_COUNTEREXAMPLE, elapsed)
                return lemma, model
        finally:
            solver.pop()
    return None


def _compare_refined(
    pairs: list[OutputPair], replacements: list[tuple[z3.ExprRef, z3.ExprRef]],
    solver: z3.Solver, deadline: float, lemmas: tuple[OutputLemma, ...],
    preprocessing: ScalarPreprocessing,
) -> OutputEqualityResult:
    """Compare every refined output under the original constraints and budget."""
    if not _remaining_ms(deadline):
        return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, OutputLemmaReason.BUDGET.value)
    proved_outputs = {lemma.output for lemma in lemmas if lemma.status is ProofStatus.PROVED}
    pairs = [pair for pair in pairs if pair[0] not in proved_outputs]
    if any(lemma.status is ProofStatus.UNKNOWN for lemma in lemmas):
        witness = _scalar_counterexample(pairs, replacements, solver, deadline, preprocessing)
        if witness is not None:
            lemma, model = witness
            return OutputEqualityResult(ProofStatus.COUNTEREXAMPLE, (*lemmas, lemma), model=model)
    pairs = sorted(pairs, key=lambda pair: _is_array_value(pair[1]))
    inequalities = [z3.simplify(inequality, blast_select_store=True,
                               sort_store=True, expand_select_ite=True)
                    for inequality in _refined_inequalities(pairs, replacements, preprocessing)]
    # Exact false inequalities are discharged observations. Retain every other
    # output and the complete caller domain without spending queries on false.
    inequalities = [inequality for inequality in inequalities if not z3.is_false(inequality)]
    remaining = _remaining_ms(deadline)
    if not remaining:
        return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, OutputLemmaReason.BUDGET.value)
    if not inequalities:
        return OutputEqualityResult(ProofStatus.PROVED, lemmas)
    constraints = [z3.simplify(assertion, blast_select_store=True, sort_store=True,
                                expand_select_ite=True) for assertion in solver.assertions()]
    # Prove the conjunction by checking each output's negation independently.
    # Every check retains the full original domain and shares one deadline.
    for inequality in inequalities:
        query = z3.Solver(ctx=solver.ctx)
        query.add(*constraints)
        query.add(inequality)
        remaining = _remaining_ms(deadline)
        if not remaining:
            return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, OutputLemmaReason.BUDGET.value)
        query.set(timeout=remaining)
        outcome = query.check()
        if outcome == z3.sat:
            return OutputEqualityResult(ProofStatus.COUNTEREXAMPLE, lemmas, model=query.model())
        if outcome != z3.unsat:
            return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, query.reason_unknown())
    return OutputEqualityResult(ProofStatus.PROVED, lemmas)


def _prove_expanded_scalar(
    name: str, left: z3.ExprRef, right: z3.ExprRef, solver: z3.Solver, deadline: float,
) -> OutputLemma | None:
    """Discharge exact read-over-write equality without abstracting address inputs.

    Shared-subterm abstraction can lose the relation between a saved stack slot
    and its declared input bounds. This bounded fallback retains all aliases and
    constraints. Only UNSAT supplies a lemma; SAT/unknown changes no assumptions.
    """
    if not z3.is_bv(left) or not z3.is_bv(right) or left.eq(right) or not _remaining_ms(deadline):
        return None
    started = time.monotonic()
    expanded_left = z3.simplify(left, blast_select_store=True)
    expanded_right = z3.simplify(right, blast_select_store=True)
    if (expanded_left.eq(z3.simplify(left))
            and expanded_right.eq(z3.simplify(right))):
        return None
    remaining = min(500, _remaining_ms(deadline))
    if not remaining:
        return None
    # Array probes can leave expensive learned state even after pop(). Copy
    # every active assertion into an isolated query, retaining the same domain.
    probe = z3.Solver(ctx=solver.ctx)
    probe.set(timeout=remaining)
    probe.add(*solver.assertions(), expanded_left != expanded_right)
    if probe.check() != z3.unsat or not _remaining_ms(deadline):
        return None
    return OutputLemma(name, ProofStatus.PROVED, OutputLemmaReason.READ_SCALAR,
                       int((time.monotonic() - started) * 1000))


def _prove_scalar_lemmas(
    pairs: list[OutputPair], solver: z3.Solver, deadline: float,
    lemmas: list[OutputLemma],
) -> None:
    """Refine only scalar identities proved within the shared caller budget."""
    probe_deadline = min(deadline, time.monotonic() + min(2000, _remaining_ms(deadline) // 4) / 1000)
    for name, left, right in pairs:
        if time.monotonic() >= probe_deadline:
            break
        lemma = _prove_expanded_scalar(name, left, right, solver, probe_deadline)
        if lemma is None:
            proof = prove_shared_scalar(left, right, solver, deadline=min(probe_deadline, time.monotonic() + 1))
            if proof is not None:
                lemma = OutputLemma(name, ProofStatus.PROVED, OutputLemmaReason.SHARED_SCALAR,
                                    proof.elapsed_ms, f"universally abstracted {proof.subterms} identical subterms")
        if lemma is not None:
            lemmas.append(lemma)


def prove_output_equalities(
    pairs: list[OutputPair], solver: z3.Solver, *, deadline: float,
    lemma_timeout_ms: int = 1000,
    scalar_preprocessing: ScalarPreprocessing = ScalarPreprocessing.STANDARD,
) -> OutputEqualityResult:
    """Prove complete output equality using only discharged equality lemmas.

    SSA expressions must arrive before scalar simplification expands loads over
    store chains. Equal array expressions can then be substituted in subsequent
    reads by congruence. UNSAT discharges each lemma under the caller constraints;
    neither a timeout nor a proposed memory relation supplies an assumption.
    Array queries have a small per-obligation budget. An unknown lemma falls
    through to the complete original comparison with the remaining total time.
    Opt-in read-over-write preprocessing retains every possible address alias
    and consumes this same deadline before the final complete SMT query.
    Exact simplification discharges false output inequalities before querying;
    every unresolved observation still uses the full original caller domain.
    """
    if lemma_timeout_ms <= 0:
        raise ValueError('lemma_timeout_ms must be positive')
    names = {name for name, _, _ in pairs}
    if not pairs or len(names) != len(pairs) or '' in names:
        return OutputEqualityResult(ProofStatus.UNKNOWN, (), OutputLemmaReason.OUTPUTS.value)
    lemmas: list[OutputLemma] = []
    replacements: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for name, left, right in pairs:
        if not _is_array_value(left) and not _is_array_value(right):
            continue
        remaining = _remaining_ms(deadline)
        if not remaining:
            return OutputEqualityResult(ProofStatus.UNKNOWN, tuple(lemmas), OutputLemmaReason.BUDGET.value)
        lemma, model = _array_lemma(name, left, right, solver, min(lemma_timeout_ms, max(1, remaining // 2)))
        lemmas.append(lemma)
        if lemma.status is ProofStatus.COUNTEREXAMPLE:
            return OutputEqualityResult(ProofStatus.COUNTEREXAMPLE, tuple(lemmas), model=model)
        if lemma.status is ProofStatus.PROVED:
            replacements.append((right, left))
    _prove_scalar_lemmas(pairs, solver, deadline, lemmas)
    return _compare_refined(pairs, replacements, solver, deadline, tuple(lemmas), scalar_preprocessing)
