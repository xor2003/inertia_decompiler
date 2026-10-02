"""Discharged array equalities refine complete SSA output comparisons.

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

from tools.dosunit.proof_contracts import ProofStatus

type OutputPair = tuple[str, z3.ExprRef, z3.ExprRef]
"""Named opaque Z3 expressions at the external SMT-library boundary."""


class ScalarPreprocessing(StrEnum):
    """Exact scalar simplification policy; neither policy adds assumptions."""

    STANDARD = "standard"
    READ_OVER_WRITE = "read_over_write"


class OutputLemmaReason(StrEnum):
    """Exact proof or non-result of an attempted output equality."""

    PROVED = 'output_array_equality_proved'
    SYNTACTIC = 'output_array_terms_identical'
    COUNTEREXAMPLE = 'output_array_equality_counterexample'
    UNKNOWN = 'output_array_equality_unknown'
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


def _array_lemma(
    name: str, left: z3.ExprRef, right: z3.ExprRef, solver: z3.Solver, timeout_ms: int,
) -> tuple[OutputLemma, z3.ModelRef | None]:
    """Query one array equality at the opaque third-party solver boundary."""
    if left.eq(right):
        return OutputLemma(name, ProofStatus.PROVED, OutputLemmaReason.SYNTACTIC, 0), None
    solver.push()
    solver.set(timeout=timeout_ms)
    solver.add(left != right)
    started = time.monotonic()
    outcome = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    detail = solver.reason_unknown() if outcome == z3.unknown else ''
    model = solver.model() if outcome == z3.sat else None
    solver.pop()
    if outcome == z3.unsat:
        return OutputLemma(name, ProofStatus.PROVED, OutputLemmaReason.PROVED, elapsed), None
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
        changed = z3.Not(z3.simplify(left, blast_select_store=expand)
                         == z3.simplify(right, blast_select_store=expand))
        if not isinstance(changed, z3.BoolRef):
            raise TypeError('Z3 output inequality must be a Boolean expression')
        inequalities.append(changed)
    return inequalities


def _compare_refined(
    pairs: list[OutputPair], replacements: list[tuple[z3.ExprRef, z3.ExprRef]],
    solver: z3.Solver, deadline: float, lemmas: tuple[OutputLemma, ...],
    preprocessing: ScalarPreprocessing,
) -> OutputEqualityResult:
    """Compare every refined output under the original constraints and budget."""
    if not _remaining_ms(deadline):
        return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, OutputLemmaReason.BUDGET.value)
    inequalities = _refined_inequalities(pairs, replacements, preprocessing)
    remaining = _remaining_ms(deadline)
    if not remaining:
        return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, OutputLemmaReason.BUDGET.value)
    solver.set(timeout=remaining)
    solver.add(z3.Or(*inequalities))
    outcome = solver.check()
    if outcome == z3.unsat:
        return OutputEqualityResult(ProofStatus.PROVED, lemmas)
    if outcome == z3.sat:
        return OutputEqualityResult(ProofStatus.COUNTEREXAMPLE, lemmas, model=solver.model())
    return OutputEqualityResult(ProofStatus.UNKNOWN, lemmas, solver.reason_unknown())


def prove_output_equalities(
    pairs: list[OutputPair], solver: z3.Solver, *, deadline: float,
    lemma_timeout_ms: int = 1000,
    scalar_preprocessing: ScalarPreprocessing = ScalarPreprocessing.STANDARD,
) -> OutputEqualityResult:
    """Prove complete output equality using only discharged array lemmas.

    SSA expressions must arrive before scalar simplification expands loads over
    store chains. Equal array expressions can then be substituted in subsequent
    reads by congruence. UNSAT discharges each lemma under the caller constraints;
    neither a timeout nor a proposed memory relation supplies an assumption.
    Array queries have a small per-obligation budget. An unknown lemma falls
    through to the complete original comparison with the remaining total time.
    Opt-in read-over-write preprocessing retains every possible address alias
    and consumes this same deadline before the final complete SMT query.
    """
    if lemma_timeout_ms <= 0:
        raise ValueError('lemma_timeout_ms must be positive')
    names = {name for name, _, _ in pairs}
    if not pairs or len(names) != len(pairs) or '' in names:
        return OutputEqualityResult(ProofStatus.UNKNOWN, (), OutputLemmaReason.OUTPUTS.value)
    lemmas: list[OutputLemma] = []
    replacements: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for name, left, right in pairs:
        if not z3.is_array(left) and not z3.is_array(right):
            continue
        remaining = _remaining_ms(deadline)
        if not remaining:
            return OutputEqualityResult(ProofStatus.UNKNOWN, tuple(lemmas), OutputLemmaReason.BUDGET.value)
        lemma, model = _array_lemma(name, left, right, solver, min(lemma_timeout_ms, max(1, remaining // 2)))
        lemmas.append(lemma)
        if lemma.status is ProofStatus.COUNTEREXAMPLE:
            return OutputEqualityResult(ProofStatus.COUNTEREXAMPLE, tuple(lemmas), model=model)
        if lemma.status is ProofStatus.PROVED:
            solver.add(left == right)
            replacements.append((right, left))
    return _compare_refined(pairs, replacements, solver, deadline, tuple(lemmas), scalar_preprocessing)
