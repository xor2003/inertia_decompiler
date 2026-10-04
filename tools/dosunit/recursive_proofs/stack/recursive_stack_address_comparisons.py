"""Layer: dosunit recursive proof staging.

Responsibility: prove finite byte-address comparison identities globally before
substituting them into native select/store expansions. No memory is excluded.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

import z3

from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordDomain


class AddressComparisonReason(StrEnum):
    """Outcome of the independent Boolean-congruence theorem."""

    DISCHARGED = "address_comparisons_discharged"
    COUNTERMODEL = "address_comparison_countermodel"
    UNKNOWN = "address_comparison_unknown"
    DEADLINE = "address_comparison_deadline"


@dataclass(frozen=True, slots=True)
class AddressComparisonRule:
    """One actual byte-address equality and its proposed rank predicate."""

    actual: z3.BoolRef
    replacement: z3.BoolRef


@dataclass(frozen=True, slots=True)
class AddressComparisonEvidence:
    """One native query discharges the conjunction of every required rule."""

    status: ProofStatus
    reason: AddressComparisonReason
    required_rules: int
    discharged_rules: int
    attempted: bool
    elapsed_ms: int
    detail: str = ""

    @property
    def proved(self) -> bool:
        """Reject empty, partial or contradictory Boolean proof evidence."""
        return (self.status is ProofStatus.PROVED and self.reason is AddressComparisonReason.DISCHARGED
                and self.attempted and self.required_rules > 0
                and self.required_rules == self.discharged_rules)


@dataclass(frozen=True, slots=True)
class AddressComparisonResult:
    """Globally checked rules plus exact required/discharged accounting."""

    rules: tuple[AddressComparisonRule, ...]
    evidence: AddressComparisonEvidence

    @property
    def proved(self) -> bool:
        """Require the checked count to bind the complete actual rule tuple."""
        return self.evidence.proved and self.evidence.required_rules == len(self.rules)


def push_address_comparisons(domain: StackWordDomain, index: z3.BitVecRef) -> tuple[AddressComparisonRule, ...]:
    """Propose comparisons for arbitrary/root reads against each pushed byte.

    Distinct frame bytes never alias, even on offset wrap. Equal byte ordinals
    alias precisely when their finite ranks agree. Both native equality orders
    are retained when distinct, since select/store simplification may emit either.
    """
    pushed = domain.rank + 1
    rules: list[AddressComparisonRule] = []
    seen: set[int] = set()
    for read_rank in (index, z3.BitVecVal(0, domain.layout.rank_bits)):
        for read_byte in range(domain.layout.frame_bytes):
            read = domain.address(domain.offset(read_rank), read_byte)
            for write_byte in range(domain.layout.frame_bytes):
                write = domain.address(domain.offset(pushed), write_byte)
                replacement = read_rank == pushed if read_byte == write_byte else z3.BoolVal(False)
                for left, right in ((read, write), (write, read)):
                    actual = z3.simplify(left == right)
                    if not isinstance(actual, z3.BoolRef) or not isinstance(replacement, z3.BoolRef):
                        raise TypeError("address comparison must retain native Boolean sorts")
                    if actual.get_id() not in seen:
                        seen.add(actual.get_id())
                        rules.append(AddressComparisonRule(actual, replacement))
    return tuple(rules)


def discharge_address_comparisons(rules: tuple[AddressComparisonRule, ...], *,
                                  deadline: float) -> AddressComparisonResult:
    """Prove every replacement without stack or memory hypotheses.

    One UNSAT result for the negated conjunction proves every Boolean equality
    globally. SAT or UNKNOWN installs no replacement, including any prefix.
    """
    if not rules or len({rule.actual.get_id() for rule in rules}) != len(rules):
        raise ValueError("address comparison rules must be nonempty and unique")
    started = time.monotonic()
    remaining = int((deadline - started) * 1000)
    if remaining <= 0:
        evidence = AddressComparisonEvidence(ProofStatus.UNKNOWN, AddressComparisonReason.DEADLINE,
                                             len(rules), 0, False, 0)
        return AddressComparisonResult(rules, evidence)
    solver = z3.Solver()
    solver.set(timeout=remaining)
    solver.add(z3.Not(z3.And(*(rule.actual == rule.replacement for rule in rules))))
    checked = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    proved = checked == z3.unsat
    reason = (AddressComparisonReason.DISCHARGED if proved else
              AddressComparisonReason.COUNTERMODEL if checked == z3.sat else AddressComparisonReason.UNKNOWN)
    detail = solver.reason_unknown() if checked == z3.unknown else ""
    evidence = AddressComparisonEvidence(ProofStatus.PROVED if proved else ProofStatus.UNKNOWN, reason,
                                         len(rules), len(rules) if proved else 0, True, elapsed, detail)
    return AddressComparisonResult(rules, evidence)


def refine_address_comparisons(condition: z3.BoolRef, result: AddressComparisonResult | None) -> z3.BoolRef:
    """Use native read-over-write expansion plus only globally proved identities."""
    if result is None or not result.proved:
        return condition
    expanded = z3.simplify(condition, blast_select_store=True)
    replacements = tuple((rule.actual, rule.replacement) for rule in result.rules)
    refined = z3.simplify(z3.substitute(expanded, *replacements))
    if not isinstance(refined, z3.BoolRef):
        raise TypeError("Boolean address refinement must preserve the goal sort")
    return refined
