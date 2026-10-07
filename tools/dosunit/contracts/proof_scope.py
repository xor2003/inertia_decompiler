"""Admit solver results only within their declared proof scope.

Layer: dosunit proof accounting.
Responsibility: distinguish complete entry-to-terminal comparisons from
simulation obligations at arbitrary cutpoints. A SAT cutpoint state refutes a
proposed relation, but need not be reachable in either executable.
"""

from __future__ import annotations

from enum import StrEnum

from tools.dosunit.contracts.proof_contracts import ProofStatus


class ProofScope(StrEnum):
    """The initial-state and execution coverage of one proof obligation."""

    COMPLETE_FUNCTION = "complete_function"
    CUTPOINT_SIMULATION = "cutpoint_simulation"


def admit_scope_status(status: ProofStatus, scope: ProofScope) -> ProofStatus:
    """Preserve complete-function SAT; retain internal SAT as unknown behavior.

    Raw solver results and countermodels must remain in diagnostic evidence.
    This admission changes only the status attributed to the whole function.
    """
    if scope is ProofScope.CUTPOINT_SIMULATION and status is ProofStatus.COUNTEREXAMPLE:
        return ProofStatus.UNKNOWN
    return status
