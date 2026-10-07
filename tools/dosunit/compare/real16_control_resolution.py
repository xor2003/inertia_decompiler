"""Layer: dosunit real16 control destination proof.

Responsibility: prove a proposed full loaded destination under every selector
in the architectural entry domain. Metadata proposes a target; solver evidence
admits it. This local fact establishes neither source binding nor equivalence.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.compare.real16_call_contracts import prove_terms_equal
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.contracts.real16_entry_domain import Real16EntryDomain, code_entry_domain


class ControlResolutionReason(StrEnum):
    """The exact target premise discharged or refused."""

    PROVED = "full_loaded_control_target_proved"
    DOMAIN = "control_entry_domain_missing"
    WIDTH = "control_destination_not_full_dword"
    TARGET = "proposed_control_destination_countermodel"
    UNKNOWN = "control_destination_solver_unknown"
    DEADLINE = "control_destination_original_deadline_exhausted"


@dataclass(frozen=True, slots=True)
class ControlDestinationProof:
    """One universal target result with its explicit nonvacuous entry domain."""

    status: ProofStatus
    reason: ControlResolutionReason
    proposed: int
    domain: Real16EntryDomain | None


def prove_control_destination(
    term: dict[str, Any], proposed: int, entry: int, *, deadline: float,
    max_solver_ms: int,
) -> ControlDestinationProof:
    """Prove a full target without narrowing CS or replenishing the deadline.

    Every possible selector whose code window contains the entry is admitted.
    Wrap-dependent destinations therefore refuse a single metadata target.
    SSA JSON is the existing solver boundary, not target recovery authority.
    """
    if type(proposed) is not int or not 0 <= proposed <= 0xFFFFFFFF:
        raise ValueError("control proposal requires a full unsigned32 loaded target")
    if type(max_solver_ms) is not int or max_solver_ms <= 0:
        raise ValueError("control destination requires a positive solver budget")
    if not math.isfinite(deadline):
        raise ValueError("control destination requires a finite absolute deadline")
    domain = code_entry_domain(entry)
    if domain is None:
        return ControlDestinationProof(ProofStatus.UNKNOWN, ControlResolutionReason.DOMAIN, proposed, domain)
    if term.get("width") != 32:
        return ControlDestinationProof(ProofStatus.UNKNOWN, ControlResolutionReason.WIDTH, proposed, domain)
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        return ControlDestinationProof(ProofStatus.UNKNOWN, ControlResolutionReason.DEADLINE, proposed, domain)
    expected = {"op": "const", "width": 32, "value": hex(proposed)}
    status = prove_terms_equal(term, expected, min(remaining, max_solver_ms),
                               input_constraints=domain.constraints())
    if time.monotonic() >= deadline:
        return ControlDestinationProof(ProofStatus.UNKNOWN, ControlResolutionReason.DEADLINE, proposed, domain)
    if status is ProofStatus.PROVED:
        reason = ControlResolutionReason.PROVED
    elif status is ProofStatus.COUNTEREXAMPLE:
        reason = ControlResolutionReason.TARGET
    else:
        reason = ControlResolutionReason.UNKNOWN
    return ControlDestinationProof(status, reason, proposed, domain)
