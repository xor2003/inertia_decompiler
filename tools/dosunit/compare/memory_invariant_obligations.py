"""Full-state fixed-point obligations for proposed interior memory invariants.

Layer: dosunit induction proof obligations.
Responsibility: discharge initiation or preservation against a complete state,
retain the raw solver result, and distinguish arbitrary cutpoint countermodels
from reachable whole-function counterexamples. Projections alone prove nothing.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.memory_state_invariants import MemoryInvariant
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.contracts.register_state_relations import MachineState


class MemoryInvariantObligation(StrEnum):
    """The inductive fact needed before projected interior inputs are admitted."""

    INITIATION = "memory_invariant_initiation"
    PRESERVATION = "memory_invariant_preservation"


@dataclass(frozen=True, slots=True)
class MemoryInvariantProof:
    """One independently discharged fixed-point obligation with raw evidence."""

    obligation: MemoryInvariantObligation
    status: ProofStatus
    diagnostics: dict[str, Any]


def continuing_projection(
    invariant: MemoryInvariant, state: MachineState, *, control_field: str,
    reenters_entry: bool = False, entry_token: int = 0,
) -> MachineState:
    """Require the invariant only for successors outside the function entry.

    Entry backedges return to the unprojected entry domain. All other continuing
    successors must reestablish the interior fixed point. No scalar component,
    event array, control token or unmentioned memory byte is discarded.
    """
    projected = invariant.apply(state)
    if reenters_entry:
        guard = {"op": "eq", "width": 1, "args": [state[control_field],
                 {"op": "const", "width": 32, "value": hex(entry_token)}]}
        projected["memory"] = {"op": "ite", "width": 0,
                               "args": [guard, state["memory"], projected["memory"]]}
    return projected


def prove_fixed_point(
    invariant: MemoryInvariant, state: MachineState, obligation: MemoryInvariantObligation,
    *, timeout_ms: int, control_field: str, reenters_entry: bool = False,
    constraints: list[dict[str, Any]] | None = None,
) -> MemoryInvariantProof:
    """Prove complete-state equality with its continuing-domain projection."""
    projected = continuing_projection(invariant, state, control_field=control_field,
                                      reenters_entry=reenters_entry)
    compared = S._compare_functions(materialize_function("invariant:state", state),
                                    materialize_function("invariant:projected", projected),
                                    timeout_ms=timeout_ms, input_constraints=constraints or [])
    raw_status = proof_status_from_legacy(compared.get("status")) or ProofStatus.UNKNOWN
    status = ProofStatus.PROVED if raw_status is ProofStatus.PROVED and not compared.get("skipped_layout_outputs") else ProofStatus.UNKNOWN
    return MemoryInvariantProof(obligation, status, compared)
