"""Layer: validation function-boundary observations.

Responsibility: admit explicit scalar return contracts for closed loop proofs,
without projecting internal memory or guessing a function's return type.
"""
from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any

from tools.comparator.verdict import Status
from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation, record_abi_observation
from tools.dosunit.contracts.proof_scope import ProofScope


class LoopObservationReason(StrEnum):
    """Capabilities required before an ABI premise can reach loop induction."""

    UNSUPPORTED = "loop_abi_observation_unsupported"
    INCOMPLETE = "loop_abi_observation_incomplete_scope"


def compare_observed_loop(
    check: Callable[[tuple[str, ...]], dict[str, Any]], contract: Flat32AbiObservation,
) -> dict[str, Any]:
    """Select root return registers and publish success only as conditional.

    The underlying engine still lowers full internal transitions and proves
    their dependency projection. Memory remains fully observed. Narrow EAX
    returns and private-stack lifetime projections require additional machinery
    and are deliberately not applied to arbitrary interior cutpoints.
    """
    if (contract.private_stack_bytes or contract.stack_disjoint_buffers or contract.entry_memory_ranges
            or contract.return_bits not in (0, 32, 64)):
        return {"status": Status.REFUSED, "reason": LoopObservationReason.UNSUPPORTED,
                "abi_observation": contract.premise(())}
    result = check(contract.outputs())
    if (result.get("status") in {Status.PASSED, Status.CONDITIONAL}
            and result.get("proof_scope") != ProofScope.CUTPOINT_SIMULATION):
        return {"status": Status.REFUSED, "reason": LoopObservationReason.INCOMPLETE}
    record_abi_observation(result, contract.premise(()))
    return result
