"""Flat32 adapter boundary for independently discharged memory invariants.

Layer: dosunit flat32 induction adapter.
Responsibility: bind the active driver register model and shared deadline while
recording every initiation/preservation obligation, without treating proposals
as assumptions or dropping state components.
"""
from __future__ import annotations

import time
from typing import Any

from tools.dosunit.memory_invariant_obligations import (
    MemoryInvariantObligation,
    MemoryInvariantProof,
    prove_fixed_point,
)
from tools.dosunit.memory_state_invariants import MemoryInvariant
from tools.dosunit.register_state_relations import MachineState


def record_invariant_proof(
    invariant: MemoryInvariant | None, state: MachineState,
    proofs: list[MemoryInvariantProof] | None, *, adapter: Any,  # noqa: ANN401
    refusal: type[Exception], deadline: float | None, is_entry: bool,
    reenters_entry: bool,
) -> None:
    """Discharge a continuing-state fixed point under the driver's full model.

    ``adapter`` is the dynamic artifact-driver boundary. Both lanes bind their
    own register/control semantics through its installation context; the typed
    invariant and proof contracts belong to shared dosunit.
    """
    if invariant is None or proofs is None:
        return
    if deadline is None or time.monotonic() >= deadline:
        raise refusal("memory_invariant_deadline_exceeded")
    obligation = MemoryInvariantObligation.INITIATION if is_entry else MemoryInvariantObligation.PRESERVATION
    with adapter.installed():
        proofs.append(prove_fixed_point(
            invariant, state, obligation, timeout_ms=max(1, int((deadline - time.monotonic()) * 1000)),
            control_field="eip", reenters_entry=reenters_entry,
        ))
