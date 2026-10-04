"""Combined invertible register and full-memory cutpoint coordinates.

Layer: dosunit relational state contracts.
Responsibility: compose register relations with finite byte-address permutations
while retaining identity at function entry and final return boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.dosunit.memory_state_relations import MemoryPermutation
from tools.dosunit.register_affine_relations import RegisterRelation
from tools.dosunit.register_state_relations import IDENTITY_RELATION, MachineState


@dataclass(frozen=True, slots=True)
class CutpointStateRelation:
    """Invertible interior coordinates; proposals require complete SMT proofs."""

    memory: MemoryPermutation
    registers: RegisterRelation = IDENTITY_RELATION

    @property
    def is_identity(self) -> bool:
        """Expose whether both state projections retain identical coordinates."""
        return self.memory.is_identity and self.registers.is_identity

    def candidate_inputs(self, oracle: MachineState) -> MachineState:
        """Evaluate memory addresses in oracle coordinates before register mapping."""
        result = self.registers.candidate_inputs(oracle)
        result['memory'] = self.memory.apply(oracle['memory'], oracle)
        return result

    def continuing_outputs(
        self, candidate: MachineState, *, control_field: str,
        reenters_entry: bool = False, entry_token: int = 0,
    ) -> MachineState:
        """Invert registers then memory; entry backedges demand full identity."""
        result = self.registers.continuing_outputs(candidate, control_field=control_field)
        memory = self.memory.apply(candidate['memory'], result, inverse=True)
        if reenters_entry:
            guard: dict[str, Any] = {'op': 'eq', 'width': 1, 'args': [candidate[control_field],
                {'op': 'const', 'width': 32, 'value': hex(entry_token)}]}
            memory = {'op': 'ite', 'width': 0, 'args': [guard, candidate['memory'], memory]}
            result = self.registers.continuing_outputs(candidate, control_field=control_field,
                                                      reenters_entry=True, entry_token=entry_token)
        result['memory'] = memory
        return result


type CutpointRelation = RegisterRelation | CutpointStateRelation
