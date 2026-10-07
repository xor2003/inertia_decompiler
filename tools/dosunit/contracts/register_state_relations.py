"""Bijective register cutpoint proposals consumed by complete SMT proofs.

Layer: dosunit relational state contracts.
Responsibility: propose width-preserving register permutations from typed SSA
entry effects and apply their exact input/output substitution. A proposal never
establishes equivalence; initiation, preservation, progress and exits must prove.
Memory, control, segments and flags remain unchanged by register proposals.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from tools.dosunit.contracts.model import canonical_json_bytes

type MachineState = dict[str, dict[str, Any]]


class RegisterRelationReason(StrEnum):
    """Missing or contradictory evidence for a proposed register relation."""

    BINARY_EFFECTS = "entry_effect_permutation_proposed"
    AFFINE_EFFECTS = "entry_affine_effects_proposed"
    NONINVERTIBLE = "register_affine_multiplier_not_invertible"
    SYNTHESIS_LIMIT = "register_relation_synthesis_limit"
    NO_MATCH = "entry_register_effects_unpaired"
    AMBIGUOUS = "entry_register_effects_ambiguous"
    BIJECTION = "register_relation_not_bijective"
    WIDTH = "register_relation_width_mismatch"
    MISSING = "register_relation_state_missing"


class RegisterRelationRefusal(Exception):
    """Fail closed when an attempted register relation is not well-defined."""

    def __init__(self, reason: RegisterRelationReason) -> None:
        """Retain the typed missing relation obligation."""
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class RegisterBinding:
    """A candidate register carrying one equal-width oracle register value."""

    candidate: str
    oracle: str
    width: int


@dataclass(frozen=True, slots=True)
class RegisterPermutation:
    """Invertible finite cutpoint register correspondence with identity elsewhere."""

    bindings: tuple[RegisterBinding, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate names, non-bijective domains and conflicting widths."""
        candidate = {binding.candidate for binding in self.bindings}
        oracle = {binding.oracle for binding in self.bindings}
        if candidate != oracle or len(candidate) != len(self.bindings):
            raise RegisterRelationRefusal(RegisterRelationReason.BIJECTION)
        widths = {binding.candidate: binding.width for binding in self.bindings}
        if any(binding.width <= 0 or widths[binding.oracle] != binding.width for binding in self.bindings):
            raise RegisterRelationRefusal(RegisterRelationReason.WIDTH)

    @property
    def is_identity(self) -> bool:
        """Expose whether all state components have their original correspondence."""
        return all(binding.candidate == binding.oracle for binding in self.bindings)

    def _term(self, state: MachineState, name: str, width: int) -> dict[str, Any]:
        """Read an existing exact-width state component; never invent a value."""
        if name not in state:
            raise RegisterRelationRefusal(RegisterRelationReason.MISSING)
        term = state[name]
        if term.get("width") != width:
            raise RegisterRelationRefusal(RegisterRelationReason.WIDTH)
        return term

    def candidate_inputs(self, oracle: MachineState) -> MachineState:
        """Bind interior candidate inputs to oracle values under this permutation."""
        related = dict(oracle)
        for binding in self.bindings:
            self._term(oracle, binding.candidate, binding.width)
            related[binding.candidate] = self._term(oracle, binding.oracle, binding.width)
        return related

    def continuing_outputs(
        self, candidate: MachineState, *, control_field: str,
        reenters_entry: bool = False, entry_token: int = 0,
    ) -> MachineState:
        """Express candidate continuing state in oracle coordinates.

        Initiation uses identity at the function entry. A transition returning
        there must restore identity, so its data relation is selected by the
        proved paired control token rather than assuming an interior relation.
        Actual function returns bypass this method and retain final identity.
        """
        related = dict(candidate)
        for binding in self.bindings:
            term = self._term(candidate, binding.candidate, binding.width)
            if reenters_entry:
                control = self._term(candidate, control_field, 32)
                identity = self._term(candidate, binding.oracle, binding.width)
                guard = {"op": "eq", "width": 1,
                         "args": [control, {"op": "const", "width": 32, "value": hex(entry_token)}]}
                term = {"op": "ite", "width": binding.width, "args": [guard, identity, term]}
            related[binding.oracle] = term
        return related


IDENTITY_RELATION: Final[RegisterPermutation] = RegisterPermutation()
"""Immutable identity relation shared by proof contracts and default attempts."""


@dataclass(frozen=True, slots=True)
class RegisterProposal:
    """An untrusted entry-effect proposal or an explicit synthesis non-result."""

    reason: RegisterRelationReason
    relation: RegisterPermutation | None


def propose_entry_permutation(
    oracle: MachineState, candidate: MachineState, widths: dict[str, int],
) -> RegisterProposal:
    """Propose a unique width-preserving permutation from binary SSA effects.

    Structural equality selects a candidate only. Ambiguous equal constants
    and missing state do not justify guessing a register map. The consumer
    must still prove the entire entry transition and all interior/exit effects.
    """
    keys: dict[str, bytes] = {}
    for name, width in widths.items():
        if name not in oracle or name not in candidate:
            return RegisterProposal(RegisterRelationReason.MISSING, None)
        if oracle[name].get("width") != width or candidate[name].get("width") != width:
            return RegisterProposal(RegisterRelationReason.WIDTH, None)
        keys[name] = canonical_json_bytes(oracle[name])
    bindings: list[RegisterBinding] = []
    for name, width in sorted(widths.items()):
        key = canonical_json_bytes(candidate[name])
        if key == keys[name]:
            continue
        matches = [original for original in widths if widths[original] == width and keys[original] == key]
        if not matches:
            return RegisterProposal(RegisterRelationReason.NO_MATCH, None)
        if len(matches) != 1:
            return RegisterProposal(RegisterRelationReason.AMBIGUOUS, None)
        bindings.append(RegisterBinding(name, matches[0], width))
    try:
        relation = RegisterPermutation(tuple(bindings))
    except RegisterRelationRefusal as error:
        return RegisterProposal(error.reason, None)
    return RegisterProposal(RegisterRelationReason.BINARY_EFFECTS, relation)
