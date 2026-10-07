"""Invertible modular affine register proposals for complete cutpoint proofs.

Layer: dosunit relational state contracts.
Responsibility: derive candidate affine maps from typed entry SSA, retain exact
bitvector widths and apply forward/inverse substitutions. Structural synthesis
never establishes equivalence; consumers prove complete state and every edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.register_state_relations import (
    MachineState,
    RegisterBinding,
    RegisterPermutation,
    RegisterRelationReason,
    RegisterRelationRefusal,
    propose_entry_permutation,
)
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector

MAX_SYNTHESIS_DEPTH: int = 128


@dataclass(frozen=True, slots=True)
class AffineRegisterBinding:
    """Candidate register equals multiplier times oracle register plus offset."""

    candidate: str
    oracle: str
    width: int
    multiplier: int = 1
    offset: int = 0


def _constant(value: int, width: int) -> dict[str, Any]:
    """Publish a canonical unsigned bit pattern in the declared modular ring."""
    return {"op": "const", "width": width, "value": hex(value % (1 << width))}


def _affine(term: dict[str, Any], multiplier: int, offset: int, width: int) -> dict[str, Any]:
    """Apply an exact modular affine transformation without changing flags."""
    result = term
    if multiplier != 1:
        result = {"op": "mul", "width": width, "args": [result, _constant(multiplier, width)]}
    if offset:
        result = {"op": "add", "width": width, "args": [result, _constant(offset, width)]}
    return result


def _read(state: MachineState, name: str, width: int) -> dict[str, Any]:
    """Require an existing state component of the exact declared width."""
    if name not in state:
        raise RegisterRelationRefusal(RegisterRelationReason.MISSING)
    if state[name].get("width") != width:
        raise RegisterRelationRefusal(RegisterRelationReason.WIDTH)
    return state[name]


@dataclass(frozen=True, slots=True)
class RegisterAffineRelation:
    """Bijective register correspondence over finite-width modular arithmetic."""

    bindings: tuple[AffineRegisterBinding, ...] = ()

    def __post_init__(self) -> None:
        """Require a width-preserving permutation and odd invertible multipliers."""
        RegisterPermutation(tuple(RegisterBinding(b.candidate, b.oracle, b.width) for b in self.bindings))
        for binding in self.bindings:
            modulus = 1 << binding.width
            if not 0 < binding.multiplier < modulus or binding.multiplier % 2 != 1:
                raise RegisterRelationRefusal(RegisterRelationReason.NONINVERTIBLE)
            if not 0 <= binding.offset < modulus:
                raise RegisterRelationRefusal(RegisterRelationReason.WIDTH)

    @property
    def is_identity(self) -> bool:
        """Expose whether every register keeps its original value and identity."""
        return all(b.candidate == b.oracle and b.multiplier == 1 and b.offset == 0 for b in self.bindings)

    def candidate_inputs(self, oracle: MachineState) -> MachineState:
        """Construct candidate interior inputs from exact oracle state values."""
        related = dict(oracle)
        for binding in self.bindings:
            _read(oracle, binding.candidate, binding.width)
            related[binding.candidate] = _affine(_read(oracle, binding.oracle, binding.width),
                                                binding.multiplier, binding.offset, binding.width)
        return related

    def continuing_outputs(
        self, candidate: MachineState, *, control_field: str,
        reenters_entry: bool = False, entry_token: int = 0,
    ) -> MachineState:
        """Invert interior outputs; entry backedges must instead restore identity."""
        related = dict(candidate)
        for binding in self.bindings:
            modulus = 1 << binding.width
            inverse = pow(binding.multiplier, -1, modulus)
            term = _affine(_read(candidate, binding.candidate, binding.width), inverse,
                           (-inverse * binding.offset) % modulus, binding.width)
            if reenters_entry:
                control = _read(candidate, control_field, 32)
                guard = {"op": "eq", "width": 1, "args": [control, _constant(entry_token, 32)]}
                term = {"op": "ite", "width": binding.width,
                        "args": [guard, _read(candidate, binding.oracle, binding.width), term]}
            related[binding.oracle] = term
        return related


type RegisterRelation = RegisterPermutation | RegisterAffineRelation


@dataclass(frozen=True, slots=True)
class StateRelationProposal:
    """An untrusted register relation or explicit synthesis non-result."""

    reason: RegisterRelationReason
    relation: RegisterRelation | None


@dataclass(frozen=True, slots=True)
class _LinearEffect:
    """One structurally shared base term and its modular linear coefficients."""

    base: dict[str, Any] | None
    multiplier: int
    offset: int


def _atom(term: dict[str, Any], width: int) -> _LinearEffect:
    """Retain an unrecognized typed expression as an uninterpreted proposal base."""
    base = term if term.get("width") == width else {"op": "trunc", "width": width, "args": [term]}
    return _LinearEffect(base, 1, 0)


def _linear_effect(term: dict[str, Any], width: int, depth: int = 0) -> _LinearEffect:
    """Normalize only modular linear arithmetic and sound low-bit projections."""
    if depth >= MAX_SYNTHESIS_DEPTH:
        raise RegisterRelationRefusal(RegisterRelationReason.SYNTHESIS_LIMIT)
    actual_width = term.get("width")
    if type(actual_width) is not int or actual_width < width:
        raise RegisterRelationRefusal(RegisterRelationReason.WIDTH)
    literal = constant_bitvector(term)
    if literal is not None:
        return _LinearEffect(None, 0, literal[0] % (1 << width))
    operation, args = term.get("op"), term.get("args")
    if not isinstance(args, list) or not all(isinstance(arg, dict) for arg in args):
        return _atom(term, width)
    projectable = (operation in {"trunc", "zext", "sext"} and len(args) == 1
                   and type(args[0].get("width")) is int and args[0]["width"] >= width)
    if projectable:
        return _linear_effect(args[0], width, depth + 1)
    if operation == "shl" and len(args) == 2:
        return _shift_effect(args, term, width, depth)
    if operation == "or" and len(args) == 2:
        return _projected_or_effect(args, term, width, depth)
    if operation not in {"add", "sub", "mul"} or len(args) != 2:
        return _atom(term, width)
    left = _linear_effect(args[0], width, depth + 1)
    right = _linear_effect(args[1], width, depth + 1)
    return _combine(operation, left, right, term, width)


def _projected_or_effect(
    args: list[dict[str, Any]], original: dict[str, Any], width: int, depth: int,
) -> _LinearEffect:
    """Discard an OR arm only when its projected bits are identically zero.

    Lifting a wide register may join the shifted high half with the extended
    low half. Truncation distributes over OR, so a high half shifted entirely
    beyond the requested width cannot affect the modular low-bit recurrence.
    Overlapping nonzero arms remain opaque; OR is never treated as addition.
    """
    left = _linear_effect(args[0], width, depth + 1)
    right = _linear_effect(args[1], width, depth + 1)
    if left.base is None and left.offset == 0:
        return right
    if right.base is None and right.offset == 0:
        return left
    return _atom(original, width)


def _shift_effect(
    args: list[dict[str, Any]], original: dict[str, Any], width: int, depth: int,
) -> _LinearEffect:
    """Treat only a constant logical left shift as exact modular multiplication."""
    literal = constant_bitvector(args[1])
    if literal is None:
        return _atom(original, width)
    effect = _linear_effect(args[0], width, depth + 1)
    modulus = 1 << width
    factor = pow(2, literal[0], modulus)
    multiplier = effect.multiplier * factor % modulus
    return _LinearEffect(effect.base if multiplier else None, multiplier, effect.offset * factor % modulus)


def _combine(
    operation: str, left: _LinearEffect, right: _LinearEffect,
    original: dict[str, Any], width: int,
) -> _LinearEffect:
    """Collect coefficients only when both expressions share one structural base."""
    modulus = 1 << width
    if operation == "mul":
        if left.base is not None and right.base is not None:
            return _atom(original, width)
        symbolic, factor = (left, right.offset) if right.base is None else (right, left.offset)
        return _LinearEffect(symbolic.base, symbolic.multiplier * factor % modulus, symbolic.offset * factor % modulus)
    if (left.base is not None and right.base is not None
            and canonical_json_bytes(left.base) != canonical_json_bytes(right.base)):
        return _atom(original, width)
    sign = 1 if operation == "add" else -1
    return _LinearEffect(left.base if left.base is not None else right.base,
                         (left.multiplier + sign * right.multiplier) % modulus,
                         (left.offset + sign * right.offset) % modulus)


def _matching_binding(
    name: str, effect: _LinearEffect, originals: dict[str, _LinearEffect], widths: dict[str, int],
) -> AffineRegisterBinding:
    """Select a unique base correspondence, never guess an ambiguous pairing."""
    width = widths[name]
    modulus = 1 << width
    matches = [key for key, original in originals.items() if widths[key] == width
               and canonical_json_bytes(original.base) == canonical_json_bytes(effect.base)
               and original.multiplier % 2 == 1]
    if not matches:
        raise RegisterRelationRefusal(RegisterRelationReason.NO_MATCH)
    if len(matches) != 1:
        raise RegisterRelationRefusal(RegisterRelationReason.AMBIGUOUS)
    original_name = matches[0]
    original = originals[original_name]
    multiplier = effect.multiplier * pow(original.multiplier, -1, modulus) % modulus
    offset = (effect.offset - multiplier * original.offset) % modulus
    return AffineRegisterBinding(name, original_name, width, multiplier, offset)


def propose_entry_relation(oracle: MachineState, candidate: MachineState, widths: dict[str, int]) -> StateRelationProposal:
    """Propose an exact-width permutation or affine map from binary entry SSA.

    Every result remains unproved until the consumer discharges full-state
    initiation, preservation, exits and progress. No solver status is synthesized
    here. Even invertible arithmetic does not establish a memory/flag relation.
    """
    permutation = propose_entry_permutation(oracle, candidate, widths)
    if permutation.relation is not None:
        return StateRelationProposal(permutation.reason, permutation.relation)
    try:
        originals = {name: _linear_effect(_read(oracle, name, width), width) for name, width in widths.items()}
        bindings: list[AffineRegisterBinding] = []
        for name, width in sorted(widths.items()):
            effect = _linear_effect(_read(candidate, name, width), width)
            if canonical_json_bytes(_read(oracle, name, width)) == canonical_json_bytes(candidate[name]):
                continue
            bindings.append(_matching_binding(name, effect, originals, widths))
        return StateRelationProposal(RegisterRelationReason.AFFINE_EFFECTS, RegisterAffineRelation(tuple(bindings)))
    except RegisterRelationRefusal as error:
        return StateRelationProposal(error.reason, None)
