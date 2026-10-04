"""Layer: dosunit native artifact equality boundary (staging).

Responsibility: decode bounded immutable effect proposals and prove complete
state equality against independently lifted effects. Syntactically different
literal conversions require proof; no field or array may be omitted.
"""
from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, cast

import z3

from tools.dosunit import straightline_ssa as S
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.register_state_relations import MachineState
from tools.dosunit.ssa_output_lemmas import OutputEqualityResult, prove_output_equalities

MAX_PROPOSAL_BYTES: int = 1048576
MAX_PROPOSAL_NODES: int = 262144
MAX_PROPOSAL_DEPTH: int = 128


class NativeProposalReason(StrEnum):
    """Named serialized artifact or native-expression boundary failures."""

    MALFORMED = "native_proposal_malformed"
    RESOURCE = "native_proposal_expression_budget_exceeded"


class NativeProposalRefusal(Exception):
    """Expose the exact untrusted artifact boundary rather than guessing a state."""

    def __init__(self, reason: NativeProposalReason, detail: str) -> None:
        """Retain the typed reason and original error detail."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def _guard(state: dict[str, Any], limits: LoadedRelationLimits) -> None:
    """Bound the JSON term tree before owned recursive SSA materialization."""
    pending = [(term, 1) for term in state.values()]
    count = 0
    while pending:
        limits.check_time()
        node, depth = pending.pop()
        count += 1
        if count > MAX_PROPOSAL_NODES or depth > MAX_PROPOSAL_DEPTH:
            raise NativeProposalRefusal(NativeProposalReason.RESOURCE, "serialized native term tree exceeds budget")
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native effect operand lacks a typed operation")
        width = node.get("width", 0)
        if type(width) is not int or not 0 <= width <= 64:
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native effect operand width is invalid")
        args = node.get("args", [])
        if not isinstance(args, list):
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native effect operand list is invalid")
        pending.extend((child, depth + 1) for child in args)


def decode_native_proposal(data: bytes, limits: LoadedRelationLimits) -> MachineState:
    """Parse one canonical bounded JSON proposal and require every native field."""
    limits.check_time()
    if type(data) is not bytes or not data or len(data) > MAX_PROPOSAL_BYTES:
        raise NativeProposalRefusal(NativeProposalReason.RESOURCE, "native proposal byte intake is invalid or oversized")
    try:
        parsed = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, str(error)) from error
    except RecursionError as error:
        raise NativeProposalRefusal(NativeProposalReason.RESOURCE, str(error)) from error
    if not isinstance(parsed, dict):
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native proposal is not an output mapping")
    _guard(parsed, limits)
    if canonical_json_bytes(parsed) != data:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native proposal is not canonical or contains duplicate keys")
    baseline = initial_state()
    if set(parsed) != set(baseline):
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native proposal full output manifest differs")
    for name, expected in baseline.items():
        if name not in {"memory", "io"} and parsed[name].get("width") != expected["width"]:
            raise NativeProposalRefusal(NativeProposalReason.MALFORMED, f"native proposal output width differs: {name}")
    # JSON is a dynamic third-party boundary; the complete term tree and
    # manifest have been validated before narrowing to the owned state type.
    return cast(MachineState, parsed)


def _compare(independent: MachineState, claimed: MachineState,
              limits: LoadedRelationLimits) -> OutputEqualityResult:
    """Materialize and compare every output at the opaque SMT-library boundary."""
    before = materialize_function("native:independent", independent)
    after = materialize_function("native:claimed", claimed)
    limits.check_time()
    inputs = S._z3_inputs(before, after, z3)
    names = sorted(initial_state())
    pairs, skipped = S._z3_output_pairs(names, oracle=before, candidate=after,
        oracle_outputs=before["outputs"], candidate_outputs=after["outputs"],
        inputs=inputs, z3=z3, simplify_terms=False)
    if skipped or len(pairs) != len(names) or {name for name, _, _ in pairs} != set(names):
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, "native output comparison omitted fields")
    limits.check_time()
    return prove_output_equalities(pairs, z3.Solver(), deadline=limits.deadline)


def prove_native_effect_identity(independent: MachineState, proposal: bytes,
                                 limits: LoadedRelationLimits) -> OutputEqualityResult:
    """Compare all native outputs with unrestricted inputs and no callee premise."""
    claimed = decode_native_proposal(proposal, limits)
    try:
        return _compare(independent, claimed, limits)
    except z3.Z3Exception as error:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, f"native expression sort: {error}") from error
    except S.LowerFailure as error:
        raise NativeProposalRefusal(NativeProposalReason.MALFORMED, f"{error.reason}: {error.message}") from error
