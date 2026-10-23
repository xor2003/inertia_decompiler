"""Layer: dosunit relational state contracts.

Responsibility: propose bounded three-register cycles from a cross-register
entry effect. Relocation is used only in proposal keys, never as proof.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.register_state_relations import (
    MachineState,
    RegisterBinding,
    RegisterPermutation,
)
from tools.dosunit.ssa.ssa_constant_terms import constant_bitvector


def _proposal_term(
    term: dict[str, Any], relocation: Mapping[int, int], budget: list[int], depth: int = 0,
) -> dict[str, Any] | None:
    """Build a bounded copy for matching only; retain actual SSA unchanged."""
    budget[0] -= 1
    if budget[0] < 0 or depth >= 128:
        return None
    literal = constant_bitvector(term) if term.get("op") == "const" else None
    if literal is not None:
        value, width = literal
        return {"op": "const", "width": width, "value": hex(relocation.get(value, value) % (1 << width))}
    result = dict(term)
    if "args" in term:
        args = []
        for child in term["args"]:
            copied = _proposal_term(child, relocation, budget, depth + 1)
            if copied is None:
                return None
            args.append(copied)
        result["args"] = args
    return result


def propose_entry_cycles(
    oracle: MachineState, candidate: MachineState, widths: dict[str, int],
    relocation: Mapping[int, int] | None = None,
) -> tuple[RegisterPermutation, ...]:
    """Propose at most six three-cycles anchored by one matching entry effect.

    The third coordinate may be unchanged at entry and written later. Every
    proposal remains untrusted and requires full initiation, preservation and
    exit proofs, including liveness of any mismatching scratch coordinates.
    """
    originals: dict[str, bytes] = {}
    rebuilt: dict[str, bytes] = {}
    budget = [4096]
    for name, width in sorted(widths.items()):
        if name not in oracle or name not in candidate:
            continue
        if oracle[name].get("width") != width or candidate[name].get("width") != width:
            continue
        left = _proposal_term(oracle[name], {}, budget)
        right = _proposal_term(candidate[name], relocation or {}, budget)
        if left is None or right is None:
            return ()
        originals[name], rebuilt[name] = canonical_json_bytes(left), canonical_json_bytes(right)
    return _cycles(originals, rebuilt, widths)


def _cycles(
    originals: dict[str, bytes], rebuilt: dict[str, bytes], widths: dict[str, int],
) -> tuple[RegisterPermutation, ...]:
    """Close matching directed edges into deterministic width-preserving cycles."""
    proposals: list[RegisterPermutation] = []
    for candidate, key in rebuilt.items():
        for oracle, original in originals.items():
            if candidate == oracle or key != original or widths[candidate] != widths[oracle]:
                continue
            for third in originals:
                if third in {candidate, oracle} or widths[third] != widths[oracle]:
                    continue
                relation = RegisterPermutation(tuple(sorted((
                    RegisterBinding(candidate, oracle, widths[oracle]),
                    RegisterBinding(oracle, third, widths[oracle]),
                    RegisterBinding(third, candidate, widths[oracle]),
                ), key=lambda binding: binding.candidate)))
                if relation not in proposals:
                    proposals.append(relation)
                if len(proposals) >= 6:
                    return tuple(proposals)
    return tuple(proposals)
