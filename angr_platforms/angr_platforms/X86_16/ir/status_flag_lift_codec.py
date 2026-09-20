"""Serialize durable status-flag lift evidence for angr FunctionInfo.

Layer: IR.
Responsibility: losslessly project the typed status-flag lift artifact to and
from the JSON-compatible mapping accepted by angr's function knowledge base.
This module does not infer flag semantics or accept malformed evidence.

Owns typed Value, Address, Condition, instruction facts, and lossless
normalization. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..semantics.status_flag_contracts import STATUS_FLAGS_8616, StatusFlag8616, StatusFlagEffect8616
from .status_flag_lift_context import (
    StatusFlagLiftArtifact8616,
    StatusFlagLiftCandidate8616,
)


def _plain_int_8616(value: object) -> int | None:
    """Return one non-boolean integer from a serialized artifact field."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def encode_status_flag_lift_artifact_8616(
    artifact: StatusFlagLiftArtifact8616,
) -> dict[str, object]:
    """Encode one complete typed artifact without losing masks or addresses."""
    return {
        "function_address": artifact.function_address,
        "candidates": [
            {
                "instruction_address": candidate.instruction_address,
                "written": int(candidate.written),
                "dead_writes": int(candidate.dead_writes),
            }
            for candidate in artifact.candidates
        ],
        "packed_preservation_addresses": sorted(artifact.packed_preservation_addresses),
        "original_linear_delta": artifact.original_linear_delta,
        "callee_effects": [
            {"target": target, "reads": int(effect.reads), "overwrites": int(effect.overwrites)}
            for target, effect in artifact.callee_effects
        ],
    }


def decode_status_flag_lift_artifact_8616(
    payload: object,
) -> StatusFlagLiftArtifact8616 | None:
    """Decode a complete artifact, refusing any malformed structured field."""
    if not isinstance(payload, Mapping):
        return None
    function_address = _plain_int_8616(payload.get("function_address"))
    original_linear_delta = _plain_int_8616(payload.get("original_linear_delta"))
    candidate_payloads = payload.get("candidates")
    preservation_payload = payload.get("packed_preservation_addresses")
    if (
        function_address is None
        or original_linear_delta is None
        or not isinstance(candidate_payloads, list)
        or not isinstance(preservation_payload, list)
    ):
        return None
    candidates: list[StatusFlagLiftCandidate8616] = []
    for item in candidate_payloads:
        if not isinstance(item, Mapping):
            return None
        instruction_address = _plain_int_8616(item.get("instruction_address"))
        written = _plain_int_8616(item.get("written"))
        dead_writes = _plain_int_8616(item.get("dead_writes"))
        if instruction_address is None or written is None or dead_writes is None:
            return None
        candidates.append(
            StatusFlagLiftCandidate8616(
                instruction_address=instruction_address,
                written=StatusFlag8616(written),
                dead_writes=StatusFlag8616(dead_writes),
            )
        )
    preservation_addresses: set[int] = set()
    for value in preservation_payload:
        address = _plain_int_8616(value)
        if address is None:
            return None
        preservation_addresses.add(address)
    return StatusFlagLiftArtifact8616(
        function_address=function_address,
        candidates=tuple(candidates),
        packed_preservation_addresses=frozenset(preservation_addresses),
        original_linear_delta=original_linear_delta,
        callee_effects=_decode_callee_effects_8616(payload.get("callee_effects", [])),
    )


def _decode_callee_effects_8616(payload: object) -> tuple[tuple[int, StatusFlagEffect8616], ...]:
    """Refuse malformed or conflicting summaries without promoting evidence."""
    if not isinstance(payload, list):
        return ()
    effects: dict[int, StatusFlagEffect8616] = {}
    for entry in payload:
        if not isinstance(entry, Mapping):
            return ()
        target = _plain_int_8616(entry.get("target"))
        reads = _plain_int_8616(entry.get("reads"))
        overwrites = _plain_int_8616(entry.get("overwrites"))
        if target is None or reads is None or overwrites is None:
            return ()
        invalid_mask = reads < 0 or overwrites < 0 or (reads | overwrites) & ~int(STATUS_FLAGS_8616)
        if target < 0 or invalid_mask or target in effects:
            return ()
        effects[target] = StatusFlagEffect8616(StatusFlag8616(reads), StatusFlag8616(overwrites))
    return tuple(sorted(effects.items()))


__all__ = [
    "decode_status_flag_lift_artifact_8616",
    "encode_status_flag_lift_artifact_8616",
]
