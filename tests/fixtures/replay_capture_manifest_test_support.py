"""Layer: test support.
Responsibility: own replay capture manifest fixture contracts and evidence.
"""
from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from tests.fixtures.replay_capture_contracts_test_support import WindowCheck, WindowRole
from tests.fixtures.replay_capture_fixture_test_support import F32_OUT, R16_LOAD, R16_OUT, R16_TRAP_OFF

from tools.dosunit.contracts.model import canonical_json_bytes


class VectorKind(StrEnum):
    """Provenance class carried beside every emitted vector."""

    RUNTIME = "runtime_capture"
    FUZZ = "deterministic_fuzz"
    EDGE = "deterministic_edge"


def _seg(segment: int, offset: int) -> dict[str, str]:
    return {"segment": f"{segment:#06x}", "offset": f"{offset:#06x}"}


def _r16_vector(
    vector_id: str, *, entry_off: int, regs: dict[str, int],
    segs: dict[str, int], memory: list[dict[str, Any]],
    observations: list[dict[str, Any]] | None = None,
    high_halves: dict[str, int] | None = None,
) -> dict[str, Any]:
    vector: dict[str, Any] = {
        "id": vector_id,
        "oracle_entry": _seg(R16_LOAD, entry_off),
        "candidate_entry": _seg(R16_LOAD, entry_off),
        "registers": {name: f"{value & 0xFFFF:#06x}" for name, value in sorted(regs.items())},
        "segments": {name: f"{value & 0xFFFF:#06x}" for name, value in sorted(segs.items())},
        "frame": {"kind": "near16", "target": _seg(R16_LOAD, R16_TRAP_OFF)},
        "memory": memory,
        "observations": observations
        if observations is not None
        else [{"segment": f"{R16_LOAD:#06x}", "offset": f"{R16_OUT:#06x}", "size": 2}],
    }
    if high_halves:
        vector["high_halves"] = {name: f"{value & 0xFFFF:#06x}" for name, value in sorted(high_halves.items())}
    return vector


def _f32_vector(
    vector_id: str, *, entry: int, regs: dict[str, int],
    memory: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    mappings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": vector_id,
        "oracle_entry": f"{entry:#x}",
        "candidate_entry": f"{entry:#x}",
        "registers": {name: f"{value & 0xFFFFFFFF:#x}" for name, value in sorted(regs.items())},
        "memory": memory or [],
        "observations": observations
        if observations is not None
        else [{"address": f"{F32_OUT:#x}", "size": 4}],
        "mappings": mappings or [],
    }


def _window_rows(check: WindowCheck) -> list[dict[str, Any]]:
    """Project per-window admission evidence into the provenance record."""
    return [
        {
            "name": evidence.name,
            "role": evidence.role.value,
            "address": f"{evidence.address:#x}",
            "linear": f"{evidence.linear:#x}",
            "size": evidence.size,
            "admission": evidence.admission.value,
            "provenance": evidence.provenance,
            "origins": list(evidence.origins),
            "bytes": evidence.data.hex(),
            "detail": evidence.detail,
        }
        for evidence in check.windows
    ]


def _r16_window_patches(check: WindowCheck, ss: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert admitted windows into patches plus replaced-cell evidence."""
    patches: list[dict[str, Any]] = []
    replaced: list[dict[str, Any]] = []
    for evidence in check.windows:
        if evidence.role is WindowRole.RETURN_SLOT:
            replaced.append({
                "segment": f"{ss:#06x}", "offset": f"{evidence.address:#06x}", "size": evidence.size,
                "captured_bytes": evidence.data.hex(),
                "replacement": "near16 caller-frame return trap occupies the captured return slot",
            })
        else:
            patches.append({"segment": f"{ss:#06x}", "offset": f"{evidence.address:#06x}", "bytes": evidence.data.hex()})
    return patches, replaced


def _f32_window_patches(check: WindowCheck) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert admitted windows into patches, replaced cells and mappings."""
    patches: list[dict[str, Any]] = []
    replaced: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    for evidence in check.windows:
        if evidence.role is WindowRole.RETURN_SLOT:
            replaced.append({
                "address": f"{evidence.address:#x}", "size": evidence.size,
                "captured_bytes": evidence.data.hex(),
                "replacement": "flat32 harness return trap occupies the captured return slot",
            })
        elif evidence.role is WindowRole.ABOVE:
            # Above the emitted harness stack extent: explicit VECTOR scratch
            # declaration carries the region, a patch seeds the captured bytes.
            mappings.append({"address": f"{evidence.address:#x}", "size": evidence.size, "access": ["read", "write"]})
            patches.append({"address": f"{evidence.address:#x}", "bytes": evidence.data.hex()})
        else:
            patches.append({"address": f"{evidence.address:#x}", "bytes": evidence.data.hex()})
    return patches, replaced, mappings


def _capture_record(
    boundary_linear: int,
    status: str,
    execution_status: str | None,
    instructions: int,
    detail: str,
    fetch_trace: tuple[int, ...],
    trap_linear: int,
    check: WindowCheck,
    replaced: list[dict[str, Any]],
    source: str,
) -> dict[str, Any]:
    """Full typed provenance for one admitted runtime vector."""
    return {
        "boundary_linear": f"{boundary_linear:#x}",
        "status": status,
        "execution_status": execution_status,
        "instructions": instructions,
        "detail": detail,
        "fetch_trace": [f"{address:#x}" for address in fetch_trace],
        "call_edge": {
            "from": f"{fetch_trace[-2]:#x}",
            "to": f"{fetch_trace[-1]:#x}",
        } if len(fetch_trace) >= 2 else None,
        "trap_linear": f"{trap_linear:#x}",
        "windows": _window_rows(check),
        "replaced_cells": replaced,
        "source": source,
    }


def _capture_refusal(
    status: str,
    execution_status: str | None,
    instructions: int,
    detail: str,
    fetch_trace: tuple[int, ...],
    check: WindowCheck | None = None,
) -> dict[str, Any]:
    """Typed refusal record; no vector is emitted in place of evidence."""
    refusal: dict[str, Any] = {
        "status": status,
        "execution_status": execution_status,
        "instructions": instructions,
        "detail": detail,
        "fetch_trace": [f"{address:#x}" for address in fetch_trace],
    }
    if check is not None:
        refusal["window_refusal"] = check.refusal.value if check.refusal is not None else None
        refusal["windows"] = _window_rows(check)
    return refusal


def vector_sha256(vector: dict[str, Any]) -> str:
    """Fingerprint one emitted manifest vector for per-vector accounting."""
    return hashlib.sha256(canonical_json_bytes(vector)).hexdigest()
