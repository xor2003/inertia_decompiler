"""Report contract for independent real16 concrete differential replay.

Layer: dosunit concrete execution reporting.
Responsibility: serialize replayed observations, execution events and image
fingerprints under an explicit ``not_established_by_execution`` proof status.
This module owns the document shape only; CLI wiring is the parent's
integration boundary.

Proposed command: ``dosunit replay-real16 --oracle-exe --candidate-exe
--vectors --instruction-limit --out`` returning 0/1/2 for
agreement/mismatch/incomplete, mirroring ``replay-flat32``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from tools.dosunit.runtime.real16_replay_model import (
    Real16Agreement,
    Real16Comparison,
    Real16Image,
    Real16ReplayPolicy,
    Real16ReplayResult,
    Real16Vector,
    SegOffset,
)

REPORT_SCHEMA: str = "dosunit.real16_replay.v1"


@dataclass(frozen=True, slots=True)
class Real16ReplayRow:
    """A typed comparison and both executed outcomes before JSON serialization."""

    vector_id: str
    comparison: Real16Comparison
    oracle: Real16ReplayResult
    candidate: Real16ReplayResult
    vector: Real16Vector
    oracle_entry: SegOffset
    candidate_entry: SegOffset
    declared_observables: bool = False


def _result_document(result: Real16ReplayResult) -> dict[str, object]:
    """Serialize actual observations without promoting them to a proof."""
    return {
        "status": result.status.value,
        "detail": result.detail,
        "instructions": result.instructions,
        "effective_flags_mask": hex(result.flags_mask),
        "registers": {name: hex(value) for name, value in result.registers},
        "observations": [
            {"linear": hex(address), "bytes": data.hex()}
            for address, data in result.observations
        ],
        "writes": [
            {"linear": hex(address), "bytes": data.hex()}
            for address, data in result.writes
        ],
        "events": [
            {"kind": event.kind.value, "detail": event.detail,
             "linear": hex(event.address), "bytes": event.data.hex()}
            for event in result.events
        ],
    }


def _image_document(image: Real16Image) -> dict[str, object]:
    """Publish the loaded-image fingerprints that bind this report."""
    return {
        "file_sha256": image.file_sha256,
        "image_sha256": image.image_sha256,
        "reloc_sha256": image.reloc_sha256,
        "load_segment": hex(image.load_segment),
        "image_size": image.image_size,
        "bss_size": image.bss_size,
        "code_scope": image.code_scope,
        "code_ranges": [{"address": hex(region.address), "size": region.size}
                        for region in image.code_ranges],
    }


def _policy_document(policy: Real16ReplayPolicy) -> dict[str, object]:
    """Publish the explicit architectural policies the run was bound to."""
    return {
        "a20": policy.a20.value,
        "straddle": policy.straddle.value,
        "high_half_default": policy.high_half_default,
        "max_patch_bytes": policy.max_patch_bytes,
        "max_observation_bytes": policy.max_observation_bytes,
        "initial_memory": "mapped pages start zero; relocated image, patches and caller frame are applied in order",
        "initial_registers": "absent integer registers, high halves and non-CS segments start zero; flags default to 0x2",
        "instruction_model": "Unicorn x86 real mode, integer observations; unsupported effects refuse",
    }


def replay16_report_document(
    *,
    oracle_path: Path,
    candidate_path: Path,
    oracle_image: Real16Image,
    candidate_image: Real16Image,
    rows: list[Real16ReplayRow],
    policy: Real16ReplayPolicy,
    instruction_limit: int,
) -> dict[str, object]:
    """Seal replay rows with input fingerprints and an explicit non-proof status."""
    # The loaded images bind the exact bytes executed. Reading paths again here
    # could report fingerprints for different files after an external change.
    counts = Counter(row.comparison.agreement for row in rows)
    summary = {
        "total": len(rows),
        **{status.value: counts[status] for status in Real16Agreement},
    }
    return {
        "schema": REPORT_SCHEMA,
        "proof_status": "not_established_by_execution",
        "summary": summary,
        "policy": _policy_document(policy),
        "instruction_limit": instruction_limit,
        "scope": (
            "declared concrete vectors on relocated MZ images; segmented "
            "registers and caller frames are explicit; agreement is test "
            "evidence only and never a semantic proof"
        ),
        "inputs": {
            "oracle": {"path": str(oracle_path), "sha256": oracle_image.file_sha256,
                       "image": _image_document(oracle_image)},
            "candidate": {"path": str(candidate_path), "sha256": candidate_image.file_sha256,
                          "image": _image_document(candidate_image)},
        },
        "results": [row_document(row) for row in rows],
    }


def row_document(row: Real16ReplayRow) -> dict[str, object]:
    """Serialize one differential row with both sides' typed outcomes."""
    return {
        "id": row.vector_id,
        "status": row.comparison.agreement.value,
        "oracle": _result_document(row.oracle),
        "candidate": _result_document(row.candidate),
        "initial_state": {
            "oracle_entry": {"segment": hex(row.oracle_entry.segment), "offset": hex(row.oracle_entry.offset)},
            "candidate_entry": {"segment": hex(row.candidate_entry.segment), "offset": hex(row.candidate_entry.offset)},
            "registers": {name: hex(value) for name, value in row.vector.registers},
            "segments": {name: hex(value) for name, value in row.vector.segments},
            "high_halves": {name: hex(value) for name, value in row.vector.high_halves},
            "frame": {"kind": row.vector.frame.kind.value,
                      "target": {"segment": hex(row.vector.frame.target.segment),
                                 "offset": hex(row.vector.frame.target.offset)}},
            "memory": [{"segment": hex(address.segment), "offset": hex(address.offset), "bytes": data.hex()}
                       for address, data in row.vector.memory],
            "observations": [{"segment": hex(address.segment), "offset": hex(address.offset), "size": size}
                             for address, size in row.vector.observations],
        },
        "comparison": {
            "observables": list(row.comparison.observables),
            "observables_source": "declared" if row.declared_observables else "default",
            "flags_mask": hex(row.comparison.flags_mask),
            "reason": row.comparison.reason,
        },
    }


__all__ = [
    "REPORT_SCHEMA",
    "Real16ReplayRow",
    "replay16_report_document",
    "row_document",
]
