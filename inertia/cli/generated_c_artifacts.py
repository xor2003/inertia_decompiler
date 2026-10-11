"""Write accepted generated C separately from CLI diagnostics.

Layer: CLI/fallback/reporting.
Responsibility: persist validated per-function C payloads byte-for-byte for
translation-unit assembly and external compilation gates. This module does not
parse, repair, or infer semantics from rendered C.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from inertia.cli.accepted_payload_integrity import verify_accepted_payload_integrity_8616
from inertia.validation.tail_validation import x86_16_tail_validation_result_preserves_behavior

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def write_generated_function_c(
    output_dir: Path,
    *,
    address: int,
    name: str,
    payload: str,
) -> Path:
    """Atomically write one validated function payload without transforming it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _SAFE_NAME_RE.sub("_", name).strip("._") or f"sub_{address:x}"
    destination = output_dir / f"{address:08x}-{safe_name}.c"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, destination)
    return destination


def write_generated_translation_unit_c(
    output_dir: Path,
    *,
    payload: str,
    complete: bool,
) -> Path:
    """Atomically persist deterministic complete or honest partial batch C."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = "translation-unit.c" if complete else "partial-translation-unit.c"
    destination = output_dir / filename
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, destination)
    counterpart_name = "partial-translation-unit.c" if complete else "translation-unit.c"
    (output_dir / counterpart_name).unlink(missing_ok=True)
    return destination


__all__ = [
    "conditional_tail_snapshot_8616",
    "write_conditional_function_c_8616",
    "write_generated_function_c",
    "write_generated_translation_unit_c",
]


def conditional_tail_snapshot_8616(
    snapshot: Mapping[str, object] | None,
    *, expected_stages: Sequence[str] = ("structuring", "postprocess"),
) -> bool:
    """Recognize complete same-premise conditional comparison receipts.

    This consumes retained comparison results, never creates live proof authority.
    Missing stages, changed effects and differing entry premises fail closed.
    """
    if not isinstance(snapshot, Mapping) or not expected_stages:
        return False
    premise: object = None
    for stage in expected_stages:
        result = snapshot.get(stage)
        if not isinstance(result, Mapping) or result.get("status") != "conditional":
            return False
        if not x86_16_tail_validation_result_preserves_behavior(result):
            return False
        current = result.get("entry_premise")
        if premise is not None and current != premise:
            return False
        premise = current
    return premise is not None


def write_conditional_function_c_8616(
    output_dir: Path, *, address: int, name: str, payload: str,
    snapshot: Mapping[str, object], validated_payload_hash: str | None,
    gcc_checked_payload_hash: str | None,
) -> tuple[Path, Path]:
    """Write checked conditional C with its exact payload hash and premise receipts."""
    integrity = verify_accepted_payload_integrity_8616(
        payload, validated_payload_hash=validated_payload_hash,
        gcc_checked_payload_hash=gcc_checked_payload_hash,
    )
    if not integrity.passed or not conditional_tail_snapshot_8616(snapshot):
        raise ValueError("conditional C requires intact premises and checked payload identity")
    record = {
        "schema": "inertia.conditional-c.v1", "status": "conditional", "merge_gate": "hold",
        "address": address, "name": name, "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "validated_payload_sha256": validated_payload_hash, "compiler_payload_sha256": gcc_checked_payload_hash,
        "tail_validation": dict(snapshot),
    }
    encoded_receipt = json.dumps(record, sort_keys=True, indent=2) + "\n"
    destination = write_generated_function_c(output_dir / "conditional", address=address, name=name, payload=payload)
    receipt = destination.with_suffix(".json")
    temporary = receipt.with_suffix(".json.tmp")
    temporary.write_text(encoded_receipt, encoding="utf-8")
    os.replace(temporary, receipt)
    return destination, receipt
