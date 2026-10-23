"""Transport fresh conditional function evidence without granting acceptance.

Layer: Tooling/gates.
Responsibility: bind one fresh child-emitted ``inertia.conditional-c.v1``
receipt and its unchanged payload to the exact selected binary target and
image. This module transports evidence for a later case-composition consumer;
it never classifies a function as clean, passed or accepted, and it never
re-derives semantics from rendered C, names or stderr text.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from inertia.cli.work_items import FunctionWorkResult

from tools.compiler_toolchain.msc6_function_targets import BinaryFunctionTarget

CONDITIONAL_C_SCHEMA: str = "inertia.conditional-c.v1"
CONDITIONAL_CHILD_EXIT_CODE: int = 5


class ConditionalTransportOrigin(StrEnum):
    """Distinguish direct terminal status from successful worker IPC delivery."""

    DIRECT_CLI = 'direct_cli'
    SERIAL_WORKER = 'serial_worker'
    FULL_SWEEP = 'full_sweep'


class ConditionalTransportStatus(StrEnum):
    """Typed outcome of binding one conditional artifact to its request."""

    BOUND = "bound"
    NOT_CONDITIONAL = "not_conditional"
    CHILD_INCOMPLETE = "child_incomplete"
    STALE_DIRECTORY = "stale_directory"
    MISSING_RECEIPT = "missing_receipt"
    MALFORMED_RECEIPT = "malformed_receipt"
    TARGET_MISMATCH = "target_mismatch"
    PAYLOAD_MISMATCH = "payload_mismatch"
    PREMISE_INCOMPLETE = "premise_incomplete"
    IMAGE_MISMATCH = "image_mismatch"


@dataclass(frozen=True, slots=True)
class ConditionalFunctionTransport:
    """Structured conditional receipt bound to one exact request, or refusal.

    A ``BOUND`` record proves only that this attempt's fresh artifact directory
    contains a receipt matching the requested address and an unchanged payload.
    It is conditional evidence on hold; it is never an acceptance credential.
    """

    status: ConditionalTransportStatus
    address: int | None = None
    name: str | None = None
    c_path: str | None = None
    receipt_path: str | None = None
    binary_sha256: str | None = None
    payload_sha256: str | None = None
    validated_payload_sha256: str | None = None
    compiler_payload_sha256: str | None = None
    tail_validation_json: str | None = None

    @property
    def bound(self) -> bool:
        """Return whether a complete exact receipt was bound this attempt."""
        return self.status is ConditionalTransportStatus.BOUND

    def to_dict(self) -> dict[str, object]:
        """Return JSON-safe evidence for the focused function report."""
        return {
            "status": self.status.value,
            "address": self.address,
            "name": self.name,
            "c_path": self.c_path,
            "receipt_path": self.receipt_path,
            "binary_sha256": self.binary_sha256,
            "payload_sha256": self.payload_sha256,
            "validated_payload_sha256": self.validated_payload_sha256,
            "compiler_payload_sha256": self.compiler_payload_sha256,
            "tail_validation": json.loads(self.tail_validation_json) if self.tail_validation_json is not None else None,
        }


def binary_image_sha256(binary_path: Path | None) -> str | None:
    """Hash the exact requested image when it is readable, else stay honest."""
    if binary_path is None or not binary_path.is_file():
        return None
    try:
        return hashlib.sha256(binary_path.read_bytes()).hexdigest()
    except OSError:
        return None


def _str_field(record: dict[str, object], field: str) -> str | None:
    """Return one optional receipt string field without inventing a value."""
    value = record.get(field)
    return value if isinstance(value, str) else None


def _read_receipt_records(
    artifact_dir: Path,
) -> list[tuple[Path, dict[str, object]]] | ConditionalTransportStatus:
    """Parse every sibling receipt JSON, refusing missing or damaged input."""
    conditional_dir = artifact_dir / "conditional"
    receipt_paths = sorted(conditional_dir.glob("*.json")) if conditional_dir.is_dir() else []
    if not receipt_paths:
        return ConditionalTransportStatus.MISSING_RECEIPT
    records: list[tuple[Path, dict[str, object]]] = []
    for receipt_path in receipt_paths:
        try:
            record = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return ConditionalTransportStatus.MALFORMED_RECEIPT
        if not isinstance(record, dict):
            return ConditionalTransportStatus.MALFORMED_RECEIPT
        records.append((receipt_path, record))
    return records


def _bind_receipt_record(
    records: list[tuple[Path, dict[str, object]]],
    target: BinaryFunctionTarget,
) -> tuple[Path, dict[str, object]] | ConditionalTransportStatus:
    """Select the unique receipt for the exact requested target and gate fields."""
    matching = [item for item in records
                if type(item[1].get("address")) is int and item[1]["address"] == target.address]
    if len(matching) != 1:
        return ConditionalTransportStatus.TARGET_MISMATCH
    receipt_path, record = matching[0]
    if (
        record.get("schema") != CONDITIONAL_C_SCHEMA
        or record.get("status") != "conditional"
        or record.get("merge_gate") != "hold"
        or record.get("name") not in {target.name, target.emitted_name}
    ):
        return ConditionalTransportStatus.TARGET_MISMATCH
    return receipt_path, record


def _payload_matches(record: dict[str, object], c_path: Path) -> bool:
    """Require all three producer/validator/compiler hashes for the consumed bytes."""
    try:
        digest = hashlib.sha256(c_path.read_bytes()).hexdigest()
    except OSError:
        return False
    return all(record.get(key) == digest for key in
               ("payload_sha256", "validated_payload_sha256", "compiler_payload_sha256"))


def _premise_bound(premise: object, target: BinaryFunctionTarget, image_hash: str) -> bool:
    """Check transported metadata against this request; never mint native authority."""
    from inertia.frontend.x86_16.declared_entry_document import parse_declared_function_entry_spec_8616

    if not isinstance(premise, dict) or not isinstance(payload := premise.get("payload"), dict):
        return False
    declaration, domain, boundary = (payload.get(name) for name in ("declaration", "domain", "boundary"))
    if not all(isinstance(value, dict) for value in (declaration, domain, boundary)):
        return False
    assert isinstance(declaration, dict) and isinstance(domain, dict) and isinstance(boundary, dict)
    try:
        spec = parse_declared_function_entry_spec_8616(declaration.get("spec"))
    except ValueError:
        return False
    return bool(
        spec.source_sha256 == image_hash and spec.version == 1
        and spec.range_start == target.address and spec.range_end > spec.range_start
        and (spec.entry_segment << 4) + spec.entry_offset == target.address
        and domain.get("source_sha256") == image_hash
        and domain.get("kind") == "declared_function_entry"
        and type(domain.get("entry_segment")) is int and domain["entry_segment"] == spec.entry_segment
        and type(domain.get("entry_offset")) is int and domain["entry_offset"] == spec.entry_offset
        and type(boundary.get("start")) is int and boundary["start"] == spec.range_start
        and type(boundary.get("size")) is int and boundary["size"] == spec.range_end - spec.range_start
    )


def _snapshot_bound(snapshot: object, target: BinaryFunctionTarget, image_hash: str) -> bool:
    """Keep canonical stage checks and reject hidden extra unsuccessful phases."""
    from inertia.cli.generated_c_artifacts import conditional_tail_snapshot_8616
    from inertia.validation.tail_validation import x86_16_tail_validation_result_preserves_behavior

    if not isinstance(snapshot, dict) or not conditional_tail_snapshot_8616(snapshot):
        return False
    premise = snapshot["structuring"]["entry_premise"]
    for result in snapshot.values():
        if not isinstance(result, dict) or not x86_16_tail_validation_result_preserves_behavior(result):
            return False
        if result.get("status") == "conditional" and result.get("entry_premise") != premise:
            return False
    return _premise_bound(premise, target, image_hash)


def bind_conditional_function_artifact(
    artifact_dir: Path,
    *,
    target: BinaryFunctionTarget,
    binary_path: Path | None,
    child_returncode: int | None,
    expected_binary_sha256: str | None = None,
    stale_directory: bool = False,
    origin: ConditionalTransportOrigin = ConditionalTransportOrigin.DIRECT_CLI,
    decoded_result: FunctionWorkResult | None = None,
) -> ConditionalFunctionTransport:
    """Bind a fresh child conditional receipt to the exact request, or refuse.

    Only a child that emitted the conditional terminal exit in this attempt's
    own fresh artifact directory can be bound. Stale directories, missing or
    malformed receipts, wrong target/address, changed payload bytes and
    incomplete same-premise stage receipts all refuse closed; an earlier
    attempt's payload can never be reused because the directory is per-attempt.
    """
    if stale_directory:
        return ConditionalFunctionTransport(ConditionalTransportStatus.STALE_DIRECTORY)
    if child_returncode is None:
        return ConditionalFunctionTransport(ConditionalTransportStatus.CHILD_INCOMPLETE)
    if not _conditional_delivery_complete(origin, child_returncode, decoded_result):
        return ConditionalFunctionTransport(ConditionalTransportStatus.NOT_CONDITIONAL)
    if expected_binary_sha256 is None or binary_image_sha256(binary_path) != expected_binary_sha256:
        return ConditionalFunctionTransport(ConditionalTransportStatus.IMAGE_MISMATCH)
    records = _read_receipt_records(artifact_dir)
    if isinstance(records, ConditionalTransportStatus):
        return ConditionalFunctionTransport(records)
    selected = _bind_receipt_record(records, target)
    if isinstance(selected, ConditionalTransportStatus):
        return ConditionalFunctionTransport(selected)
    receipt_path, record = selected
    payload_sha256 = _str_field(record, "payload_sha256")
    if payload_sha256 is None:
        return ConditionalFunctionTransport(ConditionalTransportStatus.MALFORMED_RECEIPT)
    c_path = receipt_path.with_suffix(".c")
    if not _payload_matches(record, c_path):
        return ConditionalFunctionTransport(ConditionalTransportStatus.PAYLOAD_MISMATCH)
    tail_validation = record.get("tail_validation")
    stage_failure = _bound_stage_failure(
        tail_validation, target, expected_binary_sha256, decoded_result, payload_sha256,
    )
    if stage_failure is not None:
        return ConditionalFunctionTransport(stage_failure)
    return ConditionalFunctionTransport(
        status=ConditionalTransportStatus.BOUND,
        address=target.address,
        name=str(record["name"]),
        c_path=str(c_path),
        receipt_path=str(receipt_path),
        binary_sha256=expected_binary_sha256,
        payload_sha256=payload_sha256,
        validated_payload_sha256=_str_field(record, "validated_payload_sha256"),
        compiler_payload_sha256=_str_field(record, "compiler_payload_sha256"),
        tail_validation_json=json.dumps(tail_validation, sort_keys=True, separators=(",", ":")),
    )


def _bound_stage_failure(
    snapshot: object, target: BinaryFunctionTarget, image_hash: str,
    result: FunctionWorkResult | None, payload_sha256: str,
) -> ConditionalTransportStatus | None:
    """Bind stage premises and optional serial evidence to the companion receipt."""
    if not _snapshot_bound(snapshot, target, image_hash):
        return ConditionalTransportStatus.PREMISE_INCOMPLETE
    if result is not None and (result.tail_validation != snapshot
            or hashlib.sha256(result.payload.encode()).hexdigest() != payload_sha256):
        return ConditionalTransportStatus.PAYLOAD_MISMATCH
    return None


def _conditional_delivery_complete(
    origin: ConditionalTransportOrigin, returncode: int, result: FunctionWorkResult | None,
) -> bool:
    """Keep observed exits exact and require decoded conditional worker evidence."""
    from inertia.cli.accepted_payload_integrity import verify_function_work_result_payload_integrity_8616
    from inertia.cli.work_items import FunctionWorkResult, WorkItemStatus

    if origin is ConditionalTransportOrigin.DIRECT_CLI:
        return returncode == CONDITIONAL_CHILD_EXIT_CODE and result is None
    if origin is ConditionalTransportOrigin.FULL_SWEEP:
        return (returncode == CONDITIONAL_CHILD_EXIT_CODE and isinstance(result, FunctionWorkResult)
                and result.status == WorkItemStatus.CONDITIONAL.value
                and verify_function_work_result_payload_integrity_8616(result).passed)
    if origin is not ConditionalTransportOrigin.SERIAL_WORKER:
        return False
    return (returncode == 0 and isinstance(result, FunctionWorkResult)
            and result.status == WorkItemStatus.CONDITIONAL.value
            and verify_function_work_result_payload_integrity_8616(result).passed)
