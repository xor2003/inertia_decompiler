"""Binary block coverage retained across flat32 proof retries.

Layer: dosunit binary evidence.
Responsibility: preserve every discovered member block's physical address,
byte size and — for lanes that lowered the compared block — the retained
source-bound SSA event evidence for independent environment admission after
proof composition.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tools.dosunit.compare.flat32_call_contracts import _LiftedBlock


def environment_parts(blocks: Mapping[int, Any]) -> list[dict[str, Any]]:
    """Record exact VEX member ranges at the foreign driver-block boundary.

    Superblock outputs cannot substitute for these original byte ranges.
    Consumers independently scan the recorded bytes and IR before publication.

    When the owning lane kept the block's lowered SSA part — composed-call
    and call-loop ``_LiftedBlock`` records do — its materialized
    ``assignments``/``outputs`` are retained on the record by reference,
    bounded by the lane's own per-block assignment limit: no relift, no
    recursive copy.  The receipt is attached only when the part's own
    ``entry``/``source`` binding matches the scanned block range; a part
    that exists but cannot be tied to those bytes marks
    ``receipt_bound=False`` so the scan refuses under a declared ordered-I/O
    contract instead of silently passing on unbound evidence.  Blocks
    without retained SSA (CFG discovery lanes) keep emitting bare ranges.
    """
    parts: list[dict[str, Any]] = []
    for address, block in sorted(blocks.items()):
        record: dict[str, Any] = {
            "entry": {"linear": hex(address)},
            "source": {"machine_code_size": block.irsb.size},
        }
        # Only the owned lifted-block contract carries compared SSA evidence.
        # Foreign CFG discovery blocks retain bare ranges and cannot attest I/O.
        if isinstance(block, _LiftedBlock):
            _retain_part_receipt(record, block.part, address, block.irsb.size)
        parts.append(record)
    return parts


def _retain_part_receipt(
    record: dict[str, Any], part: object, address: int, size: int
) -> None:
    """Attach a block's retained SSA receipt only when it is source-bound.

    The receipt is accepted only when the part's own ``entry.linear`` and
    ``source.machine_code_size`` match the scanned block — a retained SSA
    document that cannot be tied to those exact bytes marks the record
    ``receipt_bound=False`` so the environment scan treats it as an
    integrity failure rather than absent evidence.  ``assignments`` and
    ``outputs`` are carried verbatim (including malformed values), so the
    scan's ``part_io_events`` extraction remains the single owner of event
    shape validation and nothing is normalized away here.
    """
    if not isinstance(part, Mapping):
        record["receipt_bound"] = False
        return
    part_entry = part.get("entry")
    part_source = part.get("source")
    bound = (
        isinstance(part_entry, Mapping)
        and part_entry.get("linear") == hex(address)
        and isinstance(part_source, Mapping)
        and part_source.get("machine_code_size") == size
    )
    if not bound:
        record["receipt_bound"] = False
        return
    for key in ("assignments", "outputs"):
        if key in part:
            record[key] = part[key]
